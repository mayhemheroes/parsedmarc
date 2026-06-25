#!/usr/bin/env bash
#
# mayhem/build.sh — build the parsedmarc Atheris fuzz harness (Python).
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The org base image
# (ghcr.io/mayhemheroes/base) exports the build contract (CC, SANITIZER_FLAGS, DEBUG_FLAGS, SRC, …)
# and ships python3 + pip + clang/llvm.
#
# parsedmarc is fuzzed with Google's Atheris (a coverage-guided Python fuzzer that emulates the
# libFuzzer CLI), so the harness is a Python script. Mayhem requires the target `cmd` to be an ELF
# (it rejects script/wrapper targets), so we build a thin ELF LAUNCHER that execs
# `python3 <harness>.py`, forwarding all libFuzzer args. exec() replaces the process image, so the
# running process IS the Atheris/libFuzzer harness — transparent to Mayhem.
#
# Air-gapped (SPEC §6.5): the first (online) run bakes a wheelhouse (the parsedmarc wheel + ALL its
# runtime deps + atheris); the offline PATCH re-run installs from it with --no-index, never reaching
# PyPI. parsedmarc has heavy deps (dnspython, mailsuite, lxml, boto3, azure-*, elasticsearch, …) —
# they are all pre-baked into the wheelhouse so `import parsedmarc` works offline.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs from the ENVIRONMENT (overridable) with sane defaults. SANITIZER_FLAGS is referenced
# for contract parity; it does NOT apply to the fuzzed code here — Atheris instruments the *Python*
# bytecode at runtime (no compiled project to sanitize). `=` (not `:=`) honors an explicit empty
# --build-arg. DEBUG_FLAGS carries DWARF (< 4) onto the ELF launchers so Mayhem's triage can read
# them; clang-19's plain -g emits DWARF-5, hence the explicit -gdwarf-3.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${SRC:=/mayhem}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC SRC MAYHEM_JOBS

# hatchling derives the version from parsedmarc/constants.py (a static __version__), so no VCS/tag
# dependency — nothing to pin for a reproducible/shallow build.

cd "$SRC"
HARNESS_DIR="$SRC/mayhem"
WHEELHOUSE="$HARNESS_DIR/wheelhouse"
PIP="python3 -m pip"

# 1) Python deps — air-gapped via a baked wheelhouse. First (online) run builds the parsedmarc wheel
#    from the in-tree source + downloads every runtime dep (and atheris) into the wheelhouse; the
#    offline re-run reuses it. A pinned atheris keeps the engine stable across rebuilds.
mkdir -p "$WHEELHOUSE"
if [ ! -f "$WHEELHOUSE/.populated" ]; then
  $PIP wheel --wheel-dir "$WHEELHOUSE" "$SRC" "atheris==3.1.0"
  touch "$WHEELHOUSE/.populated"
fi
# Install offline from the wheelhouse (idempotent: a satisfied requirement is a no-op, no network).
$PIP install --no-index --find-links "$WHEELHOUSE" --user --break-system-packages \
  parsedmarc "atheris==3.1.0"

# 2) Build the ELF launcher (Mayhem target). A tiny clang-compiled shim (ELF + DWARF<4 via
#    $DEBUG_FLAGS) that exec()s python3 on the baked-in harness. Sanitizing a 30-line exec shim is
#    pointless (it would drag the ASan runtime into the python child), so the launcher is built
#    WITHOUT $SANITIZER_FLAGS but WITH $DEBUG_FLAGS. The Python code is instrumented by Atheris.
#
# 2a) Parity target — the original mayhemheroes harness (mayhem/fuzz_parse_report.py):
#     parsedmarc.parse_report_file over an attacker-controlled report blob.
$CC $DEBUG_FLAGS -O1 \
    -DSCRIPT_PATH="\"$HARNESS_DIR/fuzz_parse_report.py\"" \
    "$HARNESS_DIR/launcher.c" -o "$SRC/fuzz_parse_report"
# Standalone run-once reproducer (Atheris replays a single file argument).
cp -f "$SRC/fuzz_parse_report" "$SRC/fuzz_parse_report-standalone"

# 3) Build the ELF launcher for the behavioral oracle (test.sh runs this — a /mayhem-rooted ELF so
#    the anti-reward-hack sabotage check can neuter it).
$CC $DEBUG_FLAGS -O1 \
    -DORACLE_PATH="\"$HARNESS_DIR/oracle.py\"" \
    "$HARNESS_DIR/oracle_launch.c" -o "$SRC/parsedmarc_oracle"

# 4) Fail the build early if the harnessed API drifted (atheris + the package must import cleanly,
#    and the fuzzed entry point must still exist).
python3 -c "import atheris, parsedmarc, parsedmarc.utils; assert hasattr(parsedmarc, 'parse_report_file'); assert hasattr(parsedmarc, 'ParserError')"

echo ">> build.sh done: $SRC/fuzz_parse_report (Mayhem target), $SRC/parsedmarc_oracle (oracle)"
