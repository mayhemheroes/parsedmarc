#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the parsedmarc behavioral oracle that mayhem/build.sh produced.
#
# It runs the known-answer self-test via the /mayhem/parsedmarc_oracle launcher (a NON-system ELF, so
# the verify-repo §6.3 sabotage neuter can trip it) and asserts that parsedmarc parsed a real DMARC
# aggregate report (the RFC 9990 sample) to specific decoded values. A no-op / exit(0) PATCH FAILS
# this (the expected SELFTEST_PASS marker + values are absent). Emits a CTRF (https://ctrf.io)
# summary. It never builds.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

ORACLE="$SRC/parsedmarc_oracle"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -x "$ORACLE" ]; then
  echo "FAIL: $ORACLE missing — mayhem/build.sh did not build the oracle launcher" >&2
  emit_ctrf "parsedmarc-knownanswer" 0 1
  exit 1
fi

# The oracle asserts behavior internally and prints a marker carrying the asserted values ONLY when
# every assertion holds; any failure (or a neutered binary) yields no marker.
out="$("$ORACLE" 2>&1)"; rc=$?
echo "$out"

passed=0; failed=0
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'SELFTEST_PASS org=Sample Reporter report_id=3v98abbp8ya9n3va8yr8oa3ya p=quarantine ip=192.0.2.123 count=123'; then
  passed=1
else
  failed=1
  echo "FAIL: parsedmarc oracle did not assert the expected behavior (rc=$rc)" >&2
fi

emit_ctrf "parsedmarc-knownanswer" "$passed" "$failed"
