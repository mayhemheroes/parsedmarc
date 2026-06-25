#!/usr/bin/env python3
"""Atheris harness for parsedmarc's report-parsing surface.

Drives parsedmarc.parse_report_file — the public entry point that auto-detects and parses DMARC
aggregate / failure / SMTP-TLS reports (raw XML, gzip/zip-compressed XML, or a full report email).
Everything runs offline (offline=True, dns_timeout=0) so no network is touched while fuzzing.

NOTE (API drift fix): the original mayhemheroes harness passed `parallel=True`, but
parse_report_file no longer accepts that keyword (the signature is now keyword-only and has no
`parallel` parameter), so it has been dropped — otherwise every input would raise TypeError.
"""

import atheris
import sys
import fuzz_helpers

with atheris.instrument_imports(include=["parsedmarc"]):
    import parsedmarc
    import parsedmarc.utils


def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
        strip = fdp.ConsumeBool()

        parsedmarc.parse_report_file(
            fdp.ConsumeRemainingBytes(),
            dns_timeout=0,
            strip_attachment_payloads=strip,
            offline=True,
        )
    except parsedmarc.ParserError:
        return -1


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
