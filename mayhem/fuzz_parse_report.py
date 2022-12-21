#!/usr/bin/env python3

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

        parsedmarc.parse_report_file(fdp.ConsumeRemainingBytes(), dns_timeout=0, strip_attachment_payloads=strip,
                                     offline=True, parallel=True)
    except parsedmarc.ParserError:
        return -1

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
