#!/usr/bin/env python3
"""Behavioral oracle (known-answer test) for parsedmarc.

Exercises the SAME parsing pipeline the fuzzer drives — parsedmarc.parse_report_file on a real DMARC
aggregate report (the RFC 9990 Appendix B sample shipped in samples/aggregate/rfc9990-sample.xml) —
and ASSERTS specific decoded values (org name, report id, published policy, the per-source record,
and the DKIM/SPF auth results). A no-op / neutered program (which prints nothing) FAILS test.sh,
because the SELFTEST_PASS marker and its asserted values are only printed when every assertion holds.

Runs fully offline (offline=True, always_use_local_files=True) so no network/DNS is touched.
"""
import os
import sys
from typing import cast

import parsedmarc
from parsedmarc.types import AggregateReport

# Resolve the sample relative to the repo root (/mayhem), regardless of CWD.
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SAMPLE = os.path.join(ROOT, "samples", "aggregate", "rfc9990-sample.xml")

# 1) Parse a known aggregate report through the public entry point the fuzzer drives.
result = parsedmarc.parse_report_file(
    SAMPLE, always_use_local_files=True, offline=True
)
assert result["report_type"] == "aggregate", result["report_type"]
report = cast(AggregateReport, result["report"])

# 2) Assert report metadata.
assert report["xml_schema"] == "1.0", report["xml_schema"]
md = report["report_metadata"]
assert md["org_name"] == "Sample Reporter", md["org_name"]
assert md["org_email"] == "report_sender@example-reporter.com", md["org_email"]
assert md["report_id"] == "3v98abbp8ya9n3va8yr8oa3ya", md["report_id"]

# 3) Assert the published policy.
pp = report["policy_published"]
assert pp["domain"] == "example.com", pp["domain"]
assert pp["p"] == "quarantine", pp["p"]
assert pp["sp"] == "none", pp["sp"]
assert pp["adkim"] == "r", pp["adkim"]
assert pp["aspf"] == "r", pp["aspf"]

# 4) Assert the single record and its evaluated policy.
assert len(report["records"]) == 1, len(report["records"])
rec = report["records"][0]
assert rec["source"]["ip_address"] == "192.0.2.123", rec["source"]["ip_address"]
assert rec["count"] == 123, rec["count"]
assert rec["policy_evaluated"]["disposition"] == "pass", rec["policy_evaluated"]["disposition"]
assert rec["policy_evaluated"]["dkim"] == "pass", rec["policy_evaluated"]["dkim"]
assert rec["policy_evaluated"]["spf"] == "fail", rec["policy_evaluated"]["spf"]

# 5) Assert the DKIM / SPF auth results.
dkim = rec["auth_results"]["dkim"][0]
assert dkim["domain"] == "example.com", dkim["domain"]
assert dkim["selector"] == "abc123", dkim["selector"]
assert dkim["result"] == "pass", dkim["result"]
spf = rec["auth_results"]["spf"][0]
assert spf["domain"] == "example.com", spf["domain"]
assert spf["result"] == "fail", spf["result"]

print(
    "SELFTEST_PASS org=%s report_id=%s p=%s ip=%s count=%d"
    % (md["org_name"], md["report_id"], pp["p"], rec["source"]["ip_address"], rec["count"])
)
sys.exit(0)
