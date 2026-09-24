#!/usr/bin/env python3
"""Select the findings the AI consensus engine is asked about.

    python3 tools/engine-input.py --report report.json -o engine-findings.json

The scan workflow used to hand the engine every finding in the report with
`jq '.findings'`. The engine rates whatever it is given as a risk to remediate,
and on a real run that meant six of eight analyses were of good news — DMARC at
`p=reject`, published DKIM keys, an SPF record ending in `-all` — and their
"remediation" was advice to weaken each one. On a domain with nothing wrong,
that advice is the headline of the client's AI panel.

The rule lives in `dnsguard.consensus.for_engine`, and the store step pairs the
engine's answers against the same rule, so what is sent and what is matched up
afterwards cannot drift apart. This tool only applies it.

Writes a JSON list — possibly empty — and prints what was sent and what was
withheld, so a run's log says which findings the engine saw. Exit codes: 0
written, 2 a usage problem.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dnsguard.consensus import for_engine  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dnsguard-engine-input")
    parser.add_argument("--report", required=True, help="the scan report to read findings from")
    parser.add_argument("-o", "--output", required=True, help="where to write the JSON list")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    report_path = pathlib.Path(args.report)
    if not report_path.is_file():
        print(f"no such report: {report_path}", file=sys.stderr)
        return 2
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"{report_path} is not valid JSON: {exc}", file=sys.stderr)
        return 2

    findings = report.get("findings") if isinstance(report, dict) else None
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    selected = for_engine(findings)

    pathlib.Path(args.output).write_text(
        json.dumps(selected, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )

    withheld = [f for f in findings if f not in selected]
    print(f"{len(selected)} of {len(findings)} finding(s) sent to the engine")
    for finding in withheld:
        why = (
            "inconclusive"
            if str(finding.get("confidence", "")).lower() == "inconclusive"
            else "informational, nothing to do"
        )
        print(f"  withheld  {finding.get('severity', '?'):8} {finding.get('title', '')}  ({why})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
