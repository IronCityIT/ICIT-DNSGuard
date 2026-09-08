#!/usr/bin/env python3
"""Fold the AI consensus into a scan report, ready for storage.

    python3 tools/enrich.py --report report.json --consensus-b64-file b64.txt -o payload.json
    CONSENSUS_B64=... python3 tools/enrich.py --report report.json -o payload.json

The scan workflow calls the shared consensus engine, which hands back a
base64-encoded analysis as its `consensus_b64` output. Until now the store step
recorded only whether that job had succeeded and discarded the analysis itself,
so the dashboard's AI panel — which looks for `ai_consensus` — never had anything
to render.

This reads the engine's output and merges it in. It does no analysis of its own:
the fleet rule is one source of truth for AI, and this is a consumer of it.

**Vendor names are removed.** The engine's per-model responses carry the provider
and model that produced them; a client-facing report never names underlying
tools. The counts survive, because "13 of 15 models agreed" is the useful part
and names nobody.

Exit codes: 0 written, 2 a usage problem. A failed or empty analysis is not an
error — the report is written through unchanged, and the dashboard correctly
hides a panel it has no data for.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dnsguard.consensus import attach, decode  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dnsguard-enrich")
    parser.add_argument("--report", required=True, help="the scan report to enrich")
    parser.add_argument(
        "--consensus-b64-file",
        help="file holding the engine's consensus_b64 output; "
        "otherwise read from the CONSENSUS_B64 environment variable",
    )
    parser.add_argument("-o", "--output", required=True, help="where to write the merged payload")
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

    if args.consensus_b64_file:
        path = pathlib.Path(args.consensus_b64_file)
        # Missing is not fatal: the enrichment is optional and the scan is not.
        raw = path.read_text(encoding="utf-8") if path.is_file() else ""
    else:
        raw = os.environ.get("CONSENSUS_B64", "")

    entries = decode(raw)
    enriched = attach(report, entries)

    pathlib.Path(args.output).write_text(
        json.dumps(enriched, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )

    if "ai_consensus" in enriched:
        summary = enriched["ai_consensus"]
        print(
            f"consensus merged: {summary.get('consensus_severity')} at "
            f"{summary.get('confidence_percent')}% "
            f"({summary.get('successful_models')}/{summary.get('total_models')} models, "
            f"{summary.get('analysed_findings')} finding(s) analysed)"
        )
    else:
        # Said plainly rather than left to be inferred from a silent success: a
        # scan whose enrichment did not run should look different in the log
        # from one where it did.
        print("no consensus to merge - the report is stored unenriched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
