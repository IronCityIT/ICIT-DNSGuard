#!/usr/bin/env python3
"""DNS Guard scan entry point.

Runs the selected modules against a domain and writes a client-facing report.
This is what the scan workflow invokes; it is the same registry and the same
module selection the dashboard's picker offers, so a scan run from CI and a scan
described in the UI are the same scan.

  python3 tools/scan.py --domain example.com --client Acme --output ./reports
  python3 tools/scan.py --domain example.com --group email
  python3 tools/scan.py --domain example.com --modules spf_audit,dmarc_audit
  python3 tools/scan.py --list-modules
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
for path in (str(ROOT), str(ROOT / "module_framework")):
    if path not in sys.path:
        sys.path.insert(0, path)

import registry  # noqa: E402
from targets import parse_targets  # noqa: E402

from dnsguard.report import build, make_scan_id  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dnsguard-scan", description="Iron City DNS Guard")
    parser.add_argument("-d", "--domain", help="domain, hostname or URL to assess")
    parser.add_argument("-c", "--client", default="Unknown", help="client name")
    parser.add_argument(
        "--client-id", default="", help="tenant id (defaults to a slug of --client)"
    )
    parser.add_argument("-o", "--output", default="", help="directory to write the report into")
    parser.add_argument("--scan-id", default="", help="scan id (supplied by the trigger function)")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--modules", help="comma list of module names")
    selection.add_argument(
        "--group",
        default="standard",
        help="named group: quick | standard | deep | email | surface | performance",
    )
    parser.add_argument("--list-modules", action="store_true", help="print the catalogue and exit")
    parser.add_argument(
        "--nameservers",
        default="",
        help=(
            "comma list of resolvers to query instead of the host's. Worth setting: some "
            "resolvers do not report NXDOMAIN for names that do not exist, and checks that "
            "distinguish absence from misconfiguration report inconclusive rather than guess"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate the target and module selection, then stop without querying anything",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    found = registry.discover("modules")

    if args.list_modules:
        print(
            json.dumps(
                {"modules": registry.catalog(found), "groups": sorted(registry.all_groups(found))},
                indent=2,
            )
        )
        return 0

    if not args.domain:
        print("--domain is required", file=sys.stderr)
        return 2

    targets = parse_targets([args.domain])
    if not targets:
        print(f"no usable target in {args.domain!r}", file=sys.stderr)
        return 2

    try:
        selected = registry.select(
            found,
            modules=[m.strip() for m in args.modules.split(",")] if args.modules else None,
            group=None if args.modules else args.group,
        )
    except KeyError as exc:
        print(f"selection error: {exc}", file=sys.stderr)
        return 2

    scan_id = args.scan_id or make_scan_id(args.domain)
    started = time.perf_counter()
    findings: list[Any] = []
    errors: list[str] = []
    ctx: dict[str, Any] = {"client": args.client, "scan_id": scan_id}
    if args.nameservers:
        ctx["nameservers"] = [ns.strip() for ns in args.nameservers.split(",") if ns.strip()]

    if not args.dry_run:
        for target in targets:
            for module in selected:
                if not module.applies_to(target.kind):
                    continue
                try:
                    findings.extend(module.run(target, ctx))
                except Exception as exc:  # noqa: BLE001 - one module must not end the scan
                    # A module that fails is a gap in the report, not a failed
                    # scan. Recorded so the gap is visible rather than silent.
                    errors.append(f"{module.name}: {exc}")
                    print(f"module {module.name} failed: {exc}", file=sys.stderr)

    report = build(
        findings,
        domain=targets[0].value if targets[0].kind != "url" else args.domain,
        client_name=args.client,
        client_id=args.client_id,
        scan_id=scan_id,
        modules_run=[m.name for m in selected],
        duration_seconds=time.perf_counter() - started,
        errors=errors,
    )
    report["dry_run"] = args.dry_run

    payload = json.dumps(report, indent=2, default=str)
    if args.output:
        directory = pathlib.Path(args.output)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"dnsguard-{report['domain']}-{scan_id}.json"
        path.write_text(payload, encoding="utf-8")
        print(f"Report: {path}")
    else:
        print(payload)

    print(
        f"  domain={report['domain']} grade={report['email_security']['grade']} "
        f"risk={report['overall_risk_score']}/100 findings={len(report['findings'])} "
        f"modules={len(selected)}",
        file=sys.stderr,
    )
    # A scan that produced nothing at all is a failure worth surfacing in CI;
    # a scan whose individual modules had partial errors is not.
    return 1 if not args.dry_run and not findings and errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
