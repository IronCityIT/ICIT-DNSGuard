#!/usr/bin/env python3
"""Run one maintenance pass: refresh feeds, expire exceptions, evaluate alerts.

This is the loop the control plane needs to stay correct, and it is meant to run
unattended — from cron, a Cloud Scheduler job, or a Jenkins timer.

  python3 tools/maintain.py --data-dir ./data --all
  python3 tools/maintain.py --data-dir ./data --tenant acme --fetch
  python3 tools/maintain.py --data-dir ./data --tenant acme --dry-run

Fetching is OFF unless --fetch is given. A maintenance pass that quietly reached
out to every registered feed URL the first time someone ran it would be a
surprise, and feed URLs are operator-supplied — the fetch guard in
dnsguard.fetcher is what makes that safe, and it should be opted into knowingly.

Exit codes: 0 every tenant clean, 1 at least one tenant reported an error,
2 a usage problem. So cron mail arrives only when something is actually wrong.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dnsguard.alerts import AlertService  # noqa: E402
from dnsguard.approvals import ApprovalGate  # noqa: E402
from dnsguard.audit import AuditLog  # noqa: E402
from dnsguard.clock import Clock  # noqa: E402
from dnsguard.exceptions_policy import ExceptionService  # noqa: E402
from dnsguard.feeds import FeedFetcher, FeedRegistry  # noqa: E402
from dnsguard.fetcher import HttpFetcher  # noqa: E402
from dnsguard.maintenance import MaintenanceRunner  # noqa: E402
from dnsguard.resilience import BreakerRegistry  # noqa: E402
from dnsguard.store import JsonFileStore  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dnsguard-maintain")
    parser.add_argument("--data-dir", required=True, help="control-plane document root")
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--tenant", help="run for one tenant")
    scope.add_argument("--all", action="store_true", help="run for every tenant found")
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="actually refresh threat feeds over the network (off by default)",
    )
    parser.add_argument(
        "--allow-insecure-feeds",
        action="store_true",
        help="permit plain-http feed URLs; they can be rewritten in transit",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report what a pass would cover without refreshing, expiring or alerting",
    )
    parser.add_argument("--json", action="store_true", help="emit the raw report as JSON")
    return parser


def build_runner(args: argparse.Namespace) -> MaintenanceRunner:
    store = JsonFileStore(args.data_dir)
    clock = Clock()
    audit = AuditLog(store, clock)
    gate = ApprovalGate(store=store, audit=audit, clock=clock)
    registry = FeedRegistry(store, clock)
    breakers = BreakerRegistry(clock=clock)

    fetcher = None
    if args.fetch:
        fetcher = FeedFetcher(
            registry=registry,
            fetch=HttpFetcher(allow_insecure=args.allow_insecure_feeds),
            clock=clock,
            breakers=breakers,
        )

    return MaintenanceRunner(
        registry=registry,
        fetcher=fetcher,
        exceptions=ExceptionService(store=store, audit=audit, gate=gate, clock=clock),
        alerts=AlertService(store=store, audit=audit, clock=clock),
        gate=gate,
        audit=audit,
        clock=clock,
    )


def describe(report: dict[str, Any]) -> str:
    """A line a human reading cron output can act on."""
    tenant = report["tenant_id"]
    if not report.get("ok", False):
        return f"{tenant}: PROBLEM — " + "; ".join(report.get("errors", ["unknown"]))

    feeds = report.get("feeds", {})
    parts = []
    if feeds.get("attempted"):
        refreshed = len(feeds.get("refreshed", []))
        unchanged = len(feeds.get("unchanged", []))
        parts.append(f"{refreshed} feed(s) checked, {unchanged} unchanged")
        if feeds.get("stale_after_refresh"):
            parts.append(f"STILL STALE: {', '.join(feeds['stale_after_refresh'])}")
    else:
        parts.append("feeds not fetched")

    expired = report.get("expired_exceptions", [])
    if expired:
        parts.append(f"{len(expired)} exception(s) expired")
    alerts = report.get("alerts", [])
    if alerts:
        parts.append(f"{len(alerts)} alert(s) raised")
    return f"{tenant}: ok — " + "; ".join(parts)


def dry_run(runner: MaintenanceRunner, tenant_ids: list[str]) -> list[dict[str, Any]]:
    """What a pass would touch, without touching it."""
    out = []
    for tenant_id in tenant_ids:
        health = runner.registry.health(tenant_id)
        out.append(
            {
                "tenant_id": tenant_id,
                "dry_run": True,
                "ok": True,
                "feeds": {
                    "attempted": False,
                    "reason": "dry run",
                    "registered": [row["feed_id"] for row in health],
                    "stale": [row["feed_id"] for row in health if row["stale"]],
                },
                "exceptions_lapsed": [
                    record.id
                    for record in runner.exceptions.all(tenant_id)
                    if record.state == "active" and runner.exceptions._expired(record)
                ],
                "alert_rules": len(runner.alerts.rules(tenant_id)),
                "audit_chain": runner.audit.verify(tenant_id),
            }
        )
    return out


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not pathlib.Path(args.data_dir).is_dir():
        print(f"no such data directory: {args.data_dir}", file=sys.stderr)
        return 2

    runner = build_runner(args)
    tenant_ids = [args.tenant] if args.tenant else runner.registry.store.tenants()
    if not tenant_ids:
        print("no tenants found", file=sys.stderr)
        return 0

    reports = dry_run(runner, tenant_ids) if args.dry_run else runner.run_all(tenant_ids)

    if args.json:
        print(json.dumps(reports, indent=2, default=str))
    else:
        for report in reports:
            print(describe(report))

    return 1 if any(not report.get("ok", False) for report in reports) else 0


if __name__ == "__main__":
    raise SystemExit(main())
