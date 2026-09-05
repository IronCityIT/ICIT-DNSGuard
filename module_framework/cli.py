"""
cli.py — the CLI-first entry point (access gate lives here).

  python -m module_framework.cli --list-modules
  python -m module_framework.cli --group deep     --targets 10.0.0.0/30,example.com
  python -m module_framework.cli --modules a,b     --targets-file targets.txt
  python -m module_framework.cli --group standard  --targets https://app.example.com \
      --client acme --scan-id 2026-07-08-01

Output is JSON on stdout — this is what gets POSTed to consensus-engine and then
the storeScanResults Cloud Function. Same JSON contract for every tool.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

# The framework is importable two ways: `python3 cli.py` from inside
# module_framework/ (how the scan workflow invokes it) and `python -m
# module_framework.cli` from the repo root (how a developer does). Only one of
# those puts module_framework on the path, and neither puts BOTH it and the repo
# root there — which the control-plane package needs. Fix both, once, here.
_HERE = pathlib.Path(__file__).resolve().parent
for _path in (str(_HERE), str(_HERE.parent)):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import registry  # noqa: E402
from targets import parse_targets  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dnsguard-scan")
    p.add_argument(
        "--targets",
        action="append",
        default=[],
        help="IP, CIDR, URL, domain or hostname (comma-separated, repeatable)",
    )
    p.add_argument(
        "--targets-file",
        action="append",
        default=[],
        help="file of targets, one per line (# comments allowed)",
    )
    sel = p.add_mutually_exclusive_group()
    sel.add_argument("--modules", help="comma list of module names to run")
    sel.add_argument("--group", help="named group: quick | standard | deep | ...")
    p.add_argument("--client", default="", help="client identifier (multi-tenant)")
    p.add_argument("--scan-id", default="", help="unique scan id")
    p.add_argument(
        "--list-modules", action="store_true", help="print available modules and groups, then exit"
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="validate targets and module selection, then exit without "
        "running any module (no network traffic, no findings)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    reg = registry.discover("modules")

    if args.list_modules:
        print(
            json.dumps(
                {"modules": registry.catalog(reg), "groups": sorted(registry.all_groups(reg))},
                indent=2,
            )
        )
        return 0

    targets = parse_targets(args.targets, args.targets_file)
    if not targets:
        print("no valid targets", file=sys.stderr)
        return 2

    try:
        mods = registry.select(
            reg,
            modules=[m.strip() for m in args.modules.split(",")] if args.modules else None,
            group=args.group,
        )
    except KeyError as e:
        print(f"selection error: {e}", file=sys.stderr)
        return 2

    ctx = {"client": args.client, "scan_id": args.scan_id}
    findings: list[dict] = []
    # THE GUARD. m.run() is the only place a module touches the network, so a dry
    # run stops exactly here — after targets and selection have been validated for
    # real, before anything reaches a live host. Emitting an empty findings set is
    # the honest result: nothing was scanned, so nothing was found.
    if not args.dry_run:
        for t in targets:
            for m in mods:
                if m.applies_to(t.kind):
                    findings.extend(f.to_dict() for f in m.run(t, ctx))
    else:
        print(
            f"dry-run: validated {len(targets)} target(s) and "
            f"{len(mods)} module(s); no module executed",
            file=sys.stderr,
        )

    # Schema is identical either way so every downstream consumer (workflow jq,
    # payload builder, dashboard) exercises the same path in a dry run.
    print(
        json.dumps(
            {
                "client": args.client,
                "scan_id": args.scan_id,
                "modules_run": [m.name for m in mods],
                "target_count": len(targets),
                "dry_run": args.dry_run,
                "findings": findings,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
