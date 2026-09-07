#!/usr/bin/env python3
"""Re-check the aliases published under our own domains, against a recorded baseline.

    python3 tools/check-dns-exposure.py --baseline dns-baseline.json
    python3 tools/check-dns-exposure.py --domain ironcityit.com
    python3 tools/check-dns-exposure.py --baseline dns-baseline.json --json

Read-only, and it never touches the scanned host: this runs the product's own
`alias_takeover` module, which uses recursive resolvers only and never attempts
to claim, register or reserve anything.

Exit codes, which are distinct because they need different responses:

  0  every alias is as recorded, or better
  1  at least one alias is **worse** than recorded, or a new bad one appeared
  2  nothing could be verified — the resolver's negative answers could not be
     trusted, so a pass would be a false one; or, with
     --require-certificate-transparency, discovery covered less than it was asked to
  3  a usage problem

The known and recorded state does not fail. A gate that stays red for a condition
the author of an unrelated pull request cannot fix is a gate that gets ignored.
An improvement does not fail either, but it is reported with a prompt to tighten
the baseline, so a gain that was actually made gets held.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parent.parent
for path in (str(ROOT), str(ROOT / "module_framework")):
    if path not in sys.path:
        sys.path.insert(0, path)

from targets import parse_targets  # noqa: E402

from dnsguard.dns_exposure import compare, summarise  # noqa: E402


# The resolver defaults to the host's own. In CI that is the right choice — a
# gate that depends on a third party has its own failure mode — and when the
# host's resolver turns out to rewrite negative answers the check reports
# `unverified` instead of a pass. --nameservers is the fix for that case.
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="check-dns-exposure")
    scope = parser.add_mutually_exclusive_group(required=True)
    scope.add_argument("--baseline", help="path to the recorded alias baseline")
    scope.add_argument("--domain", help="check one domain with no baseline to compare against")
    parser.add_argument(
        "--nameservers",
        default="",
        help="comma list of resolvers to use instead of the host's",
    )
    parser.add_argument(
        "--no-certificate-transparency",
        action="store_true",
        help="probe conventional names only; do not ask a third party what names exist",
    )
    parser.add_argument(
        "--require-certificate-transparency",
        action="store_true",
        help=(
            "treat a certificate-transparency lookup that did not answer as a failure. Off by "
            "default: it would put a third party's uptime in the path of every pull request. "
            "Reduced coverage is reported either way"
        ),
    )
    parser.add_argument("--json", action="store_true", help="emit the comparison as JSON")
    return parser


def observe(domain: str, args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Run the takeover module and return its per-alias rows and what it covered."""
    from modules.alias_takeover import AliasTakeover

    ctx: dict[str, Any] = {"use_certificate_transparency": not args.no_certificate_transparency}
    if args.nameservers:
        ctx["nameservers"] = [ns.strip() for ns in args.nameservers.split(",") if ns.strip()]

    findings = AliasTakeover().run(parse_targets([domain])[0], ctx)
    for finding in findings:
        evidence = finding.evidence or {}
        if "checked" in evidence:
            return list(evidence["checked"]), dict(evidence.get("coverage", {}))
    # No aliases at all. The sweep still happened, so its coverage is still the
    # honest thing to report about this domain.
    return [], dict((ctx.get("alias_candidates") or {}).get("coverage", {}))


def describe(summary: dict[str, Any]) -> str:
    lines: list[str] = []

    for row in summary["regressions"]:
        lines.append(
            f"REGRESSED  {row['host']} -> {row['destination']}\n"
            f"           recorded {row['recorded']}, now {row['observed']} — {row['meaning']}"
        )
    for row in summary["unverified"]:
        lines.append(
            f"UNVERIFIED {row['host']} -> {row['destination']}\n"
            f"           {row['reason']}.\n"
            f"           This is not a pass. Re-run with --nameservers pointing at a resolver "
            f"that returns NXDOMAIN for names that do not exist."
        )
    for row in summary["reduced_coverage"]:
        lines.append(
            f"COVERAGE   {row['domain']} — certificate transparency did not answer, so only "
            f"{row['coverage'].get('probe_names', 0)} conventional names were swept.\n"
            f"           A dangling alias on a name nobody would guess would not have been found."
        )
    for row in summary["improvements"]:
        lines.append(
            f"IMPROVED   {row['host']} — recorded {row['recorded']}, now {row['observed']}.\n"
            f"           Tighten the baseline so this is held."
        )

    for result in summary["domains"]:
        held = result["unchanged"]
        bad = [r for r in held if r["observed"] != "resolves"]
        lines.append(
            f"{result['domain']}: {len(held)} alias(es) as recorded"
            + (f", {len(bad)} of them still exposed" if bad else "")
        )
        for row in bad:
            lines.append(f"           still open: {row['host']} — {row['meaning']}")

    lines.append("")
    lines.append(
        {
            "held": "DNS exposure has not regressed.",
            "regressed": "DNS exposure has REGRESSED — see above.",
            "unverified": "DNS exposure could NOT be verified — see above. This is not a pass.",
            "reduced_coverage": (
                "DNS exposure held over a REDUCED surface — see above. Requested strictly, "
                "so this is not a pass."
            ),
        }[summary["verdict"]]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.baseline:
        path = pathlib.Path(args.baseline)
        if not path.is_file():
            print(f"no such baseline: {path}", file=sys.stderr)
            return 3
        baselines = json.loads(path.read_text())["domains"]
    else:
        baselines = [{"domain": args.domain, "aliases": []}]

    results = []
    for entry in baselines:
        rows, coverage = observe(entry["domain"], args)
        results.append(compare(rows, entry, coverage))
    summary = summarise(results, strict_coverage=args.require_certificate_transparency)

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print(describe(summary))

    return int(summary["exit_code"])


if __name__ == "__main__":
    raise SystemExit(main())
