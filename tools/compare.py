#!/usr/bin/env python3
"""Compare two scan reports and say what moved.

    python3 tools/compare.py --current new.json --previous old.json
    python3 tools/compare.py --current new.json --candidates ./previous-runs
    python3 tools/compare.py --current new.json --candidates ./runs --summary-md >> "$GITHUB_STEP_SUMMARY"

`dnsguard/diff.py` computes the comparison; this is the third caller, alongside
the control-plane API and the operator console. It exists because the one
pipeline that actually runs in production — the weekly scheduled assessment —
produces a report artifact every week and nothing has ever compared two of them.
A year of weekly scans with no diff is an archive, not a monitor.

## Selecting the previous report

`--candidates` takes a directory of previously downloaded reports and picks the
most recent one **for the same target**. That matters: this workflow scans
whatever domain it is asked to, so the run before this one is frequently a
different client's domain entirely, and comparing across targets produces a diff
in which everything is new and everything is resolved — true, and useless.

## Exit codes

    0  nothing got worse (the default, even when something did)
    1  something got worse, and --fail-on-regression was given
    2  a usage problem, or the comparison could not be made

**Regression does not fail by default, deliberately.** This runs inside the
pipeline that serves the public free scan. A client's posture getting worse is
news for the report, not a reason to fail the job that produced it — and a red
run would be read as "the scan broke" rather than "your DNS got worse", which is
the opposite of the message.
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

from dnsguard.diff import compare  # noqa: E402

#: Severity order for the summary, worst first.
SEVERITIES = ("critical", "high", "medium", "low", "info")


def load(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def target_of(report: dict[str, Any]) -> str:
    return str(report.get("target") or report.get("domain") or "").lower()


def pick_previous(
    candidates: pathlib.Path, current: dict[str, Any]
) -> tuple[dict[str, Any] | None, str]:
    """The most recent earlier report for the same target, and why.

    Returns the reason as well as the report, because "no previous scan" and
    "previous scans exist but all for other domains" are different situations and
    a caller reading only a null cannot tell them apart.
    """
    target = target_of(current)
    scanned_at = str(current.get("scan_timestamp", ""))
    seen = 0
    matching: list[tuple[str, dict[str, Any]]] = []

    for path in sorted(candidates.rglob("*.json")):
        try:
            report = load(path)
        except (OSError, json.JSONDecodeError):
            # A candidate that will not parse is skipped rather than fatal: it is
            # somebody else's artifact, not this comparison's problem.
            continue
        if not isinstance(report, dict) or "findings" not in report:
            continue
        seen += 1
        if target_of(report) != target:
            continue
        if report.get("scan_id") == current.get("scan_id"):
            continue
        stamp = str(report.get("scan_timestamp", ""))
        if scanned_at and stamp >= scanned_at:
            continue
        matching.append((stamp, report))

    if not matching:
        if seen:
            return None, f"{seen} earlier report(s) found, none of them for {target}"
        return None, "no earlier report was available"

    matching.sort(key=lambda pair: pair[0])
    return matching[-1][1], ""


def was(change: Any) -> str:
    """The previous severity, when it is different from the current one.

    A resolved finding carries its own severity as its previous one, so printing
    "(was info)" next to "info" is noise dressed as detail. The console applies
    the same guard; this keeps the two callers saying the same thing."""
    prior = getattr(change, "previous_severity", "")
    return f" (was {prior})" if prior and prior != change.severity else ""


def describe(result: Any, target: str, reason: str) -> str:
    lines: list[str] = []
    if result.baseline:
        lines.append(f"{target}: baseline — {len(result.of('new'))} finding(s) recorded")
        lines.append("  Nothing to compare against, so this is where the target stands")
        lines.append("  rather than a set of new problems.")
        if reason:
            lines.append(f"  ({reason})")
        return "\n".join(lines)

    headline = "SOMETHING GOT WORSE" if result.regressed else "nothing got worse"
    lines.append(f"{target}: {headline} since {result.previous_scan_id}")
    summary = result.summary()
    lines.append(
        "  " + "  ".join(f"{name}: {count}" for name, count in summary.items() if count)
        or "  nothing moved"
    )
    for outcome in ("worsened", "new", "resolved", "improved"):
        for change in result.of(outcome):
            lines.append(
                f"  {outcome:<9} {change.severity:<8}{was(change):<14} "
                f"{change.asset}  {change.title}"
            )
    return "\n".join(lines)


def markdown(result: Any, target: str, reason: str) -> str:
    """A GitHub job summary. Read by whoever opens the run, so it leads with the
    answer rather than with a table."""
    if result.baseline:
        note = f" ({reason})" if reason else ""
        return (
            f"### DNS Guard — {target}\n\n"
            f"**Baseline.** Nothing to compare against{note}; "
            f"{len(result.of('new'))} finding(s) recorded.\n"
        )

    head = "⚠️ **Something got worse**" if result.regressed else "✅ **Nothing got worse**"
    rows = [
        f"### DNS Guard — {target}",
        "",
        f"{head} since `{result.previous_scan_id}`.",
        "",
        "| Change | Severity | Affected | Finding |",
        "| --- | --- | --- | --- |",
    ]
    moved = [c for c in result.changes if c.outcome != "unchanged"]
    if not moved:
        rows.append("| _nothing moved_ | | | |")
    for change in moved:
        rows.append(
            f"| {change.outcome} | {change.severity}{was(change)} "
            f"| `{change.asset}` | {change.title} |"
        )
    return "\n".join(rows) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dnsguard-compare")
    parser.add_argument("--current", required=True, help="the report just produced")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--previous", help="an explicit earlier report")
    source.add_argument(
        "--candidates",
        help="a directory of earlier reports; the newest for the same target is used",
    )
    parser.add_argument("--json", action="store_true", help="emit the comparison as JSON")
    parser.add_argument("--summary-md", action="store_true", help="emit GitHub-flavoured markdown")
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="exit 1 when something got worse. Off by default: a client's posture "
        "worsening is news for the report, not a reason to fail the job that "
        "produced it",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    current_path = pathlib.Path(args.current)
    if not current_path.is_file():
        print(f"no such report: {current_path}", file=sys.stderr)
        return 2
    current = load(current_path)
    target = target_of(current) or "unknown"

    reason = ""
    previous: dict[str, Any] | None
    if args.previous:
        previous_path = pathlib.Path(args.previous)
        if not previous_path.is_file():
            print(f"no such report: {previous_path}", file=sys.stderr)
            return 2
        previous = load(previous_path)
        if target_of(previous) != target:
            print(
                f"refusing to compare {target} against {target_of(previous)}: "
                "a diff across targets reports everything as new and everything as resolved",
                file=sys.stderr,
            )
            return 2
    else:
        directory = pathlib.Path(args.candidates)
        if not directory.is_dir():
            print(f"no such directory: {directory}", file=sys.stderr)
            return 2
        previous, reason = pick_previous(directory, current)

    # No previous report is a baseline, which is what compare() already reports
    # for a first scan. `reason` is carried alongside it because "first ever
    # assessment" and "earlier assessments exist, all of other domains" are
    # different situations that produce the same comparison.
    result = compare(previous, current)

    if args.json:
        payload = result.to_dict()
        if reason:
            payload["no_previous_because"] = reason
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif args.summary_md:
        print(markdown(result, target, reason))
    else:
        print(describe(result, target, reason))

    return 1 if (result.regressed and args.fail_on_regression) else 0


if __name__ == "__main__":
    raise SystemExit(main())
