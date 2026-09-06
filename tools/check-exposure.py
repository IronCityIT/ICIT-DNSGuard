#!/usr/bin/env python3
"""Report what the live Firestore project exposes to an unauthenticated caller.

    python3 tools/check-exposure.py --project icit-dnsguard
    python3 tools/check-exposure.py --project icit-dnsguard --json
    python3 tools/check-exposure.py --baseline exposure-baseline.json --all

Read-only. It issues three unauthenticated GETs against the Firestore REST API,
reads status codes, and never reads a real scan document: the document probes
use an id the product does not mint, and the list probe requests a single row
and discards the body without parsing it.

Writes are never attempted. The report says so rather than leaving a reader to
assume the write path was checked.

Without a baseline, the exit code is the number of high-severity findings, so a
person running it by hand gets a non-zero exit while anything is open.

With ``--baseline``, the exit code is the number of *regressions* instead — a
project weaker than the file records. The known state is reported and does not
fail, because a gate that is permanently red for a reason the author of an
unrelated pull request cannot act on is a gate that gets ignored. An improvement
is reported too, with a prompt to tighten the baseline so the gain is held.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from dnsguard.exposure import check_exposure, compare_to_baseline  # noqa: E402

TIMEOUT_SECONDS = 20
ALLOWED_SCHEME = "https"


def http_status(url: str) -> int:
    """GET the URL and return the status code, discarding the body unread.

    The body of the list probe is a page of real scan documents. It is never
    parsed, never printed and never written anywhere — only the fact that the
    server was willing to send it is recorded.
    """
    # The URL is built from a project id supplied on the command line, so the
    # scheme is checked rather than assumed: without this, a crafted --project
    # could turn a network probe into a local file read.
    if not url.startswith(f"{ALLOWED_SCHEME}://"):
        raise ValueError(f"refusing a non-{ALLOWED_SCHEME} probe target: {url[:40]!r}")
    request = urllib.request.Request(url, method="GET")  # noqa: S310 — scheme checked above
    try:
        # S310 suppressed on both calls: the scheme is constrained to https
        # immediately above, which is the check the rule asks for.
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except OSError as exc:
        print(f"probe failed to reach {url}: {exc}", file=sys.stderr)
        # 0 is not a status. It is reported as one so the caller can see which
        # probe never completed rather than reading a network failure as a pass.
        return 0


VERDICT_MARK = {
    "unchanged": "=",
    "improved": "+",
    "regressed": "!",
    "unknown": "?",
    "unrecognised": "?",
}


def run_against_baseline(path: str, as_json: bool) -> int:
    """Compare every project the baseline names against its recorded posture."""
    with open(path, encoding="utf-8") as handle:
        baseline = json.load(handle)

    comparisons = []
    for entry in baseline.get("projects", []):
        report = check_exposure(
            http_status,
            entry["project_id"],
            entry.get("collection", "scans"),
        )
        comparisons.append(
            compare_to_baseline(report, entry.get("expected", ""), entry.get("note", ""))
        )

    if as_json:
        print(
            json.dumps(
                {
                    "baseline": path,
                    "verified_at": baseline.get("verified_at"),
                    "comparisons": [c.to_dict() for c in comparisons],
                },
                indent=2,
            )
        )
    else:
        print(f"baseline: {path} (recorded {baseline.get('verified_at', 'unknown')})")
        print()
        for c in comparisons:
            mark = VERDICT_MARK.get(c.verdict, "?")
            print(f"  {mark} {c.project_id:32} {c.observed:14} expected {c.expected}")
            if c.verdict != "unchanged" and c.note:
                print(f"      {c.note}")
        print()
        regressions = [c for c in comparisons if c.failed]
        improvements = [c for c in comparisons if c.verdict == "improved"]
        unknown = [c for c in comparisons if c.verdict in ("unknown", "unrecognised")]
        if regressions:
            print(f"{len(regressions)} project(s) got worse than the baseline records.")
        if improvements:
            print(
                f"{len(improvements)} project(s) improved — tighten exposure-baseline.json "
                "so the gain cannot be lost again."
            )
        if unknown:
            print(f"{len(unknown)} project(s) could not be established; not treated as a failure.")
        if not regressions and not improvements and not unknown:
            print("Every project matches the baseline. Nothing got worse.")

    return sum(1 for c in comparisons if c.failed)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", help="Firebase project id")
    parser.add_argument("--collection", default="scans", help="collection to probe")
    parser.add_argument("--baseline", help="baseline file to compare the fleet against")
    parser.add_argument(
        "--all",
        action="store_true",
        help="check every project named in the baseline (requires --baseline)",
    )
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = parser.parse_args()

    if args.all and not args.baseline:
        parser.error("--all needs --baseline to know which projects to check")
    if not args.baseline and not args.project:
        parser.error("give either --project or --baseline")

    if args.baseline:
        return run_against_baseline(args.baseline, args.json)

    report = check_exposure(http_status, args.project, args.collection)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(f"project:    {report.project_id}")
        print(f"collection: {report.collection}")
        print()
        for probe in report.probes:
            verdict = "PERMITTED" if probe.permitted else "refused"
            print(f"  {probe.name:24} {probe.status_code:>4}  {verdict}")
        print()
        print(f"  rules deployed:   {'yes' if report.rules_deployed else 'NO'}")
        print(f"  single-doc reads: {'open' if report.get_permitted else 'closed'}")
        print(f"  enumeration:      {'OPEN' if report.list_permitted else 'closed'}")
        print("  writes:           not probed (needs a write to a live system)")
        print()
        if not report.findings:
            print("No findings. The live rules match what this repository intends.")
        for finding in report.findings:
            print(f"  [{finding['severity'].upper()}] {finding['title']}")
            print(f"      {finding['finding']}")
            print(f"      Fix: {finding['remediation']}")
            print()

    return sum(1 for f in report.findings if f["severity"] == "high")


if __name__ == "__main__":
    raise SystemExit(main())
