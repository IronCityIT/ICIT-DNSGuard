#!/usr/bin/env python3
"""Report what the live Firestore project exposes to an unauthenticated caller.

    python3 tools/check-exposure.py --project icit-dnsguard
    python3 tools/check-exposure.py --project icit-dnsguard --json

Read-only. It issues three unauthenticated GETs against the Firestore REST API,
reads status codes, and never reads a real scan document: the document probes
use an id the product does not mint, and the list probe requests a single row
and discards the body without parsing it.

Writes are never attempted. The report says so rather than leaving a reader to
assume the write path was checked.

Exit code is the number of high-severity findings, so CI can gate on it once the
rules are deployed.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from dnsguard.exposure import check_exposure  # noqa: E402

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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, help="Firebase project id")
    parser.add_argument("--collection", default="scans", help="collection to probe")
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = parser.parse_args()

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
