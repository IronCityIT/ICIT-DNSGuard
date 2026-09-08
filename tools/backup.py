#!/usr/bin/env python3
"""Back up, verify, restore and reconcile a tenant's control-plane data.

    python3 tools/backup.py export    --data-dir ./data --tenant acme -o acme.json
    python3 tools/backup.py verify    acme.json
    python3 tools/backup.py restore   --data-dir ./restored --tenant acme acme.json
    python3 tools/backup.py reconcile --data-dir ./restored --tenant acme acme.json

`verify` is the one to run on a schedule. A backup nobody has checked is a
hypothesis, and the moment you need it is a poor time to find out.

`reconcile` is what makes a migration checkable rather than hopeful: after moving
data somewhere new, the question is not whether the import reported success but
whether what is now there is the same as what was there before.

Exit codes: 0 fine, 1 a problem was found, 2 a usage error. So this can be run
from cron or a pipeline and only speak up when something is wrong.

The archive contains everything a tenant's store holds, including — for the
free-scan tenant — submitter email addresses. It is not encrypted. Treat the file
as the personal data it contains; encryption belongs to whatever stores it.
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

from dnsguard.backup import export_tenant, reconcile, restore, verify  # noqa: E402
from dnsguard.errors import DnsGuardError  # noqa: E402
from dnsguard.store import JsonFileStore  # noqa: E402

#: Every collection the control plane writes. Listed rather than discovered
#: because DocumentStore cannot enumerate collections — it lists documents within
#: one, and tenants across the store, and nothing in between.
#:
#: A collection missing from here is a collection missing from every backup, so
#: `tests/test_backup.py` fails if the code writes one this list does not name.
COLLECTIONS = [
    "scans",
    "scansubmitters",
    "scanrequests",
    "policies",
    # The policy *content*. Omitting this — as the first draft of this list did —
    # restores policies with no versions behind them, which is worse than not
    # restoring them at all, because it looks like it worked.
    "policyversions",
    # Singular. The constant is TENANT_COLLECTION = "tenant"; writing the obvious
    # plural here backed up nothing and reported success.
    "tenant",
    "sites",
    "feeds",
    "feedsnapshots",
    "feedindicators",
    "exceptions",
    "approvals",
    "audit",
    "alerts",
    "alertrules",
    "evidence",
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dnsguard-backup")
    sub = parser.add_subparsers(dest="command", required=True)

    export = sub.add_parser("export", help="write an archive of one tenant")
    export.add_argument("--data-dir", required=True)
    export.add_argument("--tenant", required=True)
    export.add_argument("-o", "--output", required=True)

    check = sub.add_parser("verify", help="check an archive against itself")
    check.add_argument("archive")

    put = sub.add_parser("restore", help="write an archive into a store")
    put.add_argument("archive")
    put.add_argument("--data-dir", required=True)
    put.add_argument("--tenant", help="restore under a different tenant id")
    put.add_argument(
        "--overwrite",
        action="store_true",
        help="replace documents that already exist. Off by default: restoring "
        "into a live store is otherwise a way to lose the newer copy of "
        "something while believing you are recovering it",
    )

    check_live = sub.add_parser("reconcile", help="compare a store against an archive")
    check_live.add_argument("archive")
    check_live.add_argument("--data-dir", required=True)
    check_live.add_argument("--tenant")
    return parser


def load(path: str) -> dict[str, Any]:
    return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.command == "export":
            store = JsonFileStore(args.data_dir)
            archive = export_tenant(store, args.tenant, COLLECTIONS)
            pathlib.Path(args.output).write_text(archive.to_json() + "\n", encoding="utf-8")
            print(f"{archive.document_count} document(s) from {args.tenant} -> {args.output}")
            for collection, count in sorted(archive.counts.items()):
                print(f"  {collection}: {count}")
            # Verified immediately, because an archive that cannot pass its own
            # check is not a backup and finding that out later is the whole
            # problem this tool exists to avoid.
            report = verify(archive.to_dict())
            if not report["valid"]:
                print("the archive failed its own verification:", file=sys.stderr)
                for problem in report["problems"]:
                    print(f"  {problem}", file=sys.stderr)
                return 1
            print(f"verified: {report['documents_checked']} document hash(es)")
            return 0

        if args.command == "verify":
            report = verify(load(args.archive))
            if report["valid"]:
                print(
                    f"{args.archive}: intact — {report['documents_checked']} document(s) "
                    f"for {report['tenant_id']}"
                )
                return 0
            print(f"{args.archive}: FAILED", file=sys.stderr)
            for problem in report["problems"]:
                print(f"  {problem}", file=sys.stderr)
            return 1

        if args.command == "restore":
            store = JsonFileStore(args.data_dir)
            result = restore(store, load(args.archive), args.tenant, args.overwrite)
            print(f"restored {len(result['written'])} document(s) into {result['tenant_id']}")
            if result["skipped"]:
                print(
                    f"skipped {len(result['skipped'])} that already existed; "
                    "pass --overwrite if replacing them is what you meant",
                    file=sys.stderr,
                )
                for path in result["skipped"][:10]:
                    print(f"  {path}", file=sys.stderr)
                return 1
            return 0

        result = reconcile(JsonFileStore(args.data_dir), load(args.archive), args.tenant)
        if result["reconciled"]:
            print(f"reconciled: {result['matched']} document(s) match the archive exactly")
            return 0
        print(f"NOT reconciled — {result['matched']} matched", file=sys.stderr)
        for path in result["missing"][:10]:
            print(f"  missing: {path}", file=sys.stderr)
        for path in result["differing"][:10]:
            print(f"  differs: {path}", file=sys.stderr)
        return 1

    except DnsGuardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
