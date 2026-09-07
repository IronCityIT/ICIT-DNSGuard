#!/usr/bin/env python3
"""Mint and inspect control-plane credentials.

    python3 tools/credential.py mint --tenant acme --actor bill --roles viewer,operator
    python3 tools/credential.py mint --tenant acme --actor ann --roles approver \
        --append credentials.json
    python3 tools/credential.py show credentials.json

A credential binds one token to one tenant, one actor and an explicit set of
roles. The registry only ever holds a SHA-256 digest, so the file this writes is
not a set of working credentials — losing it does not hand anybody access, and
the token cannot be recovered from it.

**The token is printed once, to stdout, and never stored.** Copy it into the
secret manager at that moment. If it is lost, mint a new one and disable the old:
that is cheaper than any mechanism for recovering it, and it is the behaviour you
want anyway.

Roles are least-privilege by default. `viewer` reads. `operator` makes changes.
`approver` signs off disruptive ones — and should be a *different* credential
from the operator it approves, or the approval gate is checking a box rather
than separating duties.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dnsguard.errors import DnsGuardError  # noqa: E402
from dnsguard.identity import (  # noqa: E402
    ROLES,
    Credential,
    CredentialRegistry,
    hash_token,
    mint_token,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dnsguard-credential")
    sub = parser.add_subparsers(dest="command", required=True)

    mint = sub.add_parser("mint", help="create a credential and print its token once")
    mint.add_argument("--tenant", required=True, help="the one tenant this credential may act as")
    mint.add_argument("--actor", required=True, help="who the audit chain will record")
    mint.add_argument(
        "--roles",
        default="viewer",
        help=f"comma list from {','.join(ROLES)} (default: viewer — least privilege)",
    )
    mint.add_argument("--id", default="", help="a name for this credential, used in logs")
    mint.add_argument(
        "--append",
        default="",
        help="registry file to add this credential to; created if absent",
    )

    show = sub.add_parser("show", help="list a registry file without revealing anything")
    show.add_argument("path", help="registry file")
    return parser


def load(path: pathlib.Path) -> CredentialRegistry:
    if not path.exists():
        return CredentialRegistry([])
    return CredentialRegistry.from_json(path.read_text(encoding="utf-8"))


def write(path: pathlib.Path, registry: CredentialRegistry) -> None:
    payload = {"credentials": [c.to_dict() for c in registry.credentials]}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # The file holds digests, not tokens — but it still says who can do what, so
    # it is not world-readable.
    path.chmod(0o600)


def do_mint(args: argparse.Namespace) -> int:
    roles = tuple(r.strip() for r in args.roles.split(",") if r.strip())
    token = mint_token()
    credential = Credential(
        credential_id=args.id or f"{args.tenant}-{args.actor}",
        token_sha256=hash_token(token),
        tenant_id=args.tenant,
        actor=args.actor,
        roles=roles,
    )

    if args.append:
        path = pathlib.Path(args.append)
        registry = load(path)
        registry.credentials.append(credential)
        CredentialRegistry(registry.credentials)  # re-validate: no duplicate tokens
        write(path, registry)

    print(f"credential_id : {credential.credential_id}")
    print(f"tenant        : {credential.tenant_id}")
    print(f"actor         : {credential.actor}")
    print(f"roles         : {', '.join(credential.roles)}")
    print(f"sha256        : {credential.token_sha256}")
    if args.append:
        print(f"written to    : {args.append}")
    print()
    print("Token — shown once, stored nowhere. Copy it now:")
    print()
    print(f"    {token}")
    print()
    if "approver" in roles and len(roles) > 1:
        print(
            "NOTE: this credential both makes changes and approves them. The approval "
            "gate cannot separate duties that one credential holds — issue approver "
            "separately unless you mean this."
        )
    return 0


def do_show(args: argparse.Namespace) -> int:
    path = pathlib.Path(args.path)
    if not path.is_file():
        print(f"no such registry file: {path}", file=sys.stderr)
        return 2
    registry = load(path)
    if not len(registry):
        print("no credentials")
        return 0
    print(f"{'credential_id':<28} {'tenant':<16} {'actor':<16} {'roles':<28} enabled")
    for c in registry.credentials:
        print(
            f"{c.credential_id:<28} {c.tenant_id:<16} {c.actor:<16} "
            f"{','.join(c.roles):<28} {'yes' if c.enabled else 'no'}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return do_mint(args) if args.command == "mint" else do_show(args)
    except DnsGuardError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
