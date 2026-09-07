"""Who is calling, established from the credential rather than from a header.

## The defect this replaces

The control plane authenticated with a single shared bearer token and then took
the caller's tenant from an `X-Client-Id` request header and their roles from
nowhere at all — every authenticated caller was handed `viewer`, `operator` *and*
`approver`, unconditionally. So one token holder could act as any tenant, in
every role, including approving their own disruptive changes.

The tenant check itself was never broken: `scoped()` compares the caller's tenant
to the tenant in the path and refuses a mismatch. The problem was upstream of it.
A check that faithfully compares two values a caller supplies is not a boundary,
and the approval gate's separation of duties is not separation if the same
credential holds both sides.

Nothing was exposed by it — the API has never been deployed — so this is a
blocker being cleared before deployment rather than an incident.

## What replaces it

A credential registry. Each credential binds a token to exactly one tenant, one
actor and an explicit set of roles. Authentication returns that binding; the
caller no longer contributes to it.

  * **Tokens are never stored.** Only a SHA-256 digest, compared with
    `hmac.compare_digest` so a wrong token takes the same time as a right one.
    A registry file that leaks is not a set of working credentials.
  * **Roles are explicit and least-privilege.** A credential with no roles named
    gets `viewer`. Nothing grants `approver` by accident, which is the whole
    point of having an approval gate.
  * **`X-Client-Id` is an assertion, not an instruction.** It may still be sent —
    existing clients do — but it must *match* the credential's tenant, and a
    mismatch is refused rather than obeyed.
  * **`X-Actor` no longer decides the actor.** It was caller-supplied and lands
    in the audit chain, so it was forgeable attribution on an append-only log
    whose whole value is that you can believe it.
  * **Fail closed.** No credentials configured means the app does not start.
    An unknown, disabled or malformed credential is refused with one generic
    message, so nothing is learned from which of the three it was.

## What this is not

It is not per-user identity. A shared credential still attributes every action to
whatever actor that credential names. Real per-person attribution needs the
Auth0 organisation work, and until it lands the audit chain records the
credential, honestly, rather than a header anyone could set. That is the smaller
claim, and it is the true one.
"""

from __future__ import annotations

import builtins
import hashlib
import hmac
import json
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .errors import ValidationError

VIEWER, OPERATOR, APPROVER = "viewer", "operator", "approver"
ROLES = (VIEWER, OPERATOR, APPROVER)

#: Shortest token the registry will accept. A short shared secret on an endpoint
#: that reaches tenant data is not worth the ceremony around it.
MIN_TOKEN_LENGTH = 24


def hash_token(token: str) -> str:
    """SHA-256 hex digest of a token. The only form the registry ever holds."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def mint_token(length: int = 32) -> str:
    """A new token, from the system CSPRNG."""
    return secrets.token_urlsafe(length)


@dataclass(frozen=True)
class Credential:
    """One token's binding: a tenant, an actor, and what it may do."""

    credential_id: str
    token_sha256: str
    tenant_id: str
    actor: str
    roles: tuple[str, ...] = (VIEWER,)
    enabled: bool = True

    def __post_init__(self) -> None:
        for name, value in (
            ("credential_id", self.credential_id),
            ("tenant_id", self.tenant_id),
            ("actor", self.actor),
        ):
            if not value or not isinstance(value, str):
                raise ValidationError(f"credential {name} is required")
        if len(self.token_sha256) != 64 or not all(
            c in "0123456789abcdef" for c in self.token_sha256.lower()
        ):
            raise ValidationError(
                f"credential {self.credential_id!r} needs a sha256 hex digest, not a token. "
                "Mint one with tools/credential.py — plaintext tokens are never stored."
            )
        unknown = [r for r in self.roles if r not in ROLES]
        if unknown:
            raise ValidationError(
                f"credential {self.credential_id!r} names unknown role(s) {unknown}; "
                f"expected any of {list(ROLES)}"
            )

    def may(self, role: str) -> bool:
        return role in self.roles

    def to_dict(self) -> dict[str, Any]:
        """Serialisable form. Carries the digest, never a token."""
        return {
            "credential_id": self.credential_id,
            "token_sha256": self.token_sha256,
            "tenant_id": self.tenant_id,
            "actor": self.actor,
            "roles": list(self.roles),
            "enabled": self.enabled,
        }


@dataclass
class CredentialRegistry:
    """The set of credentials the control plane will accept."""

    credentials: builtins.list[Credential] = field(default_factory=list)

    def __post_init__(self) -> None:
        digests = [c.token_sha256 for c in self.credentials]
        duplicated = {d for d in digests if digests.count(d) > 1}
        if duplicated:
            # Two credentials sharing a token means which tenant you get depends
            # on list order. That is a tenant boundary decided by a coincidence.
            raise ValidationError("two credentials share a token; each token binds one tenant")

    def __len__(self) -> int:
        return len(self.credentials)

    def authenticate(self, presented: str) -> Credential | None:
        """The credential this token belongs to, or None.

        Every credential is compared, and comparison is constant-time, so
        neither the answer nor the time taken says which token was close.
        """
        digest = hash_token(presented) if presented else ""
        found: Credential | None = None
        for credential in self.credentials:
            if not credential.enabled:
                continue
            if digest and hmac.compare_digest(credential.token_sha256, digest):
                found = credential
        return found

    # ── loading ─────────────────────────────────────────────────────────────

    @classmethod
    def from_records(cls, records: builtins.list[Mapping[str, Any]]) -> CredentialRegistry:
        return cls(
            [
                Credential(
                    credential_id=str(r.get("credential_id", "")),
                    token_sha256=str(r.get("token_sha256", "")),
                    tenant_id=str(r.get("tenant_id", "")),
                    actor=str(r.get("actor", "")),
                    roles=tuple(r.get("roles") or (VIEWER,)),
                    enabled=bool(r.get("enabled", True)),
                )
                for r in records
            ]
        )

    @classmethod
    def from_json(cls, text: str) -> CredentialRegistry:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValidationError(f"credential file is not valid JSON: {exc}") from exc
        records = data.get("credentials") if isinstance(data, dict) else data
        if not isinstance(records, builtins.list):
            raise ValidationError(
                'credential file must be a list, or an object with a "credentials" list'
            )
        return cls.from_records(records)

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> CredentialRegistry:
        """Build from the environment.

        Two ways, and the file is the one to use in anger:

          DNSGUARD_CREDENTIALS_FILE  a JSON file of digests. Mount it read-only.
          DNSGUARD_API_TOKEN         a single credential, for development and
                                     for the single-tenant case. It now REQUIRES
                                     DNSGUARD_API_TENANT, and grants only the
                                     roles named in DNSGUARD_API_ROLES —
                                     defaulting to viewer, not to everything.
        """
        path = environ.get("DNSGUARD_CREDENTIALS_FILE", "").strip()
        if path:
            from pathlib import Path

            try:
                text = Path(path).read_text(encoding="utf-8")
            except OSError as exc:
                raise ValidationError(
                    f"cannot read DNSGUARD_CREDENTIALS_FILE {path}: {exc}"
                ) from exc
            return cls.from_json(text)

        token = environ.get("DNSGUARD_API_TOKEN", "").strip()
        if not token:
            return cls([])

        tenant = environ.get("DNSGUARD_API_TENANT", "").strip()
        if not tenant:
            raise ValidationError(
                "DNSGUARD_API_TOKEN is set but DNSGUARD_API_TENANT is not. A token has to "
                "belong to a tenant — taking the tenant from a request header is what let "
                "one caller act as any client."
            )
        if len(token) < MIN_TOKEN_LENGTH:
            raise ValidationError(
                f"DNSGUARD_API_TOKEN must be at least {MIN_TOKEN_LENGTH} characters"
            )

        raw_roles = environ.get("DNSGUARD_API_ROLES", "").strip()
        roles = tuple(r.strip() for r in raw_roles.split(",") if r.strip()) or (VIEWER,)
        return cls(
            [
                Credential(
                    credential_id="env",
                    token_sha256=hash_token(token),
                    tenant_id=tenant,
                    actor=environ.get("DNSGUARD_API_ACTOR", "").strip() or "env-credential",
                    roles=roles,
                )
            ]
        )
