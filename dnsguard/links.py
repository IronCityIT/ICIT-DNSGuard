"""Signed, expiring links to one scan result.

## The problem this exists to close

The free-scan funnel has no identity. Somebody types an email address and a
domain, waits ninety seconds, and is shown their result — they have no account
and never will. Whatever serves that page has to hand a stranger exactly one
scan and nothing else.

Today that is done by making the scan id unguessable and treating knowledge of it
as permission. Two things are wrong with it, and the live project demonstrates
both: the permission never expires, and the store it reads from cannot tell the
difference between "fetch this one" and "list them all", so the collection is
enumerable and every submitter's address with it.

## What replaces it

A capability in the URL: the tenant, the scan and an expiry, signed with HMAC-
SHA256. Presenting it proves nothing about who you are and everything about what
you were given — which is the correct shape, because the recipient genuinely has
no identity to prove.

  * **It expires.** A link in an email inbox forever is a permission granted
    forever. Ninety days is long enough for somebody to come back to their
    report, short enough that a leaked mailbox from two years ago is not a live
    credential.
  * **It names its own scope.** The tenant and the scan id are inside the signed
    payload, so a token cannot be pointed at a different scan by editing the URL,
    and the reader never consults a caller-supplied tenant.
  * **It cannot be minted without the secret**, and the secret is never in the
    token. A leaked link is one scan; it is not the ability to make more.
  * **It fails closed.** No secret configured means no signing and no
    verification — not a permissive default.

Verification is constant-time on the signature, and every failure — bad
signature, wrong secret, expired, malformed — raises the same error with the same
message. Which of them it was is not the presenter's business, and telling them
turns a link checker into an oracle.

## What this is not

It is not authentication, and it does not make the scan private *from* whoever
holds the link. Anyone who has the URL has the scan, exactly as with a password
reset link or a shared document. That is the intended property; the point is that
holding one link grants one scan for a bounded time, rather than holding one id
granting the collection forever.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any

from .errors import ValidationError

#: How long a free-scan link stays valid. Long enough to come back to the report
#: after a fortnight of not getting round to it; short enough that an old mailbox
#: is not a live credential.
DEFAULT_TTL_SECONDS = 90 * 24 * 3600

#: Bumped if the payload shape changes, so an old token is rejected rather than
#: misread as a new one with fields missing.
VERSION = 1

#: One message for every failure. Which of them it was is not the presenter's
#: business, and saying turns a link checker into an oracle.
REFUSED = "this link is not valid"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


@dataclass(frozen=True)
class ScanLink:
    """What a verified token grants."""

    tenant_id: str
    scan_id: str
    expires_at: int


def sign(
    tenant_id: str, scan_id: str, secret: str, issued_at: float, ttl: int | None = None
) -> str:
    """Mint a link token.

    `issued_at` is passed rather than read from the clock so that expiry is
    testable without waiting, and so a caller with an injected clock stays
    consistent with the rest of the control plane.
    """
    if not secret:
        raise ValidationError(
            "no link secret is configured, so no link can be signed. Set DNSGUARD_LINK_SECRET."
        )
    if not tenant_id or not scan_id:
        raise ValidationError("a link needs both a tenant and a scan to point at")

    payload = {
        "v": VERSION,
        "t": tenant_id,
        "s": scan_id,
        "e": int(issued_at) + int(DEFAULT_TTL_SECONDS if ttl is None else ttl),
    }
    body = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return f"{body}.{_b64(_mac(body, secret))}"


def _mac(body: str, secret: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()


def verify(token: str, secret: str, now: float) -> ScanLink:
    """What this token grants, or `ValidationError`.

    The signature is checked before the payload is trusted for anything, and
    compared in constant time. Every rejection raises the same message.
    """
    if not secret:
        raise ValidationError(
            "no link secret is configured, so no link can be verified. Set DNSGUARD_LINK_SECRET."
        )
    body, _, presented = token.partition(".")
    if not body or not presented:
        raise ValidationError(REFUSED)

    try:
        expected = _mac(body, secret)
        if not hmac.compare_digest(_unb64(presented), expected):
            raise ValidationError(REFUSED)
        payload: dict[str, Any] = json.loads(_unb64(body))
    except ValidationError:
        raise
    except Exception as exc:
        # Malformed base64, malformed JSON, anything else: same answer.
        raise ValidationError(REFUSED) from exc

    if payload.get("v") != VERSION:
        raise ValidationError(REFUSED)
    tenant_id, scan_id, expires_at = payload.get("t"), payload.get("s"), payload.get("e")
    if not isinstance(tenant_id, str) or not isinstance(scan_id, str):
        raise ValidationError(REFUSED)
    if not isinstance(expires_at, int) or expires_at <= int(now):
        raise ValidationError(REFUSED)

    return ScanLink(tenant_id=tenant_id, scan_id=scan_id, expires_at=expires_at)
