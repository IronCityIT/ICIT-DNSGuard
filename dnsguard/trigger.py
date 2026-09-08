"""Starting a free scan: the public front door, and what stops it being abused.

This is the other half of the Cloud Function replacement. `scans.py` took the
result path; this takes the request path — somebody types an email address and a
domain on a public page, and a scan happens.

## What makes this endpoint different from every other one

It is unauthenticated, by necessity: the person using it has no account and the
whole point of the funnel is that they do not need one. So it is the only route
in the product where a stranger can cause work to happen — a record written, and
a CI pipeline dispatched that runs for a minute or two and makes DNS queries
against a domain they named.

That is a resource for somebody else to spend, and the deployed version it
replaces has **no rate limiting that this repository can find**. Rebuilding it
that way on new infrastructure would be carrying a defect across a migration
deliberately, so the limit is part of this rather than a later hardening pass:

  * **Per submitter and per source**, because either alone is trivially evaded —
    one address from a thousand hosts, or a thousand addresses from one.
  * **Counted in the store**, so a restart does not reset somebody's budget and
    a second instance does not double it.
  * **Refused with 429 and a retry-after**, not silently dropped. A caller who is
    over the limit should be able to tell that from a caller who broke something.

## Validation

The domain is proven to be a hostname before anything else happens. It ends up in
a workflow input, and the workflow puts it on a command line — the existing
pipeline validates it there too, and this is the other end of the same defence
rather than a substitute for it.

Free-mail addresses are refused because the funnel exists to reach businesses,
which is a product decision rather than a security one; it is here because it is
where the address arrives, and it is marked as such so nobody later mistakes it
for a control.

## Dispatch is injected

What actually starts the pipeline is a callable. The default belongs to whatever
deployment wires it up — today a GitHub `workflow_dispatch`, tomorrow whatever
replaces it — and no test starts a real one.
"""

from __future__ import annotations

import builtins
import hashlib
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .clock import Clock, iso
from .errors import ValidationError
from .scans import ScanService
from .store import DocumentStore

RATE_COLLECTION = "scanrequests"

#: How many scans one address, or one source, may start in a window.
DEFAULT_LIMIT = 3
DEFAULT_WINDOW_SECONDS = 3600

#: RFC 1123 hostname. Deliberately strict: this value reaches a workflow input
#: and then a command line.
HOSTNAME = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)
MAX_HOSTNAME = 253

EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

#: A product decision, not a security control — the funnel exists to reach
#: businesses. Named as such so nobody later reads it as one.
FREE_MAIL = frozenset(
    {
        "gmail.com",
        "yahoo.com",
        "hotmail.com",
        "outlook.com",
        "aol.com",
        "icloud.com",
        "mail.com",
        "protonmail.com",
        "proton.me",
        "gmx.com",
        "yandex.com",
    }
)


class RateLimitError(ValidationError):
    """Too many requests from this submitter or source."""

    status_code = 429


def normalise_domain(raw: str) -> str:
    """A bare hostname, or `ValidationError`.

    Strips what people actually paste — a scheme, a `www.`, a path — and then
    *proves* what is left is a hostname. Stripping is not validation, and the
    order matters: the check happens last, on the value that will be used.
    """
    value = (raw or "").strip().lower()
    value = re.sub(r"^https?://", "", value)
    value = re.sub(r"^www\.", "", value)
    value = value.split("/")[0].split("?")[0].strip()
    if not value or len(value) > MAX_HOSTNAME or not HOSTNAME.match(value):
        raise ValidationError(f"{raw!r} is not a valid domain name")
    return value


def check_email(raw: str) -> str:
    value = (raw or "").strip().lower()
    if not EMAIL.match(value):
        raise ValidationError("a valid email address is required")
    if value.split("@", 1)[1] in FREE_MAIL:
        raise ValidationError("please use your work email address")
    return value


def _bucket(value: str) -> str:
    """A stable, non-reversible id for a rate-limit subject.

    The email address and the source address are both personal data, and a
    counter does not need to know either — only whether it has seen this one
    before.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


@dataclass
class ScanTrigger:
    """Accepts a free-scan request, or explains why it will not."""

    scans: ScanService
    store: DocumentStore
    dispatch: Callable[[str, str], None]
    clock: Clock = field(default_factory=Clock)
    tenant_id: str = "free-scan"
    limit: int = DEFAULT_LIMIT
    window_seconds: int = DEFAULT_WINDOW_SECONDS

    def request(self, email: str, domain: str, source: str = "") -> dict[str, Any]:
        """Validate, rate-limit, record, and start a scan.

        Returns the scan id. The caller turns that into a link — this does not
        mint one, because deciding what somebody may hold is the link module's
        job and duplicating it here would be a second place to get it wrong.
        """
        address = check_email(email)
        target = normalise_domain(domain)

        # Both, and before anything is written: one address from a thousand
        # hosts and a thousand addresses from one host are the same abuse, and
        # limiting only one of them stops neither.
        for subject in (f"email:{address}", f"source:{source or 'unknown'}"):
            self._consume(subject)

        scan_id = f"scan-{int(self.clock.now().timestamp())}-{secrets.token_hex(5)}"
        self.scans.ingest(
            self.tenant_id,
            {
                "scan_id": scan_id,
                "status": "queued",
                "domain": target,
                "target": target,
                "email": address,
                "source": "free-scan",
                "client_name": "Free Scan User",
                "findings": [],
            },
            actor="free-scan",
        )

        try:
            self.dispatch(target, scan_id)
        except Exception as exc:  # noqa: BLE001 - whatever the transport raises
            # The record already exists and the dashboard is about to poll it.
            # Leaving it queued forever is the failure mode that makes a page
            # spin until the browser gives up, so it is closed here.
            self.scans.ingest(
                self.tenant_id,
                {
                    "scan_id": scan_id,
                    "status": "failed",
                    "domain": target,
                    "target": target,
                    "findings": [],
                    "error": {"stage": "dispatch", "message": "the scan could not be started"},
                },
                actor="free-scan",
            )
            raise ValidationError("the scan could not be started; please try again") from exc

        return {"scan_id": scan_id, "domain": target, "status": "queued"}

    # ── rate limiting ───────────────────────────────────────────────────────

    def _consume(self, subject: str) -> None:
        now = self.clock.now().timestamp()
        window_start = now - self.window_seconds
        doc_id = _bucket(subject)
        record = self.store.get(self.tenant_id, RATE_COLLECTION, doc_id) or {}
        recent = [t for t in record.get("at", []) if float(t) > window_start]

        if len(recent) >= self.limit:
            retry_after = int(min(float(t) for t in recent) + self.window_seconds - now) + 1
            raise RateLimitError(
                f"too many scans requested; try again in {max(retry_after, 1)} seconds"
            )

        recent.append(now)
        self.store.put(
            self.tenant_id,
            RATE_COLLECTION,
            doc_id,
            # The subject itself is not stored: the hash is the key, and a
            # counter has no business holding an email address.
            {"at": recent, "updated_at": iso(self.clock.now())},
        )

    def recent(self, subject: str) -> builtins.list[float]:
        """What the limiter currently remembers. For tests and diagnostics."""
        record = self.store.get(self.tenant_id, RATE_COLLECTION, _bucket(subject)) or {}
        return [float(t) for t in record.get("at", [])]
