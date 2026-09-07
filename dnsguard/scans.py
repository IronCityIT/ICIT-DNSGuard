"""Scan results, stored by us, on our own infrastructure.

Phase 2 of moving off managed storage. This is the replacement for the
`storeScanResults` and `getScanStatus` Cloud Functions: the same job, done by the
control plane, writing through `DocumentStore` — which now has a SQL
implementation, so the same code lands in MariaDB when the connection details
exist.

**Nothing is cut over here.** The workflow still POSTs to the Cloud Function; the
dashboard still reads Firestore. Repointing them is its own change, with its own
evidence, after the store this writes to is running somewhere. Building the
destination first is the whole point of not doing a destructive migration.

## Three things the old implementation got right, kept deliberately

**Status is monotonic.** The workflow reports failure whenever *any* job in the
run failed — which includes a run whose scan succeeded and whose AI analysis did
not. That run has already stored real findings, and overwriting them with an
empty failure record loses them. A failure never downgrades a completed scan; it
attaches its error and leaves the results alone. This was learned the hard way
once already and re-learning it during a migration would be worse.

**A terminal state is always written.** The dashboard polls until the scan
reaches one. A run that dies without recording anything leaves the page spinning
until the browser gives up, which reads to a client as "your scan is still
running" forever.

**The submitter's address is never returned.** `getScanStatus` is public, so it
stripped `email` from its response.

## One thing it got wrong, fixed here

**Tenant partitioning.** The old store is a flat `scans/{scan_id}` collection
with a `client_id` *field*, which means isolation depends on every reader
remembering to filter. Here a scan lives at `clients/{tenant}/scans/{scan_id}`
and there is no call that returns a scan without a tenant — the same mechanical
guarantee the rest of the control plane already has.

## Personal data

A free-scan record carries the submitter's email address. It is stored in its own
collection rather than inside the scan document, for two reasons: the scan can be
read, exported into evidence packs and shown in a dashboard without the address
travelling with it, and a deletion request can be honoured by removing one
document instead of rewriting history. `purge_submitter` does exactly that and is
audited, because "we deleted it" is a claim that should be checkable.
"""

from __future__ import annotations

import builtins
from dataclasses import dataclass, field
from typing import Any

from .audit import AuditLog
from .clock import Clock, iso
from .errors import ValidationError
from .store import DocumentStore, validate_segment

SCAN_COLLECTION = "scans"
#: Submitter contact details. Separate so a scan can be read, exported and
#: rendered without carrying an email address around with it.
SUBMITTER_COLLECTION = "scansubmitters"

#: Where a scan can be in its life. `queued` and `running` are not terminal; the
#: dashboard keeps polling through them.
STATUSES = ("queued", "running", "complete", "failed")
TERMINAL = ("complete", "failed")

#: Fields lifted out of an incoming payload and never stored on the scan itself.
PRIVATE_FIELDS = ("email",)


def _is_terminal(status: str) -> bool:
    return status in TERMINAL


@dataclass
class ScanService:
    """Ingest and retrieval for scan results, tenant-partitioned."""

    store: DocumentStore
    audit: AuditLog
    clock: Clock = field(default_factory=Clock)

    # ── ingest ──────────────────────────────────────────────────────────────

    def ingest(
        self,
        tenant_id: str,
        payload: dict[str, Any],
        actor: str = "scanner",
    ) -> dict[str, Any]:
        """Record a scan result. Idempotent on `scan_id`.

        Returns the stored document. Raises rather than storing something
        unaddressable: a scan with no id cannot be polled for, so accepting one
        would produce a record nobody can ever find.
        """
        scan_id = str(payload.get("scan_id", "")).strip()
        if not scan_id:
            raise ValidationError("scan_id is required: a scan without one can never be read back")
        validate_segment(scan_id, "scan_id")
        validate_segment(tenant_id, "tenant_id")

        status = str(payload.get("status", "")).strip() or "complete"
        if status not in STATUSES:
            raise ValidationError(f"unknown scan status {status!r}; expected one of {STATUSES}")

        # A payload that names a different tenant than the credential is acting
        # for is refused rather than silently filed under the caller's tenant.
        # Quietly relabelling somebody's data is how it ends up in the wrong
        # client's report.
        claimed = str(payload.get("client_id", "")).strip()
        if claimed and claimed != tenant_id:
            raise ValidationError(
                f"payload claims client_id {claimed!r} but this credential acts for {tenant_id!r}"
            )

        document = {k: v for k, v in payload.items() if k not in PRIVATE_FIELDS}
        document["scan_id"] = scan_id
        document["client_id"] = tenant_id
        document["status"] = status

        existing = self.store.get(tenant_id, SCAN_COLLECTION, scan_id)
        now = iso(self.clock.now())

        if existing is not None and existing.get("status") == "complete" and status == "failed":
            # Monotonic. The run reported a failure because some stage of it
            # failed, but the scan itself already produced findings and they are
            # worth more than the failure notice.
            merged = dict(existing)
            merged["error"] = payload.get("error") or {"message": "a stage of this run failed"}
            merged["updated_at"] = now
            self.store.put(tenant_id, SCAN_COLLECTION, scan_id, merged)
            self._record(tenant_id, actor, "scan.failure_ignored", scan_id, status="complete")
            return merged

        document["received_at"] = existing.get("received_at", now) if existing else now
        document["updated_at"] = now
        if _is_terminal(status):
            document["completed_at"] = now

        self.store.put(tenant_id, SCAN_COLLECTION, scan_id, document)
        self._store_submitter(tenant_id, scan_id, payload, now)
        self._record(tenant_id, actor, "scan.ingested", scan_id, status=status)
        return document

    def _store_submitter(
        self, tenant_id: str, scan_id: str, payload: dict[str, Any], now: str
    ) -> None:
        contact = {k: payload[k] for k in PRIVATE_FIELDS if payload.get(k)}
        if not contact:
            return
        self.store.put(
            tenant_id,
            SUBMITTER_COLLECTION,
            scan_id,
            {"scan_id": scan_id, "recorded_at": now, **contact},
        )

    def _record(self, tenant_id: str, actor: str, action: str, scan_id: str, **detail: Any) -> None:
        self.audit.append(
            tenant_id=tenant_id,
            actor=actor or "scanner",
            action=action,
            subject=f"scan/{scan_id}",
            detail=detail,
        )

    # ── retrieval ───────────────────────────────────────────────────────────

    def get(self, tenant_id: str, scan_id: str) -> dict[str, Any] | None:
        """One scan. Never carries the submitter's address — that lives in its
        own collection and is not joined in here by accident."""
        validate_segment(scan_id, "scan_id")
        return self.store.get(tenant_id, SCAN_COLLECTION, scan_id)

    def list(self, tenant_id: str, limit: int = 50) -> builtins.list[dict[str, Any]]:
        """Most recent first. Bounded, because an unbounded list over a tenant
        with years of scans is a slow query behind an HTTP timeout."""
        if limit < 1:
            raise ValidationError("limit must be positive")
        scans = self.store.list(tenant_id, SCAN_COLLECTION)
        scans.sort(key=lambda d: str(d.get("received_at", "")), reverse=True)
        return scans[:limit]

    def submitter(self, tenant_id: str, scan_id: str) -> dict[str, Any] | None:
        """The contact details, fetched deliberately and separately. Reading
        personal data should be an explicit act, not a field that arrives with
        everything else."""
        validate_segment(scan_id, "scan_id")
        return self.store.get(tenant_id, SUBMITTER_COLLECTION, scan_id)

    def purge_submitter(self, tenant_id: str, scan_id: str, actor: str) -> bool:
        """Erase the submitter's details, keeping the scan. Audited, because
        "we deleted it" is a claim somebody may later have to evidence."""
        validate_segment(scan_id, "scan_id")
        removed = self.store.delete(tenant_id, SUBMITTER_COLLECTION, scan_id)
        self._record(tenant_id, actor, "scan.submitter_purged", scan_id, removed=removed)
        return removed
