"""Append-only, tamper-evident audit log.

Every control-plane action lands here: who did it, to what, whether it was
allowed, and which approval authorised it. Records are chained by hash, so a
record cannot be altered or removed after the fact without breaking every record
that follows it — verify() finds exactly where.

This is the substrate the evidence exporter reads: an auditor asking "prove this
block was approved before it took effect" is answered from the chain, not from
someone's recollection.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

from .clock import Clock, iso
from .errors import ValidationError
from .store import DocumentStore

GENESIS_HASH = "0" * 64
AUDIT_COLLECTION = "audit"

# Outcomes an action can have. "pending_approval" is a real outcome, not an
# error: it is what a disruptive action does when nobody has signed it off.
OUTCOMES = ("executed", "denied", "pending_approval", "failed", "recorded")


def canonical(payload: Any) -> str:
    """Stable JSON. The hash is only meaningful if serialisation is."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def digest(payload: Any) -> str:
    return hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditRecord:
    seq: int
    timestamp: str
    tenant_id: str
    actor: str
    action: str
    subject: str
    outcome: str
    detail: dict[str, Any] = field(default_factory=dict)
    approval_id: str = ""
    prev_hash: str = GENESIS_HASH
    hash: str = ""

    def body(self) -> dict[str, Any]:
        """Everything the hash covers — i.e. the record minus the hash itself."""
        payload = asdict(self)
        payload.pop("hash")
        return payload

    def compute_hash(self) -> str:
        return digest(self.body())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuditLog:
    """Per-tenant chain. Sequence numbers start at 1; seq 1 chains to GENESIS."""

    def __init__(self, store: DocumentStore, clock: Clock | None = None) -> None:
        self._store = store
        self._clock = clock or Clock()

    # ── writing ─────────────────────────────────────────────────────────────

    def append(
        self,
        tenant_id: str,
        actor: str,
        action: str,
        subject: str,
        outcome: str = "recorded",
        detail: dict[str, Any] | None = None,
        approval_id: str = "",
    ) -> AuditRecord:
        if outcome not in OUTCOMES:
            raise ValidationError(f"unknown audit outcome {outcome!r}; expected one of {OUTCOMES}")
        if not actor:
            raise ValidationError("audit records must name an actor")

        records = self.records(tenant_id)
        seq = records[-1].seq + 1 if records else 1
        prev_hash = records[-1].hash if records else GENESIS_HASH

        record = AuditRecord(
            seq=seq,
            timestamp=iso(self._clock.now()),
            tenant_id=tenant_id,
            actor=actor,
            action=action,
            subject=subject,
            outcome=outcome,
            detail=detail or {},
            approval_id=approval_id,
            prev_hash=prev_hash,
        )
        sealed = AuditRecord(**{**record.body(), "hash": record.compute_hash()})
        # Zero-padded id so lexical ordering in the store equals sequence order.
        self._store.put(tenant_id, AUDIT_COLLECTION, f"{sealed.seq:012d}", sealed.to_dict())
        return sealed

    # ── reading ─────────────────────────────────────────────────────────────

    def records(self, tenant_id: str) -> list[AuditRecord]:
        raw = self._store.list(tenant_id, AUDIT_COLLECTION)
        return sorted((AuditRecord(**d) for d in raw), key=lambda r: r.seq)

    def since(self, tenant_id: str, seq: int) -> list[AuditRecord]:
        return [r for r in self.records(tenant_id) if r.seq > seq]

    def for_subject(self, tenant_id: str, subject: str) -> list[AuditRecord]:
        return [r for r in self.records(tenant_id) if r.subject == subject]

    # ── verification ────────────────────────────────────────────────────────

    def verify(self, tenant_id: str) -> dict[str, Any]:
        """Walk the chain. Reports the first break rather than just a boolean,
        because "the log is broken" is not actionable and "record 47 was altered"
        is."""
        records = self.records(tenant_id)
        expected_seq = 1
        prev_hash = GENESIS_HASH

        for record in records:
            if record.seq != expected_seq:
                return _broken(
                    records,
                    record.seq,
                    f"sequence gap: expected {expected_seq}, found {record.seq}",
                )
            if record.prev_hash != prev_hash:
                return _broken(
                    records,
                    record.seq,
                    "chain break: prev_hash does not match the preceding record",
                )
            if record.hash != record.compute_hash():
                return _broken(records, record.seq, "record contents do not match their hash")
            prev_hash = record.hash
            expected_seq += 1

        return {
            "valid": True,
            "records": len(records),
            "head_hash": prev_hash,
            "broken_at": None,
            "reason": "",
        }


def _broken(records: list[AuditRecord], seq: int, reason: str) -> dict[str, Any]:
    return {
        "valid": False,
        "records": len(records),
        "head_hash": "",
        "broken_at": seq,
        "reason": reason,
    }
