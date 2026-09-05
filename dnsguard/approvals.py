"""The approval gate for disruptive actions.

DNS Guard can stop a name from resolving. That is a production-affecting act: a
wrong block takes down a client's payroll provider as effectively as an outage
does. So the rule this module enforces is simple and absolute — an action
classified as disruptive does not execute until a second person has approved
exactly that action, on exactly that payload.

Mechanically:

  1. classify(action)   -> Disruption. Unknown actions are treated as disruptive,
                           because forgetting to register a new destructive action
                           must fail safe rather than fail open.
  2. gate.authorise(...) -> either proceeds, or opens an ApprovalRequest and
                           raises ApprovalRequiredError. It never executes.
  3. gate.decide(...)    -> a *different* principal approves or rejects.
  4. gate.authorise(..., approval_id=...) -> the approval is checked against the
                           action, the subject and a hash of the payload, then
                           consumed. Single use, so an approval for one change
                           cannot be replayed to push a different one.

Everything above is written to the audit chain, including the refusals.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from enum import Enum
from typing import Any

from .audit import AuditLog, digest
from .clock import Clock, iso, parse_iso
from .errors import ApprovalRequiredError, ConflictError, NotFoundError, ValidationError
from .store import DocumentStore

APPROVAL_COLLECTION = "approvals"
DEFAULT_TTL_SECONDS = 7 * 24 * 3600


class Disruption(str, Enum):
    """How much damage the action can do if it is wrong."""

    NONE = "none"  # read-only or advisory; runs freely
    LOW = "low"  # changes state, no client-visible effect; runs freely, audited
    HIGH = "high"  # changes what resolves, or what a client is told; needs approval


# The registry. An action absent from this map is treated as HIGH — see classify().
ACTION_RISK: dict[str, Disruption] = {
    # Reads and drafts — safe.
    "scan.run": Disruption.NONE,
    "policy.draft": Disruption.LOW,
    "policy.submit": Disruption.LOW,
    "policy.reject": Disruption.LOW,
    "policy.approve": Disruption.LOW,
    "feed.register": Disruption.LOW,
    "feed.refresh": Disruption.LOW,
    "site.create": Disruption.LOW,
    "site.update": Disruption.LOW,
    "tenant.create": Disruption.LOW,
    "alertrule.create": Disruption.LOW,
    "alertrule.update": Disruption.LOW,
    "exception.request": Disruption.LOW,
    "evidence.export": Disruption.LOW,
    # Anything that changes what resolves, or reaches a client, or disables a
    # control — approval required.
    "policy.publish": Disruption.HIGH,
    "policy.rollback": Disruption.HIGH,
    "policy.assign": Disruption.HIGH,
    "policy.unassign": Disruption.HIGH,
    "exception.grant": Disruption.HIGH,
    "exception.revoke": Disruption.HIGH,
    "feed.disable": Disruption.HIGH,
    "feed.trust_change": Disruption.HIGH,
    "enforcement.push": Disruption.HIGH,
    "fleetfix.dispatch": Disruption.HIGH,
    "tenant.delete": Disruption.HIGH,
}


def classify(action: str) -> Disruption:
    """Unknown actions are disruptive. A new destructive verb that nobody
    remembered to register must be blocked, not waved through."""
    return ACTION_RISK.get(action, Disruption.HIGH)


@dataclass
class ApprovalRequest:
    id: str
    tenant_id: str
    action: str
    subject: str
    payload_hash: str
    requested_by: str
    requested_at: str
    expires_at: str
    state: str = "pending"  # pending | approved | rejected | consumed | expired
    reason: str = ""
    decided_by: str = ""
    decided_at: str = ""
    summary: str = ""
    consumed_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ApprovalGate:
    """Guards every disruptive action in the control plane."""

    store: DocumentStore
    audit: AuditLog
    clock: Clock = field(default_factory=Clock)
    require_separation_of_duties: bool = True
    ttl_seconds: int = DEFAULT_TTL_SECONDS

    # ── the gate ────────────────────────────────────────────────────────────

    def authorise(
        self,
        tenant_id: str,
        actor: str,
        action: str,
        subject: str,
        payload: dict[str, Any] | None = None,
        approval_id: str = "",
        summary: str = "",
    ) -> ApprovalRequest | None:
        """Permit `action`, or refuse and open a request for it.

        Returns the consumed ApprovalRequest when one was required and supplied,
        None when the action needed no approval. Raises ApprovalRequiredError
        otherwise — the caller must not execute.
        """
        payload = payload or {}
        risk = classify(action)

        if risk is not Disruption.HIGH:
            self.audit.append(
                tenant_id,
                actor,
                action,
                subject,
                outcome="executed",
                detail={"risk": risk.value, "approval": "not required"},
            )
            return None

        payload_hash = digest({"action": action, "subject": subject, "payload": payload})

        if not approval_id:
            request = self._open(tenant_id, actor, action, subject, payload_hash, summary)
            raise ApprovalRequiredError(
                f"{action} on {subject} is a disruptive action and needs approval "
                f"(request {request.id})",
                request_id=request.id,
                action=action,
            )

        request = self.get(tenant_id, approval_id)
        self._check_usable(request, action, subject, payload_hash, actor)

        request.state = "consumed"
        request.consumed_at = iso(self.clock.now())
        self._save(request)
        self.audit.append(
            tenant_id,
            actor,
            action,
            subject,
            outcome="executed",
            detail={"risk": risk.value, "approved_by": request.decided_by},
            approval_id=request.id,
        )
        return request

    # ── request lifecycle ───────────────────────────────────────────────────

    def _open(
        self, tenant_id: str, actor: str, action: str, subject: str, payload_hash: str, summary: str
    ) -> ApprovalRequest:
        now = self.clock.now()
        request = ApprovalRequest(
            id=f"apr-{uuid.uuid4().hex[:16]}",
            tenant_id=tenant_id,
            action=action,
            subject=subject,
            payload_hash=payload_hash,
            requested_by=actor,
            requested_at=iso(now),
            expires_at=iso(now + timedelta(seconds=self.ttl_seconds)),
            summary=summary or f"{action} on {subject}",
        )
        self._save(request)
        self.audit.append(
            tenant_id,
            actor,
            action,
            subject,
            outcome="pending_approval",
            detail={
                "risk": Disruption.HIGH.value,
                "payload_hash": payload_hash,
                "summary": request.summary,
            },
            approval_id=request.id,
        )
        return request

    def decide(
        self, tenant_id: str, approval_id: str, approver: str, approve: bool, reason: str = ""
    ) -> ApprovalRequest:
        request = self.get(tenant_id, approval_id)

        if request.state != "pending":
            raise ConflictError(f"approval {approval_id} is {request.state}, not pending")
        if self._expired(request):
            request.state = "expired"
            self._save(request)
            raise ConflictError(f"approval {approval_id} expired at {request.expires_at}")
        if self.require_separation_of_duties and approver == request.requested_by:
            self.audit.append(
                tenant_id,
                approver,
                "approval.decide",
                approval_id,
                outcome="denied",
                detail={
                    "reason": "separation of duties: requester cannot approve their own change"
                },
                approval_id=approval_id,
            )
            raise ValidationError(
                "separation of duties: the person who requested a change cannot approve it"
            )

        request.state = "approved" if approve else "rejected"
        request.decided_by = approver
        request.decided_at = iso(self.clock.now())
        request.reason = reason
        self._save(request)
        self.audit.append(
            tenant_id,
            approver,
            "approval.decide",
            approval_id,
            outcome="executed" if approve else "denied",
            detail={
                "decision": request.state,
                "reason": reason,
                "for_action": request.action,
                "for_subject": request.subject,
            },
            approval_id=approval_id,
        )
        return request

    # ── queries ─────────────────────────────────────────────────────────────

    def get(self, tenant_id: str, approval_id: str) -> ApprovalRequest:
        document = self.store.get(tenant_id, APPROVAL_COLLECTION, approval_id)
        if document is None:
            raise NotFoundError(f"approval {approval_id} not found")
        return ApprovalRequest(**document)

    def pending(self, tenant_id: str) -> list[ApprovalRequest]:
        out = []
        for document in self.store.list(tenant_id, APPROVAL_COLLECTION):
            request = ApprovalRequest(**document)
            if request.state == "pending" and not self._expired(request):
                out.append(request)
        return sorted(out, key=lambda r: r.requested_at)

    def all(self, tenant_id: str) -> list[ApprovalRequest]:
        return sorted(
            (ApprovalRequest(**d) for d in self.store.list(tenant_id, APPROVAL_COLLECTION)),
            key=lambda r: r.requested_at,
        )

    # ── internals ───────────────────────────────────────────────────────────

    def _save(self, request: ApprovalRequest) -> None:
        self.store.put(request.tenant_id, APPROVAL_COLLECTION, request.id, request.to_dict())

    def _expired(self, request: ApprovalRequest) -> bool:
        return self.clock.now() > parse_iso(request.expires_at)

    def _check_usable(
        self, request: ApprovalRequest, action: str, subject: str, payload_hash: str, actor: str
    ) -> None:
        """An approval authorises one action, on one subject, with one payload, once."""
        if request.state == "consumed":
            raise ConflictError(f"approval {request.id} has already been used")
        if request.state != "approved":
            raise ConflictError(f"approval {request.id} is {request.state}, not approved")
        if self._expired(request):
            request.state = "expired"
            self._save(request)
            raise ConflictError(f"approval {request.id} expired at {request.expires_at}")
        if request.action != action or request.subject != subject:
            raise ValidationError(
                f"approval {request.id} authorises {request.action} on {request.subject}, "
                f"not {action} on {subject}"
            )
        if request.payload_hash != payload_hash:
            # The change was edited after sign-off. Approving a draft is not
            # approving whatever it later became.
            raise ValidationError(
                f"approval {request.id} was granted for different content; "
                "re-submit the change for approval"
            )
        # Who executes an approved change is deliberately not restricted: the
        # check that matters (requester != approver) was enforced at decide().
        _ = actor
