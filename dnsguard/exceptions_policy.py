"""Exceptions: the supervised way to say "yes, I know, let this one through".

Every protective DNS deployment accumulates these — a supplier's mail scanner on
a spam list, a marketing tool that looks like tracking, a newly registered domain
the client actually just registered. The failure mode is not that exceptions
exist; it is that they are permanent, unattributed and invisible, until the
allowlist is the largest and least understood object in the system.

So three things are enforced here rather than left to discipline:

  * An exception must expire. There is a maximum lifetime and no way to ask for
    "forever"; renewing is a deliberate act that goes back through approval.
  * Granting one is disruptive — it stops a control from applying — so it is
    approval-gated exactly like publishing a policy is.
  * A reason is mandatory, and a ticket reference is carried when there is one,
    because the review a year from now is done by someone who was not there.

Exceptions are evaluated ahead of policy rules: that is what makes them an
override rather than another rule with a lucky precedence number.
"""

from __future__ import annotations

import builtins
import uuid
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from typing import Any

from .approvals import ApprovalGate
from .audit import AuditLog
from .clock import Clock, iso, parse_iso
from .errors import ConflictError, NotFoundError, ValidationError
from .feeds import normalise
from .policy import Decision

EXCEPTION_COLLECTION = "exceptions"

STATES = ("pending", "active", "expired", "revoked", "rejected")
MATCH_KINDS = ("domain", "wildcard")

DEFAULT_TTL_DAYS = 90
MAX_TTL_DAYS = 365


@dataclass
class Exception_:  # noqa: N801 - trailing underscore avoids shadowing the builtin
    """One supervised hole in the policy."""

    tenant_id: str
    match_kind: str
    match_value: str
    reason: str
    requested_by: str
    id: str = ""
    scope: str = "tenant"  # "tenant" or "site:<site_id>"
    state: str = "pending"
    created_at: str = ""
    expires_at: str = ""
    approved_by: str = ""
    approved_at: str = ""
    revoked_by: str = ""
    revoked_at: str = ""
    ticket_ref: str = ""
    approval_id: str = ""

    def __post_init__(self) -> None:
        if self.match_kind not in MATCH_KINDS:
            raise ValidationError(f"unknown match kind {self.match_kind!r}; expected {MATCH_KINDS}")
        if not self.match_value:
            raise ValidationError("an exception must say what it applies to")
        if not self.reason:
            raise ValidationError("an exception must carry a reason")
        if not self.requested_by:
            raise ValidationError("an exception must name who asked for it")
        self.match_value = normalise(self.match_value)
        if not self.id:
            self.id = f"exc-{uuid.uuid4().hex[:12]}"

    @property
    def subject(self) -> str:
        return f"exception/{self.id}"

    def applies_to_site(self, site_id: str) -> bool:
        return self.scope == "tenant" or self.scope == f"site:{site_id}"

    def matches(self, name: str) -> bool:
        if self.match_kind == "domain":
            return name == self.match_value
        bare = self.match_value.removeprefix("*.")
        return name == bare or name.endswith("." + bare)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExceptionService:
    store: Any
    audit: AuditLog
    gate: ApprovalGate
    clock: Clock = field(default_factory=Clock)
    default_ttl_days: int = DEFAULT_TTL_DAYS
    max_ttl_days: int = MAX_TTL_DAYS

    # ── lifecycle ───────────────────────────────────────────────────────────

    def request(
        self,
        tenant_id: str,
        actor: str,
        match_value: str,
        reason: str,
        match_kind: str = "domain",
        scope: str = "tenant",
        ttl_days: int | None = None,
        ticket_ref: str = "",
    ) -> Exception_:
        ttl = self.default_ttl_days if ttl_days is None else ttl_days
        if ttl < 1:
            raise ValidationError("an exception must last at least a day")
        if ttl > self.max_ttl_days:
            raise ValidationError(
                f"an exception may not last longer than {self.max_ttl_days} days; "
                "renew it deliberately instead"
            )

        now = self.clock.now()
        record = Exception_(
            tenant_id=tenant_id,
            match_kind=match_kind,
            match_value=match_value,
            reason=reason,
            requested_by=actor,
            scope=scope,
            created_at=iso(now),
            expires_at=iso(now + timedelta(days=ttl)),
            ticket_ref=ticket_ref,
        )
        self.gate.authorise(
            tenant_id,
            actor,
            "exception.request",
            record.subject,
            {"match": record.match_value, "scope": scope, "ttl_days": ttl},
        )
        self._save(record)
        return record

    def grant(
        self, tenant_id: str, exception_id: str, actor: str, approval_id: str = ""
    ) -> Exception_:
        """Activate an exception. Disruptive — it disables a control."""
        record = self.get(tenant_id, exception_id)
        if record.state != "pending":
            raise ConflictError(f"exception {exception_id} is {record.state}, not pending")
        if self._expired(record):
            record.state = "expired"
            self._save(record)
            raise ConflictError(f"exception {exception_id} expired before it was granted")

        approval = self.gate.authorise(
            tenant_id,
            actor,
            "exception.grant",
            record.subject,
            {"match": record.match_value, "scope": record.scope, "expires_at": record.expires_at},
            approval_id=approval_id,
            summary=f"allow {record.match_value} for {record.scope} until {record.expires_at}: {record.reason}",
        )

        record.state = "active"
        record.approved_by = actor
        record.approved_at = iso(self.clock.now())
        record.approval_id = approval.id if approval else ""
        self._save(record)
        return record

    def revoke(
        self, tenant_id: str, exception_id: str, actor: str, reason: str = "", approval_id: str = ""
    ) -> Exception_:
        """Withdraw an active exception. Also disruptive: a name that has been
        resolving for a client stops resolving."""
        record = self.get(tenant_id, exception_id)
        if record.state != "active":
            raise ConflictError(f"exception {exception_id} is {record.state}, not active")

        self.gate.authorise(
            tenant_id,
            actor,
            "exception.revoke",
            record.subject,
            {"match": record.match_value, "reason": reason},
            approval_id=approval_id,
            summary=f"revoke the exception allowing {record.match_value}: {reason}",
        )

        record.state = "revoked"
        record.revoked_by = actor
        record.revoked_at = iso(self.clock.now())
        self._save(record)
        return record

    def reject(self, tenant_id: str, exception_id: str, actor: str, reason: str) -> Exception_:
        record = self.get(tenant_id, exception_id)
        if record.state != "pending":
            raise ConflictError(f"exception {exception_id} is {record.state}, not pending")
        record.state = "rejected"
        record.reason = f"{record.reason} | rejected: {reason}"
        self.audit.append(
            tenant_id,
            actor,
            "exception.reject",
            record.subject,
            outcome="denied",
            detail={"reason": reason},
        )
        self._save(record)
        return record

    # ── queries ─────────────────────────────────────────────────────────────

    def get(self, tenant_id: str, exception_id: str) -> Exception_:
        document = self.store.get(tenant_id, EXCEPTION_COLLECTION, exception_id)
        if document is None:
            raise NotFoundError(f"exception {exception_id} not found")
        return Exception_(**document)

    def all(self, tenant_id: str) -> builtins.list[Exception_]:
        records = [Exception_(**d) for d in self.store.list(tenant_id, EXCEPTION_COLLECTION)]
        return sorted(records, key=lambda e: e.created_at)

    def active(self, tenant_id: str, site_id: str = "") -> builtins.list[Exception_]:
        """Exceptions in force right now, for this site.

        Expiry is applied on read as well as on the sweep, so a lapsed exception
        stops working the moment it lapses even if nothing has run the sweep.
        """
        out = []
        for record in self.all(tenant_id):
            if record.state != "active" or self._expired(record):
                continue
            if site_id and not record.applies_to_site(site_id):
                continue
            out.append(record)
        return out

    def expiring_within(self, tenant_id: str, days: int) -> builtins.list[Exception_]:
        """What is about to lapse — the queue a reviewer actually works from."""
        horizon = self.clock.now() + timedelta(days=days)
        return [e for e in self.active(tenant_id) if parse_iso(e.expires_at) <= horizon]

    def sweep(self, tenant_id: str) -> builtins.list[Exception_]:
        """Persist the expiry of anything that has lapsed. Not disruptive: it
        restores a control rather than removing one, and it is what the tenant
        already agreed to when they set an end date."""
        expired = []
        for record in self.all(tenant_id):
            if record.state == "active" and self._expired(record):
                record.state = "expired"
                self._save(record)
                self.audit.append(
                    tenant_id,
                    "system",
                    "exception.expire",
                    record.subject,
                    outcome="executed",
                    detail={"match": record.match_value, "expired_at": record.expires_at},
                )
                expired.append(record)
        return expired

    # ── internals ───────────────────────────────────────────────────────────

    def _save(self, record: Exception_) -> None:
        self.store.put(record.tenant_id, EXCEPTION_COLLECTION, record.id, record.to_dict())

    def _expired(self, record: Exception_) -> bool:
        return self.clock.now() > parse_iso(record.expires_at)


def apply_exceptions(
    name: str, decision: Decision, exceptions: builtins.list[Exception_]
) -> Decision:
    """Let an active exception override a restrictive decision.

    Only ever loosens: an exception cannot turn an allow into a block, so a
    mistaken exception can cause an unwanted allow but never an unwanted outage.
    The original action is kept on the decision so the dashboard and the evidence
    pack show what would have happened.
    """
    if decision.action == "allow":
        return decision

    query = normalise(name)
    for record in exceptions:
        if not record.matches(query):
            continue
        return Decision(
            name=query,
            action="allow",
            reason=(
                f"allowed by exception {record.id} ({record.reason}), expires {record.expires_at}"
            ),
            rule_id=record.id,
            matched_on=f"exception:{record.match_value}",
            policy_version=decision.policy_version,
            provenance=decision.provenance,
            degraded_from=decision.action,
        )
    return decision
