"""The FleetFix contract: how a finding becomes a piece of remediation work.

FleetFix is the downstream system that actually changes things on client estates.
Handing it free-form findings would push every judgement call — is this safe to
automate? does it need a change window? who signs it off? — onto whatever runs
last. So the contract is explicit and versioned, and two fields carry the weight:

  `disruptive`  — does applying this change what users experience? A DNS record
                  edit does; publishing a CAA record barely does; anything that
                  touches MX does, loudly.
  `approval`    — a disruptive work order is not dispatched until an approval
                  exists for it. This is the same gate the rest of the product
                  uses, deliberately: there is one place where "this could break
                  something" is decided, not one per integration.

Dispatch itself is approval-gated (`fleetfix.dispatch`) because it hands work to
a system that will act on it. Building work orders is free; sending them is not.

Every work order carries its compliance mapping, so the ticket a technician picks
up already says which control it closes — which is also what makes the evidence
pack line up with the work that was done.
"""

from __future__ import annotations

import builtins
import uuid
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from typing import Any

from .approvals import ApprovalGate
from .audit import AuditLog, digest
from .clock import Clock, iso
from .compliance import controls_for_finding
from .errors import ValidationError

SCHEMA = "icit.fleetfix.workorder.v1"

# How long remediation has, by severity. Not a promise to the client — an
# internal default the tenant's contract can override.
SLA_HOURS = {"critical": 24, "high": 72, "medium": 168, "low": 720, "info": 720}

# Modules whose remediation touches live mail or name resolution. Getting these
# wrong takes a client off the air, so they are disruptive by default and the
# classification lives here rather than being decided per ticket.
DISRUPTIVE_MODULES = frozenset(
    {"spf_audit", "dkim_audit", "dmarc_audit", "transport_security_audit", "dnssec_audit"}
)
# Findings whose fix is purely additive and reversible.
NON_DISRUPTIVE_TITLES = frozenset(
    {
        "Any certificate authority may issue certificates for this domain",
        "Mail authentication reports go nowhere",
        "Mail transport failures are not reported",
    }
)


@dataclass
class Approval:
    required: bool
    state: str = "not_required"  # not_required | pending | approved
    approval_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WorkOrder:
    schema: str
    id: str
    tenant_id: str
    site_id: str
    title: str
    description: str
    severity: str
    asset_kind: str
    asset_id: str
    remediation: str
    disruptive: bool
    approval: Approval
    created_at: str
    sla_due_at: str
    source: dict[str, Any] = field(default_factory=dict)
    compliance: builtins.list[dict[str, str]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    state: str = "draft"  # draft | dispatched | rejected
    content_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["approval"] = self.approval.to_dict()
        return payload


def is_disruptive(finding: Any) -> bool:
    """Whether applying this finding's fix changes what users experience."""
    if getattr(finding, "title", "") in NON_DISRUPTIVE_TITLES:
        return False
    return getattr(finding, "module", "") in DISRUPTIVE_MODULES


def build_work_order(
    finding: Any,
    tenant_id: str,
    site_id: str,
    clock: Clock,
    scan_id: str = "",
    sla_hours: dict[str, int] | None = None,
) -> WorkOrder:
    """One finding -> one work order. Findings with no remediation are skipped
    by build_work_orders(); this raises if called on one directly, because a
    work order that does not say what to do is worse than no ticket."""
    remediation = (getattr(finding, "evidence", None) or {}).get("remediation", "")
    if not remediation:
        raise ValidationError(
            f"{getattr(finding, 'title', 'finding')} carries no remediation; "
            "there is nothing to dispatch"
        )

    now = clock.now()
    severity = getattr(finding, "severity", "info")
    hours = (sla_hours or SLA_HOURS).get(severity, 720)
    disruptive = is_disruptive(finding)

    order = WorkOrder(
        schema=SCHEMA,
        id=f"wo-{uuid.uuid4().hex[:16]}",
        tenant_id=tenant_id,
        site_id=site_id,
        title=finding.title,
        description=getattr(finding, "detail", ""),
        severity=severity,
        asset_kind="domain",
        asset_id=getattr(finding, "target", ""),
        remediation=remediation,
        disruptive=disruptive,
        approval=Approval(required=disruptive, state="pending" if disruptive else "not_required"),
        created_at=iso(now),
        sla_due_at=iso(now + timedelta(hours=hours)),
        source={
            "product": "dnsguard",
            "module": getattr(finding, "module", ""),
            "scan_id": scan_id,
        },
        compliance=[
            {"framework": c.framework, "id": c.id, "title": c.title}
            for c in controls_for_finding(finding)
        ],
        evidence={
            k: v
            for k, v in (getattr(finding, "evidence", None) or {}).items()
            if k != "remediation"
        },
    )
    order.content_hash = digest(
        {
            "title": order.title,
            "asset": order.asset_id,
            "remediation": order.remediation,
            "severity": order.severity,
        }
    )
    return order


def build_work_orders(
    findings: builtins.list[Any],
    tenant_id: str,
    site_id: str,
    clock: Clock,
    scan_id: str = "",
    min_severity: str = "low",
) -> builtins.list[WorkOrder]:
    """Work orders for everything actionable, worst first.

    info-level findings are excluded by default: they are inventory, not work,
    and a queue full of them is a queue nobody reads.
    """
    order = ("info", "low", "medium", "high", "critical")
    floor = order.index(min_severity)
    selected = [
        f
        for f in findings
        if order.index(getattr(f, "severity", "info")) >= floor
        and (getattr(f, "evidence", None) or {}).get("remediation")
    ]
    selected.sort(key=lambda f: order.index(f.severity), reverse=True)
    return [build_work_order(f, tenant_id, site_id, clock, scan_id) for f in selected]


def validate(order: WorkOrder) -> WorkOrder:
    """Contract check, applied before anything leaves this product.

    FleetFix is entitled to assume these hold; if they do not, the failure should
    surface here with a name attached rather than downstream as a null.
    """
    if order.schema != SCHEMA:
        raise ValidationError(f"unknown work order schema {order.schema!r}; expected {SCHEMA}")
    for field_name in (
        "id",
        "tenant_id",
        "title",
        "remediation",
        "asset_id",
        "created_at",
        "sla_due_at",
    ):
        if not getattr(order, field_name):
            raise ValidationError(f"work order is missing {field_name}")
    if order.severity not in SLA_HOURS:
        raise ValidationError(f"unknown severity {order.severity!r}")
    if order.disruptive and not order.approval.required:
        raise ValidationError(f"work order {order.id} is disruptive but does not require approval")
    return order


@dataclass
class FleetFixDispatcher:
    """Sends approved work orders onward. Injectable transport, so tests and the
    local server exercise the same path without a live endpoint."""

    audit: AuditLog
    gate: ApprovalGate
    clock: Clock = field(default_factory=Clock)
    transport: Any = None  # Callable[[list[dict]], Any]

    def dispatch(
        self,
        tenant_id: str,
        orders: builtins.list[WorkOrder],
        actor: str,
        approval_id: str = "",
    ) -> dict[str, Any]:
        """Hand work to FleetFix. Disruptive — gated.

        The approval is bound to the exact set being sent (content hashes of
        every order), so a batch cannot be approved and then quietly extended
        before it goes out.
        """
        for order in orders:
            validate(order)

        payload_hashes = sorted(o.content_hash for o in orders)
        subject = f"fleetfix/{tenant_id}"

        approval = self.gate.authorise(
            tenant_id,
            actor,
            "fleetfix.dispatch",
            subject,
            {"orders": payload_hashes},
            approval_id=approval_id,
            summary=(
                f"dispatch {len(orders)} remediation work order(s) to FleetFix, "
                f"{sum(1 for o in orders if o.disruptive)} of them disruptive"
            ),
        )

        for order in orders:
            order.state = "dispatched"
            if order.approval.required:
                order.approval.state = "approved"
                order.approval.approval_id = approval.id if approval else ""

        body = [o.to_dict() for o in orders]
        if self.transport is not None:
            self.transport(body)

        self.audit.append(
            tenant_id,
            actor,
            "fleetfix.dispatched",
            subject,
            outcome="executed",
            detail={
                "count": len(orders),
                "order_ids": [o.id for o in orders],
                "disruptive": sum(1 for o in orders if o.disruptive),
            },
            approval_id=approval.id if approval else "",
        )
        return {"schema": SCHEMA, "dispatched": len(orders), "orders": body}
