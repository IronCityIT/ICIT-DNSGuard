"""Alert rules, and the discipline that stops them becoming noise.

An alerting system earns its place by being believed. Three things here are
aimed at that rather than at raising more alerts:

  * Rules are evaluated against a named, documented metric set. An operator can
    see the exact number a rule fires on, and reproduce it.
  * Every alert carries the evidence that triggered it — the sample events, the
    feeds, the value and the threshold — so the first question ("says who?") is
    already answered in the alert.
  * Cooldown is per rule and per scope. A condition that stays true produces one
    alert and then goes quiet until it is resolved or the cooldown lapses.

Alerts are not disruptive: raising one changes nothing about what resolves. So
they are audited but not approval-gated. Acting on one — pushing a block,
dispatching remediation — goes back through the gate like anything else.
"""

from __future__ import annotations

import builtins
import uuid
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from typing import Any

from .analytics import QueryEvent, summarise
from .audit import AuditLog
from .clock import Clock, iso, parse_iso
from .errors import NotFoundError, ValidationError
from .store import DocumentStore

RULE_COLLECTION = "alertrules"
ALERT_COLLECTION = "alerts"

COMPARATORS = {
    "gt": lambda value, threshold: value > threshold,
    "gte": lambda value, threshold: value >= threshold,
    "lt": lambda value, threshold: value < threshold,
    "lte": lambda value, threshold: value <= threshold,
}

SEVERITIES = ("info", "low", "medium", "high", "critical")

# The metric vocabulary. Anything not in here is rejected at rule-creation time
# rather than silently never firing.
METRICS = (
    "blocked_count",
    "block_rate",
    "unique_blocked_names",
    "would_block_count",
    "stale_feeds",
    "failed_feed_fetches",
    "exceptions_expiring_30d",
    "critical_findings",
    "high_findings",
    "pending_approvals",
)


@dataclass
class AlertRule:
    tenant_id: str
    name: str
    metric: str
    threshold: float
    comparator: str = "gt"
    severity: str = "medium"
    window_minutes: int = 60
    scope: str = "tenant"  # "tenant" or "site:<site_id>"
    cooldown_minutes: int = 60
    enabled: bool = True
    id: str = ""
    description: str = ""

    def __post_init__(self) -> None:
        if self.metric not in METRICS:
            raise ValidationError(f"unknown metric {self.metric!r}; expected one of {METRICS}")
        if self.comparator not in COMPARATORS:
            raise ValidationError(
                f"unknown comparator {self.comparator!r}; expected {tuple(COMPARATORS)}"
            )
        if self.severity not in SEVERITIES:
            raise ValidationError(f"unknown severity {self.severity!r}")
        if self.window_minutes < 1:
            raise ValidationError("an alert window must be at least a minute")
        if not self.id:
            self.id = f"rule-{uuid.uuid4().hex[:12]}"

    def fires_on(self, value: float) -> bool:
        return bool(COMPARATORS[self.comparator](value, self.threshold))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Alert:
    id: str
    tenant_id: str
    rule_id: str
    rule_name: str
    metric: str
    value: float
    threshold: float
    severity: str
    scope: str
    triggered_at: str
    message: str
    state: str = "open"  # open | acknowledged | resolved
    evidence: dict[str, Any] = field(default_factory=dict)
    acknowledged_by: str = ""
    acknowledged_at: str = ""
    resolved_at: str = ""
    resolution: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def compute_metrics(
    events: builtins.list[QueryEvent],
    feed_health: builtins.list[dict[str, Any]] | None = None,
    findings: builtins.list[Any] | None = None,
    expiring_exceptions: int = 0,
    pending_approvals: int = 0,
) -> dict[str, float]:
    """The metric set, computed once and shared by every rule in the pass.

    Kept a plain dict so a rule can be explained to an operator as "this named
    number, compared to this threshold" with nothing hidden behind it.
    """
    stats = summarise(events)
    health = feed_health or []
    found = findings or []
    return {
        "blocked_count": float(stats["blocked"]),
        "block_rate": float(stats["block_rate"]),
        "unique_blocked_names": float(stats["unique_blocked_names"]),
        "would_block_count": float(stats["would_block"]),
        "stale_feeds": float(sum(1 for f in health if f.get("stale"))),
        "failed_feed_fetches": float(sum(int(f.get("failed_fetches", 0)) for f in health)),
        "exceptions_expiring_30d": float(expiring_exceptions),
        "critical_findings": float(
            sum(1 for f in found if getattr(f, "severity", "") == "critical")
        ),
        "high_findings": float(sum(1 for f in found if getattr(f, "severity", "") == "high")),
        "pending_approvals": float(pending_approvals),
    }


@dataclass
class AlertService:
    store: DocumentStore
    audit: AuditLog
    clock: Clock = field(default_factory=Clock)

    # ── rules ───────────────────────────────────────────────────────────────

    def create_rule(self, rule: AlertRule, actor: str) -> AlertRule:
        self.store.put(rule.tenant_id, RULE_COLLECTION, rule.id, rule.to_dict())
        self.audit.append(
            rule.tenant_id,
            actor,
            "alertrule.create",
            f"alertrule/{rule.id}",
            outcome="executed",
            detail={
                "metric": rule.metric,
                "comparator": rule.comparator,
                "threshold": rule.threshold,
            },
        )
        return rule

    def rules(self, tenant_id: str, enabled_only: bool = True) -> builtins.list[AlertRule]:
        found = [AlertRule(**d) for d in self.store.list(tenant_id, RULE_COLLECTION)]
        return [r for r in found if r.enabled] if enabled_only else found

    def set_enabled(self, tenant_id: str, rule_id: str, enabled: bool, actor: str) -> AlertRule:
        document = self.store.get(tenant_id, RULE_COLLECTION, rule_id)
        if document is None:
            raise NotFoundError(f"alert rule {rule_id} not found")
        rule = AlertRule(**document)
        rule.enabled = enabled
        self.store.put(tenant_id, RULE_COLLECTION, rule.id, rule.to_dict())
        self.audit.append(
            tenant_id,
            actor,
            "alertrule.update",
            f"alertrule/{rule.id}",
            outcome="executed",
            detail={"enabled": enabled},
        )
        return rule

    # ── evaluation ──────────────────────────────────────────────────────────

    def evaluate(
        self,
        tenant_id: str,
        metrics: dict[str, float],
        evidence: dict[str, Any] | None = None,
        scope: str = "tenant",
    ) -> builtins.list[Alert]:
        """Run every enabled rule for this scope. Returns only what actually fired."""
        raised: builtins.list[Alert] = []
        now = self.clock.now()

        for rule in self.rules(tenant_id):
            if rule.scope != scope:
                continue
            value = metrics.get(rule.metric)
            if value is None or not rule.fires_on(value):
                continue
            if self._in_cooldown(tenant_id, rule, now):
                continue

            alert = Alert(
                id=f"alert-{uuid.uuid4().hex[:12]}",
                tenant_id=tenant_id,
                rule_id=rule.id,
                rule_name=rule.name,
                metric=rule.metric,
                value=value,
                threshold=rule.threshold,
                severity=rule.severity,
                scope=scope,
                triggered_at=iso(now),
                message=(
                    f"{rule.name}: {rule.metric} is {value:g}, which is "
                    f"{rule.comparator} the threshold of {rule.threshold:g} "
                    f"over the last {rule.window_minutes} minute(s)"
                ),
                evidence=evidence or {},
            )
            self.store.put(tenant_id, ALERT_COLLECTION, alert.id, alert.to_dict())
            self.audit.append(
                tenant_id,
                "system",
                "alert.raise",
                f"alert/{alert.id}",
                outcome="recorded",
                detail={
                    "rule": rule.name,
                    "metric": rule.metric,
                    "value": value,
                    "threshold": rule.threshold,
                    "severity": rule.severity,
                },
            )
            raised.append(alert)
        return raised

    def _in_cooldown(self, tenant_id: str, rule: AlertRule, now: Any) -> bool:
        """Has this rule already fired for this scope recently and not resolved?"""
        cutoff = now - timedelta(minutes=rule.cooldown_minutes)
        for alert in self.alerts(tenant_id):
            if alert.rule_id != rule.id or alert.state == "resolved":
                continue
            if parse_iso(alert.triggered_at) > cutoff:
                return True
        return False

    # ── alert lifecycle ─────────────────────────────────────────────────────

    def alerts(self, tenant_id: str, state: str = "") -> builtins.list[Alert]:
        found = [Alert(**d) for d in self.store.list(tenant_id, ALERT_COLLECTION)]
        if state:
            found = [a for a in found if a.state == state]
        return sorted(found, key=lambda a: a.triggered_at, reverse=True)

    def get(self, tenant_id: str, alert_id: str) -> Alert:
        document = self.store.get(tenant_id, ALERT_COLLECTION, alert_id)
        if document is None:
            raise NotFoundError(f"alert {alert_id} not found")
        return Alert(**document)

    def acknowledge(self, tenant_id: str, alert_id: str, actor: str) -> Alert:
        alert = self.get(tenant_id, alert_id)
        alert.state = "acknowledged"
        alert.acknowledged_by = actor
        alert.acknowledged_at = iso(self.clock.now())
        self.store.put(tenant_id, ALERT_COLLECTION, alert.id, alert.to_dict())
        self.audit.append(
            tenant_id,
            actor,
            "alert.acknowledge",
            f"alert/{alert.id}",
            outcome="executed",
            detail={},
        )
        return alert

    def resolve(self, tenant_id: str, alert_id: str, actor: str, resolution: str) -> Alert:
        if not resolution:
            raise ValidationError("resolving an alert requires saying what was done about it")
        alert = self.get(tenant_id, alert_id)
        alert.state = "resolved"
        alert.resolved_at = iso(self.clock.now())
        alert.resolution = resolution
        self.store.put(tenant_id, ALERT_COLLECTION, alert.id, alert.to_dict())
        self.audit.append(
            tenant_id,
            actor,
            "alert.resolve",
            f"alert/{alert.id}",
            outcome="executed",
            detail={"resolution": resolution},
        )
        return alert


def default_rules(tenant_id: str) -> builtins.list[AlertRule]:
    """The rules a new tenant starts with.

    Deliberately few. A default set that fires constantly teaches operators to
    ignore the product, and every one of these describes a condition that means
    the product itself is not doing its job.
    """
    return [
        AlertRule(
            tenant_id=tenant_id,
            name="Threat feed has gone stale",
            metric="stale_feeds",
            threshold=0,
            comparator="gt",
            severity="high",
            window_minutes=1440,
            description="A feed has not refreshed inside its freshness window, so its entries can no longer justify new blocks.",
        ),
        AlertRule(
            tenant_id=tenant_id,
            name="Blocking has spiked",
            metric="blocked_count",
            threshold=100,
            comparator="gt",
            severity="medium",
            window_minutes=60,
            description="An unusual volume of blocked lookups in an hour — either an incident or an over-broad rule.",
        ),
        AlertRule(
            tenant_id=tenant_id,
            name="Exceptions are about to lapse",
            metric="exceptions_expiring_30d",
            threshold=0,
            comparator="gt",
            severity="low",
            window_minutes=1440,
            cooldown_minutes=10080,
            description="Allowlist entries expiring within 30 days need review before they lapse and cause a surprise block.",
        ),
        AlertRule(
            tenant_id=tenant_id,
            name="Critical exposure found",
            metric="critical_findings",
            threshold=0,
            comparator="gt",
            severity="critical",
            window_minutes=1440,
            description="A scan found a critical issue, such as a sender policy that authorises the whole internet.",
        ),
        AlertRule(
            tenant_id=tenant_id,
            name="Changes are waiting for sign-off",
            metric="pending_approvals",
            threshold=5,
            comparator="gt",
            severity="low",
            window_minutes=1440,
            cooldown_minutes=1440,
            description="Approval requests are queuing up; protection changes are sitting unapplied.",
        ),
    ]
