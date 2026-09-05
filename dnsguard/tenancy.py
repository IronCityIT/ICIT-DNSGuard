"""Tenants, sites, and which policy actually applies where.

A client is not one uniform network. The head office, the guest wifi, a clinical
network and a pool of remote laptops need different answers to the same name, and
a product that can only express one policy per client gets used at its weakest
setting everywhere.

So: a Tenant carries a baseline policy; each Site may override it with its own,
and the effective ruleset is the site's rules stacked in front of the tenant's
baseline. Site rules win, because that is the direction people expect an
override to work, and because it is the only ordering where reading the site
policy tells you what the site does.

Two safety properties are structural rather than procedural:

  * A new site starts non-enforcing. Blocks compute, get recorded, and do not
    take effect until someone turns enforcement on — which is itself an
    approval-gated action. Nobody has ever regretted a monitor-mode first week.
  * Binding a policy to a tenant or a site is disruptive (it changes what
    resolves) and goes through the approval gate.
"""

from __future__ import annotations

import builtins
from dataclasses import asdict, dataclass, field
from typing import Any

from .approvals import ApprovalGate
from .audit import AuditLog
from .clock import Clock, iso
from .errors import ConflictError, NotFoundError, ValidationError
from .exceptions_policy import ExceptionService, apply_exceptions
from .feeds import IndicatorIndex
from .policy import Decision, PolicyService, PolicyVersion, evaluate
from .store import DocumentStore, validate_segment

TENANT_COLLECTION = "tenant"
SITE_COLLECTION = "sites"

SITE_KINDS = ("office", "remote", "datacenter", "guest", "clinical", "ot", "other")

# Where a site's own rules sit relative to the tenant baseline. Lower is earlier.
SITE_RULE_PRECEDENCE = 50
TENANT_RULE_PRECEDENCE = 100


@dataclass
class Tenant:
    id: str
    name: str
    auth0_org_id: str = ""
    default_policy_id: str = ""
    status: str = "active"  # active | suspended
    created_at: str = ""
    contact_email: str = ""
    compliance_frameworks: builtins.list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Site:
    id: str
    tenant_id: str
    name: str
    kind: str = "office"
    policy_id: str = ""  # empty => inherit the tenant baseline
    enforcing: bool = False
    egress_networks: builtins.list[str] = field(default_factory=list)
    timezone: str = "UTC"
    tags: builtins.list[str] = field(default_factory=list)
    created_at: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        if self.kind not in SITE_KINDS:
            raise ValidationError(f"unknown site kind {self.kind!r}; expected {SITE_KINDS}")
        validate_segment(self.id, "site id")

    @property
    def subject(self) -> str:
        return f"site/{self.id}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EffectivePolicy:
    """What a site actually runs, and where each part of it came from."""

    tenant_id: str
    site_id: str
    version: PolicyVersion
    enforcing: bool
    tenant_policy_id: str
    tenant_policy_version: int
    site_policy_id: str
    site_policy_version: int

    def explain(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "site_id": self.site_id,
            "enforcing": self.enforcing,
            "tenant_policy": f"{self.tenant_policy_id}@{self.tenant_policy_version}"
            if self.tenant_policy_id
            else None,
            "site_policy": f"{self.site_policy_id}@{self.site_policy_version}"
            if self.site_policy_id
            else None,
            "rule_count": len(self.version.rules),
            "default_action": self.version.default_action,
        }


@dataclass
class TenantDirectory:
    store: DocumentStore
    audit: AuditLog
    gate: ApprovalGate
    policies: PolicyService
    exceptions: ExceptionService
    clock: Clock = field(default_factory=Clock)

    # ── tenants ─────────────────────────────────────────────────────────────

    def create_tenant(self, tenant: Tenant, actor: str) -> Tenant:
        validate_segment(tenant.id, "tenant id")
        if not tenant.created_at:
            tenant.created_at = iso(self.clock.now())
        self.gate.authorise(
            tenant.id, actor, "tenant.create", f"tenant/{tenant.id}", {"name": tenant.name}
        )
        self.store.put(tenant.id, TENANT_COLLECTION, "profile", tenant.to_dict())
        return tenant

    def tenant(self, tenant_id: str) -> Tenant:
        document = self.store.get(tenant_id, TENANT_COLLECTION, "profile")
        if document is None:
            raise NotFoundError(f"tenant {tenant_id} not found")
        return Tenant(**document)

    def assign_tenant_policy(
        self, tenant_id: str, policy_id: str, actor: str, approval_id: str = ""
    ) -> Tenant:
        """Change the baseline every site inherits. Disruptive."""
        tenant = self.tenant(tenant_id)
        if self.policies.published(tenant_id, policy_id) is None:
            raise ConflictError(f"policy {policy_id} has no published version to bind")

        self.gate.authorise(
            tenant_id,
            actor,
            "policy.assign",
            f"tenant/{tenant_id}",
            {"policy_id": policy_id, "previous": tenant.default_policy_id},
            approval_id=approval_id,
            summary=f"make {policy_id} the baseline policy for every site in {tenant_id}",
        )
        tenant.default_policy_id = policy_id
        self.store.put(tenant_id, TENANT_COLLECTION, "profile", tenant.to_dict())
        return tenant

    # ── sites ───────────────────────────────────────────────────────────────

    def create_site(self, site: Site, actor: str) -> Site:
        """A site is created in monitor mode. Turning on enforcement is a
        separate, approval-gated act."""
        if not site.created_at:
            site.created_at = iso(self.clock.now())
        site.enforcing = False
        self.gate.authorise(
            site.tenant_id,
            actor,
            "site.create",
            site.subject,
            {"name": site.name, "kind": site.kind},
        )
        self.store.put(site.tenant_id, SITE_COLLECTION, site.id, site.to_dict())
        return site

    def site(self, tenant_id: str, site_id: str) -> Site:
        document = self.store.get(tenant_id, SITE_COLLECTION, site_id)
        if document is None:
            raise NotFoundError(f"site {site_id} not found for tenant {tenant_id}")
        return Site(**document)

    def sites(self, tenant_id: str) -> builtins.list[Site]:
        return [Site(**d) for d in self.store.list(tenant_id, SITE_COLLECTION)]

    def assign_site_policy(
        self, tenant_id: str, site_id: str, policy_id: str, actor: str, approval_id: str = ""
    ) -> Site:
        """Override the baseline for one site, or clear the override with ""."""
        site = self.site(tenant_id, site_id)
        if policy_id and self.policies.published(tenant_id, policy_id) is None:
            raise ConflictError(f"policy {policy_id} has no published version to bind")

        action = "policy.assign" if policy_id else "policy.unassign"
        self.gate.authorise(
            tenant_id,
            actor,
            action,
            site.subject,
            {"policy_id": policy_id, "previous": site.policy_id},
            approval_id=approval_id,
            summary=(
                f"bind {policy_id} to site {site_id}"
                if policy_id
                else f"clear the policy override on site {site_id}, returning it to the tenant baseline"
            ),
        )
        site.policy_id = policy_id
        self.store.put(tenant_id, SITE_COLLECTION, site.id, site.to_dict())
        return site

    def set_enforcing(
        self, tenant_id: str, site_id: str, enforcing: bool, actor: str, approval_id: str = ""
    ) -> Site:
        """Turn real enforcement on or off for a site.

        Both directions are disruptive. Switching on starts blocking traffic that
        was flowing; switching off silently removes protection the client thinks
        they have, which is worse, not better.
        """
        site = self.site(tenant_id, site_id)
        self.gate.authorise(
            tenant_id,
            actor,
            "enforcement.push",
            site.subject,
            {"enforcing": enforcing, "previous": site.enforcing},
            approval_id=approval_id,
            summary=(
                f"start enforcing policy at site {site_id}"
                if enforcing
                else f"STOP enforcing policy at site {site_id} — protection is removed"
            ),
        )
        site.enforcing = enforcing
        self.store.put(tenant_id, SITE_COLLECTION, site.id, site.to_dict())
        return site

    # ── resolution ──────────────────────────────────────────────────────────

    def effective_policy(self, tenant_id: str, site_id: str) -> EffectivePolicy:
        """Stack the site's rules in front of the tenant baseline.

        Both sets are re-stamped with their layer's precedence, so a site rule
        beats a tenant rule regardless of what precedence numbers each policy
        happened to use internally. Within a layer, the author's ordering holds.
        """
        tenant = self.tenant(tenant_id)
        site = self.site(tenant_id, site_id)

        baseline = (
            self.policies.published(tenant_id, tenant.default_policy_id)
            if tenant.default_policy_id
            else None
        )
        override = self.policies.published(tenant_id, site.policy_id) if site.policy_id else None

        if baseline is None and override is None:
            raise ConflictError(
                f"site {site_id} has no published policy: neither the tenant baseline "
                f"({tenant.default_policy_id or 'unset'}) nor a site override is live"
            )

        def layered(version: PolicyVersion | None, base: int, layer: dict[str, Any]) -> list[Any]:
            """Flatten one layer: keep the author's ordering, then stamp every
            rule with the layer's precedence so the layers cannot interleave.

            evaluate() sorts stably, so ordering inside a layer survives while
            the layer boundary becomes absolute — a site rule beats a tenant rule
            whatever precedence numbers either policy happened to use internally.
            """
            if version is None:
                return []
            out = []
            for rule in sorted(version.rules, key=lambda r: r.precedence):
                copied = type(rule)(**rule.to_dict())
                copied.precedence = base
                copied.source = {**copied.source, **layer}
                out.append(copied)
            return out

        rules = layered(override, SITE_RULE_PRECEDENCE, {"layer": "site", "site_id": site_id})
        rules += layered(baseline, TENANT_RULE_PRECEDENCE, {"layer": "tenant"})

        # The stricter of the two defaults wins: an override must not silently
        # loosen a tenant that has chosen deny-by-default.
        defaults = [p.default_action for p in (override, baseline) if p is not None]
        default_action = (
            "block" if "block" in defaults else ("monitor" if "monitor" in defaults else "allow")
        )

        merged = PolicyVersion(
            tenant_id=tenant_id,
            policy_id=f"effective:{site_id}",
            version=(override or baseline).version,  # type: ignore[union-attr]
            rules=rules,
            state="published",
            default_action=default_action,
        )
        return EffectivePolicy(
            tenant_id=tenant_id,
            site_id=site_id,
            version=merged,
            enforcing=site.enforcing,
            tenant_policy_id=tenant.default_policy_id if baseline else "",
            tenant_policy_version=baseline.version if baseline else 0,
            site_policy_id=site.policy_id if override else "",
            site_policy_version=override.version if override else 0,
        )

    def decide(
        self,
        tenant_id: str,
        site_id: str,
        name: str,
        index: IndicatorIndex | None = None,
    ) -> Decision:
        """The whole decision path for one name at one site.

        Order matters and is fixed: policy rules decide, active exceptions can
        loosen that decision, and finally a non-enforcing site downgrades any
        remaining restriction to monitor. Enforcement last, so the record still
        shows what would have happened — that is the entire value of a monitor
        rollout.
        """
        effective = self.effective_policy(tenant_id, site_id)
        decision = evaluate(name, effective.version, index)
        decision = apply_exceptions(name, decision, self.exceptions.active(tenant_id, site_id))

        if not effective.enforcing and decision.action in ("block", "redirect"):
            return Decision(
                name=decision.name,
                action="monitor",
                reason=f"site {site_id} is in monitor mode; would have been {decision.action}: {decision.reason}",
                rule_id=decision.rule_id,
                matched_on=decision.matched_on,
                policy_version=decision.policy_version,
                provenance=decision.provenance,
                degraded_from=decision.action,
            )
        return decision
