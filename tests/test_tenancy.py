"""Tenant/site policy resolution, exceptions, and the composed decision path."""

from __future__ import annotations

import pytest

from dnsguard.approvals import ApprovalGate
from dnsguard.audit import AuditLog
from dnsguard.clock import FrozenClock
from dnsguard.errors import ApprovalRequiredError, ConflictError, NotFoundError, ValidationError
from dnsguard.exceptions_policy import ExceptionService, apply_exceptions
from dnsguard.policy import PolicyService, Rule
from dnsguard.store import MemoryStore
from dnsguard.tenancy import Site, Tenant, TenantDirectory


@pytest.fixture
def clock():
    return FrozenClock()


@pytest.fixture
def kit(clock):
    store = MemoryStore()
    log = AuditLog(store, clock)
    gate = ApprovalGate(store=store, audit=log, clock=clock)
    policies = PolicyService(store=store, audit=log, gate=gate, clock=clock)
    exceptions = ExceptionService(store=store, audit=log, gate=gate, clock=clock)
    directory = TenantDirectory(
        store=store, audit=log, gate=gate, policies=policies, exceptions=exceptions, clock=clock
    )
    return type(
        "Kit",
        (),
        {
            "store": store,
            "log": log,
            "gate": gate,
            "policies": policies,
            "exceptions": exceptions,
            "directory": directory,
            "clock": clock,
        },
    )


def approve_and_run(kit, call, approver="ann"):
    """Run a gated call: expect the refusal, approve it, run it again."""
    with pytest.raises(ApprovalRequiredError) as excinfo:
        call()
    request_id = excinfo.value.request_id
    kit.gate.decide("acme", request_id, approver, approve=True)
    return call(approval_id=request_id)


def block(value, **kwargs):
    return Rule(
        action="block",
        match_kind=kwargs.pop("match_kind", "domain"),
        match_value=value,
        justification=kwargs.pop("justification", "known bad"),
        **kwargs,
    )


def publish_policy(kit, policy_id, rules, default_action="allow"):
    version = kit.policies.draft("acme", policy_id, "bill", rules, default_action=default_action)
    kit.policies.submit("acme", policy_id, version.version, "bill")
    return approve_and_run(
        kit,
        lambda approval_id="": kit.policies.publish(
            "acme", policy_id, version.version, "bill", approval_id
        ),
    )


@pytest.fixture
def tenant(kit):
    kit.directory.create_tenant(Tenant(id="acme", name="Acme Ltd"), "bill")
    publish_policy(kit, "baseline", [block("evil.example", justification="malware host")])
    approve_and_run(
        kit,
        lambda approval_id="": kit.directory.assign_tenant_policy(
            "acme", "baseline", "bill", approval_id
        ),
    )
    kit.directory.create_site(Site(id="hq", tenant_id="acme", name="Head office"), "bill")
    return kit


# ── tenants and sites ────────────────────────────────────────────────────────


def test_a_site_is_created_in_monitor_mode(kit):
    kit.directory.create_tenant(Tenant(id="acme", name="Acme Ltd"), "bill")
    site = kit.directory.create_site(
        Site(id="hq", tenant_id="acme", name="Head office", enforcing=True), "bill"
    )
    assert site.enforcing is False, "a new site must not start enforcing"


def test_unknown_site_kinds_are_rejected():
    with pytest.raises(ValidationError):
        Site(id="hq", tenant_id="acme", name="HQ", kind="spaceship")


def test_site_ids_cannot_traverse_the_store():
    with pytest.raises(ValidationError):
        Site(id="../../etc", tenant_id="acme", name="bad")


def test_sites_are_per_tenant(tenant):
    with pytest.raises(NotFoundError):
        tenant.directory.site("globex", "hq")


def test_binding_an_unpublished_policy_is_refused(tenant):
    tenant.policies.draft("acme", "draft-only", "bill", [block("x.example")])
    with pytest.raises(ConflictError, match="no published version"):
        tenant.directory.assign_tenant_policy("acme", "draft-only", "bill")


def test_binding_a_policy_needs_approval(tenant):
    publish_policy(tenant, "strict", [block("other.example")])
    with pytest.raises(ApprovalRequiredError):
        tenant.directory.assign_tenant_policy("acme", "strict", "bill")
    assert tenant.directory.tenant("acme").default_policy_id == "baseline"


def test_turning_enforcement_on_needs_approval(tenant):
    with pytest.raises(ApprovalRequiredError):
        tenant.directory.set_enforcing("acme", "hq", True, "bill")
    assert tenant.directory.site("acme", "hq").enforcing is False


def test_turning_enforcement_off_needs_approval_too(tenant):
    approve_and_run(
        tenant,
        lambda approval_id="": tenant.directory.set_enforcing(
            "acme", "hq", True, "bill", approval_id
        ),
    )
    assert tenant.directory.site("acme", "hq").enforcing is True
    with pytest.raises(ApprovalRequiredError):
        tenant.directory.set_enforcing("acme", "hq", False, "bill")
    assert tenant.directory.site("acme", "hq").enforcing is True


# ── policy resolution ────────────────────────────────────────────────────────


def test_a_site_with_no_override_inherits_the_tenant_baseline(tenant):
    effective = tenant.directory.effective_policy("acme", "hq")
    assert effective.tenant_policy_id == "baseline"
    assert effective.site_policy_id == ""
    assert [r.match_value for r in effective.version.rules] == ["evil.example"]
    assert all(r.source["layer"] == "tenant" for r in effective.version.rules)


def test_a_site_override_stacks_in_front_of_the_baseline(tenant):
    publish_policy(
        tenant,
        "clinical",
        [
            Rule(action="allow", match_kind="domain", match_value="evil.example"),
        ],
    )
    approve_and_run(
        tenant,
        lambda approval_id="": tenant.directory.assign_site_policy(
            "acme", "hq", "clinical", "bill", approval_id
        ),
    )
    effective = tenant.directory.effective_policy("acme", "hq")
    layers = [
        r.source["layer"] for r in sorted(effective.version.rules, key=lambda r: r.precedence)
    ]
    assert layers == ["site", "tenant"]
    assert tenant.directory.decide("acme", "hq", "evil.example").action == "allow"


def test_a_site_rule_beats_a_tenant_rule_whatever_numbers_each_policy_used(tenant):
    """Layer boundaries are absolute — a tenant policy cannot out-prioritise a
    site override by writing precedence=1 into its own rules."""
    publish_policy(tenant, "aggressive", [block("evil.example", precedence=1)])
    approve_and_run(
        tenant,
        lambda approval_id="": tenant.directory.assign_tenant_policy(
            "acme", "aggressive", "bill", approval_id
        ),
    )
    publish_policy(
        tenant,
        "site-allow",
        [
            Rule(action="allow", match_kind="domain", match_value="evil.example", precedence=9999),
        ],
    )
    approve_and_run(
        tenant,
        lambda approval_id="": tenant.directory.assign_site_policy(
            "acme", "hq", "site-allow", "bill", approval_id
        ),
    )
    assert tenant.directory.decide("acme", "hq", "evil.example").action == "allow"


def test_the_stricter_default_action_wins(tenant):
    publish_policy(tenant, "deny-all", [block("x.example")], default_action="block")
    approve_and_run(
        tenant,
        lambda approval_id="": tenant.directory.assign_tenant_policy(
            "acme", "deny-all", "bill", approval_id
        ),
    )
    publish_policy(
        tenant, "loose", [Rule(action="allow", match_kind="domain", match_value="y.example")]
    )
    approve_and_run(
        tenant,
        lambda approval_id="": tenant.directory.assign_site_policy(
            "acme", "hq", "loose", "bill", approval_id
        ),
    )
    assert tenant.directory.effective_policy("acme", "hq").version.default_action == "block"


def test_a_site_with_no_policy_anywhere_is_an_explicit_error(kit):
    kit.directory.create_tenant(Tenant(id="acme", name="Acme"), "bill")
    kit.directory.create_site(Site(id="hq", tenant_id="acme", name="HQ"), "bill")
    with pytest.raises(ConflictError, match="no published policy"):
        kit.directory.effective_policy("acme", "hq")


# ── enforcement mode ─────────────────────────────────────────────────────────


def test_a_monitor_mode_site_records_what_it_would_have_blocked(tenant):
    decision = tenant.directory.decide("acme", "hq", "evil.example")
    assert decision.action == "monitor"
    assert decision.degraded_from == "block"
    assert "monitor mode" in decision.reason
    assert decision.matched_on == "domain:evil.example"


def test_an_enforcing_site_actually_blocks(tenant):
    approve_and_run(
        tenant,
        lambda approval_id="": tenant.directory.set_enforcing(
            "acme", "hq", True, "bill", approval_id
        ),
    )
    assert tenant.directory.decide("acme", "hq", "evil.example").action == "block"


def test_monitor_mode_does_not_touch_an_allow(tenant):
    assert tenant.directory.decide("acme", "hq", "ironcityit.com").action == "allow"


# ── exceptions ───────────────────────────────────────────────────────────────


def test_an_exception_must_expire(kit):
    with pytest.raises(ValidationError, match="longer than"):
        kit.exceptions.request("acme", "bill", "supplier.example", "false positive", ttl_days=400)


def test_an_exception_must_carry_a_reason_and_a_requester():
    from dnsguard.exceptions_policy import Exception_

    with pytest.raises(ValidationError, match="reason"):
        Exception_(
            tenant_id="acme",
            match_kind="domain",
            match_value="x.example",
            reason="",
            requested_by="bill",
        )
    with pytest.raises(ValidationError, match="who asked"):
        Exception_(
            tenant_id="acme",
            match_kind="domain",
            match_value="x.example",
            reason="r",
            requested_by="",
        )


def test_a_requested_exception_does_nothing_until_granted(tenant):
    approve_and_run(
        tenant,
        lambda approval_id="": tenant.directory.set_enforcing(
            "acme", "hq", True, "bill", approval_id
        ),
    )
    tenant.exceptions.request("acme", "bill", "evil.example", "supplier false positive")
    assert tenant.directory.decide("acme", "hq", "evil.example").action == "block"


def test_granting_an_exception_needs_approval(tenant):
    record = tenant.exceptions.request("acme", "bill", "evil.example", "supplier false positive")
    with pytest.raises(ApprovalRequiredError):
        tenant.exceptions.grant("acme", record.id, "bill")
    assert tenant.exceptions.get("acme", record.id).state == "pending"


def test_a_granted_exception_overrides_a_block(tenant):
    approve_and_run(
        tenant,
        lambda approval_id="": tenant.directory.set_enforcing(
            "acme", "hq", True, "bill", approval_id
        ),
    )
    record = tenant.exceptions.request("acme", "bill", "evil.example", "supplier false positive")
    approve_and_run(
        tenant,
        lambda approval_id="": tenant.exceptions.grant("acme", record.id, "bill", approval_id),
    )

    decision = tenant.directory.decide("acme", "hq", "evil.example")
    assert decision.action == "allow"
    assert record.id in decision.reason
    assert decision.degraded_from == "block"


def test_an_exception_lapses_on_its_own(tenant):
    approve_and_run(
        tenant,
        lambda approval_id="": tenant.directory.set_enforcing(
            "acme", "hq", True, "bill", approval_id
        ),
    )
    record = tenant.exceptions.request("acme", "bill", "evil.example", "temporary", ttl_days=7)
    approve_and_run(
        tenant,
        lambda approval_id="": tenant.exceptions.grant("acme", record.id, "bill", approval_id),
    )
    assert tenant.directory.decide("acme", "hq", "evil.example").action == "allow"

    tenant.clock.advance(8 * 24 * 3600)
    assert tenant.exceptions.active("acme") == []
    assert tenant.directory.decide("acme", "hq", "evil.example").action == "block"


def test_the_sweep_records_expiry_on_the_audit_chain(tenant):
    record = tenant.exceptions.request("acme", "bill", "evil.example", "temporary", ttl_days=1)
    approve_and_run(
        tenant,
        lambda approval_id="": tenant.exceptions.grant("acme", record.id, "bill", approval_id),
    )
    tenant.clock.advance(2 * 24 * 3600)

    expired = tenant.exceptions.sweep("acme")
    assert [e.id for e in expired] == [record.id]
    assert tenant.exceptions.get("acme", record.id).state == "expired"
    assert any(r.action == "exception.expire" for r in tenant.log.records("acme"))


def test_the_review_queue_shows_what_is_about_to_lapse(tenant):
    soon = tenant.exceptions.request("acme", "bill", "a.example", "short", ttl_days=5)
    later = tenant.exceptions.request("acme", "bill", "b.example", "long", ttl_days=180)
    for record in (soon, later):
        approve_and_run(
            tenant,
            lambda approval_id="", r=record: tenant.exceptions.grant(
                "acme", r.id, "bill", approval_id
            ),
        )
    assert [e.match_value for e in tenant.exceptions.expiring_within("acme", 30)] == ["a.example"]


def test_revoking_an_exception_needs_approval(tenant):
    record = tenant.exceptions.request("acme", "bill", "evil.example", "supplier")
    approve_and_run(
        tenant,
        lambda approval_id="": tenant.exceptions.grant("acme", record.id, "bill", approval_id),
    )
    with pytest.raises(ApprovalRequiredError):
        tenant.exceptions.revoke("acme", record.id, "bill", "no longer needed")
    assert tenant.exceptions.get("acme", record.id).state == "active"


def test_a_site_scoped_exception_does_not_leak_to_other_sites(tenant):
    tenant.directory.create_site(Site(id="branch", tenant_id="acme", name="Branch"), "bill")
    for site_id in ("hq", "branch"):
        approve_and_run(
            tenant,
            lambda approval_id="", s=site_id: tenant.directory.set_enforcing(
                "acme", s, True, "bill", approval_id
            ),
        )
    record = tenant.exceptions.request("acme", "bill", "evil.example", "hq only", scope="site:hq")
    approve_and_run(
        tenant,
        lambda approval_id="": tenant.exceptions.grant("acme", record.id, "bill", approval_id),
    )

    assert tenant.directory.decide("acme", "hq", "evil.example").action == "allow"
    assert tenant.directory.decide("acme", "branch", "evil.example").action == "block"


def test_an_exception_can_never_turn_an_allow_into_a_block():
    from dnsguard.exceptions_policy import Exception_
    from dnsguard.policy import Decision

    allow = Decision(name="x.example", action="allow", reason="default")
    record = Exception_(
        tenant_id="acme",
        match_kind="domain",
        match_value="x.example",
        reason="r",
        requested_by="bill",
        state="active",
        expires_at="2099-01-01T00:00:00Z",
    )
    assert apply_exceptions("x.example", allow, [record]) is allow


def test_a_wildcard_exception_covers_subdomains():
    from dnsguard.exceptions_policy import Exception_
    from dnsguard.policy import Decision

    blocked = Decision(name="cdn.supplier.example", action="block", reason="listed")
    record = Exception_(
        tenant_id="acme",
        match_kind="wildcard",
        match_value="*.supplier.example",
        reason="whole supplier estate cleared",
        requested_by="bill",
        state="active",
        expires_at="2099-01-01T00:00:00Z",
    )
    assert apply_exceptions("cdn.supplier.example", blocked, [record]).action == "allow"
