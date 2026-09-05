"""Policy lifecycle and the decision engine.

The two properties that matter most: nothing reaches production without an
approval bound to exactly the content that was reviewed, and a decision always
explains itself.
"""

from __future__ import annotations

import pytest

from dnsguard.approvals import ApprovalGate
from dnsguard.audit import AuditLog
from dnsguard.clock import FrozenClock
from dnsguard.errors import ApprovalRequiredError, ConflictError, NotFoundError, ValidationError
from dnsguard.feeds import FeedFetcher, FeedRegistry, FeedSource, FetchResponse, IndicatorIndex
from dnsguard.policy import PolicyService, PolicyVersion, Rule, evaluate
from dnsguard.resilience import BreakerRegistry, RetryPolicy
from dnsguard.store import MemoryStore

FEED_BODY = "0.0.0.0 evil.example\n0.0.0.0 phish.example\n"


@pytest.fixture
def clock():
    return FrozenClock()


@pytest.fixture
def store():
    return MemoryStore()


@pytest.fixture
def service(store, clock):
    log = AuditLog(store, clock)
    gate = ApprovalGate(store=store, audit=log, clock=clock)
    return PolicyService(store=store, audit=log, gate=gate, clock=clock)


def block(value, kind="domain", **kwargs):
    return Rule(
        action="block",
        match_kind=kind,
        match_value=value,
        justification=kwargs.pop("justification", "known bad"),
        **kwargs,
    )


def publish(service, tenant="acme", policy="default", rules=None, actor="bill", approver="ann"):
    """Draft -> submit -> approve -> publish, the whole way through the gate."""
    version = service.draft(
        tenant, policy, actor, rules if rules is not None else [block("evil.example")]
    )
    service.submit(tenant, policy, version.version, actor)
    with pytest.raises(ApprovalRequiredError) as excinfo:
        service.publish(tenant, policy, version.version, actor)
    request_id = excinfo.value.request_id
    service.gate.decide(tenant, request_id, approver, approve=True)
    return service.publish(tenant, policy, version.version, actor, approval_id=request_id)


# ── rules ────────────────────────────────────────────────────────────────────


def test_a_block_rule_must_be_justified():
    with pytest.raises(ValidationError, match="justification"):
        Rule(action="block", match_kind="domain", match_value="evil.example")


def test_an_allow_rule_needs_no_justification():
    assert Rule(action="allow", match_kind="domain", match_value="payroll.example").id


def test_a_redirect_must_say_where_to():
    with pytest.raises(ValidationError, match="redirects to"):
        Rule(action="redirect", match_kind="domain", match_value="x.example")


def test_unknown_actions_and_match_kinds_are_rejected():
    with pytest.raises(ValidationError):
        Rule(action="nuke", match_kind="domain", match_value="x.example")
    with pytest.raises(ValidationError):
        Rule(action="allow", match_kind="vibes", match_value="x.example")


def test_domain_values_are_normalised():
    assert (
        Rule(action="allow", match_kind="domain", match_value="  Evil.Example.  ").match_value
        == "evil.example"
    )


def test_wildcard_covers_the_apex_and_everything_under_it():
    rule = block("*.evil.example", kind="wildcard")
    assert rule.matches("evil.example", set(), set())
    assert rule.matches("login.evil.example", set(), set())
    assert not rule.matches("notevil.example", set(), set())


def test_a_disabled_rule_matches_nothing():
    assert not block("evil.example", enabled=False).matches("evil.example", set(), set())


# ── lifecycle ────────────────────────────────────────────────────────────────


def test_a_draft_starts_at_version_one(service):
    version = service.draft("acme", "default", "bill", [block("evil.example")])
    assert (version.version, version.state) == (1, "draft")


def test_editing_a_draft_replaces_it_rather_than_stacking(service):
    service.draft("acme", "default", "bill", [block("a.example")])
    second = service.draft("acme", "default", "bill", [block("b.example")])
    assert second.version == 1
    assert len(service.versions("acme", "default")) == 1


def test_publishing_requires_approval_and_does_not_happen_without_one(service):
    version = service.draft("acme", "default", "bill", [block("evil.example")])
    service.submit("acme", "default", version.version, "bill")
    with pytest.raises(ApprovalRequiredError):
        service.publish("acme", "default", version.version, "bill")
    assert service.published("acme", "default") is None
    assert service.version("acme", "default", 1).state == "in_review"


def test_an_approved_version_publishes(service):
    published = publish(service)
    assert published.state == "published"
    assert published.published_by == "bill"
    assert published.approval_id
    assert service.published("acme", "default").version == 1


def test_editing_a_version_after_sign_off_blocks_the_publish(service):
    """The approval is bound to a content hash, so a swapped-in ruleset fails."""
    version = service.draft("acme", "default", "bill", [block("evil.example")])
    service.submit("acme", "default", version.version, "bill")
    with pytest.raises(ApprovalRequiredError) as excinfo:
        service.publish("acme", "default", version.version, "bill")
    request_id = excinfo.value.request_id
    service.gate.decide("acme", request_id, "ann", approve=True)

    # Someone rewrites the frozen version directly in the store.
    tampered = service.store.get("acme", "policyversions", "default.1")
    tampered["rules"].append(block("payroll.example").to_dict())
    service.store.put("acme", "policyversions", "default.1", tampered)

    with pytest.raises(ValidationError, match="different content"):
        service.publish("acme", "default", version.version, "bill", approval_id=request_id)


def test_a_frozen_version_cannot_have_its_content_rewritten(service):
    version = service.draft("acme", "default", "bill", [block("evil.example")])
    service.submit("acme", "default", version.version, "bill")
    frozen = service.version("acme", "default", 1)
    frozen.rules.append(block("payroll.example"))
    with pytest.raises(ConflictError, match="cannot be changed"):
        service._save(frozen)


def test_a_second_publish_supersedes_the_first(service):
    publish(service, rules=[block("a.example")])
    service.draft("acme", "default", "bill", [block("b.example")])
    publish(service, rules=[block("b.example")])

    states = {v.version: v.state for v in service.versions("acme", "default")}
    assert states == {1: "superseded", 2: "published"}


def test_an_empty_ruleset_cannot_be_submitted(service):
    service.draft("acme", "default", "bill", [])
    with pytest.raises(ValidationError, match="nothing to review"):
        service.submit("acme", "default", 1, "bill")


def test_a_rejected_version_cannot_be_published(service):
    service.draft("acme", "default", "bill", [block("evil.example")])
    service.submit("acme", "default", 1, "bill")
    service.reject("acme", "default", 1, "ann", "blocks the payroll provider")
    with pytest.raises(ConflictError, match="rejected"):
        service.publish("acme", "default", 1, "bill")


def test_rollback_copies_the_old_version_forward_and_keeps_history(service):
    publish(service, rules=[block("a.example")])
    publish(service, rules=[block("b.example")])

    with pytest.raises(ApprovalRequiredError) as excinfo:
        service.rollback("acme", "default", 1, "bill")
    service.gate.decide("acme", excinfo.value.request_id, "ann", approve=True)
    restored = service.rollback("acme", "default", 1, "bill", approval_id=excinfo.value.request_id)

    assert restored.version == 3
    assert restored.rollback_of == 1
    assert [r.match_value for r in restored.rules] == ["a.example"]
    states = {v.version: v.state for v in service.versions("acme", "default")}
    assert states == {1: "superseded", 2: "rolled_back", 3: "published"}


def test_rollback_needs_approval_too(service):
    publish(service, rules=[block("a.example")])
    with pytest.raises(ApprovalRequiredError):
        service.rollback("acme", "default", 1, "bill")
    assert service.published("acme", "default").version == 1


def test_rollback_to_a_version_that_never_shipped_is_refused(service):
    publish(service, rules=[block("a.example")])
    service.draft("acme", "default", "bill", [block("b.example")])
    with pytest.raises(ConflictError, match="never published"):
        service.rollback("acme", "default", 2, "bill")


def test_policies_are_per_tenant(service):
    publish(service, tenant="acme")
    assert service.versions("globex", "default") == []
    with pytest.raises(NotFoundError):
        service.version("globex", "default", 1)


def test_history_is_the_whole_lifecycle(service):
    publish(service, rules=[block("a.example")])
    history = service.history("acme", "default")
    assert len(history) == 1
    assert history[0]["state"] == "published"
    assert history[0]["approval_id"]
    assert history[0]["content_hash"]


def test_the_whole_lifecycle_lands_on_the_audit_chain(service, store, clock):
    publish(service)
    log = AuditLog(store, clock)
    actions = [r.action for r in log.records("acme")]
    assert actions == [
        "policy.draft",
        "policy.submit",
        "policy.publish",
        "approval.decide",
        "policy.publish",
    ]
    assert log.verify("acme")["valid"] is True


# ── decision engine ──────────────────────────────────────────────────────────


def a_version(rules, default_action="allow"):
    return PolicyVersion(
        tenant_id="acme", policy_id="default", version=7, rules=rules, default_action=default_action
    )


def an_index(clock, category="malware", stale_after=86400):
    registry = FeedRegistry(MemoryStore(), clock)
    registry.register(
        "acme",
        FeedSource(
            id="icit-malware",
            name="Curated malware list",
            publisher="Iron City IT",
            url="https://feeds.example/m.txt",
            category=category,
            trust_tier="vetted",
            fmt="hosts",
            stale_after_seconds=stale_after,
        ),
    )
    fetcher = FeedFetcher(
        registry=registry,
        fetch=lambda url: FetchResponse(FEED_BODY),
        clock=clock,
        breakers=BreakerRegistry(clock=clock),
        policy=RetryPolicy(attempts=1, jitter=False),
    )
    _, indicators = fetcher.refresh("acme", "icit-malware")
    return IndicatorIndex(indicators, registry=registry, tenant_id="acme")


def test_an_unmatched_name_gets_the_policy_default():
    decision = evaluate("ironcityit.com", a_version([block("evil.example")]))
    assert decision.action == "allow"
    assert "policy default" in decision.reason


def test_an_explicit_block_is_reported_with_its_justification():
    rules = [block("evil.example", justification="hosts the invoice-fraud kit")]
    decision = evaluate("evil.example", a_version(rules))
    assert decision.action == "block"
    assert "invoice-fraud kit" in decision.reason
    assert decision.matched_on == "domain:evil.example"


def test_first_match_wins_in_precedence_order():
    rules = [
        block("evil.example", precedence=200),
        Rule(action="allow", match_kind="domain", match_value="evil.example", precedence=10),
    ]
    assert evaluate("evil.example", a_version(rules)).action == "allow"


def test_a_category_rule_blocks_and_cites_the_feed(clock):
    index = an_index(clock)
    rules = [block("malware", kind="category", justification="tenant blocks malware categorically")]
    decision = evaluate("evil.example", a_version(rules), index)

    assert decision.action == "block"
    assert len(decision.provenance) == 1
    citation = decision.provenance[0]
    assert citation["feed_id"] == "icit-malware"
    assert citation["line_no"] == 1
    assert citation["snapshot_sha256"]


def test_a_feed_rule_matches_by_feed_id(clock):
    index = an_index(clock)
    rules = [block("icit-malware", kind="feed", justification="trusted list")]
    assert evaluate("phish.example", a_version(rules), index).action == "block"


def test_a_subdomain_of_a_listed_name_is_covered(clock):
    index = an_index(clock)
    rules = [block("malware", kind="category", justification="tenant blocks malware")]
    decision = evaluate("login.evil.example", a_version(rules), index)
    assert decision.action == "block"
    assert decision.provenance[0]["match_type"] == "parent"


def test_a_stale_feed_cannot_justify_a_new_block(clock):
    """The core staleness rule: if we cannot confirm a list still says what it
    said, we record rather than block."""
    index = an_index(clock, stale_after=3600)
    rules = [block("malware", kind="category", justification="tenant blocks malware")]
    assert evaluate("evil.example", a_version(rules), index).action == "block"

    clock.advance(7200)
    decision = evaluate("evil.example", a_version(rules), index)
    assert decision.action == "monitor"
    assert decision.degraded_from == "block"
    assert "stale" in decision.reason


def test_staleness_degradation_can_be_overridden_deliberately(clock):
    index = an_index(clock, stale_after=3600)
    clock.advance(7200)
    rules = [block("malware", kind="category", justification="tenant blocks malware")]
    decision = evaluate("evil.example", a_version(rules), index, allow_stale_blocks=True)
    assert decision.action == "block"
    assert decision.degraded_from == ""


def test_a_human_written_block_is_not_weakened_by_an_unrelated_stale_feed(clock):
    index = an_index(clock, stale_after=3600)
    clock.advance(7200)
    rules = [block("evil.example", justification="confirmed by the client")]
    decision = evaluate("evil.example", a_version(rules), index)
    assert decision.action == "block"
    assert decision.degraded_from == ""


def test_a_redirect_carries_its_destination():
    rules = [
        Rule(
            action="redirect",
            match_kind="domain",
            match_value="blocked.example",
            redirect_to="https://safe.ironcityit.com/blocked",
        )
    ]
    decision = evaluate("blocked.example", a_version(rules))
    assert decision.action == "redirect"
    assert decision.redirect_to == "https://safe.ironcityit.com/blocked"


def test_a_deny_by_default_policy_cites_what_it_knows(clock):
    index = an_index(clock)
    decision = evaluate("evil.example", a_version([], default_action="block"), index)
    assert decision.action == "block"
    assert decision.provenance
