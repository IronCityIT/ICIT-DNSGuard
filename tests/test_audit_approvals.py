"""The audit chain and the approval gate.

These two are the product's accountability story, so the tests are adversarial:
they tamper with records, replay approvals, edit payloads after sign-off, and
check that each is caught.
"""

from __future__ import annotations

import pytest

from dnsguard.approvals import ACTION_RISK, ApprovalGate, Disruption, classify
from dnsguard.audit import AUDIT_COLLECTION, GENESIS_HASH, AuditLog
from dnsguard.clock import FrozenClock
from dnsguard.errors import ApprovalRequiredError, ConflictError, NotFoundError, ValidationError
from dnsguard.store import MemoryStore


@pytest.fixture
def clock():
    return FrozenClock()


@pytest.fixture
def store():
    return MemoryStore()


@pytest.fixture
def log(store, clock):
    return AuditLog(store, clock)


@pytest.fixture
def gate(store, log, clock):
    return ApprovalGate(store=store, audit=log, clock=clock)


# ── audit chain ──────────────────────────────────────────────────────────────


def test_first_record_chains_to_genesis(log):
    record = log.append("acme", "bill", "policy.draft", "policy/default", outcome="executed")
    assert record.seq == 1
    assert record.prev_hash == GENESIS_HASH
    assert record.hash == record.compute_hash()


def test_records_chain_in_sequence(log):
    first = log.append("acme", "bill", "policy.draft", "p/1", outcome="executed")
    second = log.append("acme", "bill", "policy.submit", "p/1", outcome="executed")
    assert second.seq == 2
    assert second.prev_hash == first.hash
    assert log.verify("acme")["valid"] is True


def test_each_tenant_has_its_own_chain(log):
    log.append("acme", "bill", "a", "s", outcome="executed")
    log.append("globex", "ann", "a", "s", outcome="executed")
    assert [r.seq for r in log.records("acme")] == [1]
    assert [r.seq for r in log.records("globex")] == [1]
    assert log.verify("acme")["valid"] and log.verify("globex")["valid"]


def test_an_empty_chain_verifies(log):
    assert log.verify("acme") == {
        "valid": True,
        "records": 0,
        "head_hash": GENESIS_HASH,
        "broken_at": None,
        "reason": "",
    }


def test_editing_a_record_is_detected(log, store):
    log.append("acme", "bill", "policy.publish", "p/1", outcome="executed")
    log.append("acme", "bill", "policy.publish", "p/2", outcome="executed")
    log.append("acme", "bill", "policy.publish", "p/3", outcome="executed")

    tampered = store.get("acme", AUDIT_COLLECTION, f"{2:012d}")
    tampered["actor"] = "someone-else"
    store.put("acme", AUDIT_COLLECTION, f"{2:012d}", tampered)

    result = log.verify("acme")
    assert result["valid"] is False
    assert result["broken_at"] == 2
    assert "hash" in result["reason"]


def test_removing_a_record_is_detected(log, store):
    for n in range(1, 4):
        log.append("acme", "bill", "policy.publish", f"p/{n}", outcome="executed")
    store.delete("acme", AUDIT_COLLECTION, f"{2:012d}")

    result = log.verify("acme")
    assert result["valid"] is False
    assert result["broken_at"] == 3


def test_re_signing_a_tampered_record_still_breaks_the_chain(log, store):
    """An attacker who recomputes the record's own hash still cannot fix the
    successor's prev_hash without rewriting every record after it."""
    for n in range(1, 4):
        log.append("acme", "bill", "policy.publish", f"p/{n}", outcome="executed")

    from dnsguard.audit import AuditRecord

    doc = store.get("acme", AUDIT_COLLECTION, f"{2:012d}")
    doc["actor"] = "mallory"
    record = AuditRecord(**{**doc, "hash": ""})
    doc["hash"] = record.compute_hash()
    store.put("acme", AUDIT_COLLECTION, f"{2:012d}", doc)

    result = log.verify("acme")
    assert result["valid"] is False
    assert result["broken_at"] == 3
    assert "chain break" in result["reason"]


def test_unknown_outcome_is_rejected(log):
    with pytest.raises(ValidationError):
        log.append("acme", "bill", "a", "s", outcome="probably-fine")


def test_an_anonymous_actor_is_rejected(log):
    with pytest.raises(ValidationError):
        log.append("acme", "", "a", "s", outcome="executed")


def test_records_are_queryable_by_subject(log):
    log.append("acme", "bill", "policy.draft", "policy/default", outcome="executed")
    log.append("acme", "bill", "policy.draft", "policy/other", outcome="executed")
    assert [r.subject for r in log.for_subject("acme", "policy/default")] == ["policy/default"]


# ── risk classification ──────────────────────────────────────────────────────


def test_reads_and_drafts_are_not_disruptive():
    assert classify("scan.run") is Disruption.NONE
    assert classify("policy.draft") is Disruption.LOW


def test_actions_that_change_resolution_are_disruptive():
    for action in ("policy.publish", "policy.rollback", "exception.grant", "enforcement.push"):
        assert classify(action) is Disruption.HIGH, action


def test_an_unregistered_action_fails_closed():
    """Forgetting to register a new destructive verb must block it, not allow it."""
    assert "policy.nuke_everything" not in ACTION_RISK
    assert classify("policy.nuke_everything") is Disruption.HIGH


# ── the gate ─────────────────────────────────────────────────────────────────


def test_a_safe_action_runs_and_is_audited(gate, log):
    assert gate.authorise("acme", "bill", "policy.draft", "policy/default") is None
    record = log.records("acme")[-1]
    assert record.action == "policy.draft"
    assert record.outcome == "executed"


def test_a_disruptive_action_is_refused_and_opens_a_request(gate, log):
    with pytest.raises(ApprovalRequiredError) as excinfo:
        gate.authorise("acme", "bill", "policy.publish", "policy/default@3", {"rules": 12})

    assert excinfo.value.request_id.startswith("apr-")
    assert excinfo.value.status_code == 202
    pending = gate.pending("acme")
    assert len(pending) == 1
    assert pending[0].action == "policy.publish"
    assert log.records("acme")[-1].outcome == "pending_approval"


def test_an_approved_request_lets_the_action_through_once(gate):
    with pytest.raises(ApprovalRequiredError) as excinfo:
        gate.authorise("acme", "bill", "policy.publish", "policy/default@3", {"rules": 12})
    request_id = excinfo.value.request_id

    gate.decide("acme", request_id, "ann", approve=True, reason="reviewed the diff")
    consumed = gate.authorise(
        "acme", "bill", "policy.publish", "policy/default@3", {"rules": 12}, approval_id=request_id
    )
    assert consumed.state == "consumed"
    assert consumed.decided_by == "ann"

    # Replay of the same approval must fail.
    with pytest.raises(ConflictError):
        gate.authorise(
            "acme",
            "bill",
            "policy.publish",
            "policy/default@3",
            {"rules": 12},
            approval_id=request_id,
        )


def test_the_requester_cannot_approve_their_own_change(gate):
    with pytest.raises(ApprovalRequiredError) as excinfo:
        gate.authorise("acme", "bill", "policy.publish", "policy/default@3", {})
    with pytest.raises(ValidationError, match="separation of duties"):
        gate.decide("acme", excinfo.value.request_id, "bill", approve=True)


def test_separation_of_duties_can_be_relaxed_deliberately(store, log, clock):
    gate = ApprovalGate(store=store, audit=log, clock=clock, require_separation_of_duties=False)
    with pytest.raises(ApprovalRequiredError) as excinfo:
        gate.authorise("acme", "bill", "policy.publish", "p@1", {})
    assert gate.decide("acme", excinfo.value.request_id, "bill", approve=True).state == "approved"


def test_a_rejected_request_does_not_authorise_anything(gate):
    with pytest.raises(ApprovalRequiredError) as excinfo:
        gate.authorise("acme", "bill", "policy.publish", "p@1", {})
    request_id = excinfo.value.request_id
    gate.decide("acme", request_id, "ann", approve=False, reason="blocks the payroll provider")
    with pytest.raises(ConflictError, match="rejected"):
        gate.authorise("acme", "bill", "policy.publish", "p@1", {}, approval_id=request_id)


def test_an_approval_cannot_be_moved_to_a_different_change(gate):
    with pytest.raises(ApprovalRequiredError) as excinfo:
        gate.authorise("acme", "bill", "policy.publish", "p@1", {})
    request_id = excinfo.value.request_id
    gate.decide("acme", request_id, "ann", approve=True)
    with pytest.raises(ValidationError, match="authorises"):
        gate.authorise("acme", "bill", "policy.publish", "p@2", {}, approval_id=request_id)


def test_editing_the_payload_after_sign_off_invalidates_the_approval(gate):
    with pytest.raises(ApprovalRequiredError) as excinfo:
        gate.authorise("acme", "bill", "policy.publish", "p@1", {"rules": ["block a.example"]})
    request_id = excinfo.value.request_id
    gate.decide("acme", request_id, "ann", approve=True)

    with pytest.raises(ValidationError, match="different content"):
        gate.authorise(
            "acme",
            "bill",
            "policy.publish",
            "p@1",
            {"rules": ["block a.example", "block payroll.example"]},
            approval_id=request_id,
        )


def test_an_expired_request_cannot_be_approved(gate, clock):
    with pytest.raises(ApprovalRequiredError) as excinfo:
        gate.authorise("acme", "bill", "policy.publish", "p@1", {})
    clock.advance(8 * 24 * 3600)
    with pytest.raises(ConflictError, match="expired"):
        gate.decide("acme", excinfo.value.request_id, "ann", approve=True)


def test_an_approval_expires_before_it_is_used(store, log, clock):
    gate = ApprovalGate(store=store, audit=log, clock=clock, ttl_seconds=3600)
    with pytest.raises(ApprovalRequiredError) as excinfo:
        gate.authorise("acme", "bill", "policy.publish", "p@1", {})
    request_id = excinfo.value.request_id
    gate.decide("acme", request_id, "ann", approve=True)
    clock.advance(7200)
    with pytest.raises(ConflictError, match="expired"):
        gate.authorise("acme", "bill", "policy.publish", "p@1", {}, approval_id=request_id)


def test_expired_requests_drop_out_of_the_pending_queue(gate, clock):
    with pytest.raises(ApprovalRequiredError):
        gate.authorise("acme", "bill", "policy.publish", "p@1", {})
    assert len(gate.pending("acme")) == 1
    clock.advance(8 * 24 * 3600)
    assert gate.pending("acme") == []


def test_an_approval_from_another_tenant_is_not_visible(gate):
    with pytest.raises(ApprovalRequiredError) as excinfo:
        gate.authorise("acme", "bill", "policy.publish", "p@1", {})
    with pytest.raises(NotFoundError):
        gate.get("globex", excinfo.value.request_id)


def test_decisions_and_refusals_are_all_on_the_chain(gate, log):
    with pytest.raises(ApprovalRequiredError) as excinfo:
        gate.authorise("acme", "bill", "policy.publish", "p@1", {})
    request_id = excinfo.value.request_id
    gate.decide("acme", request_id, "ann", approve=True)
    gate.authorise("acme", "bill", "policy.publish", "p@1", {}, approval_id=request_id)

    outcomes = [(r.action, r.outcome) for r in log.records("acme")]
    assert outcomes == [
        ("policy.publish", "pending_approval"),
        ("approval.decide", "executed"),
        ("policy.publish", "executed"),
    ]
    assert log.verify("acme")["valid"] is True
    assert all(r.approval_id == request_id for r in log.records("acme"))
