"""Compliance mapping, the FleetFix contract, and evidence bundles."""

from __future__ import annotations

import json

import pytest
from base import Finding

from dnsguard.approvals import ApprovalGate
from dnsguard.audit import AUDIT_COLLECTION, AuditLog
from dnsguard.clock import FrozenClock
from dnsguard.compliance import (
    CONTROLS,
    DEFICIENT,
    NOT_ASSESSED,
    SATISFIED,
    assess,
    controls_for_finding,
    coverage,
)
from dnsguard.errors import ApprovalRequiredError, ValidationError
from dnsguard.evidence import SCHEMA as EVIDENCE_SCHEMA
from dnsguard.evidence import EvidenceExporter, verify
from dnsguard.exceptions_policy import ExceptionService
from dnsguard.feeds import FeedRegistry, FeedSource
from dnsguard.fleetfix import SCHEMA as FLEETFIX_SCHEMA
from dnsguard.fleetfix import (
    FleetFixDispatcher,
    build_work_orders,
    is_disruptive,
)
from dnsguard.fleetfix import validate as validate_order
from dnsguard.policy import PolicyService, Rule
from dnsguard.store import MemoryStore


def finding(module, severity, title="An issue", remediation="", target="example.com"):
    return Finding(
        module=module,
        target=target,
        severity=severity,
        title=title,
        detail="detail",
        evidence={"remediation": remediation} if remediation else {},
    )


@pytest.fixture
def clock():
    return FrozenClock()


@pytest.fixture
def kit(clock):
    store = MemoryStore()
    log = AuditLog(store, clock)
    gate = ApprovalGate(store=store, audit=log, clock=clock)
    return type(
        "Kit",
        (),
        {
            "store": store,
            "log": log,
            "gate": gate,
            "clock": clock,
            "policies": PolicyService(store=store, audit=log, gate=gate, clock=clock),
            "feeds": FeedRegistry(store, clock),
            "exceptions": ExceptionService(store=store, audit=log, gate=gate, clock=clock),
        },
    )


# ── compliance mapping ───────────────────────────────────────────────────────


def test_every_mapped_control_key_exists():
    """A typo in the mapping would silently drop a control from every report."""
    from dnsguard.compliance import CAPABILITY_CONTROLS, MODULE_CONTROLS

    for source in (MODULE_CONTROLS, CAPABILITY_CONTROLS):
        for keys in source.values():
            for key in keys:
                assert key in CONTROLS, key


def test_a_clean_finding_satisfies_its_controls():
    statuses = {s.control.key: s for s in assess([finding("dmarc_audit", "info")])}
    assert statuses["CIS_V8:9.5"].status == SATISFIED
    assert statuses["SOC2:CC6.7"].status == SATISFIED


def test_a_material_finding_makes_its_controls_deficient():
    statuses = {s.control.key: s for s in assess([finding("dmarc_audit", "high")])}
    assert statuses["CIS_V8:9.5"].status == DEFICIENT
    assert statuses["CIS_V8:9.5"].evidence[0]["severity"] == "high"


def test_low_and_info_findings_are_observations_not_failures():
    statuses = {s.control.key: s for s in assess([finding("dnssec_audit", "low")])}
    assert statuses["NIST_800_53:SC-20"].status == SATISFIED


def test_one_deficiency_outweighs_a_pass_on_the_same_control():
    statuses = {
        s.control.key: s
        for s in assess([finding("spf_audit", "info"), finding("dkim_audit", "high")])
    }
    assert statuses["CIS_V8:9.5"].status == DEFICIENT


def test_unexamined_controls_are_not_assessed_rather_than_passed():
    statuses = {s.control.key: s for s in assess([finding("dmarc_audit", "info")])}
    assert statuses["SOC2:CC8.1"].status == NOT_ASSESSED
    assert statuses["SOC2:CC8.1"].evidence == []


def test_the_control_plane_itself_is_evidence():
    statuses = {
        s.control.key: s
        for s in assess(
            [], {"audit_chain": {"records": 42, "verified": True}, "approval_gate": {"requests": 3}}
        )
    }
    assert statuses["HIPAA:164.312(b)"].status == SATISFIED
    assert statuses["SOC2:CC8.1"].status == SATISFIED


def test_a_broken_audit_chain_is_not_evidence_of_audit_controls():
    statuses = {
        s.control.key: s for s in assess([], {"audit_chain": {"records": 42, "verified": False}})
    }
    assert statuses["HIPAA:164.312(b)"].status == NOT_ASSESSED


def test_coverage_reports_what_was_not_assessed_alongside_the_rate():
    statuses = assess([finding("dmarc_audit", "high")], frameworks=("CIS_V8",))
    report = coverage(statuses)
    cis = report["frameworks"]["CIS_V8"]
    assert cis["deficient"] == 1
    assert cis["satisfied_rate"] == 0.0
    assert cis["not_assessed_controls"]
    assert cis["total"] == cis["satisfied"] + cis["deficient"] + cis["not_assessed"]


def test_coverage_of_nothing_does_not_divide_by_zero():
    assert coverage(assess([]))["totals"]["satisfied"] == 0


def test_a_finding_knows_which_controls_it_bears_on():
    keys = {c.key for c in controls_for_finding(finding("spf_audit", "high"))}
    assert "CIS_V8:9.5" in keys


# ── FleetFix contract ────────────────────────────────────────────────────────


def test_mail_and_resolution_changes_are_disruptive_by_default():
    assert is_disruptive(finding("dmarc_audit", "high")) is True
    assert is_disruptive(finding("dnssec_audit", "medium")) is True


def test_additive_reversible_fixes_are_not_disruptive():
    assert (
        is_disruptive(
            finding(
                "dns_records",
                "low",
                title="Any certificate authority may issue certificates for this domain",
            )
        )
        is False
    )
    assert is_disruptive(finding("subdomain_discovery", "medium")) is False


def test_a_work_order_carries_severity_sla_and_compliance(clock):
    orders = build_work_orders(
        [finding("dmarc_audit", "high", "Missing DMARC", "Publish a DMARC record")],
        "acme",
        "hq",
        clock,
        scan_id="scan-1",
    )
    assert len(orders) == 1
    order = orders[0]
    assert order.schema == FLEETFIX_SCHEMA
    assert order.severity == "high"
    assert order.sla_due_at > order.created_at
    assert order.source["scan_id"] == "scan-1"
    assert any(c["id"] == "9.5" for c in order.compliance)
    assert order.disruptive is True
    assert order.approval.required is True
    assert order.approval.state == "pending"


def test_findings_without_a_fix_produce_no_work(clock):
    assert build_work_orders([finding("dns_records", "high")], "acme", "hq", clock) == []


def test_informational_findings_are_not_queued_as_work(clock):
    findings = [
        finding("dns_records", "info", remediation="nothing urgent"),
        finding("spf_audit", "high", remediation="fix spf"),
    ]
    orders = build_work_orders(findings, "acme", "hq", clock)
    assert [o.severity for o in orders] == ["high"]


def test_work_is_ordered_worst_first(clock):
    findings = [
        finding("dns_records", "low", remediation="a"),
        finding("spf_audit", "critical", remediation="b"),
        finding("dkim_audit", "medium", remediation="c"),
    ]
    assert [o.severity for o in build_work_orders(findings, "acme", "hq", clock)] == [
        "critical",
        "medium",
        "low",
    ]


def test_a_more_urgent_finding_gets_a_tighter_sla(clock):
    critical = build_work_orders(
        [finding("spf_audit", "critical", remediation="x")], "acme", "hq", clock
    )[0]
    low = build_work_orders([finding("dns_records", "low", remediation="y")], "acme", "hq", clock)[
        0
    ]
    assert critical.sla_due_at < low.sla_due_at


def test_contract_validation_rejects_an_incomplete_order(clock):
    order = build_work_orders(
        [finding("spf_audit", "high", remediation="fix")], "acme", "hq", clock
    )[0]
    validate_order(order)
    order.remediation = ""
    with pytest.raises(ValidationError, match="missing remediation"):
        validate_order(order)


def test_contract_validation_catches_a_disruptive_order_that_skips_approval(clock):
    order = build_work_orders(
        [finding("dmarc_audit", "high", remediation="fix")], "acme", "hq", clock
    )[0]
    order.approval.required = False
    with pytest.raises(ValidationError, match="disruptive but does not require approval"):
        validate_order(order)


def test_an_unknown_schema_is_rejected(clock):
    order = build_work_orders(
        [finding("spf_audit", "high", remediation="fix")], "acme", "hq", clock
    )[0]
    order.schema = "something.else.v9"
    with pytest.raises(ValidationError, match="unknown work order schema"):
        validate_order(order)


def test_dispatch_needs_approval_and_sends_nothing_without_it(kit):
    sent: list = []
    dispatcher = FleetFixDispatcher(
        audit=kit.log, gate=kit.gate, clock=kit.clock, transport=sent.append
    )
    orders = build_work_orders(
        [finding("spf_audit", "high", remediation="fix")], "acme", "hq", kit.clock
    )
    with pytest.raises(ApprovalRequiredError):
        dispatcher.dispatch("acme", orders, "bill")
    assert sent == []
    assert orders[0].state == "draft"


def test_an_approved_dispatch_sends_and_stamps_the_orders(kit):
    sent: list = []
    dispatcher = FleetFixDispatcher(
        audit=kit.log, gate=kit.gate, clock=kit.clock, transport=sent.append
    )
    orders = build_work_orders(
        [finding("dmarc_audit", "high", remediation="fix")], "acme", "hq", kit.clock
    )
    with pytest.raises(ApprovalRequiredError) as excinfo:
        dispatcher.dispatch("acme", orders, "bill")
    kit.gate.decide("acme", excinfo.value.request_id, "ann", approve=True)

    result = dispatcher.dispatch("acme", orders, "bill", approval_id=excinfo.value.request_id)
    assert result["dispatched"] == 1
    assert len(sent) == 1
    assert orders[0].state == "dispatched"
    assert orders[0].approval.state == "approved"
    assert orders[0].approval.approval_id == excinfo.value.request_id


def test_a_batch_cannot_be_extended_after_it_is_approved(kit):
    """The approval covers the exact set of orders, by content hash."""
    dispatcher = FleetFixDispatcher(audit=kit.log, gate=kit.gate, clock=kit.clock)
    orders = build_work_orders(
        [finding("spf_audit", "high", remediation="fix spf")], "acme", "hq", kit.clock
    )
    with pytest.raises(ApprovalRequiredError) as excinfo:
        dispatcher.dispatch("acme", orders, "bill")
    kit.gate.decide("acme", excinfo.value.request_id, "ann", approve=True)

    orders += build_work_orders(
        [finding("dmarc_audit", "critical", remediation="rewrite dmarc")], "acme", "hq", kit.clock
    )
    with pytest.raises(ValidationError, match="different content"):
        dispatcher.dispatch("acme", orders, "bill", approval_id=excinfo.value.request_id)


def test_a_work_order_serialises_to_plain_json(clock):
    """FleetFix receives JSON, so every field has to survive a round trip
    unchanged — including the nested approval block."""
    order = build_work_orders(
        [finding("dmarc_audit", "high", remediation="fix")], "acme", "hq", clock
    )[0]
    payload = json.loads(json.dumps(order.to_dict()))
    assert payload["schema"] == FLEETFIX_SCHEMA
    assert payload["approval"] == {"required": True, "state": "pending", "approval_id": ""}
    assert payload["compliance"] and all(
        {"framework", "id", "title"} <= set(c) for c in payload["compliance"]
    )
    assert payload["content_hash"]


# ── evidence bundles ─────────────────────────────────────────────────────────


def populated(kit):
    """A tenant with some history to export."""
    version = kit.policies.draft(
        "acme",
        "default",
        "bill",
        [
            Rule(
                action="block",
                match_kind="domain",
                match_value="evil.example",
                justification="malware",
            )
        ],
    )
    kit.policies.submit("acme", "default", version.version, "bill")
    with pytest.raises(ApprovalRequiredError) as excinfo:
        kit.policies.publish("acme", "default", version.version, "bill")
    kit.gate.decide("acme", excinfo.value.request_id, "ann", approve=True)
    kit.policies.publish(
        "acme", "default", version.version, "bill", approval_id=excinfo.value.request_id
    )
    kit.feeds.register(
        "acme",
        FeedSource(
            id="icit-malware",
            name="Curated list",
            publisher="Iron City IT",
            url="https://feeds.example/m.txt",
            category="malware",
            trust_tier="vetted",
        ),
    )
    kit.exceptions.request("acme", "bill", "supplier.example", "false positive")
    return EvidenceExporter(
        audit=kit.log,
        policies=kit.policies,
        gate=kit.gate,
        feeds=kit.feeds,
        exceptions=kit.exceptions,
        clock=kit.clock,
    )


def test_a_bundle_contains_every_section_an_auditor_asks_for(kit):
    bundle = populated(kit).export("acme", "bill", [finding("dmarc_audit", "high")])
    assert bundle.schema == EVIDENCE_SCHEMA
    assert set(bundle.sections) >= {
        "audit",
        "approvals",
        "policies",
        "exceptions",
        "feeds",
        "compliance",
        "findings",
    }
    assert bundle.sections["policies"]["default"][0]["state"] == "published"
    assert bundle.sections["approvals"][0]["state"] == "consumed"


def test_a_bundle_verifies_against_its_own_manifest(kit):
    bundle = populated(kit).export("acme", "bill")
    result = verify(bundle.to_dict())
    assert result["valid"] is True
    assert result["problems"] == []
    assert result["sections_checked"] == len(bundle.manifest)


def test_editing_a_bundle_section_breaks_verification(kit):
    payload = populated(kit).export("acme", "bill").to_dict()
    payload["sections"]["approvals"][0]["decided_by"] = "someone-else"
    result = verify(payload)
    assert result["valid"] is False
    assert any("approvals" in p for p in result["problems"])


def test_editing_the_manifest_to_match_still_breaks_the_manifest_hash(kit):
    from dnsguard.audit import digest

    payload = populated(kit).export("acme", "bill").to_dict()
    payload["sections"]["approvals"][0]["decided_by"] = "someone-else"
    payload["manifest"]["approvals"] = digest(payload["sections"]["approvals"])
    result = verify(payload)
    assert result["valid"] is False
    assert any("manifest hash" in p for p in result["problems"])


def test_removing_a_section_is_detected(kit):
    payload = populated(kit).export("acme", "bill").to_dict()
    del payload["sections"]["exceptions"]
    assert verify(payload)["valid"] is False


def test_a_bundle_from_a_tampered_log_says_so_rather_than_hiding_it(kit):
    exporter = populated(kit)
    tampered = kit.store.get("acme", AUDIT_COLLECTION, f"{2:012d}")
    tampered["actor"] = "mallory"
    kit.store.put("acme", AUDIT_COLLECTION, f"{2:012d}", tampered)

    bundle = exporter.export("acme", "bill")
    assert bundle.integrity["audit_chain"]["valid"] is False
    assert "AUDIT CHAIN IS BROKEN" in bundle.integrity["warning"]
    assert verify(bundle.to_dict())["valid"] is False


def test_an_unknown_bundle_schema_is_rejected():
    with pytest.raises(ValidationError, match="unknown evidence schema"):
        verify({"schema": "some.other.v1"})


def test_the_export_itself_is_recorded_on_the_chain(kit):
    exporter = populated(kit)
    bundle = exporter.export("acme", "bill")
    last = kit.log.records("acme")[-1]
    assert last.action == "evidence.export"
    assert last.detail["manifest_hash"] == bundle.manifest_hash


def test_a_bundle_is_written_under_a_name_derived_from_its_hash(kit, tmp_path):
    exporter = populated(kit)
    bundle = exporter.export("acme", "bill")
    path = exporter.write(bundle, tmp_path / "evidence")
    assert bundle.manifest_hash[:16] in path.name
    assert verify(json.loads(path.read_text()))["valid"] is True


def test_bundles_are_per_tenant(kit):
    exporter = populated(kit)
    other = exporter.export("globex", "bill")
    assert other.sections["audit"] == []
    assert other.sections["policies"] == {}
