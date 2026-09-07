"""Scan ingest: the self-hosted replacement for storeScanResults.

Most of these tests exist to stop a migration losing a lesson. The Cloud Function
this replaces had three behaviours that were each added *after* something went
wrong in production — monotonic status, a terminal state always written, and the
submitter's address never returned. Re-implementing the same job on new
infrastructure is exactly the moment those get dropped, so they are asserted here
rather than trusted to survive by being remembered.

The fourth group covers the thing the old implementation got wrong: a flat
collection whose isolation depended on every reader remembering to filter.
"""

from __future__ import annotations

import pytest

from dnsguard.audit import AuditLog
from dnsguard.clock import FrozenClock
from dnsguard.errors import ValidationError
from dnsguard.scans import SCAN_COLLECTION, SUBMITTER_COLLECTION, ScanService
from dnsguard.store import MemoryStore


@pytest.fixture
def clock():
    return FrozenClock()


@pytest.fixture
def store():
    return MemoryStore()


@pytest.fixture
def scans(store, clock):
    return ScanService(store=store, audit=AuditLog(store, clock), clock=clock)


def report(scan_id="scan-1", status="complete", **extra):
    """A payload shaped like the one the pipeline actually sends."""
    return {
        "product_id": "dnsguard",
        "scan_id": scan_id,
        "client_name": "Acme Ltd",
        "target": "acme.example",
        "status": status,
        "findings": [{"severity": "high", "title": "Missing SPF Record"}],
        "overall_risk_score": 42,
        **extra,
    }


# ── monotonic status: the lesson that cost real findings ─────────────────────


def test_a_failure_never_overwrites_a_completed_scan(scans):
    """The workflow reports failure whenever ANY job in the run failed, which
    includes a run whose scan succeeded and whose AI analysis did not. That run
    already stored real findings, and they are worth more than a failure
    notice."""
    scans.ingest("acme", report(status="complete"))
    scans.ingest("acme", report(status="failed", error={"stage": "analyze-store"}))

    stored = scans.get("acme", "scan-1")
    assert stored["status"] == "complete"
    assert stored["findings"], "the findings must survive the failure report"
    assert stored["error"]["stage"] == "analyze-store", "the failure is still recorded"


def test_a_failure_that_arrives_first_is_stored_as_a_failure(scans):
    scans.ingest("acme", report(status="failed", findings=[], error={"stage": "scan"}))
    assert scans.get("acme", "scan-1")["status"] == "failed"


def test_a_completed_scan_can_still_be_updated_with_better_results(scans):
    """Monotonic on failure only. A second complete result is a re-run, and it
    should win rather than being frozen out by the first."""
    scans.ingest("acme", report(overall_risk_score=42))
    scans.ingest("acme", report(overall_risk_score=7))
    assert scans.get("acme", "scan-1")["overall_risk_score"] == 7


def test_ignoring_a_failure_is_audited_rather_than_silent(scans):
    """A dropped failure report is exactly the kind of thing somebody later
    needs to find in a log when a run looks green but felt wrong."""
    scans.ingest("acme", report(status="complete"))
    scans.ingest("acme", report(status="failed"))
    actions = [r.action for r in scans.audit.records("acme")]
    assert "scan.failure_ignored" in actions


# ── a terminal state is always reachable ─────────────────────────────────────


@pytest.mark.parametrize("status", ["complete", "failed"])
def test_a_terminal_status_stamps_a_completion_time(scans, status):
    stored = scans.ingest("acme", report(status=status))
    assert stored["completed_at"]


@pytest.mark.parametrize("status", ["queued", "running"])
def test_a_non_terminal_status_does_not(scans, status):
    """The dashboard polls until a scan is terminal. Stamping completed_at on a
    running scan would make it look finished."""
    assert "completed_at" not in scans.ingest("acme", report(status=status))


def test_an_unknown_status_is_refused(scans):
    with pytest.raises(ValidationError, match="unknown scan status"):
        scans.ingest("acme", report(status="probably-fine"))


def test_a_scan_without_an_id_is_refused(scans):
    """A record nobody can address is a record nobody can poll for, and the page
    would spin until the browser gave up."""
    with pytest.raises(ValidationError, match="scan_id is required"):
        scans.ingest("acme", {"status": "complete"})


@pytest.mark.parametrize("bad", ["../etc", "a/b", "a b", "", "x" * 200])
def test_a_junk_scan_id_is_refused(scans, bad):
    with pytest.raises(ValidationError):
        scans.ingest("acme", report(scan_id=bad))


def test_the_first_received_time_is_kept_across_updates(scans, clock):
    scans.ingest("acme", report(status="running"))
    first = scans.get("acme", "scan-1")["received_at"]
    clock.advance(3600)
    scans.ingest("acme", report(status="complete"))
    stored = scans.get("acme", "scan-1")
    assert stored["received_at"] == first
    assert stored["updated_at"] != first


# ── personal data ────────────────────────────────────────────────────────────


def test_the_submitters_address_is_never_stored_on_the_scan(scans):
    """The scan document is read, exported into evidence packs and rendered in a
    dashboard. The address should not travel with all of that."""
    scans.ingest("acme", report(email="someone@acme.example"))
    stored = scans.get("acme", "scan-1")
    assert "email" not in stored
    assert "someone@acme.example" not in str(stored)


def test_the_address_is_still_kept_where_it_can_be_found(scans):
    scans.ingest("acme", report(email="someone@acme.example"))
    assert scans.submitter("acme", "scan-1")["email"] == "someone@acme.example"


def test_a_scan_with_no_submitter_records_none(scans, store):
    scans.ingest("acme", report())
    assert scans.submitter("acme", "scan-1") is None
    assert store.list("acme", SUBMITTER_COLLECTION) == []


def test_the_address_can_be_purged_without_losing_the_scan(scans):
    """A deletion request has to be honourable without rewriting the findings or
    breaking the audit chain over them."""
    scans.ingest("acme", report(email="someone@acme.example"))
    assert scans.purge_submitter("acme", "scan-1", actor="bill") is True
    assert scans.submitter("acme", "scan-1") is None
    assert scans.get("acme", "scan-1")["findings"], "the scan itself must survive"


def test_purging_is_audited_so_the_deletion_can_be_evidenced(scans):
    scans.ingest("acme", report(email="someone@acme.example"))
    scans.purge_submitter("acme", "scan-1", actor="bill")
    purge = [r for r in scans.audit.records("acme") if r.action == "scan.submitter_purged"]
    assert purge and purge[0].actor == "bill"
    assert purge[0].detail["removed"] is True


def test_purging_nothing_reports_that_it_removed_nothing(scans):
    assert scans.purge_submitter("acme", "scan-1", actor="bill") is False


# ── tenant partitioning: what the old flat collection got wrong ──────────────


def test_a_scan_is_stored_under_its_tenant(scans, store):
    scans.ingest("acme", report())
    assert store.get("acme", SCAN_COLLECTION, "scan-1") is not None
    assert store.get("globex", SCAN_COLLECTION, "scan-1") is None


def test_one_tenants_scans_are_invisible_to_another(scans):
    scans.ingest("acme", report(scan_id="scan-a"))
    scans.ingest("globex", report(scan_id="scan-b"))
    assert scans.get("acme", "scan-b") is None
    assert [s["scan_id"] for s in scans.list("acme")] == ["scan-a"]


def test_the_client_id_is_taken_from_the_tenant_not_the_payload(scans):
    stored = scans.ingest("acme", report())
    assert stored["client_id"] == "acme"


def test_a_payload_claiming_another_tenant_is_refused(scans):
    """Quietly refiling it under the caller's tenant is how one client's results
    end up in another's report."""
    with pytest.raises(ValidationError, match="claims client_id"):
        scans.ingest("acme", report(client_id="globex"))


def test_a_payload_agreeing_with_the_tenant_is_fine(scans):
    assert scans.ingest("acme", report(client_id="acme"))["client_id"] == "acme"


# ── listing ──────────────────────────────────────────────────────────────────


def test_scans_are_listed_newest_first(scans, clock):
    for n in range(3):
        scans.ingest("acme", report(scan_id=f"scan-{n}"))
        clock.advance(60)
    assert [s["scan_id"] for s in scans.list("acme")] == ["scan-2", "scan-1", "scan-0"]


def test_the_list_is_bounded(scans, clock):
    """An unbounded list over a tenant with years of scans is a slow query
    behind an HTTP timeout."""
    for n in range(5):
        scans.ingest("acme", report(scan_id=f"scan-{n}"))
        clock.advance(60)
    assert len(scans.list("acme", limit=2)) == 2


def test_a_nonsense_limit_is_refused(scans):
    with pytest.raises(ValidationError):
        scans.list("acme", limit=0)


def test_an_empty_tenant_lists_nothing(scans):
    assert scans.list("acme") == []


# ── the report's own shape survives ──────────────────────────────────────────


def test_the_report_is_preserved_whole(scans):
    """The report is the product's contract with the dashboard. Ingest adds
    routing fields; it does not get to decide what a report contains."""
    payload = report(executive_summary="Two things need attention.", quick_wins=["Publish SPF"])
    stored = scans.ingest("acme", payload)
    assert stored["executive_summary"] == "Two things need attention."
    assert stored["quick_wins"] == ["Publish SPF"]
    assert stored["findings"] == payload["findings"]


def test_ingest_is_audited_with_the_actor_that_did_it(scans):
    scans.ingest("acme", report(), actor="ci-pipeline")
    ingested = [r for r in scans.audit.records("acme") if r.action == "scan.ingested"]
    assert ingested and ingested[0].actor == "ci-pipeline"
    assert ingested[0].subject == "scan/scan-1"


def test_the_audit_chain_stays_valid_across_ingest_and_purge(scans):
    scans.ingest("acme", report(email="someone@acme.example"))
    scans.ingest("acme", report(status="failed"))
    scans.purge_submitter("acme", "scan-1", actor="bill")
    assert scans.audit.verify("acme")["valid"] is True
