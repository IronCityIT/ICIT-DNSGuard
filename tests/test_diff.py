"""Change detection between two scans.

Storing scans is an archive; comparing them is the product. The tests that matter
here are the ones about *not* reporting churn as change, because a diff that
cries wolf is one a client stops reading — and then the week it says something
real, nobody looks.
"""

from __future__ import annotations

import pytest

from dnsguard.audit import AuditLog
from dnsguard.clock import FrozenClock
from dnsguard.diff import compare, fingerprint_of
from dnsguard.errors import NotFoundError
from dnsguard.scans import ScanService
from dnsguard.store import MemoryStore


def finding(title="Missing SPF Record", severity="high", **extra):
    row = {
        "module": "spf_audit",
        "target": "acme.example",
        "asset": "acme.example",
        "title": title,
        "severity": severity,
        "category": "Email Security",
        "confidence": "confirmed",
        "remediation": "Publish an SPF record.",
        **extra,
    }
    row.setdefault("fingerprint", fingerprint_of(row))
    return row


def scan(scan_id="scan-2", findings=(), target="acme.example", **extra):
    return {
        "scan_id": scan_id,
        "target": target,
        "status": "complete",
        "findings": list(findings),
        **extra,
    }


# ── the first scan is a baseline, not a disaster ─────────────────────────────


def test_a_first_scan_is_reported_as_a_baseline():
    """Every finding on a first scan is technically new. Saying so turns "here
    is where you stand" into "twenty-three things just broke", which is alarming
    and false."""
    result = compare(None, scan(findings=[finding(), finding("No DKIM", "medium")]))
    assert result.baseline is True
    assert len(result.of("new")) == 2


def test_a_later_scan_is_not_a_baseline():
    assert compare(scan("scan-1"), scan("scan-2")).baseline is False


# ── severity movement is the same finding, not two ───────────────────────────


def test_a_finding_getting_worse_is_one_finding_not_two():
    """The reason `fingerprint()` excludes severity. Comparing whole rows would
    report this as one problem resolved and a different one appearing, and the
    client would see churn where there is a deterioration."""
    before = scan("scan-1", [finding(severity="medium")])
    after = scan("scan-2", [finding(severity="critical")])

    result = compare(before, after)
    assert len(result.changes) == 1
    change = result.of("worsened")[0]
    assert change.previous_severity == "medium"
    assert change.severity == "critical"
    assert not result.of("new")
    assert not result.of("resolved")


def test_a_finding_getting_better_is_reported_as_improved():
    result = compare(scan("scan-1", [finding(severity="critical")]), scan("scan-2", [finding()]))
    assert result.of("improved")[0].previous_severity == "critical"


def test_a_finding_that_has_not_moved_is_unchanged():
    result = compare(scan("scan-1", [finding()]), scan("scan-2", [finding()]))
    assert len(result.of("unchanged")) == 1
    assert result.regressed is False


# ── appearing and disappearing ───────────────────────────────────────────────


def test_a_finding_that_appears_is_new():
    result = compare(scan("scan-1", []), scan("scan-2", [finding()]))
    assert result.of("new")[0].title == "Missing SPF Record"


def test_a_finding_that_disappears_is_resolved():
    result = compare(scan("scan-1", [finding()]), scan("scan-2", []))
    assert result.of("resolved")[0].title == "Missing SPF Record"
    assert result.regressed is False, "fixing something is not a regression"


def test_two_findings_on_different_assets_do_not_collide():
    """Same title, different host. A takeover on vpn and one on api are two
    problems, and merging them would hide one."""
    before = scan("scan-1", [finding(title="Claimable alias", asset="vpn.acme.example")])
    after = scan(
        "scan-2",
        [
            finding(title="Claimable alias", asset="vpn.acme.example"),
            finding(title="Claimable alias", asset="api.acme.example"),
        ],
    )
    result = compare(before, after)
    assert len(result.of("new")) == 1
    assert result.of("new")[0].asset == "api.acme.example"
    assert len(result.of("unchanged")) == 1


# ── regression, the question a scheduled comparison is asking ────────────────


@pytest.mark.parametrize(
    ("before", "after", "regressed"),
    [
        ([], [finding()], True),
        ([finding(severity="low")], [finding(severity="high")], True),
        ([finding(severity="high")], [finding(severity="low")], False),
        ([finding()], [], False),
        ([finding()], [finding()], False),
    ],
)
def test_regressed_means_something_got_worse(before, after, regressed):
    assert compare(scan("scan-1", before), scan("scan-2", after)).regressed is regressed


# ── confidence is carried, never compared ────────────────────────────────────


def test_a_finding_becoming_confirmed_is_not_a_deterioration():
    """What changed is what we know, not what is true. Reporting it as a
    worsening would show the scanner getting better as the client getting
    worse."""
    before = scan("scan-1", [finding(confidence="possible")])
    after = scan("scan-2", [finding(confidence="confirmed")])
    result = compare(before, after)
    assert result.of("unchanged")
    assert result.regressed is False


def test_both_confidences_are_still_visible_on_the_row():
    before = scan("scan-1", [finding(confidence="possible")])
    after = scan("scan-2", [finding(confidence="confirmed")])
    change = compare(before, after).changes[0]
    assert (change.previous_confidence, change.confidence) == ("possible", "confirmed")


# ── ordering and summary ─────────────────────────────────────────────────────


def test_the_thing_to_act_on_is_at_the_top():
    before = scan("scan-1", [finding("A", "low"), finding("B", "high")])
    after = scan(
        "scan-2",
        [finding("A", "critical"), finding("B", "high"), finding("C", "medium")],
    )
    outcomes = [c.outcome for c in compare(before, after).changes]
    assert outcomes[0] == "worsened"
    assert outcomes.index("new") < outcomes.index("unchanged")


def test_the_summary_counts_every_outcome():
    before = scan("scan-1", [finding("A", "low"), finding("B")])
    after = scan("scan-2", [finding("A", "high"), finding("C")])
    summary = compare(before, after).summary()
    assert summary == {"new": 1, "resolved": 1, "worsened": 1, "improved": 0, "unchanged": 0}


def test_the_comparison_names_both_scans():
    result = compare(scan("scan-1"), scan("scan-2"))
    assert (result.previous_scan_id, result.current_scan_id) == ("scan-1", "scan-2")


# ── older reports still compare ──────────────────────────────────────────────


def test_a_report_stored_before_fingerprints_still_compares():
    """A report that predates the fingerprint reaching the client row should
    produce a slightly weaker diff, not no diff at all."""
    old = {k: v for k, v in finding().items() if k != "fingerprint"}
    result = compare(scan("scan-1", [old]), scan("scan-2", [finding()]))
    assert len(result.of("unchanged")) == 1


def test_a_scan_with_no_findings_key_is_treated_as_empty():
    assert compare({"scan_id": "s1"}, {"scan_id": "s2"}).changes == []


# ── through the scan service ─────────────────────────────────────────────────


@pytest.fixture
def scans():
    store, clock = MemoryStore(), FrozenClock()
    return ScanService(store=store, audit=AuditLog(store, clock), clock=clock), clock


def test_a_scan_is_compared_against_the_previous_one_for_the_same_target(scans):
    service, clock = scans
    service.ingest("acme", scan("scan-1", [finding(severity="medium")]))
    clock.advance(86400)
    service.ingest("acme", scan("scan-2", [finding(severity="critical")]))

    result = service.changes("acme", "scan-2")
    assert result.previous_scan_id == "scan-1"
    assert result.of("worsened")


def test_a_scan_of_a_different_target_is_not_used_as_the_baseline(scans):
    """Comparing a scan of one domain against a scan of another produces a diff
    where everything is new and everything is resolved — true, and useless."""
    service, clock = scans
    service.ingest("acme", scan("scan-1", [finding()], target="other.example"))
    clock.advance(86400)
    service.ingest("acme", scan("scan-2", [finding()]))

    result = service.changes("acme", "scan-2")
    assert result.baseline is True


def test_a_failed_scan_is_not_used_as_the_baseline(scans):
    """A failed run has no findings, so diffing against it would report every
    real finding as newly appeared."""
    service, clock = scans
    service.ingest("acme", scan("scan-1", [finding()]))
    clock.advance(60)
    service.ingest("acme", scan("scan-2", [], status="failed"))
    clock.advance(60)
    service.ingest("acme", scan("scan-3", [finding()]))

    result = service.changes("acme", "scan-3")
    assert result.previous_scan_id == "scan-1"
    assert result.of("unchanged")


def test_the_most_recent_earlier_scan_wins(scans):
    service, clock = scans
    for n in (1, 2, 3):
        service.ingest("acme", scan(f"scan-{n}", [finding()]))
        clock.advance(86400)
    assert service.changes("acme", "scan-3").previous_scan_id == "scan-2"


def test_the_first_scan_of_a_target_is_a_baseline(scans):
    service, _ = scans
    service.ingest("acme", scan("scan-1", [finding()]))
    assert service.changes("acme", "scan-1").baseline is True


def test_comparing_an_unknown_scan_is_an_error(scans):
    service, _ = scans
    with pytest.raises(NotFoundError):
        service.changes("acme", "nope")


def test_another_tenants_scan_is_never_the_baseline(scans):
    """The comparison has to respect the same boundary everything else does."""
    service, clock = scans
    service.ingest("globex", scan("scan-1", [finding()]))
    clock.advance(86400)
    service.ingest("acme", scan("scan-2", [finding()]))
    assert service.changes("acme", "scan-2").baseline is True


def test_two_scans_in_the_same_clock_tick_still_compare(scans):
    """Ordering on the timestamp alone leaves both without a predecessor, so the
    second silently reports itself as a baseline and the comparison never
    happens. Unlikely in production, certain under a frozen clock — and a
    comparison that quietly does not run is worse than one that errors."""
    service, _ = scans  # clock deliberately not advanced
    service.ingest("acme", scan("scan-1", [finding(severity="low")]))
    service.ingest("acme", scan("scan-2", [finding(severity="high")]))

    result = service.changes("acme", "scan-2")
    assert result.baseline is False
    assert result.previous_scan_id == "scan-1"
    assert result.of("worsened")


def test_the_earlier_of_two_same_tick_scans_is_still_a_baseline(scans):
    """The tiebreak has to be a strict ordering, or the two scans would each
    consider the other their predecessor."""
    service, _ = scans
    service.ingest("acme", scan("scan-1", [finding()]))
    service.ingest("acme", scan("scan-2", [finding()]))
    assert service.changes("acme", "scan-1").baseline is True
