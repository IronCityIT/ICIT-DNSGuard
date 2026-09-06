"""The exposure checker has to be right about what a status code means.

Every case here is a status code the live project has actually returned, or one
it plausibly could. No test touches the network: the probe is injected.
"""

from __future__ import annotations

from dnsguard.exposure import (
    ABSENT_DOCUMENT_ID,
    POSTURE_RANK,
    UNUSED_COLLECTION,
    check_exposure,
    collection_url,
    compare_to_baseline,
    document_url,
    posture,
)


def probe_returning(mapping: dict[str, int], default: int = 404):
    """A probe that answers by URL substring, so tests read as intent."""

    def probe(url: str) -> int:
        for fragment, status in mapping.items():
            if fragment in url:
                return status
        return default

    return probe


def test_reads_the_live_state_this_project_was_actually_in() -> None:
    # Observed 2026-09-06: absent doc 404, list 200, unused collection 403.
    # A rules file is deployed, and it still allows enumeration.
    report = check_exposure(
        probe_returning({"pageSize": 200, UNUSED_COLLECTION: 403}, default=404),
        "icit-dnsguard",
    )
    assert report.rules_deployed is True
    assert report.get_permitted is True
    assert report.list_permitted is True

    titles = [f["title"] for f in report.findings]
    assert "Stored scans can be enumerated without authentication" in titles
    high = [f for f in report.findings if f["severity"] == "high"]
    assert len(high) == 1


def test_a_404_on_the_document_probe_is_a_permitted_read_not_a_denial() -> None:
    # The mistake this guards against: reading "not found" as "not allowed",
    # which would report a wide-open project as closed.
    report = check_exposure(probe_returning({}, default=404), "p")
    assert report.get_permitted is True


def test_a_403_is_a_denial() -> None:
    report = check_exposure(probe_returning({}, default=403), "p")
    assert report.get_permitted is False
    assert report.list_permitted is False


def test_a_401_counts_as_a_denial_too() -> None:
    report = check_exposure(probe_returning({}, default=401), "p")
    assert report.get_permitted is False


def test_open_test_mode_is_reported_as_no_rules_in_force() -> None:
    # Every collection readable, including one the product never writes.
    report = check_exposure(probe_returning({}, default=404), "p")
    assert report.rules_deployed is False
    titles = [f["title"] for f in report.findings]
    assert "No rules file appears to be in force" in titles


def test_the_intended_end_state_reports_nothing_to_act_on() -> None:
    # Deployed rules that deny list and deny unknown collections, with single
    # document reads still open, is what the committed rules produce. The
    # remaining medium is the documented residual, not a high.
    report = check_exposure(
        probe_returning({"pageSize": 403, UNUSED_COLLECTION: 403}, default=404),
        "icit-dnsguard",
    )
    assert report.list_permitted is False
    assert report.rules_deployed is True
    assert [f["severity"] for f in report.findings] == ["medium"]


def test_a_failed_probe_is_not_read_as_permission() -> None:
    # A network failure returns 0. It must not be reported as a refusal, because
    # that would quietly turn an unreachable check into a clean bill of health.
    report = check_exposure(probe_returning({}, default=0), "p")
    assert report.get_permitted is True
    assert any(p.status_code == 0 for p in report.probes)


def test_the_document_probe_never_names_a_real_scan() -> None:
    report = check_exposure(probe_returning({}, default=404), "p")
    doc_probe = report.probe("get_absent_document")
    assert doc_probe is not None
    assert ABSENT_DOCUMENT_ID in doc_probe.url
    assert not doc_probe.url.startswith("scan-")


def test_urls_address_the_right_project_and_collection() -> None:
    assert document_url("proj", "scans", "abc").endswith(
        "/projects/proj/databases/(default)/documents/scans/abc"
    )
    assert "pageSize=1" in collection_url("proj", "scans")


def test_the_report_states_that_writes_were_not_probed() -> None:
    report = check_exposure(probe_returning({}, default=403), "p")
    assert "not probed" in report.to_dict()["write_posture"]


def test_the_probe_target_must_be_https() -> None:
    """A crafted --project must not turn a network probe into a file read."""
    import importlib.util
    import pathlib

    spec = importlib.util.spec_from_file_location(
        "check_exposure_cli",
        pathlib.Path(__file__).resolve().parent.parent / "tools" / "check-exposure.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    for hostile in ("file:///etc/passwd", "http://firestore.googleapis.com/v1"):
        try:
            module.http_status(hostile)
        except ValueError:
            continue
        raise AssertionError(f"accepted a target it must refuse: {hostile}")


# --------------------------------------------------------------------------
# The regression ratchet. The exposure cannot be closed from here, so the whole
# value of these tests is that the recorded state cannot quietly get worse.
# --------------------------------------------------------------------------


def report_for(posture_name: str, project: str = "p"):
    """Build a report in a named posture, via the probe statuses that produce it."""
    statuses = {
        # unknown collection readable -> no rules in force
        "no_rules": {UNUSED_COLLECTION: 404, "pageSize": 200},
        "enumerable": {UNUSED_COLLECTION: 403, "pageSize": 200},
        "readable_by_id": {UNUSED_COLLECTION: 403, "pageSize": 403},
        "closed": {UNUSED_COLLECTION: 403, "pageSize": 403},
    }[posture_name]
    default = 403 if posture_name == "closed" else 404
    return check_exposure(probe_returning(statuses, default=default), project)


def test_each_posture_is_recognised_from_its_probe_results() -> None:
    for name in ("no_rules", "enumerable", "readable_by_id", "closed"):
        assert posture(report_for(name)) == name


def test_the_recorded_state_does_not_fail_the_build() -> None:
    # Every project in the fleet is currently worse than it should be, and none
    # of it is fixable from this repository. Failing here would paint every
    # unrelated pull request red.
    result = compare_to_baseline(report_for("enumerable"), "enumerable")
    assert result.verdict == "unchanged"
    assert result.failed is False


def test_a_weaker_boundary_than_recorded_is_a_regression() -> None:
    result = compare_to_baseline(report_for("no_rules"), "enumerable")
    assert result.verdict == "regressed"
    assert result.failed is True


def test_shadowscan_losing_its_rules_would_fail() -> None:
    # The one project that is closed. If it ever stops being closed, that is
    # exactly the event this check exists to catch.
    result = compare_to_baseline(report_for("enumerable"), "closed")
    assert result.failed is True


def test_an_improvement_is_reported_and_does_not_fail() -> None:
    result = compare_to_baseline(report_for("closed"), "enumerable")
    assert result.verdict == "improved"
    assert result.failed is False
    assert "tighten" in result.note


def test_a_probe_that_did_not_complete_is_not_a_regression() -> None:
    # A network failure must not read as the boundary having collapsed, or the
    # check becomes noise and stops being read.
    report = check_exposure(probe_returning({}, default=0), "p")
    result = compare_to_baseline(report, "closed")
    assert result.verdict == "unknown"
    assert result.failed is False


def test_a_baseline_naming_an_unknown_posture_is_refused_not_guessed() -> None:
    result = compare_to_baseline(report_for("closed"), "mostly-fine")
    assert result.verdict == "unrecognised"
    assert result.failed is False


def test_the_shipped_baseline_matches_what_was_verified() -> None:
    """The committed baseline must describe postures this checker understands."""
    import json
    import pathlib

    path = pathlib.Path(__file__).resolve().parent.parent / "exposure-baseline.json"
    baseline = json.loads(path.read_text())
    assert baseline["projects"], "the baseline names no projects"
    for entry in baseline["projects"]:
        assert entry["expected"] in POSTURE_RANK, entry
        # Every entry has to say why it is what it is, or the file decays into a
        # list of codes nobody can act on.
        assert entry.get("note"), f"{entry['project_id']} has no note"
