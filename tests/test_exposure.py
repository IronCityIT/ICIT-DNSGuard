"""The exposure checker has to be right about what a status code means.

Every case here is a status code the live project has actually returned, or one
it plausibly could. No test touches the network: the probe is injected.
"""

from __future__ import annotations

from dnsguard.exposure import (
    ABSENT_DOCUMENT_ID,
    UNUSED_COLLECTION,
    check_exposure,
    collection_url,
    document_url,
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
