"""The report contract.

The deployed dashboard reads specific keys off this document. Those keys are a
contract with something already running, so they are asserted by name here — a
rename that breaks the live UI should fail in CI, not in a client's browser.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from base import Finding

from dnsguard.report import SCHEMA, build, slug

ROOT = Path(__file__).resolve().parent.parent


def finding(module, severity="info", title="t", detail="d", evidence=None, target="example.com"):
    return Finding(
        module=module,
        target=target,
        severity=severity,
        title=title,
        detail=detail,
        evidence=evidence or {},
    )


def a_healthy_scan():
    return [
        finding(
            "spf_audit",
            "info",
            "Sender authorisation policy is enforcing",
            evidence={
                "record": "v=spf1 include:_spf.google.com -all",
                "qualifier": "-all",
                "strength": "hard fail",
                "lookup_count": 1,
                "includes": ["_spf.google.com"],
            },
        ),
        finding(
            "dkim_audit",
            "info",
            "Mail signing keys are published",
            evidence={"selectors": ["google"], "selectors_probed": 26},
        ),
        finding(
            "dmarc_audit",
            "info",
            "Mail authentication policy is enforcing",
            evidence={
                "record": "v=DMARC1; p=reject; rua=mailto:d@example.com",
                "policy": "reject",
                "rua": ["mailto:d@example.com"],
                "pct": 100,
            },
        ),
        finding(
            "dnssec_audit",
            "info",
            "Domain answers are signed and trusted",
            evidence={"dnskey_count": 2, "ds_count": 1},
        ),
    ]


# ── the dashboard contract ───────────────────────────────────────────────────


def test_every_key_the_dashboard_reads_is_present():
    report = build(a_healthy_scan(), "example.com", "Acme Ltd")
    for key in (
        "findings",
        "email_security",
        "dnssec",
        "subdomains",
        "threat_indicators",
        "overall_risk_score",
        "risk_level",
        "executive_summary",
        "quick_wins",
        "scan_id",
        "domain",
        "target",
        "client_id",
        "client_name",
        "scan_timestamp",
    ):
        assert key in report, key
    email = report["email_security"]
    for key in ("grade", "spf_valid", "dkim_configured", "dmarc_valid", "dmarc_policy"):
        assert key in email, key


def test_a_finding_row_has_the_columns_the_table_renders():
    report = build(
        [finding("spf_audit", "high", "Missing SPF", evidence={"remediation": "Publish SPF"})],
        "example.com",
    )
    row = report["findings"][0]
    assert row["severity"] == "high"
    assert row["category"] == "Email Security"
    assert row["title"] == "Missing SPF"
    assert row["remediation"] == "Publish SPF"
    assert row["module"] == "spf_audit"
    assert "remediation" not in row["evidence"], "remediation is promoted, not duplicated"


def test_email_flags_come_from_evidence_not_severity():
    """A present-but-weak record must still read as present: "does SPF exist" and
    "is SPF any good" are different questions the UI shows differently."""
    findings = [
        finding(
            "spf_audit",
            "medium",
            "Sender policy is permissive",
            evidence={"record": "v=spf1 ~all", "qualifier": "~all", "strength": "soft fail"},
        ),
        finding(
            "dmarc_audit",
            "medium",
            "Mail authentication policy is monitor-only",
            evidence={"record": "v=DMARC1; p=none", "policy": "none", "rua": [], "pct": 100},
        ),
    ]
    email = build(findings, "example.com")["email_security"]
    assert email["spf_valid"] is True
    assert email["dmarc_valid"] is True
    assert email["dmarc_policy"] == "none"
    assert email["spf_issues"] == ["Sender policy is permissive"]


def test_a_missing_control_reads_as_absent():
    email = build(
        [
            finding(
                "spf_audit",
                "high",
                "No sender authorisation policy published",
                evidence={"record": ""},
            )
        ],
        "example.com",
    )["email_security"]
    assert email["spf_valid"] is False
    assert email["dkim_configured"] is False
    assert email["dmarc_valid"] is False


def test_evidence_is_taken_from_whichever_finding_carries_it():
    """A module emits several findings and the parsed record may hang off any of
    them, so the report must not depend on their order."""
    findings = [
        finding("dmarc_audit", "low", "Mail authentication reports go nowhere", evidence={}),
        finding(
            "dmarc_audit",
            "medium",
            "Mail authentication policy is monitor-only",
            evidence={"record": "v=DMARC1; p=none", "policy": "none", "rua": [], "pct": 100},
        ),
    ]
    assert build(findings, "example.com")["email_security"]["dmarc_policy"] == "none"


def test_a_signed_zone_with_no_delegation_does_not_read_as_implemented():
    """The old report called a DNSKEY alone "implemented". Unvalidated signing
    protects nobody, so the dashboard's tick must not light up for it."""
    findings = [
        finding(
            "dnssec_audit",
            "medium",
            "Signing is configured but not trusted",
            evidence={"dnskey_count": 2, "ds_count": 0},
        )
    ]
    dnssec = build(findings, "example.com")["dnssec"]
    assert dnssec["implemented"] is False
    assert dnssec["signed"] is True
    assert dnssec["delegation_present"] is False


def test_a_fully_signed_zone_reads_as_implemented():
    assert build(a_healthy_scan(), "example.com")["dnssec"]["implemented"] is True


def test_subdomains_are_reshaped_for_the_dashboard():
    findings = [
        finding(
            "subdomain_discovery",
            "info",
            "Public host inventory collected",
            evidence={
                "hosts": [
                    {
                        "host": "www.example.com",
                        "addresses": ["192.0.2.1"],
                        "aliases": [],
                        "source": "probe",
                        "label": "www",
                    },
                    {
                        "host": "old.example.com",
                        "addresses": [],
                        "aliases": ["gone.example.net"],
                        "source": "certificate-transparency",
                        "label": "old",
                    },
                ]
            },
        )
    ]
    subs = build(findings, "example.com")["subdomains"]
    assert [s["subdomain"] for s in subs] == ["www.example.com", "old.example.com"]
    assert subs[0]["ip_addresses"] == ["192.0.2.1"]
    assert subs[1]["cnames"] == ["gone.example.net"]
    assert all(s["is_alive"] for s in subs)


def test_records_are_reshaped_for_the_dashboard():
    findings = [
        finding(
            "dns_records",
            "info",
            "Zone inventory collected",
            evidence={
                "records": [
                    {
                        "name": "example.com",
                        "type": "A",
                        "value": "192.0.2.1",
                        "ttl": 300,
                        "purpose": "Website/server address",
                    }
                ]
            },
        )
    ]
    record = build(findings, "example.com")["records"][0]
    assert record == {
        "domain": "example.com",
        "record_type": "A",
        "value": "192.0.2.1",
        "ttl": 300,
        "purpose": "Website/server address",
    }


def test_missing_modules_produce_empty_collections_not_missing_keys():
    report = build(
        [finding("spf_audit", "info", evidence={"record": "v=spf1 -all"})], "example.com"
    )
    assert report["subdomains"] == []
    assert report["records"] == []
    assert report["dnssec"]["implemented"] is False


# ── white-label ──────────────────────────────────────────────────────────────


def test_the_report_never_carries_a_tools_used_list():
    """It used to, and it was stored verbatim in a client-readable document."""
    assert "tools_used" not in build(a_healthy_scan(), "example.com")


def test_no_underlying_tool_name_appears_anywhere_in_the_report():
    payload = json.dumps(build(a_healthy_scan(), "example.com")).lower()
    for term in ("crt.sh", "checkdmarc", "dnsperf", "nuclei", "zap", "traceroute", "bruteforce"):
        assert term not in payload, term


# ── identifiers ──────────────────────────────────────────────────────────────


def test_the_client_id_matches_what_the_workflow_derives():
    """Both paths must produce the same tenant id or the same client lands in two
    partitions depending on who wrote the record."""
    assert slug("Iron City IT") == "iron-city-it"
    assert slug("Acme  Ltd.") == "acme-ltd"
    assert slug("ACME") == "acme"


def test_an_explicit_client_id_wins_over_the_derived_one():
    assert build([], "example.com", "Acme Ltd", client_id="acme")["client_id"] == "acme"


def test_a_supplied_scan_id_is_preserved():
    """The trigger function mints the id the dashboard polls on; the scanner must
    not replace it."""
    assert build([], "example.com", scan_id="scan-123")["scan_id"] == "scan-123"


def test_a_generated_scan_id_is_unique_per_scan():
    first = build([], "example.com")["scan_id"]
    second = build([], "example.com")["scan_id"]
    assert first != second
    assert first.startswith("dnsguard-")


def test_the_schema_is_stamped():
    assert build([], "example.com")["schema"] == SCHEMA


# ── the CLI ──────────────────────────────────────────────────────────────────


def run_scan(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "tools/scan.py", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_the_cli_lists_the_same_modules_the_api_serves():
    proc = run_scan("--list-modules")
    assert proc.returncode == 0, proc.stderr
    names = {m["name"] for m in json.loads(proc.stdout)["modules"]}
    assert {"spf_audit", "dmarc_audit", "dns_records", "subdomain_discovery"} <= names


def test_a_dry_run_produces_a_valid_report_and_queries_nothing():
    proc = run_scan("--domain", "example.com", "--client", "Acme Ltd", "--dry-run")
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report["dry_run"] is True
    assert report["findings"] == []
    assert report["client_id"] == "acme-ltd"
    assert report["modules_run"]


def test_the_cli_writes_a_report_file_that_passes_the_json_gate(tmp_path):
    proc = run_scan("--domain", "example.com", "--dry-run", "-o", str(tmp_path))
    assert proc.returncode == 0, proc.stderr
    written = list(tmp_path.glob("*.json"))
    assert len(written) == 1
    raw = written[0].read_text()
    # The same gate the workflow applies before anything downstream consumes it.
    assert raw[0] == "{"
    assert json.loads(raw)["domain"] == "example.com"


def test_an_unknown_module_selection_fails_loudly():
    proc = run_scan("--domain", "example.com", "--modules", "no_such_module")
    assert proc.returncode == 2
    assert "selection error" in proc.stderr


def test_a_missing_domain_is_refused():
    assert run_scan("--dry-run").returncode == 2


@pytest.mark.parametrize("group", ["quick", "standard", "deep", "email", "surface"])
def test_every_advertised_group_resolves(group):
    proc = run_scan("--domain", "example.com", "--group", group, "--dry-run")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["modules_run"]
