"""Backup, verification, restore and reconciliation.

Two things depend on this being right, and they are the same mechanism.

Disaster recovery, which the handoff records as UNKNOWN with no evidence either
way — nobody knows whether the live store has ever been backed up, and no restore
has ever been rehearsed. And the migration, which has to move live documents onto
self-hosted storage and prove afterwards that what arrived is what left.

The adversarial tests are the point. A checksum somebody can recompute is not an
integrity check, so the case that matters most is an edited document *with the
manifest repaired to match it*.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from dnsguard.backup import SCHEMA, export_tenant, reconcile, restore, verify
from dnsguard.clock import FrozenClock
from dnsguard.errors import ValidationError
from dnsguard.store import JsonFileStore, MemoryStore

ROOT = Path(__file__).resolve().parent.parent
COLLECTIONS = ["scans", "policies", "audit"]


@pytest.fixture
def store():
    store = MemoryStore()
    store.put("acme", "scans", "scan-1", {"scan_id": "scan-1", "findings": [{"severity": "high"}]})
    store.put("acme", "scans", "scan-2", {"scan_id": "scan-2", "findings": []})
    store.put("acme", "policies", "default", {"id": "default", "version": 3})
    store.put("globex", "scans", "scan-9", {"scan_id": "scan-9", "findings": []})
    return store


@pytest.fixture
def archive(store):
    return export_tenant(store, "acme", COLLECTIONS, clock=FrozenClock()).to_dict()


# ── what an archive contains ─────────────────────────────────────────────────


def test_every_document_for_the_tenant_is_captured(archive):
    assert set(archive["collections"]["scans"]) == {"scan-1", "scan-2"}
    assert set(archive["collections"]["policies"]) == {"default"}


def test_another_tenants_data_is_not_in_the_archive(archive):
    """The store is tenant-partitioned and a backup must not be the thing that
    undoes that."""
    assert "scan-9" not in json.dumps(archive)


def test_an_empty_collection_is_omitted_rather_than_recorded_as_empty(archive):
    assert "audit" not in archive["collections"]


def test_the_counts_match_the_contents(archive):
    for collection, count in archive["counts"].items():
        assert len(archive["collections"][collection]) == count


def test_a_fresh_archive_verifies(archive):
    report = verify(archive)
    assert report["valid"], report["problems"]
    assert report["documents_checked"] == 3


def test_an_archive_of_nothing_is_still_valid(store):
    empty = export_tenant(MemoryStore(), "nobody", COLLECTIONS).to_dict()
    assert verify(empty)["valid"]
    assert verify(empty)["documents_checked"] == 0


# ── tampering: the tests the whole thing exists for ──────────────────────────


def test_an_edited_document_is_detected(archive):
    archive["collections"]["scans"]["scan-1"]["findings"] = []
    report = verify(archive)
    assert not report["valid"]
    assert any("scans/scan-1" in p for p in report["problems"])


def test_a_removed_document_is_detected(archive):
    del archive["collections"]["scans"]["scan-2"]
    report = verify(archive)
    assert not report["valid"]
    assert any("scans/scan-2" in p for p in report["problems"])


def test_an_added_document_is_detected(archive):
    archive["collections"]["scans"]["scan-3"] = {"scan_id": "scan-3"}
    report = verify(archive)
    assert not report["valid"]
    assert any("not covered by the manifest" in p for p in report["problems"])


def test_an_edited_document_with_a_repaired_manifest_is_still_detected(archive):
    """The case that separates a real integrity check from a checksum anybody
    can recompute. Change the document, then change its hash to match — and the
    manifest hash no longer matches the manifest."""
    from dnsguard.backup import digest

    archive["collections"]["scans"]["scan-1"]["findings"] = []
    archive["manifest"]["scans/scan-1"] = digest(archive["collections"]["scans"]["scan-1"])

    report = verify(archive)
    assert not report["valid"]
    assert any("manifest hash does not match" in p for p in report["problems"])


def test_a_tampered_count_is_detected(archive):
    archive["counts"]["scans"] = 99
    assert not verify(archive)["valid"]


def test_an_archive_of_an_unknown_schema_is_refused(archive):
    archive["schema"] = "something.else.v1"
    with pytest.raises(ValidationError, match="unknown backup schema"):
        verify(archive)


# ── restore ──────────────────────────────────────────────────────────────────


def test_a_restore_reproduces_every_document(archive):
    target = MemoryStore()
    result = restore(target, archive)
    assert result["complete"]
    assert target.get("acme", "scans", "scan-1")["findings"] == [{"severity": "high"}]
    assert target.get("acme", "policies", "default")["version"] == 3


def test_a_restore_refuses_to_replace_what_is_already_there(archive):
    """Restoring into a live store is otherwise a way to lose the newer copy of
    something while believing you are recovering it."""
    target = MemoryStore()
    target.put("acme", "scans", "scan-1", {"scan_id": "scan-1", "findings": ["newer"]})

    result = restore(target, archive)
    assert result["complete"] is False
    assert "scans/scan-1" in result["skipped"]
    assert target.get("acme", "scans", "scan-1")["findings"] == ["newer"]


def test_replacing_can_be_asked_for_explicitly(archive):
    target = MemoryStore()
    target.put("acme", "scans", "scan-1", {"scan_id": "scan-1", "findings": ["newer"]})
    result = restore(target, archive, overwrite=True)
    assert result["complete"]
    assert target.get("acme", "scans", "scan-1")["findings"] == [{"severity": "high"}]


def test_a_corrupt_archive_is_not_restored(archive):
    """A corrupt backup becoming a corrupt store is the worst outcome available,
    so verification happens before anything is written."""
    archive["collections"]["scans"]["scan-1"]["findings"] = []
    target = MemoryStore()
    with pytest.raises(ValidationError, match="fails verification"):
        restore(target, archive)
    assert target.get("acme", "scans", "scan-1") is None


def test_an_archive_can_be_restored_under_a_different_tenant(archive):
    """Useful for rehearsing a restore without touching the live tenant, which
    is the only way anybody actually rehearses one."""
    target = MemoryStore()
    restore(target, archive, tenant_id="acme-rehearsal")
    assert target.get("acme-rehearsal", "scans", "scan-1") is not None
    assert target.get("acme", "scans", "scan-1") is None


# ── reconciliation: what makes a migration checkable ─────────────────────────


def test_a_faithful_copy_reconciles(archive):
    target = MemoryStore()
    restore(target, archive)
    result = reconcile(target, archive)
    assert result["reconciled"]
    assert result["matched"] == 3


def test_a_missing_document_is_reported(archive):
    target = MemoryStore()
    restore(target, archive)
    target.delete("acme", "scans", "scan-2")
    result = reconcile(target, archive)
    assert not result["reconciled"]
    assert result["missing"] == ["scans/scan-2"]


def test_a_changed_document_is_reported(archive):
    """The question after a migration is not whether the import said success,
    but whether what is now there is what was there before."""
    target = MemoryStore()
    restore(target, archive)
    target.put("acme", "scans", "scan-1", {"scan_id": "scan-1", "findings": ["different"]})
    result = reconcile(target, archive)
    assert not result["reconciled"]
    assert result["differing"] == ["scans/scan-1"]


def test_reconciling_an_empty_store_reports_everything_missing(archive):
    result = reconcile(MemoryStore(), archive)
    assert len(result["missing"]) == 3
    assert result["matched"] == 0


# ── the collection list cannot silently go stale ─────────────────────────────


def test_the_backup_covers_every_collection_the_code_writes():
    """DocumentStore cannot enumerate collections, so the list in tools/backup.py
    is written by hand — and a collection missing from it is a collection missing
    from every backup, silently. This fails when the code writes one the list
    does not name."""
    import re

    listed = set(
        re.findall(r'"([a-z]+)",', (ROOT / "tools" / "backup.py").read_text(encoding="utf-8"))
    )
    written = set()
    for path in (ROOT / "dnsguard").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r'^([A-Z_]*COLLECTION)\s*=\s*"([a-z]+)"', text, re.M):
            written.add(match.group(2))

    assert written, "no collection constants found — this test has stopped checking anything"
    missing = sorted(written - listed)
    assert not missing, f"collections the code writes but backups omit: {missing}"


# ── end to end, through the CLI ──────────────────────────────────────────────


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "tools/backup.py", *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )


def test_export_verify_restore_reconcile_round_trips(tmp_path):
    """The rehearsal nobody has ever done on the live store, done here."""
    source = tmp_path / "live"
    live = JsonFileStore(source)
    live.put("acme", "scans", "scan-1", {"scan_id": "scan-1", "findings": [{"severity": "high"}]})
    live.put("acme", "audit", "000000000001", {"id": "000000000001", "seq": 1})

    out = tmp_path / "acme.json"
    exported = run_cli("export", "--data-dir", str(source), "--tenant", "acme", "-o", str(out))
    assert exported.returncode == 0, exported.stderr
    assert "2 document(s)" in exported.stdout

    checked = run_cli("verify", str(out))
    assert checked.returncode == 0, checked.stderr
    assert "intact" in checked.stdout

    restored_dir = tmp_path / "restored"
    restored_dir.mkdir()
    put = run_cli("restore", str(out), "--data-dir", str(restored_dir))
    assert put.returncode == 0, put.stderr

    matched = run_cli("reconcile", str(out), "--data-dir", str(restored_dir))
    assert matched.returncode == 0, matched.stderr
    assert "2 document(s) match" in matched.stdout


def test_the_cli_reports_a_tampered_archive_as_a_failure(tmp_path):
    source = tmp_path / "live"
    JsonFileStore(source).put("acme", "scans", "s1", {"scan_id": "s1", "findings": []})
    out = tmp_path / "acme.json"
    run_cli("export", "--data-dir", str(source), "--tenant", "acme", "-o", str(out))

    data = json.loads(out.read_text(encoding="utf-8"))
    data["collections"]["scans"]["s1"]["findings"] = ["injected"]
    out.write_text(json.dumps(data), encoding="utf-8")

    checked = run_cli("verify", str(out))
    assert checked.returncode == 1
    assert "FAILED" in checked.stderr


def test_the_cli_refuses_to_restore_a_tampered_archive(tmp_path):
    source = tmp_path / "live"
    JsonFileStore(source).put("acme", "scans", "s1", {"scan_id": "s1", "findings": []})
    out = tmp_path / "acme.json"
    run_cli("export", "--data-dir", str(source), "--tenant", "acme", "-o", str(out))

    data = json.loads(out.read_text(encoding="utf-8"))
    data["collections"]["scans"]["s1"]["findings"] = ["injected"]
    out.write_text(json.dumps(data), encoding="utf-8")

    target = tmp_path / "restored"
    target.mkdir()
    put = run_cli("restore", str(out), "--data-dir", str(target))
    assert put.returncode == 2
    assert "fails verification" in put.stderr


def test_an_archive_declares_its_schema(archive):
    assert archive["schema"] == SCHEMA


def test_an_audit_record_keeps_the_key_its_ordering_depends_on():
    """The audit log keys records on the zero-padded sequence number so that
    lexical order in the store equals chain order — its own comment says so.
    Restoring under a positional name preserves the data and loses the
    invariant, which is the kind of thing that works until it does not."""
    source = MemoryStore()
    source.put("acme", "audit", "000000000001", {"seq": 1, "actor": "bill"})
    source.put("acme", "audit", "000000000002", {"seq": 2, "actor": "ann"})

    archive = export_tenant(source, "acme", ["audit"]).to_dict()
    assert set(archive["collections"]["audit"]) == {"000000000001", "000000000002"}

    target = MemoryStore()
    restore(target, archive)
    assert [d["seq"] for d in target.list("acme", "audit")] == [1, 2]


def test_a_document_with_no_recognisable_id_is_kept_rather_than_dropped():
    """A backup that silently omits the awkward records is worse than one that
    restores them under an ugly name."""
    source = MemoryStore()
    source.put("acme", "scans", "odd", {"no_id_here": True})
    archive = export_tenant(source, "acme", ["scans"]).to_dict()
    assert len(archive["collections"]["scans"]) == 1
    assert verify(archive)["valid"]
