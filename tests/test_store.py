"""The store is where multi-tenancy is mechanically enforced, so its isolation
and its input validation are tested as security properties, not conveniences."""

from __future__ import annotations

import pytest

from dnsguard.errors import NotFoundError, ValidationError
from dnsguard.store import JsonFileStore, MemoryStore, validate_segment


@pytest.fixture(params=["memory", "file"])
def store(request, tmp_path):
    return MemoryStore() if request.param == "memory" else JsonFileStore(tmp_path / "data")


def test_round_trip(store):
    store.put("acme", "policies", "default", {"name": "default", "version": 1})
    assert store.get("acme", "policies", "default") == {"name": "default", "version": 1}


def test_one_tenant_cannot_see_another(store):
    store.put("acme", "policies", "default", {"owner": "acme"})
    store.put("globex", "policies", "default", {"owner": "globex"})
    assert store.get("acme", "policies", "default")["owner"] == "acme"
    assert store.get("globex", "policies", "default")["owner"] == "globex"
    assert [d["owner"] for d in store.list("acme", "policies")] == ["acme"]


def test_missing_document_is_none_and_require_raises(store):
    assert store.get("acme", "policies", "nope") is None
    with pytest.raises(NotFoundError):
        store.require("acme", "policies", "nope")


def test_delete_reports_whether_anything_was_removed(store):
    store.put("acme", "policies", "p", {})
    assert store.delete("acme", "policies", "p") is True
    assert store.delete("acme", "policies", "p") is False


def test_query_filters_on_equality(store):
    store.put("acme", "sites", "hq", {"site_id": "hq", "enforcing": True})
    store.put("acme", "sites", "branch", {"site_id": "branch", "enforcing": False})
    assert [d["site_id"] for d in store.query("acme", "sites", enforcing=True)] == ["hq"]


def test_stored_documents_are_copies_not_references(store):
    original = {"rules": [{"action": "block"}]}
    store.put("acme", "policies", "p", original)
    original["rules"].append({"action": "allow"})
    assert len(store.get("acme", "policies", "p")["rules"]) == 1


def test_list_is_deterministically_ordered(store):
    for name in ("c", "a", "b"):
        store.put("acme", "sites", name, {"site_id": name})
    assert [d["site_id"] for d in store.list("acme", "sites")] == ["a", "b", "c"]


def test_unknown_collection_lists_empty(store):
    assert store.list("acme", "nothinghere") == []


@pytest.mark.parametrize("bad", ["", "..", ".", "a/b", "../etc", "a b", "x" * 200, "-lead"])
def test_path_traversal_and_junk_segments_are_rejected(bad):
    with pytest.raises(ValidationError):
        validate_segment(bad, "tenant_id")


def test_traversal_cannot_escape_the_file_store_root(tmp_path):
    store = JsonFileStore(tmp_path / "data")
    with pytest.raises(ValidationError):
        store.put("../../etc", "passwd", "x", {})
    with pytest.raises(ValidationError):
        store.get("acme", "policies", "../../../secret")


def test_file_store_survives_a_partial_write(tmp_path):
    """Writes go via a temp file and rename, so a reader never sees half a doc."""
    root = tmp_path / "data"
    store = JsonFileStore(root)
    store.put("acme", "policies", "p", {"v": 1})
    leftovers = list((root / "acme" / "policies").glob("*.tmp"))
    assert leftovers == []


def test_file_store_reports_corruption_rather_than_returning_junk(tmp_path):
    root = tmp_path / "data"
    store = JsonFileStore(root)
    store.put("acme", "policies", "p", {"v": 1})
    (root / "acme" / "policies" / "p.json").write_text("{not json")
    with pytest.raises(ValidationError):
        store.get("acme", "policies", "p")


def test_tenants_are_enumerable(store):
    store.put("acme", "x", "1", {})
    store.put("globex", "x", "1", {})
    assert store.tenants() == ["acme", "globex"]
