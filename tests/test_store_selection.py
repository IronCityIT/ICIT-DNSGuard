"""`_default_store` wiring: which store the environment selects.

The MariaDB path itself is proven against a real engine elsewhere; what this
guards is the choice between stores, so a deployment that sets DNSGUARD_DB_HOST
gets MariaDB and one that does not keeps the in-memory/file behaviour the rest
of the suite depends on. The real `SqlDocumentStore` is stubbed here so the
selection can be tested without a database.
"""

from __future__ import annotations

import dnsguard.api as api
from dnsguard.store import JsonFileStore, MemoryStore


class _FakeSqlStore:
    def __init__(self, connect, dialect=None, create_schema=True):
        # Record what it was built with; never connect.
        self.connect = connect
        self.dialect = dialect


def _no_db(monkeypatch):
    for var in ("DNSGUARD_DB_HOST", "DNSGUARD_DATA_DIR"):
        monkeypatch.delenv(var, raising=False)


def test_memory_store_when_nothing_configured(monkeypatch):
    _no_db(monkeypatch)
    assert isinstance(api._default_store(), MemoryStore)


def test_file_store_when_only_data_dir(monkeypatch, tmp_path):
    _no_db(monkeypatch)
    monkeypatch.setenv("DNSGUARD_DATA_DIR", str(tmp_path))
    assert isinstance(api._default_store(), JsonFileStore)


def test_mariadb_selected_and_wins_over_data_dir(monkeypatch, tmp_path):
    _no_db(monkeypatch)
    monkeypatch.setattr(api, "SqlDocumentStore", _FakeSqlStore)
    monkeypatch.setenv("DNSGUARD_DATA_DIR", str(tmp_path))  # should be ignored
    monkeypatch.setenv("DNSGUARD_DB_HOST", "nas.example")
    monkeypatch.setenv("DNSGUARD_DB_USER", "dnsguard_app")
    monkeypatch.setenv("DNSGUARD_DB_PASSWORD", "secret")
    store = api._default_store()
    assert isinstance(store, _FakeSqlStore)
    assert store.dialect is api.MARIADB
    assert callable(store.connect)
