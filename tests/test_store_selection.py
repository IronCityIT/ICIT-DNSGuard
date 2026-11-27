"""`_default_store` wiring: which store the environment selects.

The MariaDB path itself is proven against a real engine elsewhere; what this
guards is the choice between stores, so a deployment that sets DNSGUARD_DB_HOST
gets MariaDB and one that does not keeps the in-memory/file behaviour the rest
of the suite depends on. The real `SqlDocumentStore` is stubbed here so the
selection can be tested without a database.
"""

from __future__ import annotations

import sqlite3
import sys
import traceback
import types

import pytest

import dnsguard.api as api
from dnsguard.sqlstore import SQLITE, SqlDocumentStore
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


# ── fail closed at start-up, and never say where the database is ─────────────
#
# A misconfigured database must stop the process rather than let it come up on
# some other store, and the reason must not carry the host, user or password:
# start-up errors land in container logs that more people can read than the
# credentials file. Placeholders only; `.invalid` is reserved (RFC 2606).

_HOST = "db-host.invalid"
_USER = "placeholder_user"
_PASSWORD = "placeholder-password"  # noqa: S105 - obvious placeholder, not a credential


def _db_env(monkeypatch, **overrides):
    _no_db(monkeypatch)
    env = {
        "DNSGUARD_DB_HOST": _HOST,
        "DNSGUARD_DB_PORT": "3306",
        "DNSGUARD_DB_NAME": "dnsguard",
        "DNSGUARD_DB_USER": _USER,
        "DNSGUARD_DB_PASSWORD": _PASSWORD,
    }
    env.update(overrides)
    for name, value in env.items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)


def _fake_driver(monkeypatch, connect):
    driver = types.ModuleType("pymysql")
    driver.connect = connect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "pymysql", driver)


def _assert_no_connection_details(exc: BaseException) -> None:
    """Nothing identifying the database, in the message or in a chained cause
    the traceback would print alongside it."""
    rendered = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    for detail in (_HOST, _USER, _PASSWORD):
        assert detail not in rendered


@pytest.mark.parametrize("port", ["not-a-port", "0", "65536", "-1", "", "³", " 3306"])
def test_a_bad_port_stops_startup_without_echoing_it(monkeypatch, port):
    _db_env(monkeypatch, DNSGUARD_DB_PORT=port)
    _fake_driver(monkeypatch, lambda **_: pytest.fail("must not connect"))
    with pytest.raises(RuntimeError, match="DNSGUARD_DB_PORT") as excinfo:
        api._default_store()
    _assert_no_connection_details(excinfo.value)
    if port:
        assert f"'{port}'" not in str(excinfo.value)


@pytest.mark.parametrize(
    ("missing", "value"),
    [
        ("DNSGUARD_DB_USER", None),
        ("DNSGUARD_DB_USER", ""),
        ("DNSGUARD_DB_PASSWORD", None),
        ("DNSGUARD_DB_PASSWORD", ""),
        # Unset, the name defaults to "dnsguard" (next test); empty is an error.
        ("DNSGUARD_DB_NAME", ""),
    ],
)
def test_missing_connection_settings_stop_startup(monkeypatch, missing, value):
    _db_env(monkeypatch, **{missing: value})
    _fake_driver(monkeypatch, lambda **_: pytest.fail("must not connect"))
    with pytest.raises(RuntimeError, match=missing) as excinfo:
        api._default_store()
    _assert_no_connection_details(excinfo.value)


def test_unset_database_name_defaults_to_dnsguard(monkeypatch):
    _db_env(monkeypatch, DNSGUARD_DB_NAME=None)
    seen = {}
    _fake_driver(monkeypatch, lambda **kwargs: seen.update(kwargs) or sqlite3.connect(":memory:"))
    monkeypatch.setattr(api, "MARIADB", SQLITE)  # run the real store's DDL on a real engine
    api._default_store()
    assert seen["database"] == "dnsguard"


def test_a_missing_driver_stops_startup_with_a_clear_reason(monkeypatch):
    _db_env(monkeypatch)
    monkeypatch.setitem(sys.modules, "pymysql", None)  # makes `import pymysql` raise
    with pytest.raises(RuntimeError, match="PyMySQL") as excinfo:
        api._default_store()
    _assert_no_connection_details(excinfo.value)


def test_an_unreachable_database_stops_startup_without_naming_it(monkeypatch):
    """The real store runs its idempotent schema DDL in the constructor, so the
    first connection happens at start-up. The driver's own message names the
    host and user; none of it may reach the error, its cause or its context."""

    class OperationalError(Exception):
        pass

    def refuse(**kwargs):
        raise OperationalError(
            2003, f"Can't connect to MySQL server on '{kwargs['host']}' as '{kwargs['user']}'"
        )

    _db_env(monkeypatch)
    _fake_driver(monkeypatch, refuse)
    with pytest.raises(RuntimeError, match="DNSGUARD_DB_") as excinfo:
        api._default_store()
    message = str(excinfo.value)
    assert "OperationalError" in message and "2003" in message, "keep it diagnosable"
    _assert_no_connection_details(excinfo.value)


def test_a_valid_configuration_builds_the_real_sql_store(monkeypatch):
    """End to end through the real `SqlDocumentStore`: the factory hands the
    driver what MariaDB needs, the schema is created, and documents round-trip.
    SQLite stands in for the engine, as in the sqlstore suite."""
    _db_env(monkeypatch, DNSGUARD_DB_PORT="3307")
    seen = {}
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    _fake_driver(monkeypatch, lambda **kwargs: seen.update(kwargs) or connection)
    monkeypatch.setattr(api, "MARIADB", SQLITE)
    store = api._default_store()
    assert isinstance(store, SqlDocumentStore)
    assert seen == {
        "host": _HOST,
        "port": 3307,
        "user": _USER,
        "password": _PASSWORD,
        "database": "dnsguard",
        "charset": "utf8mb4",
    }
    store.put("tenant-a", "scans", "s1", {"ok": True})
    assert store.get("tenant-a", "scans", "s1") == {"ok": True}
