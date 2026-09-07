"""The SQL store: the parts that are not the shared contract.

`tests/test_store.py` already runs every `DocumentStore` behaviour against this
class on a real SQLite database — that is the important proof, and it lives there
rather than here because the claim being made is "same store, different engine".

What is left is what only a SQL store can get wrong: reconnection after an idle
socket dies, statements built for an engine nobody here can run, and the ways a
driver can hand back a stored value.

**The MariaDB dialect is asserted, never executed.** There is no MariaDB, no
client library and no container runtime in this environment. The tests below say
what the statements *are*; whether MariaDB accepts them is the test that has not
happened yet, and `dnsguard/sqlstore.py` says so in its own docstring too.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from dnsguard.errors import StorageError, ValidationError
from dnsguard.sqlstore import MARIADB, SQLITE, SqlDocumentStore


@pytest.fixture
def store(tmp_path):
    path = str(tmp_path / "documents.sqlite3")
    return SqlDocumentStore(lambda: sqlite3.connect(path), dialect=SQLITE)


# ── reconnection ─────────────────────────────────────────────────────────────


class FlakyConnection:
    """A connection that dies once, then works.

    Models the case this retry exists for: MariaDB closes idle connections, so
    the first statement after a quiet period fails on a socket that was healthy
    when it was opened.
    """

    def __init__(self, real, fail_first: bool):
        self.real = real
        self.fail_next = fail_first
        self.closed = False

    def cursor(self):
        if self.fail_next:
            self.fail_next = False
            raise sqlite3.OperationalError("server has gone away")
        return self.real.cursor()

    def commit(self):
        return self.real.commit()

    def close(self):
        self.closed = True


def dying_store(path):
    """A store whose first connection is already dead, with the schema built
    beforehand so the DDL is not what gets retried."""
    SqlDocumentStore(lambda: sqlite3.connect(path), dialect=SQLITE)  # schema only
    opened = []

    def connect():
        conn = FlakyConnection(sqlite3.connect(path), fail_first=not opened)
        opened.append(conn)
        return conn

    return SqlDocumentStore(connect, dialect=SQLITE, create_schema=False), opened


def test_a_dead_connection_is_replaced_and_the_statement_succeeds(tmp_path):
    store, opened = dying_store(str(tmp_path / "d.sqlite3"))
    store.put("acme", "policies", "p", {"ok": True})
    assert store.get("acme", "policies", "p") == {"ok": True}
    assert len(opened) == 2, "the dead connection should have been replaced exactly once"


def test_the_dead_connection_is_actually_closed_rather_than_leaked(tmp_path):
    store, opened = dying_store(str(tmp_path / "d.sqlite3"))
    store.put("acme", "policies", "p", {})
    assert opened[0].closed is True
    assert opened[1].closed is False


def test_a_genuinely_unavailable_database_raises_rather_than_retrying_forever(tmp_path):
    """A statement that is wrong will be wrong twice, and a database that is
    down will be down on the next attempt too. Retrying into a timeout hides an
    outage behind a hang."""
    attempts = []

    def connect():
        attempts.append(1)
        raise sqlite3.OperationalError("unable to open database file")

    with pytest.raises(StorageError) as excinfo:
        SqlDocumentStore(connect, dialect=SQLITE)
    assert "reconnect" in str(excinfo.value)
    assert len(attempts) == 2, "exactly one retry, not a loop"


def test_the_error_names_the_engine_so_a_log_line_is_actionable(tmp_path):
    def connect():
        raise sqlite3.OperationalError("nope")

    with pytest.raises(StorageError) as excinfo:
        SqlDocumentStore(connect, dialect=MARIADB)
    assert "mariadb" in str(excinfo.value)


def test_the_store_recovers_after_close(store):
    store.put("acme", "policies", "p", {"v": 1})
    store.close()
    assert store.get("acme", "policies", "p") == {"v": 1}


def test_creating_the_schema_twice_is_harmless(tmp_path):
    path = str(tmp_path / "d.sqlite3")
    store = SqlDocumentStore(lambda: sqlite3.connect(path), dialect=SQLITE)
    store.put("acme", "policies", "p", {"v": 1})
    store.create_schema()
    assert store.get("acme", "policies", "p") == {"v": 1}, "re-running DDL must not drop data"


# ── the MariaDB dialect: asserted, not executed ──────────────────────────────


def test_mariadb_uses_its_drivers_placeholder():
    """SQLite takes `?`, MySQL drivers take `%s`. Statements are written with
    `?` and translated, so there is one copy of each statement rather than two
    that can drift."""
    translated = MARIADB.sql("SELECT x FROM t WHERE a = ? AND b = ?")
    assert translated == "SELECT x FROM t WHERE a = %s AND b = %s"
    assert SQLITE.sql("SELECT x FROM t WHERE a = ?") == "SELECT x FROM t WHERE a = ?"


def test_the_mariadb_key_is_the_tenant_collection_document_triple():
    ddl = " ".join(MARIADB.ddl)
    assert "PRIMARY KEY (tenant_id, collection, doc_id)" in ddl


def test_the_mariadb_tenant_key_is_case_sensitive():
    """Under MySQL's default case-insensitive collation, tenants `acme` and
    `ACME` would collide onto one primary key — a tenant boundary failing
    silently, which is the worst way for one to fail."""
    ddl = " ".join(MARIADB.ddl)
    assert "utf8mb4_bin" in ddl


def test_the_mariadb_charset_is_real_utf8():
    """MySQL's `utf8` is three-byte and not UTF-8. A client name or scan target
    can contain anything."""
    ddl = " ".join(MARIADB.ddl)
    assert "utf8mb4" in ddl
    assert "CHARSET=utf8 " not in ddl


def test_the_mariadb_upsert_replaces_rather_than_duplicating():
    assert "ON DUPLICATE KEY UPDATE" in MARIADB.upsert


def test_both_dialects_write_the_same_four_columns():
    """The dialects differ only in engine syntax. If one starts writing a
    different set of columns, a document written on one engine would not be
    readable on the other, and the migration would silently lose fields."""
    for dialect in (MARIADB, SQLITE):
        assert "(tenant_id, collection, doc_id, document)" in dialect.upsert


def test_every_statement_the_store_issues_is_parameterised(tmp_path):
    """Values reach the database as bind parameters, never as text spliced into
    SQL. Segment validation already rejects the obvious metacharacters, but that
    is the second line, not the first."""
    seen = []

    class RecordingCursor:
        def execute(self, sql, params):
            seen.append((sql, params))

        def fetchone(self):
            return None

        def fetchall(self):
            return []

        def close(self):
            pass

        rowcount = 0

    class RecordingConnection:
        def cursor(self):
            return RecordingCursor()

        def commit(self):
            pass

        def close(self):
            pass

    store = SqlDocumentStore(RecordingConnection, dialect=MARIADB)
    store.put("acme", "policies", "p", {"a": 1})
    store.get("acme", "policies", "p")
    store.list("acme", "policies")
    store.delete("acme", "policies", "p")
    store.tenants()

    # The DDL carries no values, so it is not part of this claim.
    value_statements = [(sql, params) for sql, params in seen if "CREATE TABLE" not in sql]
    assert len(value_statements) == 5, "expected one statement per operation"
    for sql, params in value_statements:
        assert "acme" not in sql
        assert sql.count("%s") == len(params)


def test_a_document_body_containing_sql_is_stored_verbatim(store):
    """The body is data. It is never parsed as anything."""
    nasty = {"note": "'; DROP TABLE documents; --", "quote": 'he said "hi"'}
    store.put("acme", "notes", "n", nasty)
    assert store.get("acme", "notes", "n") == nasty
    assert store.list("acme", "notes") == [nasty]


@pytest.mark.parametrize("bad", ["a/b", "../etc", "a b", "x" * 200, "", "'; DROP TABLE t; --"])
def test_junk_segments_are_rejected_before_reaching_the_database(store, bad):
    with pytest.raises(ValidationError):
        store.put(bad, "policies", "p", {})
    with pytest.raises(ValidationError):
        store.get("acme", "policies", bad)


# ── what a driver may hand back ──────────────────────────────────────────────


class BodyConnection:
    """Returns a chosen representation of a stored document, as different
    drivers do: text, bytes, or an already-decoded dict for a native JSON
    column."""

    def __init__(self, body):
        self.body = body

    def cursor(self):
        body = self.body

        class Cursor:
            rowcount = 1

            def execute(self, sql, params):
                pass

            def fetchone(self):
                return (body,)

            def fetchall(self):
                return [("d", body)]

            def close(self):
                pass

        return Cursor()

    def commit(self):
        pass

    def close(self):
        pass


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(json.dumps({"v": 1}), id="text"),
        pytest.param(json.dumps({"v": 1}).encode(), id="bytes"),
        pytest.param({"v": 1}, id="already-decoded dict from a native JSON column"),
    ],
)
def test_a_document_is_decoded_whatever_shape_the_driver_returns(body):
    """Which of these arrives is a property of the driver, not of the data. A
    store that only worked with one driver would be a surprise discovered in
    production, on the engine that has never been run against."""
    store = SqlDocumentStore(lambda: BodyConnection(body), dialect=MARIADB, create_schema=False)
    assert store.get("acme", "policies", "p") == {"v": 1}
    assert store.list("acme", "policies") == [{"v": 1}]


def test_a_corrupt_row_is_reported_rather_than_returned_as_junk():
    """Matches JsonFileStore, which raises rather than handing back something
    that is not the document that was stored."""
    store = SqlDocumentStore(
        lambda: BodyConnection("{not json"), dialect=MARIADB, create_schema=False
    )
    with pytest.raises(ValidationError) as excinfo:
        store.get("acme", "policies", "p")
    assert "policies/p" in str(excinfo.value)
