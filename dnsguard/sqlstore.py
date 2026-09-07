"""A SQL-backed `DocumentStore`, for self-hosted MariaDB on NAS infrastructure.

This is phase 1 of moving persistent state off retired managed storage and onto
ICIT's own infrastructure. It is deliberately **additive**: nothing switches to
it here. `MemoryStore` and `JsonFileStore` are untouched, and this implements the
same `DocumentStore` contract, so the whole existing store test suite runs
against it unchanged. That is the point of doing it this way — the migration goes
through a seam that already existed rather than through a rewrite.

## What is stored, and why it looks like this

One row per document, keyed `(tenant_id, collection, doc_id)`, with the document
body as JSON. Those three are real indexed columns, not fields inside a blob,
because they are what every read and write addresses by — including the tenant
check that makes multi-tenancy mechanical rather than remembered.

The body stays JSON *for now* on purpose. Changing the storage engine and the
schema shape in the same step is how migrations go wrong: you lose the ability to
tell which change broke something. Fully relational tables for the entities that
need querying — findings by severity, policies by state, the audit chain by
sequence — come after this is proven, and the handoff document describes them.

## Verification status — read this before trusting it

**VERIFIED:** every behaviour in the `DocumentStore` contract, executed against a
real database engine (SQLite) through this class. Tenant isolation, segment
validation, copy semantics, list ordering, delete reporting, corruption handling,
reconnection.

**NOT VERIFIED:** execution against a live MariaDB server. No MariaDB, no client
library and no container runtime exists in the environment this was written in,
so the MariaDB dialect's DDL and upsert are asserted as *statements* and have
never been *run*. Treat the first connection to a real MariaDB as the test that
has not happened yet. The dialect is small and separated precisely so that test
is cheap when someone can run it.

## Connections

A connection factory is taken rather than a connection, and one connection is
held under a lock. MariaDB closes idle connections (`wait_timeout`, default eight
hours), and a control plane that sits quiet overnight would otherwise wake up to
a dead socket and report a storage failure that is really a bookkeeping one. So a
failed statement is retried exactly once on a fresh connection. Once, not in a
loop: if the second attempt fails too, the database is genuinely unavailable and
saying so immediately is more useful than retrying into a timeout.
"""

from __future__ import annotations

import builtins
import json
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .errors import StorageError, ValidationError
from .store import DocumentStore, validate_segment

#: Longest tenant/collection/document id the schema accepts. Matches the 128
#: characters `store.validate_segment` already allows, so a segment that passes
#: validation can never be silently truncated by the column width.
SEGMENT_LENGTH = 128


@dataclass(frozen=True)
class Dialect:
    """The handful of things that actually differ between engines.

    Kept this small on purpose: the MariaDB path cannot be executed in the
    environment this was written in, so the amount of untested code is held to
    four strings rather than a second implementation of the store.
    """

    name: str
    #: "?" for SQLite, "%s" for MySQL/MariaDB drivers using the `format` style.
    placeholder: str
    ddl: tuple[str, ...]
    upsert: str

    def sql(self, statement: str) -> str:
        """Swap the neutral `?` marker for this engine's placeholder."""
        return statement if self.placeholder == "?" else statement.replace("?", self.placeholder)


#: The target engine. **These statements have never been executed** — see the
#: module docstring. utf8mb4 throughout: a scan target or client name can contain
#: anything, and MySQL's "utf8" is not UTF-8.
MARIADB = Dialect(
    name="mariadb",
    placeholder="%s",
    ddl=(
        f"""
        CREATE TABLE IF NOT EXISTS documents (
            tenant_id   VARCHAR({SEGMENT_LENGTH}) NOT NULL,
            collection  VARCHAR({SEGMENT_LENGTH}) NOT NULL,
            doc_id      VARCHAR({SEGMENT_LENGTH}) NOT NULL,
            document    LONGTEXT NOT NULL,
            updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                        ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (tenant_id, collection, doc_id),
            KEY idx_tenant_collection (tenant_id, collection)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin
        """,
    ),
    # utf8mb4_bin above, not the default case-insensitive collation: tenant ids
    # are identifiers. Under a case-insensitive key, "acme" and "ACME" would
    # collide into one row, which is a tenant boundary failing quietly.
    upsert=(
        "INSERT INTO documents (tenant_id, collection, doc_id, document) "
        "VALUES (?, ?, ?, ?) "
        "ON DUPLICATE KEY UPDATE document = VALUES(document)"
    ),
)

#: Used by the tests and by local development. Present so the contract can be
#: executed against a real engine rather than a mock — a store proven only
#: against a fake connection is a store proven against your own assumptions.
SQLITE = Dialect(
    name="sqlite",
    placeholder="?",
    ddl=(
        """
        CREATE TABLE IF NOT EXISTS documents (
            tenant_id   TEXT NOT NULL,
            collection  TEXT NOT NULL,
            doc_id      TEXT NOT NULL,
            document    TEXT NOT NULL,
            updated_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (tenant_id, collection, doc_id)
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_tenant_collection ON documents (tenant_id, collection)",
    ),
    upsert=(
        "INSERT INTO documents (tenant_id, collection, doc_id, document) "
        "VALUES (?, ?, ?, ?) "
        "ON CONFLICT(tenant_id, collection, doc_id) DO UPDATE SET document = excluded.document"
    ),
)


class SqlDocumentStore(DocumentStore):
    """`clients/{tenant_id}/{collection}/{doc_id}` over a SQL table.

    `connect` is a zero-argument callable returning a DB-API 2.0 connection.
    A factory rather than a connection because this owns reconnection, and it
    cannot reconnect something it was merely handed.
    """

    def __init__(
        self,
        connect: Callable[[], Any],
        dialect: Dialect = MARIADB,
        create_schema: bool = True,
    ) -> None:
        self._connect = connect
        self.dialect = dialect
        self._connection: Any = None
        self._lock = threading.RLock()
        if create_schema:
            self.create_schema()

    # ── connection handling ─────────────────────────────────────────────────

    def create_schema(self) -> None:
        """Idempotent. Every statement is CREATE ... IF NOT EXISTS, so this is
        safe to call on every start-up and does not need a migration runner
        until the schema actually changes."""
        for statement in self.dialect.ddl:
            self._run(statement, (), fetch="none")

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                try:
                    self._connection.close()
                finally:
                    self._connection = None

    def _live(self) -> Any:
        if self._connection is None:
            self._connection = self._connect()
        return self._connection

    def _run(self, statement: str, params: tuple, fetch: str) -> Any:
        """Execute once; on failure, reconnect and execute exactly once more.

        The retry is not for flaky queries — a statement that is wrong will be
        wrong twice. It is for the dead-socket case: MariaDB drops idle
        connections, and the first statement after a quiet night fails on a
        connection that was fine when it was opened.
        """
        sql = self.dialect.sql(statement)
        with self._lock:
            for attempt in (1, 2):
                try:
                    return self._execute(self._live(), sql, params, fetch)
                except Exception as exc:  # noqa: BLE001 - driver exceptions vary by engine
                    self.close()
                    if attempt == 2:
                        raise StorageError(
                            f"{self.dialect.name} statement failed after a reconnect: {exc}"
                        ) from exc
        raise StorageError("unreachable")  # pragma: no cover

    def _execute(self, connection: Any, sql: str, params: tuple, fetch: str) -> Any:
        cursor = connection.cursor()
        try:
            cursor.execute(sql, params)
            if fetch == "all":
                return cursor.fetchall()
            if fetch == "one":
                return cursor.fetchone()
            if fetch == "rowcount":
                connection.commit()
                return cursor.rowcount
            connection.commit()
            return None
        finally:
            cursor.close()

    # ── the contract ────────────────────────────────────────────────────────

    def _key(self, tenant_id: str, collection: str, doc_id: str) -> tuple[str, str, str]:
        return (
            validate_segment(tenant_id, "tenant_id"),
            validate_segment(collection, "collection"),
            validate_segment(doc_id, "document id"),
        )

    def put(self, tenant_id: str, collection: str, doc_id: str, document: dict[str, Any]) -> None:
        key = self._key(tenant_id, collection, doc_id)
        body = json.dumps(document, sort_keys=True, default=str)
        self._run(self.dialect.upsert, (*key, body), fetch="none")

    def get(self, tenant_id: str, collection: str, doc_id: str) -> dict[str, Any] | None:
        key = self._key(tenant_id, collection, doc_id)
        row = self._run(
            "SELECT document FROM documents WHERE tenant_id = ? AND collection = ? AND doc_id = ?",
            key,
            fetch="one",
        )
        if row is None:
            return None
        return self._decode(row[0], collection, doc_id)

    def list(self, tenant_id: str, collection: str) -> builtins.list[dict[str, Any]]:
        tenant_id = validate_segment(tenant_id, "tenant_id")
        collection = validate_segment(collection, "collection")
        rows = self._run(
            "SELECT doc_id, document FROM documents "
            "WHERE tenant_id = ? AND collection = ? ORDER BY doc_id",
            (tenant_id, collection),
            fetch="all",
        )
        return [self._decode(body, collection, doc_id) for doc_id, body in rows or ()]

    def delete(self, tenant_id: str, collection: str, doc_id: str) -> bool:
        key = self._key(tenant_id, collection, doc_id)
        deleted = self._run(
            "DELETE FROM documents WHERE tenant_id = ? AND collection = ? AND doc_id = ?",
            key,
            fetch="rowcount",
        )
        return bool(deleted)

    def tenants(self) -> builtins.list[str]:
        rows = self._run(
            "SELECT DISTINCT tenant_id FROM documents ORDER BY tenant_id", (), fetch="all"
        )
        return [row[0] for row in rows or ()]

    # ── decoding ────────────────────────────────────────────────────────────

    def _decode(self, body: Any, collection: str, doc_id: str) -> dict[str, Any]:
        """Row body to document.

        A driver may hand back `str`, `bytes` or — where the column is a native
        JSON type and the driver is helpful — an already-decoded `dict`. All
        three are accepted, because which one arrives is a property of the
        driver rather than of the data, and a store that only worked with one
        driver would be a surprise found in production.
        """
        if isinstance(body, dict):
            return body
        if isinstance(body, (bytes, bytearray)):
            body = body.decode("utf-8")
        try:
            loaded: dict[str, Any] = json.loads(body)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValidationError(f"corrupt document {collection}/{doc_id}: {exc}") from exc
        return loaded
