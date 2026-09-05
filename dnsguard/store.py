"""Tenant-partitioned document storage.

Every read and write goes through a tenant id, and the store refuses to build a
path without one. That is the mechanical half of multi-tenancy: there is no API
in this module that can return another tenant's document, so a leak has to be a
deliberate act rather than a forgotten WHERE clause.

Two implementations:
  MemoryStore  — tests and the local dev server.
  JsonFileStore — a directory tree on disk; what the API service uses when no
                  managed backend is configured, and what the evidence exporter
                  reads from.

The document shape is the same either way: collections addressed as
clients/{tenant_id}/{collection}/{doc_id}, matching the Firestore layout the
fleet architecture calls for.
"""

from __future__ import annotations

import builtins
import copy
import json
import os
import re
import tempfile
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from .errors import NotFoundError, ValidationError

# Firestore path segments; also what keeps a tenant id out of the filesystem.
_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$")


def validate_segment(value: str, what: str) -> str:
    if not isinstance(value, str) or not _SEGMENT.match(value):
        raise ValidationError(f"invalid {what}: {value!r}")
    if value in (".", ".."):
        raise ValidationError(f"invalid {what}: {value!r}")
    return value


class DocumentStore(ABC):
    """clients/{tenant_id}/{collection}/{doc_id} -> dict."""

    @abstractmethod
    def put(
        self, tenant_id: str, collection: str, doc_id: str, document: dict[str, Any]
    ) -> None: ...

    @abstractmethod
    def get(self, tenant_id: str, collection: str, doc_id: str) -> dict[str, Any] | None: ...

    @abstractmethod
    def list(self, tenant_id: str, collection: str) -> builtins.list[dict[str, Any]]: ...

    @abstractmethod
    def delete(self, tenant_id: str, collection: str, doc_id: str) -> bool: ...

    @abstractmethod
    def tenants(self) -> builtins.list[str]: ...

    # ── shared, non-abstract helpers ────────────────────────────────────────

    def require(self, tenant_id: str, collection: str, doc_id: str) -> dict[str, Any]:
        document = self.get(tenant_id, collection, doc_id)
        if document is None:
            raise NotFoundError(f"{collection}/{doc_id} not found")
        return document

    def query(
        self, tenant_id: str, collection: str, **equals: Any
    ) -> builtins.list[dict[str, Any]]:
        """Documents in the collection matching every field=value pair given."""
        return [
            d
            for d in self.list(tenant_id, collection)
            if all(d.get(field) == value for field, value in equals.items())
        ]


class MemoryStore(DocumentStore):
    def __init__(self) -> None:
        self._data: dict[str, dict[str, dict[str, dict[str, Any]]]] = {}
        self._lock = threading.RLock()

    def put(self, tenant_id: str, collection: str, doc_id: str, document: dict[str, Any]) -> None:
        validate_segment(tenant_id, "tenant_id")
        validate_segment(collection, "collection")
        validate_segment(doc_id, "document id")
        with self._lock:
            self._data.setdefault(tenant_id, {}).setdefault(collection, {})[doc_id] = copy.deepcopy(
                document
            )

    def get(self, tenant_id: str, collection: str, doc_id: str) -> dict[str, Any] | None:
        validate_segment(tenant_id, "tenant_id")
        with self._lock:
            found = self._data.get(tenant_id, {}).get(collection, {}).get(doc_id)
            return copy.deepcopy(found) if found is not None else None

    def list(self, tenant_id: str, collection: str) -> builtins.list[dict[str, Any]]:
        validate_segment(tenant_id, "tenant_id")
        with self._lock:
            return [
                copy.deepcopy(d)
                for _, d in sorted(self._data.get(tenant_id, {}).get(collection, {}).items())
            ]

    def delete(self, tenant_id: str, collection: str, doc_id: str) -> bool:
        validate_segment(tenant_id, "tenant_id")
        with self._lock:
            return self._data.get(tenant_id, {}).get(collection, {}).pop(doc_id, None) is not None

    def tenants(self) -> builtins.list[str]:
        with self._lock:
            return sorted(self._data)


class JsonFileStore(DocumentStore):
    """One JSON file per document under root/{tenant}/{collection}/{doc}.json.

    Writes are atomic (temp file + rename) so a crash mid-write cannot leave a
    half-written policy or audit record behind.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _path(self, tenant_id: str, collection: str, doc_id: str) -> Path:
        validate_segment(tenant_id, "tenant_id")
        validate_segment(collection, "collection")
        validate_segment(doc_id, "document id")
        return self.root / tenant_id / collection / f"{doc_id}.json"

    def put(self, tenant_id: str, collection: str, doc_id: str, document: dict[str, Any]) -> None:
        path = self._path(tenant_id, collection, doc_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(document, indent=2, sort_keys=True, default=str)
        with self._lock:
            fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(payload)
                os.replace(tmp, path)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise

    def get(self, tenant_id: str, collection: str, doc_id: str) -> dict[str, Any] | None:
        path = self._path(tenant_id, collection, doc_id)
        with self._lock:
            if not path.is_file():
                return None
            try:
                loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ValidationError(f"corrupt document {collection}/{doc_id}: {exc}") from exc
            return loaded

    def list(self, tenant_id: str, collection: str) -> builtins.list[dict[str, Any]]:
        validate_segment(tenant_id, "tenant_id")
        validate_segment(collection, "collection")
        directory = self.root / tenant_id / collection
        if not directory.is_dir():
            return []
        out: builtins.list[dict[str, Any]] = []
        for path in sorted(directory.glob("*.json")):
            document = self.get(tenant_id, collection, path.stem)
            if document is not None:
                out.append(document)
        return out

    def delete(self, tenant_id: str, collection: str, doc_id: str) -> bool:
        path = self._path(tenant_id, collection, doc_id)
        with self._lock:
            if not path.is_file():
                return False
            path.unlink()
            return True

    def tenants(self) -> builtins.list[str]:
        return sorted(p.name for p in self.root.iterdir() if p.is_dir())
