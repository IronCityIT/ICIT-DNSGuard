"""Taking a tenant's data out, checking it is intact, and putting it back.

Two jobs that turn out to be the same job.

**Disaster recovery.** The handoff records this as UNKNOWN with no evidence
either way: nobody knows whether the live store has ever been backed up, and no
restore has ever been rehearsed. An untested backup is a hypothesis, and the
moment you need it is a poor time to test it.

**The migration.** Phase 3 moves 34 live scan documents onto self-hosted storage
and says they must be "exported and imported, then reconciled by count and
checksum before the old path is switched off". That is this, exactly.

## What makes an archive trustworthy

The same standard the evidence pack is held to, because the failure is the same:
a file that *says* it is complete is worth nothing unless a recipient can check
without trusting whatever produced it.

  * Every document is hashed, and the manifest of those hashes is itself hashed.
    Editing a document fails; removing one fails; and **repairing the manifest to
    match an edited document also fails**, because the manifest hash no longer
    matches the manifest. That third case is the one that separates a real
    integrity check from a checksum somebody can recompute.
  * `verify()` re-derives everything from the archive alone. It does not consult
    the store, and it does not trust the exporter.

## Restoring does not overwrite

By default a restore refuses to replace a document that already exists, and
reports which ones it skipped. Restoring into a live store is otherwise a way to
lose the newer copy of something while believing you are recovering it —
`overwrite=True` exists for the case where that is genuinely what is wanted, and
has to be asked for.

## What this does not do

It does not encrypt, and an archive contains everything a tenant's store holds —
including, for the free-scan tenant, submitter email addresses. Treat the file as
the personal data it contains. Encryption belongs to whatever stores the archive,
and inventing a scheme here would be a second place to get key management wrong.
"""

from __future__ import annotations

import builtins
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .clock import Clock, iso
from .errors import ValidationError
from .store import DocumentStore

SCHEMA = "icit.dnsguard.backup.v1"


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


@dataclass
class Archive:
    """One tenant's documents, with the means to prove they are unaltered."""

    schema: str
    tenant_id: str
    created_at: str
    collections: dict[str, dict[str, Any]]
    manifest: dict[str, str]
    manifest_hash: str
    counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at,
            "counts": self.counts,
            "manifest": self.manifest,
            "manifest_hash": self.manifest_hash,
            "collections": self.collections,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, default=str)

    @property
    def document_count(self) -> int:
        return sum(len(docs) for docs in self.collections.values())


def export_tenant(
    store: DocumentStore,
    tenant_id: str,
    collections: builtins.list[str],
    clock: Clock | None = None,
) -> Archive:
    """Everything this tenant has in the named collections.

    The collection names are passed in rather than discovered, because
    `DocumentStore` has no way to enumerate them — it can list documents in a
    collection and tenants in the store, and nothing in between. Passing them
    explicitly at least makes the omission visible to the caller instead of
    producing an archive that is quietly short.
    """
    clock = clock or Clock()
    contents: dict[str, dict[str, Any]] = {}
    manifest: dict[str, str] = {}
    counts: dict[str, int] = {}

    for collection in sorted(set(collections)):
        documents = store.list(tenant_id, collection)
        if not documents:
            continue
        keyed = {_identify(collection, index, doc): doc for index, doc in enumerate(documents)}
        contents[collection] = keyed
        counts[collection] = len(keyed)
        for key, document in keyed.items():
            manifest[f"{collection}/{key}"] = digest(document)

    return Archive(
        schema=SCHEMA,
        tenant_id=tenant_id,
        created_at=iso(clock.now()),
        collections=contents,
        manifest=manifest,
        manifest_hash=digest(manifest),
        counts=counts,
    )


def _identify(collection: str, index: int, document: dict[str, Any]) -> str:
    """The id a document should be restored under.

    Documents carry their own id under various names depending on which service
    wrote them. The fallbacks are ordered most-specific first, and the positional
    last resort keeps an archive complete rather than dropping a document whose
    shape nobody anticipated — a backup that silently omits the awkward records
    is worse than one that restores them under an ugly name.
    """
    for field_name in ("id", "scan_id", "feed_id", "snapshot_id", "policy_id", "site_id"):
        value = document.get(field_name)
        if isinstance(value, str) and value:
            return value

    # An audit record has no id field — its key is its sequence number, zero
    # padded, so that lexical order in the store equals chain order. Restoring
    # it under a positional name preserves the data and loses that invariant,
    # which the log's own comment says it depends on.
    seq = document.get("seq")
    if isinstance(seq, int):
        return f"{seq:012d}"

    return f"{collection}-{index:06d}"


def verify(archive: dict[str, Any]) -> dict[str, Any]:
    """Re-derive every hash from the archive alone.

    Deliberately independent of the exporter: a recipient checks the file without
    trusting whatever produced it, which is the only kind of check worth having.
    """
    if archive.get("schema") != SCHEMA:
        raise ValidationError(f"unknown backup schema {archive.get('schema')!r}; expected {SCHEMA}")

    collections = archive.get("collections", {})
    manifest = archive.get("manifest", {})
    problems: builtins.list[str] = []

    present: dict[str, Any] = {}
    for collection, documents in collections.items():
        for key, document in documents.items():
            present[f"{collection}/{key}"] = document

    for path in sorted(set(manifest) | set(present)):
        if path not in present:
            problems.append(f"the manifest lists {path} but the archive does not contain it")
        elif path not in manifest:
            problems.append(f"{path} is in the archive but not covered by the manifest")
        elif digest(present[path]) != manifest[path]:
            problems.append(f"{path} does not match its manifest hash")

    # The case that separates this from a checksum anybody can recompute: an
    # edited document plus a manifest repaired to match it.
    if digest(manifest) != archive.get("manifest_hash"):
        problems.append("the manifest hash does not match the manifest")

    for collection, expected in (archive.get("counts") or {}).items():
        actual = len(collections.get(collection, {}))
        if actual != expected:
            problems.append(
                f"{collection} holds {actual} document(s) but the archive claims {expected}"
            )

    return {
        "valid": not problems,
        "problems": problems,
        "documents_checked": len(manifest),
        "tenant_id": archive.get("tenant_id", ""),
    }


def restore(
    store: DocumentStore,
    archive: dict[str, Any],
    tenant_id: str | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Write an archive's documents into a store.

    Verified before anything is written: restoring an archive that fails its own
    integrity check is how a corrupt backup becomes a corrupt store.

    Refuses to replace an existing document unless `overwrite` is asked for.
    Restoring into a live store is otherwise a way to lose the newer copy of
    something while believing you are recovering it.
    """
    report = verify(archive)
    if not report["valid"]:
        raise ValidationError(
            "refusing to restore an archive that fails verification: "
            + "; ".join(report["problems"][:3])
        )

    target = tenant_id or archive.get("tenant_id", "")
    if not target:
        raise ValidationError("a restore needs a tenant to write into")

    written: builtins.list[str] = []
    skipped: builtins.list[str] = []
    for collection, documents in sorted(archive.get("collections", {}).items()):
        for key, document in sorted(documents.items()):
            if not overwrite and store.get(target, collection, key) is not None:
                skipped.append(f"{collection}/{key}")
                continue
            store.put(target, collection, key, document)
            written.append(f"{collection}/{key}")

    return {
        "tenant_id": target,
        "written": written,
        "skipped": skipped,
        "complete": not skipped,
    }


def reconcile(
    store: DocumentStore, archive: dict[str, Any], tenant_id: str | None = None
) -> dict[str, Any]:
    """Compare a live store against an archive, document by document.

    This is what makes a migration checkable rather than hopeful: after copying
    data to somewhere new, the question is not "did the import report success"
    but "is what is now there the same as what was there before".
    """
    target = tenant_id or archive.get("tenant_id", "")
    missing: builtins.list[str] = []
    differing: builtins.list[str] = []
    matched = 0

    for collection, documents in (archive.get("collections") or {}).items():
        for key, document in documents.items():
            live = store.get(target, collection, key)
            if live is None:
                missing.append(f"{collection}/{key}")
            elif digest(live) != digest(document):
                differing.append(f"{collection}/{key}")
            else:
                matched += 1

    return {
        "tenant_id": target,
        "matched": matched,
        "missing": missing,
        "differing": differing,
        "reconciled": not missing and not differing,
    }
