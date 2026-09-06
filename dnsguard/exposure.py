"""Check what the live Firestore project actually exposes to the internet.

The rules file in this repository is only a claim. What matters is the rules
Google is enforcing right now, and the two have already diverged once: this
project was recorded as carrying open test-mode rules, while the deployed rules
in fact denied unknown collections and still allowed the scans collection to be
listed. Neither the committed file nor the STATUS document would have told
anyone that.

So this asks the live project directly, using the same unauthenticated REST API
a stranger would use, and reports what came back.

Three probes, each answering one question:

  * ``get`` on a document id that does not exist — can an unauthenticated caller
    read a scan at all? A deliberately absent id is used so the probe never
    reads a real client's scan. ``404`` means the read was permitted and the
    document simply is not there; ``403`` means the rules refused.
  * ``list`` on the scans collection — can a stranger enumerate every scan ever
    run, and with it every submitter's email address? This is the harvesting
    question, and it is separate from the one above because Firestore's ``read``
    permission grants both and they have to be denied separately.
  * ``get`` on a collection this product does not use — is a catch-all deny in
    force? Under the open test-mode rules a project is created with, an unknown
    collection answers ``404``. A ``403`` proves some rules file is deployed.

Writes are never probed. Proving a write path is open means performing a write
against a live client-facing system, which is not a thing this tool will do; it
reports the write posture as unverified and says so.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

# Same shape as the feed fetcher's injection point: the caller supplies the
# transport, so tests never touch the network and the tool has no opinion about
# which HTTP library is in use.
HttpProbe = Callable[[str], int]

FIRESTORE_ROOT = "https://firestore.googleapis.com/v1"

# An id that cannot collide with a real scan. Scan ids are `scan-<ms>-<random>`,
# so this shape is not one the product ever mints.
ABSENT_DOCUMENT_ID = "dnsguard-exposure-probe-absent"

# A collection this product does not write. Used only to detect whether a
# catch-all deny is in force.
UNUSED_COLLECTION = "dnsguard-exposure-probe-unused"


@dataclass(frozen=True)
class Probe:
    """One question asked of the live project, and what came back."""

    name: str
    url: str
    status_code: int
    permitted: bool
    """True when the rules allowed the operation, whatever the result was.

    A 404 is a permitted read of a document that does not exist. Reading it as a
    denial is the mistake this field exists to prevent.
    """

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "status_code": self.status_code,
            "permitted": self.permitted,
        }


@dataclass
class ExposureReport:
    project_id: str
    collection: str
    probes: list[Probe] = field(default_factory=list)

    def probe(self, name: str) -> Probe | None:
        for item in self.probes:
            if item.name == name:
                return item
        return None

    @property
    def get_permitted(self) -> bool:
        found = self.probe("get_absent_document")
        return bool(found and found.permitted)

    @property
    def list_permitted(self) -> bool:
        found = self.probe("list_collection")
        return bool(found and found.permitted)

    @property
    def rules_deployed(self) -> bool:
        """True when an unused collection is refused.

        Open test-mode rules answer 404 for a collection nobody has written,
        because the read is allowed and there is nothing there. A refusal is
        therefore the signal that a rules file is in force at all.
        """
        found = self.probe("get_unused_collection")
        return bool(found and not found.permitted)

    @property
    def findings(self) -> list[dict[str, str]]:
        """What an operator has to act on, worst first."""
        out: list[dict[str, str]] = []
        if self.list_permitted:
            out.append(
                {
                    "severity": "high",
                    "title": "Stored scans can be enumerated without authentication",
                    "finding": (
                        "The scans collection answers an unauthenticated list request, so "
                        "anyone on the internet can retrieve every scan ever stored, "
                        "including the email address of whoever requested it and the "
                        "findings against their domain."
                    ),
                    "remediation": (
                        "Deploy the firestore.rules in this repository, which denies list "
                        "on the scans collection."
                    ),
                }
            )
        if self.get_permitted:
            out.append(
                {
                    "severity": "medium",
                    "title": "A scan can be read by anyone holding its id",
                    "finding": (
                        "Single-document reads are unauthenticated. Scan ids are "
                        "unguessable but they are not secrets and they appear in URLs."
                    ),
                    "remediation": (
                        "Expected until tenant-scoped tokens exist; closing it is step 2 "
                        "of the remediation order in PRODUCTIZE_NOTES.md."
                    ),
                }
            )
        if not self.rules_deployed:
            out.append(
                {
                    "severity": "high",
                    "title": "No rules file appears to be in force",
                    "finding": (
                        "A collection this product never writes is readable, which is how "
                        "the open test-mode rules a project is created with behave."
                    ),
                    "remediation": "Deploy firestore.rules.",
                }
            )
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "collection": self.collection,
            "rules_deployed": self.rules_deployed,
            "get_permitted": self.get_permitted,
            "list_permitted": self.list_permitted,
            # Stated rather than omitted: a reader must not infer from a report
            # about reads that writes were found to be closed.
            "write_posture": "not probed — proving it needs a write to a live system",
            "probes": [p.to_dict() for p in self.probes],
            "findings": self.findings,
        }


def document_url(project_id: str, collection: str, document_id: str) -> str:
    return f"{FIRESTORE_ROOT}/projects/{project_id}/databases/(default)/documents/{collection}/{document_id}"


def collection_url(project_id: str, collection: str, page_size: int = 1) -> str:
    return (
        f"{FIRESTORE_ROOT}/projects/{project_id}/databases/(default)/documents/"
        f"{collection}?pageSize={page_size}"
    )


def _permitted(status_code: int) -> bool:
    """Whether the rules allowed the operation.

    Anything other than a refusal is treated as permitted, including a 404: the
    document was allowed to be looked for. A 401 is grouped with 403 because
    both mean the caller was turned away rather than served.
    """
    return status_code not in (401, 403)


def check_exposure(
    probe: HttpProbe,
    project_id: str,
    collection: str = "scans",
) -> ExposureReport:
    """Ask the live project the three questions and report what it said."""
    report = ExposureReport(project_id=project_id, collection=collection)
    for name, url in (
        ("get_absent_document", document_url(project_id, collection, ABSENT_DOCUMENT_ID)),
        ("list_collection", collection_url(project_id, collection)),
        (
            "get_unused_collection",
            document_url(project_id, UNUSED_COLLECTION, ABSENT_DOCUMENT_ID),
        ),
    ):
        status_code = probe(url)
        report.probes.append(
            Probe(
                name=name,
                url=url,
                status_code=status_code,
                permitted=_permitted(status_code),
            )
        )
    return report
