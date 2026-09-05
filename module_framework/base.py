"""
base.py — the contract every module implements.

Two module TYPES, both first-class, both returning the same Finding:

  ScanModule.run(target, ctx)   — ACTIVE capabilities. Given a live target
                                  (ip, url, domain, hostname), reach out and probe.
  FileModule.ingest(file, ctx)  — PASSIVE capabilities. Given an uploaded scan
                                  export on disk, parse it into findings.

Same shape everywhere: a name, a client-safe description, the inputs it handles,
the groups it belongs to. Port existing Claude-generated logic into these — one
module per capability, no monoliths. Never bend run(target, ctx) to swallow a
file: file ingestion is its own contract (ingest) so neither side is compromised.

THREE THINGS EVERY FINDING CARRIES, and why:

  category     Groups findings across modules so a report can be organised by
               what the finding is about rather than which capability produced
               it (which is an internal name a client must never see).
  remediation  A finding without a fix is a complaint. Every non-informational
               finding states what to do about it, in the finding itself, so
               the dashboard and the report render it without a lookup table.
  fingerprint  A stable identity across scans. This is what makes change
               detection possible: the same issue on the same asset produces the
               same fingerprint next week, so diff.py can say "new", "resolved"
               or "still open" instead of re-listing everything every run.

CONTACT CLASS (`ScanModule.contact`) is the authorization control. A module
declares whether it touches the scanned host at all, and the CLI refuses to run
host-contacting modules without an explicit authorization acknowledgement.
"""

from __future__ import annotations

import hashlib
import re
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    from targets import Target

SEVERITIES = ("info", "low", "medium", "high", "critical")

#: How confident the capability is in the conclusion. `inconclusive` is a
#: first-class outcome — a check that could not complete says so rather than
#: implying a clean result.
CONFIDENCES = ("inconclusive", "possible", "likely", "confirmed")

#: What a finding is *about*. Client-facing grouping for reports and dashboards.
CATEGORIES = (
    "inventory",  # an asset was discovered / the attack surface itself
    "dns",  # naming, delegation, zone hygiene
    "email",  # sender authentication and mail routing
    "tls",  # certificates and transport security
    "http",  # web response posture
    "exposure",  # data or credentials exposed outside the estate
    "impersonation",  # lookalike domains, brand misuse
    "operational",  # a capability could not run; not a security finding
)

#: Does this capability send packets to the scanned host?
#:   passive — third-party/public sources only; the target never sees us.
#:   dns     — recursive resolvers only; still no packet to the target host.
#:   direct  — connects to the target (TLS handshake, HTTP GET). Requires an
#:             explicit authorization acknowledgement before it will run.
CONTACT_CLASSES = ("passive", "dns", "direct")

_WHITESPACE = re.compile(r"\s+")


def severity_rank(severity: str) -> int:
    """Position in SEVERITIES; used for sorting and for 'worst severity' rollups."""
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        return 0


@dataclass
class Finding:
    module: str
    target: str
    severity: str  # one of SEVERITIES
    title: str
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    # --- normalization: everything below has a default, so a module written
    # against the original four-field contract still constructs cleanly. ---
    category: str = "operational"
    remediation: str = ""
    confidence: str = "confirmed"
    #: The specific asset this is about when it is narrower than the target
    #: (a subdomain, an IP, a URL). Defaults to the target.
    asset: str = ""
    references: list[str] = field(default_factory=list)
    #: Stable identity within (module, target, asset). Set this whenever the
    #: title contains a value that changes between runs — "expires in 12 days"
    #: becomes "expires in 5 days" next week and would otherwise look like a new
    #: finding every scan. Falls back to the title when unset.
    key: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity {self.severity!r}, use one of {SEVERITIES}")
        if self.confidence not in CONFIDENCES:
            raise ValueError(f"bad confidence {self.confidence!r}, use one of {CONFIDENCES}")
        if self.category not in CATEGORIES:
            raise ValueError(f"bad category {self.category!r}, use one of {CATEGORIES}")
        if not self.asset:
            self.asset = self.target

    def fingerprint(self) -> str:
        """Stable id for this issue on this asset, across scans.

        Deliberately excludes severity, detail and evidence: a certificate that
        slips from "expires in 30 days" (medium) to "expires in 5 days" (high)
        is the *same* finding getting worse, and change detection reports it as
        a severity change rather than as one resolved and one new finding.
        """
        identity = self.key or _WHITESPACE.sub(" ", self.title).strip().lower()
        raw = f"{self.module}|{self.target}|{self.asset}|{identity}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["fingerprint"] = self.fingerprint()
        return data


@dataclass
class Asset:
    """One piece of externally-reachable attack surface.

    The inventory is a deliverable in its own right — "what of ours is on the
    internet" — so it is modelled separately from findings rather than being
    reverse-engineered out of them by the dashboard.
    """

    kind: str  # host | ip | mail_host | name_server | endpoint | certificate
    value: str
    source: str  # module that discovered it
    target: str  # scope root it was discovered under
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def identity(self) -> tuple[str, str]:
        return (self.kind, self.value.lower())

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "source": self.source,
            "target": self.target,
            "attributes": self.attributes,
            "fingerprint": hashlib.sha256(f"{self.kind}|{self.value.lower()}".encode()).hexdigest()[
                :16
            ],
        }


class AssetSink:
    """Collects assets from every module into one deduplicated inventory.

    Handed to modules on `ctx["assets"]`. Modules that discover surface append to
    it; modules that do not simply ignore it, so the ScanModule signature is
    unchanged and no existing module needed editing to keep working.
    """

    def __init__(self) -> None:
        self._by_identity: dict[tuple[str, str], Asset] = {}

    def add(self, asset: Asset) -> None:
        existing = self._by_identity.get(asset.identity)
        if existing is None:
            self._by_identity[asset.identity] = asset
            return
        # Two modules can find the same host. Merge what each learned rather
        # than letting discovery order decide which attributes survive.
        merged = dict(existing.attributes)
        merged.update(asset.attributes)
        existing.attributes = merged
        sources = {s for s in (existing.source, asset.source) if s}
        existing.source = ",".join(sorted(sources))

    def extend(self, assets: list[Asset]) -> None:
        for asset in assets:
            self.add(asset)

    @property
    def assets(self) -> list[Asset]:
        return sorted(self._by_identity.values(), key=lambda a: (a.kind, a.value))

    def to_list(self) -> list[dict[str, Any]]:
        return [a.to_dict() for a in self.assets]

    def __len__(self) -> int:
        return len(self._by_identity)


def sink_from(ctx: dict[str, Any]) -> AssetSink:
    """Get the run's asset sink, or a throwaway one when a module is run bare."""
    sink = ctx.get("assets")
    if isinstance(sink, AssetSink):
        return sink
    return AssetSink()


class ScanModule(ABC):
    # Set these on each subclass.
    name: str = ""  # short id, e.g. "port_scan"
    description: str = ""  # human-readable, client-safe (white-labeled)
    target_kinds: tuple[str, ...] = ("ip", "url", "domain", "hostname")
    groups: tuple[str, ...] = ("standard",)  # e.g. ("quick","standard","deep")
    #: Authorization class — see CONTACT_CLASSES. Default is the safe answer:
    #: a module that does not say otherwise is assumed to touch the host.
    contact: str = "direct"
    #: Default category for findings this module emits (each Finding may override).
    category: str = "operational"

    def applies_to(self, kind: str) -> bool:
        return kind in self.target_kinds

    @abstractmethod
    def run(self, target: Target, ctx: dict[str, Any]) -> list[Finding]:
        """Execute against one target. Return a list of Findings (may be empty)."""
        raise NotImplementedError


class FileModule(ABC):
    """Ingests an uploaded scan export and normalizes it into Findings.

    The passive counterpart to ScanModule. There is no live target — the input is
    a file already on disk (a vendor scan export the client uploaded). Each subclass
    wraps exactly one export format, so module selection ("ingest only these") stays
    meaningful and maps 1:1 to the dashboard, same as the active scanners.
    """

    # Set these on each subclass.
    name: str = ""  # short id, e.g. "qualys_ingest"
    description: str = ""  # human-readable, client-safe (white-labeled)
    extensions: tuple[str, ...] = ()  # lowercased, with dot: (".xml", ".csv")
    groups: tuple[str, ...] = ("ingest",)  # e.g. ("ingest","deep")
    contact: str = "passive"  # a file on disk never touches the target
    category: str = "operational"

    def accepts(self, path: Path) -> bool:
        """True if this module can, by extension, handle the file. When several
        modules accept the same extension the runtime disambiguates by content."""
        return path.suffix.lower() in self.extensions

    @abstractmethod
    def ingest(self, file: Path, ctx: dict[str, Any]) -> list[Finding]:
        """Parse one file into a list of Findings (may be empty)."""
        raise NotImplementedError
