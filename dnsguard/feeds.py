"""Threat feeds, and the provenance chain behind every indicator.

The question this module exists to answer is the one a client asks after a block
goes wrong: *why did you stop this name from resolving?* "It was on a blocklist"
is not an answer. The answer has to be a specific line, of a specific snapshot,
of a specific feed, fetched at a specific time, with a checksum proving the
content has not changed since.

So nothing here stores a bare list of domains. An Indicator carries the feed it
came from, the snapshot's sha256, and the line number within it. The snapshot
carries when it was fetched, from where, how big it was and whether the fetch
succeeded. Lookups return matches with that chain attached, and the policy layer
refuses to turn a match from a stale snapshot into a new block.

Fetching is injectable (`fetch` callable) so the whole module is testable
offline; in production it is a resilient HTTP call with a circuit breaker.
"""

from __future__ import annotations

import builtins
import hashlib
import re
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

from .clock import Clock, iso, parse_iso
from .errors import NotFoundError, ValidationError
from .resilience import BreakerRegistry, RetryPolicy, try_call
from .store import DocumentStore

FEED_COLLECTION = "feeds"
SNAPSHOT_COLLECTION = "feedsnapshots"

# How much a match from this publisher is worth. A community list is useful for
# reporting and a poor basis for blocking a client's mail provider.
TRUST_TIERS = ("authoritative", "vetted", "community", "experimental")

# What kind of harm the feed describes; drives policy category rules.
CATEGORIES = (
    "malware",
    "phishing",
    "command-and-control",
    "spam",
    "cryptomining",
    "newly-registered",
    "dynamic-dns",
    "advertising",
    "adult",
    "allowlist",
    "other",
)

FORMATS = ("domains", "hosts", "rpz", "csv")

_DOMAIN = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)
# Loopback/unspecified addresses a hosts-format feed prefixes each entry with.
_HOSTS_SINKHOLES = frozenset({"0.0.0.0", "127.0.0.1", "::", "::1", "-"})  # noqa: S104 - parsed from feed text, never bound


def is_domain(value: str) -> bool:
    return bool(_DOMAIN.match(value))


def normalise(value: str) -> str:
    return value.strip().lower().rstrip(".")


# ── model ────────────────────────────────────────────────────────────────────


@dataclass
class FeedSource:
    """A feed we are willing to consult, and the terms we consult it under."""

    id: str
    name: str
    publisher: str
    url: str
    category: str = "other"
    trust_tier: str = "community"
    fmt: str = "domains"
    license: str = "unspecified"
    refresh_interval_seconds: int = 86400
    # After this long without a successful fetch the newest snapshot is stale and
    # may no longer justify a new block. Defaults to four refresh intervals.
    stale_after_seconds: int = 4 * 86400
    enabled: bool = True
    disabled_reason: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        if self.trust_tier not in TRUST_TIERS:
            raise ValidationError(f"unknown trust tier {self.trust_tier!r}; expected {TRUST_TIERS}")
        if self.category not in CATEGORIES:
            raise ValidationError(f"unknown feed category {self.category!r}; expected {CATEGORIES}")
        if self.fmt not in FORMATS:
            raise ValidationError(f"unknown feed format {self.fmt!r}; expected {FORMATS}")
        if not self.url:
            raise ValidationError("a feed must have a source url")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FeedSnapshot:
    """One fetch of one feed. Immutable once written."""

    feed_id: str
    snapshot_id: str
    fetched_at: str
    source_url: str
    sha256: str
    entry_count: int
    byte_count: int
    status: str = "ok"  # ok | failed
    error: str = ""
    etag: str = ""
    parser: str = "domains"
    attempts: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Indicator:
    """One entry, inseparable from where it came from."""

    value: str
    feed_id: str
    snapshot_id: str
    sha256: str
    line_no: int
    category: str
    trust_tier: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Match:
    """An indicator hit, with everything needed to defend the decision."""

    query: str
    matched: str
    match_type: str  # exact | parent
    indicator: Indicator
    fetched_at: str
    stale: bool
    publisher: str
    feed_name: str

    def provenance(self) -> dict[str, Any]:
        """The citation. This is what lands in the finding and the evidence pack."""
        return {
            "query": self.query,
            "matched": self.matched,
            "match_type": self.match_type,
            "feed_id": self.indicator.feed_id,
            "feed_name": self.feed_name,
            "publisher": self.publisher,
            "category": self.indicator.category,
            "trust_tier": self.indicator.trust_tier,
            "snapshot_id": self.indicator.snapshot_id,
            "snapshot_sha256": self.indicator.sha256,
            "line_no": self.indicator.line_no,
            "fetched_at": self.fetched_at,
            "stale": self.stale,
        }


# ── parsing ──────────────────────────────────────────────────────────────────


def parse_feed(text: str, fmt: str = "domains") -> list[tuple[int, str]]:
    """(line_no, domain) pairs. Line numbers are 1-based and are part of the
    provenance chain, so they refer to the raw file including its comments."""
    if fmt not in FORMATS:
        raise ValidationError(f"unknown feed format {fmt!r}")

    out: list[tuple[int, str]] = []
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].split(";", 1)[0].strip() if fmt != "rpz" else raw.strip()
        if not line:
            continue

        if fmt == "domains":
            candidate = normalise(line.split()[0])
        elif fmt == "hosts":
            parts = line.split()
            if len(parts) < 2 or parts[0] not in _HOSTS_SINKHOLES:
                continue
            candidate = normalise(parts[1])
        elif fmt == "csv":
            candidate = normalise(line.split(",")[0].strip('"'))
        else:  # rpz
            if (
                line.startswith(("$", "@", ";"))
                or "SOA" in line
                or "\tNS\t" in line
                or " NS " in line
            ):
                continue
            candidate = normalise(line.split()[0]).lstrip("*.")

        if candidate and is_domain(candidate):
            out.append((line_no, candidate))
    return out


# ── registry and fetching ────────────────────────────────────────────────────


@dataclass
class FeedRegistry:
    """Feeds a tenant consults, and the snapshots taken of them.

    Registration and refresh are ordinary operations. Disabling a feed or moving
    its trust tier is not — both silently change what gets blocked — so those go
    through the approval gate in dnsguard.policy, not here.
    """

    store: DocumentStore
    clock: Clock = field(default_factory=Clock)

    def register(self, tenant_id: str, feed: FeedSource) -> FeedSource:
        self.store.put(tenant_id, FEED_COLLECTION, feed.id, feed.to_dict())
        return feed

    def get(self, tenant_id: str, feed_id: str) -> FeedSource:
        document = self.store.get(tenant_id, FEED_COLLECTION, feed_id)
        if document is None:
            raise NotFoundError(f"feed {feed_id} is not registered")
        return FeedSource(**document)

    def list(self, tenant_id: str, include_disabled: bool = True) -> builtins.list[FeedSource]:
        feeds = [FeedSource(**d) for d in self.store.list(tenant_id, FEED_COLLECTION)]
        return feeds if include_disabled else [f for f in feeds if f.enabled]

    def set_enabled(
        self, tenant_id: str, feed_id: str, enabled: bool, reason: str = ""
    ) -> FeedSource:
        feed = self.get(tenant_id, feed_id)
        feed.enabled = enabled
        feed.disabled_reason = "" if enabled else reason
        return self.register(tenant_id, feed)

    # ── snapshots ───────────────────────────────────────────────────────────

    def record_snapshot(self, tenant_id: str, snapshot: FeedSnapshot) -> FeedSnapshot:
        self.store.put(tenant_id, SNAPSHOT_COLLECTION, snapshot.snapshot_id, snapshot.to_dict())
        return snapshot

    def snapshots(self, tenant_id: str, feed_id: str = "") -> builtins.list[FeedSnapshot]:
        snaps = [FeedSnapshot(**d) for d in self.store.list(tenant_id, SNAPSHOT_COLLECTION)]
        if feed_id:
            snaps = [s for s in snaps if s.feed_id == feed_id]
        return sorted(snaps, key=lambda s: s.fetched_at)

    def latest_snapshot(self, tenant_id: str, feed_id: str) -> FeedSnapshot | None:
        usable = [s for s in self.snapshots(tenant_id, feed_id) if s.status == "ok"]
        return usable[-1] if usable else None

    def is_stale(self, feed: FeedSource, snapshot: FeedSnapshot | None) -> bool:
        """A feed with no successful snapshot is stale by definition."""
        if snapshot is None:
            return True
        age = (self.clock.now() - parse_iso(snapshot.fetched_at)).total_seconds()
        return age > feed.stale_after_seconds

    def health(self, tenant_id: str) -> builtins.list[dict[str, Any]]:
        """Per-feed freshness, for the dashboard and for /healthz."""
        rows = []
        for feed in sorted(self.list(tenant_id), key=lambda f: f.id):
            snapshot = self.latest_snapshot(tenant_id, feed.id)
            failures = [s for s in self.snapshots(tenant_id, feed.id) if s.status == "failed"]
            rows.append(
                {
                    "feed_id": feed.id,
                    "name": feed.name,
                    "publisher": feed.publisher,
                    "category": feed.category,
                    "trust_tier": feed.trust_tier,
                    "enabled": feed.enabled,
                    "last_success": snapshot.fetched_at if snapshot else None,
                    "entry_count": snapshot.entry_count if snapshot else 0,
                    "sha256": snapshot.sha256 if snapshot else "",
                    "stale": self.is_stale(feed, snapshot),
                    "failed_fetches": len(failures),
                }
            )
        return rows


HttpFetch = Callable[[str], "FetchResponse"]


@dataclass
class FetchResponse:
    body: str
    etag: str = ""
    status_code: int = 200


@dataclass
class FeedFetcher:
    """Pulls feeds and turns them into snapshots plus indicators.

    A failed fetch is recorded as a failed snapshot rather than thrown away: the
    dashboard has to be able to say "this feed has not updated in nine days and
    here is why", and the evidence pack has to show the gap.
    """

    registry: FeedRegistry
    fetch: HttpFetch
    clock: Clock = field(default_factory=Clock)
    breakers: BreakerRegistry = field(default_factory=BreakerRegistry)
    policy: RetryPolicy = field(default_factory=lambda: RetryPolicy(attempts=3, base_delay=1.0))

    def refresh(self, tenant_id: str, feed_id: str) -> tuple[FeedSnapshot, list[Indicator]]:
        feed = self.registry.get(tenant_id, feed_id)
        breaker = self.breakers.get(f"feed:{feed.id}")
        result = try_call(
            lambda: self.fetch(feed.url),
            policy=self.policy,
            breaker=breaker,
            clock=self.clock,
        )
        now = iso(self.clock.now())
        snapshot_id = f"{feed.id}-{now.replace(':', '').replace('-', '')}"

        if not result.ok or result.value is None:
            snapshot = FeedSnapshot(
                feed_id=feed.id,
                snapshot_id=snapshot_id,
                fetched_at=now,
                source_url=feed.url,
                sha256="",
                entry_count=0,
                byte_count=0,
                status="failed",
                error=result.error or "fetch returned nothing",
                parser=feed.fmt,
                attempts=result.attempts,
            )
            self.registry.record_snapshot(tenant_id, snapshot)
            return snapshot, []

        response: FetchResponse = result.value
        if response.status_code != 200:
            snapshot = FeedSnapshot(
                feed_id=feed.id,
                snapshot_id=snapshot_id,
                fetched_at=now,
                source_url=feed.url,
                sha256="",
                entry_count=0,
                byte_count=len(response.body),
                status="failed",
                error=f"HTTP {response.status_code}",
                parser=feed.fmt,
                attempts=result.attempts,
            )
            self.registry.record_snapshot(tenant_id, snapshot)
            return snapshot, []

        body = response.body
        sha256 = hashlib.sha256(body.encode("utf-8")).hexdigest()
        entries = parse_feed(body, feed.fmt)
        snapshot = FeedSnapshot(
            feed_id=feed.id,
            snapshot_id=snapshot_id,
            fetched_at=now,
            source_url=feed.url,
            sha256=sha256,
            entry_count=len(entries),
            byte_count=len(body.encode("utf-8")),
            status="ok",
            etag=response.etag,
            parser=feed.fmt,
            attempts=result.attempts,
        )
        self.registry.record_snapshot(tenant_id, snapshot)

        indicators = [
            Indicator(
                value=domain,
                feed_id=feed.id,
                snapshot_id=snapshot.snapshot_id,
                sha256=sha256,
                line_no=line_no,
                category=feed.category,
                trust_tier=feed.trust_tier,
            )
            for line_no, domain in entries
        ]
        return snapshot, indicators

    def refresh_all(self, tenant_id: str) -> dict[str, Any]:
        """Refresh every enabled feed. One failing feed does not stop the rest."""
        indicators: list[Indicator] = []
        results = []
        for feed in self.registry.list(tenant_id, include_disabled=False):
            snapshot, found = self.refresh(tenant_id, feed.id)
            indicators.extend(found)
            results.append(
                {
                    "feed_id": feed.id,
                    "status": snapshot.status,
                    "entries": snapshot.entry_count,
                    "error": snapshot.error,
                }
            )
        return {
            "refreshed": results,
            "indicator_count": len(indicators),
            "indicators": indicators,
            "degraded": [r["feed_id"] for r in results if r["status"] != "ok"],
        }


# ── lookup ───────────────────────────────────────────────────────────────────


class IndicatorIndex:
    """Name -> indicators, with parent-domain matching.

    A feed listing `evil.example` is understood to cover `login.evil.example`;
    that is how blocklists are meant to be read, and not doing it is the most
    common way a protective DNS product misses the thing it was pointed at. The
    match type is recorded either way, because "we blocked the parent" is a
    materially different claim from "this exact name was listed".

    The walk up stops two labels short of the root rather than consulting a
    public suffix list. That is deliberately conservative: it cannot turn one
    listed name into a match on a whole TLD, at the cost of not recognising a
    listed multi-label suffix (`example.co.uk`) as the parent of names beneath
    it. Erring towards under-matching is the right side to err on when the
    consequence of a match is a block.
    """

    def __init__(
        self,
        indicators: Iterable[Indicator] = (),
        registry: FeedRegistry | None = None,
        tenant_id: str = "",
    ) -> None:
        self._by_name: dict[str, list[Indicator]] = {}
        self._registry = registry
        self._tenant_id = tenant_id
        self._meta: dict[str, dict[str, Any]] = {}
        for indicator in indicators:
            self.add(indicator)

    def add(self, indicator: Indicator) -> None:
        self._by_name.setdefault(indicator.value, []).append(indicator)

    def __len__(self) -> int:
        return sum(len(v) for v in self._by_name.values())

    @property
    def names(self) -> set[str]:
        return set(self._by_name)

    def _feed_meta(self, feed_id: str) -> dict[str, Any]:
        """Publisher, name and current freshness for the citation.

        The feed definition and its newest snapshot are cached — neither changes
        while an index is alive. Staleness is NOT cached: it is a function of the
        clock, and an index held open across a refresh window would otherwise go
        on asserting a snapshot is fresh long after it stopped being.
        """
        if feed_id not in self._meta:
            static: dict[str, Any] = {
                "name": feed_id,
                "publisher": "unknown",
                "feed": None,
                "snapshot": None,
            }
            if self._registry is not None and self._tenant_id:
                try:
                    feed = self._registry.get(self._tenant_id, feed_id)
                except NotFoundError:
                    feed = None
                if feed is not None:
                    static = {
                        "name": feed.name,
                        "publisher": feed.publisher,
                        "feed": feed,
                        "snapshot": self._registry.latest_snapshot(self._tenant_id, feed_id),
                    }
            self._meta[feed_id] = static

        cached = self._meta[feed_id]
        feed = cached["feed"]
        snapshot = cached["snapshot"]
        stale = True
        if feed is not None and self._registry is not None:
            stale = self._registry.is_stale(feed, snapshot)
        return {
            "name": cached["name"],
            "publisher": cached["publisher"],
            "fetched_at": snapshot.fetched_at if snapshot is not None else "",
            "stale": stale,
        }

    def lookup(self, name: str, include_parents: bool = True) -> list[Match]:
        query = normalise(name)
        if not query:
            return []

        candidates: list[tuple[str, str]] = [(query, "exact")]
        if include_parents:
            labels = query.split(".")
            candidates += [(".".join(labels[i:]), "parent") for i in range(1, len(labels) - 1)]

        matches: list[Match] = []
        for candidate, match_type in candidates:
            for indicator in self._by_name.get(candidate, []):
                meta = self._feed_meta(indicator.feed_id)
                matches.append(
                    Match(
                        query=query,
                        matched=candidate,
                        match_type=match_type,
                        indicator=indicator,
                        fetched_at=str(meta["fetched_at"]),
                        stale=bool(meta["stale"]),
                        publisher=str(meta["publisher"]),
                        feed_name=str(meta["name"]),
                    )
                )
        return matches
