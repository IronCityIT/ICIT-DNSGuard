"""Feed provenance.

The property under test throughout: a match can always be traced back to a
specific line of a specific snapshot with a checksum, and a snapshot that has
gone stale says so.
"""

from __future__ import annotations

import hashlib

import pytest

from dnsguard.clock import FrozenClock
from dnsguard.errors import NotFoundError, ValidationError
from dnsguard.feeds import (
    FeedFetcher,
    FeedRegistry,
    FeedSource,
    FetchResponse,
    Indicator,
    IndicatorIndex,
    is_domain,
    parse_feed,
)
from dnsguard.resilience import BreakerRegistry, RetryPolicy
from dnsguard.store import MemoryStore

HOSTS_BODY = """# Iron City test list
0.0.0.0 evil.example
0.0.0.0 phish.example
127.0.0.1 localhost
badly formatted line
0.0.0.0 not_a_domain
"""

DOMAINS_BODY = """# comment
evil.example
  phish.example  ; trailing comment

EVIL.EXAMPLE.
"""


@pytest.fixture
def clock():
    return FrozenClock()


@pytest.fixture
def registry(clock):
    return FeedRegistry(MemoryStore(), clock)


def a_feed(**kwargs) -> FeedSource:
    defaults = {
        "id": "icit-malware",
        "name": "Iron City curated malware list",
        "publisher": "Iron City IT",
        "url": "https://feeds.example/malware.txt",
        "category": "malware",
        "trust_tier": "vetted",
        "fmt": "hosts",
        "stale_after_seconds": 4 * 86400,
    }
    return FeedSource(**{**defaults, **kwargs})


# ── parsing ──────────────────────────────────────────────────────────────────


def test_hosts_format_keeps_line_numbers_from_the_raw_file():
    assert parse_feed(HOSTS_BODY, "hosts") == [(2, "evil.example"), (3, "phish.example")]


def test_hosts_format_ignores_localhost_and_malformed_entries():
    parsed = [d for _, d in parse_feed(HOSTS_BODY, "hosts")]
    assert "localhost" not in parsed
    assert "not_a_domain" not in parsed


def test_domain_format_normalises_case_and_trailing_dots():
    parsed = parse_feed(DOMAINS_BODY, "domains")
    assert parsed == [(2, "evil.example"), (3, "phish.example"), (5, "evil.example")]


def test_csv_format_takes_the_first_column_and_skips_the_header():
    """The header row is dropped because "domain" is not a domain — no format
    sniffing needed, and a mislabelled column cannot inject a junk indicator."""
    body = 'domain,first_seen\n"evil.example",2026-01-01\nphish.example,2026-01-02\n'
    assert parse_feed(body, "csv") == [(2, "evil.example"), (3, "phish.example")]


def test_rpz_format_drops_zone_machinery_and_wildcards():
    body = (
        "$TTL 300\n"
        "@ SOA localhost. root.localhost. 1 3600 900 86400 300\n"
        "  NS localhost.\n"
        "evil.example CNAME .\n"
        "*.evil.example CNAME .\n"
    )
    assert [d for _, d in parse_feed(body, "rpz")] == ["evil.example", "evil.example"]


def test_unknown_format_is_rejected():
    with pytest.raises(ValidationError):
        parse_feed("x", "yaml")


@pytest.mark.parametrize("value", ["evil.example", "a.b.c.example", "xn--80ak6aa92e.com"])
def test_valid_domains(value):
    assert is_domain(value)


@pytest.mark.parametrize("value", ["", "no-dot", "-lead.example", "a..b", "x" * 300 + ".com"])
def test_invalid_domains(value):
    assert not is_domain(value)


# ── feed definition ──────────────────────────────────────────────────────────


def test_a_feed_must_declare_a_known_tier_category_and_format():
    with pytest.raises(ValidationError):
        a_feed(trust_tier="probably-fine")
    with pytest.raises(ValidationError):
        a_feed(category="vibes")
    with pytest.raises(ValidationError):
        a_feed(fmt="yaml")
    with pytest.raises(ValidationError):
        a_feed(url="")


def test_feeds_are_per_tenant(registry):
    registry.register("acme", a_feed())
    assert registry.list("globex") == []
    with pytest.raises(NotFoundError):
        registry.get("globex", "icit-malware")


# ── fetching ─────────────────────────────────────────────────────────────────


def fetcher_for(registry, clock, responder):
    return FeedFetcher(
        registry=registry,
        fetch=responder,
        clock=clock,
        breakers=BreakerRegistry(clock=clock),
        policy=RetryPolicy(attempts=3, base_delay=0.1, jitter=False),
    )


def test_a_successful_fetch_records_a_checksummed_snapshot(registry, clock):
    registry.register("acme", a_feed())
    fetcher = fetcher_for(registry, clock, lambda url: FetchResponse(HOSTS_BODY, etag="v1"))
    snapshot, indicators = fetcher.refresh("acme", "icit-malware")

    assert snapshot.status == "ok"
    assert snapshot.sha256 == hashlib.sha256(HOSTS_BODY.encode()).hexdigest()
    assert snapshot.entry_count == 2
    assert snapshot.etag == "v1"
    assert [i.value for i in indicators] == ["evil.example", "phish.example"]
    assert all(i.sha256 == snapshot.sha256 for i in indicators)
    assert [i.line_no for i in indicators] == [2, 3]


def test_a_failed_fetch_is_recorded_not_discarded(registry, clock):
    registry.register("acme", a_feed())

    def broken(url):
        raise ConnectionError("connection reset")

    fetcher = fetcher_for(registry, clock, broken)
    snapshot, indicators = fetcher.refresh("acme", "icit-malware")

    assert snapshot.status == "failed"
    assert "connection reset" in snapshot.error
    assert indicators == []
    assert registry.snapshots("acme", "icit-malware")[-1].status == "failed"
    assert registry.latest_snapshot("acme", "icit-malware") is None


def test_a_non_200_response_is_a_failed_snapshot(registry, clock):
    registry.register("acme", a_feed())
    fetcher = fetcher_for(
        registry, clock, lambda url: FetchResponse("<html>404</html>", status_code=404)
    )
    snapshot, _ = fetcher.refresh("acme", "icit-malware")
    assert snapshot.status == "failed"
    assert snapshot.error == "HTTP 404"


def test_a_transient_failure_is_retried(registry, clock):
    registry.register("acme", a_feed())
    calls = {"n": 0}

    def flaky(url):
        calls["n"] += 1
        if calls["n"] < 3:
            raise TimeoutError("slow")
        return FetchResponse(HOSTS_BODY)

    snapshot, _ = fetcher_for(registry, clock, flaky).refresh("acme", "icit-malware")
    assert snapshot.status == "ok"
    assert snapshot.attempts == 3


def test_one_broken_feed_does_not_stop_the_others(registry, clock):
    registry.register("acme", a_feed(id="good", url="https://feeds.example/good.txt"))
    registry.register("acme", a_feed(id="bad", url="https://feeds.example/bad.txt"))

    def responder(url):
        if url.endswith("bad.txt"):
            raise ConnectionError("down")
        return FetchResponse(HOSTS_BODY)

    result = fetcher_for(registry, clock, responder).refresh_all("acme")
    assert result["degraded"] == ["bad"]
    assert result["indicator_count"] == 2


def test_disabled_feeds_are_not_fetched(registry, clock):
    registry.register("acme", a_feed())
    registry.set_enabled("acme", "icit-malware", False, reason="publisher licence lapsed")
    seen = []
    fetcher = fetcher_for(
        registry, clock, lambda url: seen.append(url) or FetchResponse(HOSTS_BODY)
    )
    result = fetcher.refresh_all("acme")
    assert seen == []
    assert result["indicator_count"] == 0
    assert registry.get("acme", "icit-malware").disabled_reason == "publisher licence lapsed"


# ── staleness ────────────────────────────────────────────────────────────────


def test_a_feed_with_no_successful_snapshot_is_stale(registry):
    feed = registry.register("acme", a_feed())
    assert registry.is_stale(feed, None) is True


def test_a_snapshot_goes_stale_after_its_declared_window(registry, clock):
    feed = registry.register("acme", a_feed(stale_after_seconds=86400))
    fetcher = fetcher_for(registry, clock, lambda url: FetchResponse(HOSTS_BODY))
    snapshot, _ = fetcher.refresh("acme", "icit-malware")

    assert registry.is_stale(feed, snapshot) is False
    clock.advance(86401)
    assert registry.is_stale(feed, snapshot) is True


def test_health_reports_freshness_and_failure_counts(registry, clock):
    registry.register("acme", a_feed(stale_after_seconds=3600))
    calls = {"n": 0}

    def responder(url):
        calls["n"] += 1
        if calls["n"] > 1:
            raise ConnectionError("down")
        return FetchResponse(HOSTS_BODY)

    fetcher = fetcher_for(registry, clock, responder)
    fetcher.refresh("acme", "icit-malware")
    clock.advance(7200)
    fetcher.refresh("acme", "icit-malware")

    row = registry.health("acme")[0]
    assert row["stale"] is True
    assert row["failed_fetches"] == 1
    assert row["entry_count"] == 2
    assert row["sha256"]


# ── lookup and provenance ────────────────────────────────────────────────────


def indexed(registry, clock, body=HOSTS_BODY, **feed_kwargs):
    registry.register("acme", a_feed(**feed_kwargs))
    fetcher = fetcher_for(registry, clock, lambda url: FetchResponse(body))
    _, indicators = fetcher.refresh("acme", feed_kwargs.get("id", "icit-malware"))
    return IndicatorIndex(indicators, registry=registry, tenant_id="acme")


def test_an_exact_match_carries_a_full_citation(registry, clock):
    index = indexed(registry, clock)
    matches = index.lookup("evil.example")

    assert len(matches) == 1
    citation = matches[0].provenance()
    assert citation["match_type"] == "exact"
    assert citation["feed_id"] == "icit-malware"
    assert citation["publisher"] == "Iron City IT"
    assert citation["line_no"] == 2
    assert citation["snapshot_sha256"] == hashlib.sha256(HOSTS_BODY.encode()).hexdigest()
    assert citation["trust_tier"] == "vetted"
    assert citation["stale"] is False
    assert citation["fetched_at"]


def test_a_listed_parent_covers_its_subdomains_and_says_so(registry, clock):
    index = indexed(registry, clock)
    matches = index.lookup("login.evil.example")
    assert len(matches) == 1
    assert matches[0].match_type == "parent"
    assert matches[0].matched == "evil.example"


def test_parent_matching_can_be_switched_off(registry, clock):
    index = indexed(registry, clock)
    assert index.lookup("login.evil.example", include_parents=False) == []


def test_a_public_suffix_is_never_treated_as_the_listed_parent(registry, clock):
    """Walking up must stop before the registrable-suffix level, or listing one
    bad .example domain would appear to list every .example domain."""
    index = indexed(registry, clock)
    assert index.lookup("unrelated.example") == []


def test_a_clean_name_matches_nothing(registry, clock):
    assert indexed(registry, clock).lookup("ironcityit.com") == []


def test_a_stale_snapshot_marks_its_matches_stale(registry, clock):
    """Freshness is evaluated at lookup time, not frozen when the index is built
    — an index held open across a refresh window must not go on claiming a
    snapshot is current."""
    index = indexed(registry, clock, stale_after_seconds=3600)
    assert index.lookup("evil.example")[0].stale is False
    clock.advance(7200)
    assert index.lookup("evil.example")[0].stale is True


def test_the_same_name_on_two_feeds_produces_two_citations(registry, clock):
    registry.register("acme", a_feed(id="feed-a", url="https://feeds.example/a.txt"))
    registry.register(
        "acme",
        a_feed(
            id="feed-b",
            url="https://feeds.example/b.txt",
            publisher="Community Project",
            trust_tier="community",
        ),
    )
    fetcher = fetcher_for(registry, clock, lambda url: FetchResponse(HOSTS_BODY))
    indicators = fetcher.refresh_all("acme")["indicators"]
    index = IndicatorIndex(indicators, registry=registry, tenant_id="acme")

    matches = index.lookup("evil.example")
    assert {m.indicator.feed_id for m in matches} == {"feed-a", "feed-b"}
    assert {m.publisher for m in matches} == {"Iron City IT", "Community Project"}


def test_an_indicator_from_an_unregistered_feed_degrades_rather_than_crashing(registry):
    orphan = Indicator(
        value="evil.example",
        feed_id="gone",
        snapshot_id="s1",
        sha256="deadbeef",
        line_no=1,
        category="malware",
        trust_tier="community",
    )
    index = IndicatorIndex([orphan], registry=registry, tenant_id="acme")
    citation = index.lookup("evil.example")[0].provenance()
    assert citation["publisher"] == "unknown"
    assert citation["stale"] is True
