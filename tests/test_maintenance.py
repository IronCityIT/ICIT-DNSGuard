"""The periodic loop, and the persistence that makes it worth running."""

from __future__ import annotations

import pytest

from dnsguard.alerts import AlertRule, AlertService
from dnsguard.analytics import QueryEvent
from dnsguard.approvals import ApprovalGate
from dnsguard.audit import AUDIT_COLLECTION, AuditLog
from dnsguard.clock import FrozenClock
from dnsguard.exceptions_policy import ExceptionService
from dnsguard.feeds import FeedFetcher, FeedRegistry, FeedSource, FetchResponse, IndicatorIndex
from dnsguard.maintenance import MaintenanceRunner
from dnsguard.resilience import BreakerRegistry, RetryPolicy
from dnsguard.store import MemoryStore

BODY = "0.0.0.0 evil.example\n0.0.0.0 phish.example\n"


@pytest.fixture
def clock():
    return FrozenClock()


@pytest.fixture
def kit(clock):
    store = MemoryStore()
    audit = AuditLog(store, clock)
    gate = ApprovalGate(store=store, audit=audit, clock=clock)
    registry = FeedRegistry(store, clock)
    return type(
        "Kit",
        (),
        {
            "store": store,
            "audit": audit,
            "gate": gate,
            "clock": clock,
            "registry": registry,
            "exceptions": ExceptionService(store=store, audit=audit, gate=gate, clock=clock),
            "alerts": AlertService(store=store, audit=audit, clock=clock),
        },
    )


def a_feed(**kwargs):
    defaults = {
        "id": "icit-malware",
        "name": "Curated list",
        "publisher": "Iron City IT",
        "url": "https://feeds.example/m.txt",
        "category": "malware",
        "trust_tier": "vetted",
        "fmt": "hosts",
        "stale_after_seconds": 86400,
    }
    return FeedSource(**{**defaults, **kwargs})


def fetcher_for(kit, responder):
    return FeedFetcher(
        registry=kit.registry,
        fetch=responder,
        clock=kit.clock,
        breakers=BreakerRegistry(clock=kit.clock),
        policy=RetryPolicy(attempts=1, jitter=False),
    )


def runner_for(kit, fetcher=None):
    return MaintenanceRunner(
        registry=kit.registry,
        fetcher=fetcher,
        exceptions=kit.exceptions,
        alerts=kit.alerts,
        gate=kit.gate,
        audit=kit.audit,
        clock=kit.clock,
    )


# ── indicator persistence ────────────────────────────────────────────────────


def test_indicators_survive_the_process_that_fetched_them(kit):
    """Without this the index lives only in the fetching process, and a restarted
    control plane makes decisions against an empty index — which looks exactly
    like a clean lookup."""
    kit.registry.register("acme", a_feed())
    fetcher_for(kit, lambda url, etag="": FetchResponse(BODY)).refresh("acme", "icit-malware")

    reloaded = FeedRegistry(kit.store, kit.clock).load_index("acme")
    assert len(reloaded) == 2
    match = reloaded.lookup("evil.example")[0]
    assert match.indicator.line_no == 1
    assert match.provenance()["snapshot_sha256"]


def test_a_reloaded_index_still_carries_full_provenance(kit):
    kit.registry.register("acme", a_feed())
    fetcher_for(kit, lambda url, etag="": FetchResponse(BODY)).refresh("acme", "icit-malware")

    citation = kit.registry.load_index("acme").lookup("phish.example")[0].provenance()
    assert citation["feed_id"] == "icit-malware"
    assert citation["publisher"] == "Iron City IT"
    assert citation["trust_tier"] == "vetted"
    assert citation["line_no"] == 2
    assert citation["stale"] is False


def test_a_disabled_feeds_indicators_leave_the_index(kit):
    """Disabling a feed is approval-gated precisely because it changes what gets
    blocked. Leaving its entries in the index would make the act do nothing."""
    kit.registry.register("acme", a_feed())
    fetcher_for(kit, lambda url, etag="": FetchResponse(BODY)).refresh("acme", "icit-malware")
    assert len(kit.registry.load_index("acme")) == 2

    kit.registry.set_enabled("acme", "icit-malware", False, reason="licence lapsed")
    assert len(kit.registry.load_index("acme")) == 0
    assert len(kit.registry.load_index("acme", include_disabled=True)) == 2


def test_indicators_are_per_tenant(kit):
    kit.registry.register("acme", a_feed())
    fetcher_for(kit, lambda url, etag="": FetchResponse(BODY)).refresh("acme", "icit-malware")
    assert len(kit.registry.load_index("globex")) == 0


def test_an_index_with_nothing_stored_is_empty_not_broken(kit):
    index = kit.registry.load_index("acme")
    assert isinstance(index, IndicatorIndex)
    assert index.lookup("evil.example") == []


# ── conditional refresh ──────────────────────────────────────────────────────


def test_the_previous_etag_is_offered_on_the_next_refresh(kit):
    kit.registry.register("acme", a_feed())
    seen = []

    def responder(url, etag=""):
        seen.append(etag)
        return FetchResponse(BODY, etag="v1")

    fetcher = fetcher_for(kit, responder)
    fetcher.refresh("acme", "icit-malware")
    fetcher.refresh("acme", "icit-malware")
    assert seen == ["", "v1"]


def test_a_304_keeps_the_entries_and_restarts_the_freshness_clock(kit):
    """Reading an empty 304 body as "the publisher removed every entry" would
    silently drop every block the feed was supporting."""
    kit.registry.register("acme", a_feed(stale_after_seconds=3600))
    calls = {"n": 0}

    def responder(url, etag=""):
        calls["n"] += 1
        if calls["n"] == 1:
            return FetchResponse(BODY, etag="v1")
        return FetchResponse("", etag="v1", status_code=304)

    fetcher = fetcher_for(kit, responder)
    fetcher.refresh("acme", "icit-malware")
    kit.clock.advance(1800)
    snapshot, indicators = fetcher.refresh("acme", "icit-malware")

    assert snapshot.status == "unchanged"
    assert snapshot.entry_count == 2
    assert snapshot.sha256
    assert [i.value for i in indicators] == ["evil.example", "phish.example"]

    # And the feed is still considered fresh, which is the point of the 304.
    feed = kit.registry.get("acme", "icit-malware")
    assert (
        kit.registry.is_stale(feed, kit.registry.latest_snapshot("acme", "icit-malware")) is False
    )


def test_a_304_is_not_reported_as_degradation(kit):
    kit.registry.register("acme", a_feed())
    calls = {"n": 0}

    def responder(url, etag=""):
        calls["n"] += 1
        return (
            FetchResponse(BODY, etag="v1")
            if calls["n"] == 1
            else FetchResponse("", status_code=304)
        )

    fetcher = fetcher_for(kit, responder)
    fetcher.refresh_all("acme")
    result = fetcher.refresh_all("acme")
    assert result["degraded"] == []
    assert result["unchanged"] == ["icit-malware"]


def test_a_304_with_no_previous_snapshot_is_a_failure_not_a_pass(kit):
    """Nothing to fall back on means we have no entries, and saying otherwise
    would assert a list we have never actually seen."""
    kit.registry.register("acme", a_feed())
    snapshot, indicators = fetcher_for(
        kit, lambda url, etag="": FetchResponse("", status_code=304)
    ).refresh("acme", "icit-malware")
    assert snapshot.status == "failed"
    assert indicators == []


# ── the maintenance pass ─────────────────────────────────────────────────────


def test_a_clean_pass_reports_ok(kit):
    kit.registry.register("acme", a_feed())
    report = runner_for(kit, fetcher_for(kit, lambda url, etag="": FetchResponse(BODY))).run("acme")
    assert report["ok"] is True
    assert report["errors"] == []
    assert report["feeds"]["indicator_count"] == 2
    assert report["audit_chain"]["valid"] is True


def test_a_failing_feed_is_an_error_but_not_an_exception(kit):
    kit.registry.register("acme", a_feed())

    def broken(url, etag=""):
        raise ConnectionError("publisher down")

    report = runner_for(kit, fetcher_for(kit, broken)).run("acme")
    assert report["ok"] is False
    assert any("could not be refreshed" in e for e in report["errors"])
    assert report["feeds"]["degraded"] == ["icit-malware"]


def test_one_failing_feed_does_not_stop_the_others(kit):
    kit.registry.register("acme", a_feed(id="good", url="https://feeds.example/good.txt"))
    kit.registry.register("acme", a_feed(id="bad", url="https://feeds.example/bad.txt"))

    def responder(url, etag=""):
        if url.endswith("bad.txt"):
            raise ConnectionError("down")
        return FetchResponse(BODY)

    report = runner_for(kit, fetcher_for(kit, responder)).run("acme")
    assert report["feeds"]["degraded"] == ["bad"]
    assert report["feeds"]["indicator_count"] == 2


def test_a_missing_fetcher_is_an_explicit_skip_not_a_silent_pass(kit):
    report = runner_for(kit, fetcher=None).run("acme")
    assert report["feeds"]["attempted"] is False
    assert "no fetcher" in report["feeds"]["reason"]


def test_the_pass_records_lapsed_exceptions(kit):
    from dnsguard.errors import ApprovalRequiredError

    record = kit.exceptions.request("acme", "bill", "supplier.example", "temporary", ttl_days=1)
    with pytest.raises(ApprovalRequiredError) as excinfo:
        kit.exceptions.grant("acme", record.id, "bill")
    kit.gate.decide("acme", excinfo.value.request_id, "ann", approve=True)
    kit.exceptions.grant("acme", record.id, "bill", approval_id=excinfo.value.request_id)

    kit.clock.advance(2 * 24 * 3600)
    report = runner_for(kit).run("acme")
    assert report["expired_exceptions"] == [record.id]
    assert kit.exceptions.get("acme", record.id).state == "expired"


def test_the_pass_raises_alerts_for_a_stale_feed(kit):
    kit.alerts.create_rule(
        AlertRule(tenant_id="acme", name="Feed stale", metric="stale_feeds", threshold=0),
        "bill",
    )
    kit.registry.register("acme", a_feed(stale_after_seconds=1))

    def broken(url, etag=""):
        raise ConnectionError("down")

    report = runner_for(kit, fetcher_for(kit, broken)).run("acme")
    assert [a["rule_name"] for a in report["alerts"]] == ["Feed stale"]


def test_the_pass_evaluates_supplied_decision_events(kit):
    kit.alerts.create_rule(
        AlertRule(tenant_id="acme", name="Blocking spike", metric="blocked_count", threshold=1),
        "bill",
    )
    events = [
        QueryEvent(
            timestamp="2026-01-01T00:00:00Z",
            tenant_id="acme",
            site_id="hq",
            name=f"evil{n}.example",
            action="block",
        )
        for n in range(5)
    ]
    report = runner_for(kit).run("acme", events)
    assert [a["rule_name"] for a in report["alerts"]] == ["Blocking spike"]
    assert report["alerts"][0]["value"] == 5.0


def test_a_broken_audit_chain_is_the_loudest_thing_the_pass_reports(kit):
    kit.audit.append("acme", "bill", "policy.draft", "p/1", outcome="executed")
    kit.audit.append("acme", "bill", "policy.draft", "p/2", outcome="executed")
    tampered = kit.store.get("acme", AUDIT_COLLECTION, f"{1:012d}")
    tampered["actor"] = "mallory"
    kit.store.put("acme", AUDIT_COLLECTION, f"{1:012d}", tampered)

    report = runner_for(kit).run("acme")
    assert report["ok"] is False
    assert any("audit chain broken" in e for e in report["errors"])


def test_the_pass_changes_nothing_that_needs_approval(kit):
    """Refreshing, expiring and alerting are all non-disruptive by design. If a
    maintenance pass ever opened an approval request, something in it started
    changing what resolves."""
    kit.registry.register("acme", a_feed())
    runner_for(kit, fetcher_for(kit, lambda url, etag="": FetchResponse(BODY))).run("acme")
    assert kit.gate.pending("acme") == []


def test_run_all_keeps_going_when_one_tenant_fails(kit):
    kit.registry.register("acme", a_feed())
    kit.registry.register("globex", a_feed())

    def responder(url, etag=""):
        return FetchResponse(BODY)

    runner = runner_for(kit, fetcher_for(kit, responder))
    original = runner.exceptions.sweep

    def explode(tenant_id):
        if tenant_id == "acme":
            raise RuntimeError("store unavailable")
        return original(tenant_id)

    runner.exceptions.sweep = explode
    reports = runner.run_all(["acme", "globex"])
    assert [r["tenant_id"] for r in reports] == ["acme", "globex"]
    assert reports[0]["ok"] is False
    assert reports[1]["ok"] is True


def test_run_all_discovers_tenants_when_none_are_named(kit):
    kit.registry.register("acme", a_feed())
    kit.registry.register("globex", a_feed())
    reports = runner_for(kit).run_all()
    assert {r["tenant_id"] for r in reports} == {"acme", "globex"}
