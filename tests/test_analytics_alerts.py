"""Analytics aggregation, posture scoring, and alert-rule behaviour."""

from __future__ import annotations

import pytest
from base import Finding

from dnsguard.alerts import AlertRule, AlertService, compute_metrics, default_rules
from dnsguard.analytics import QueryEvent, event_from_decision, score, summarise, timeseries
from dnsguard.audit import AuditLog
from dnsguard.clock import FrozenClock
from dnsguard.errors import NotFoundError, ValidationError
from dnsguard.policy import Decision
from dnsguard.store import MemoryStore


def event(name, action, site="hq", ts="2026-01-01T00:00:00Z", **kwargs):
    return QueryEvent(
        timestamp=ts, tenant_id="acme", site_id=site, name=name, action=action, **kwargs
    )


@pytest.fixture
def clock():
    return FrozenClock()


@pytest.fixture
def alerts(clock):
    store = MemoryStore()
    return AlertService(store=store, audit=AuditLog(store, clock), clock=clock)


# ── query analytics ──────────────────────────────────────────────────────────


def test_an_empty_stream_summarises_without_dividing_by_zero():
    stats = summarise([])
    assert stats["total_queries"] == 0
    assert stats["block_rate"] == 0.0
    assert stats["top_blocked_names"] == []


def test_block_rate_and_action_split():
    events = [
        event("a.example", "block"),
        event("b.example", "allow"),
        event("c.example", "allow"),
        event("d.example", "monitor"),
    ]
    stats = summarise(events)
    assert stats["total_queries"] == 4
    assert stats["blocked"] == 1
    assert stats["block_rate"] == 0.25
    assert stats["by_action"] == {"block": 1, "allow": 2, "monitor": 1}


def test_top_blocked_names_are_ranked():
    events = [event("evil.example", "block") for _ in range(3)]
    events += [event("phish.example", "block") for _ in range(2)]
    events.append(event("clean.example", "allow"))
    assert summarise(events)["top_blocked_names"] == [
        {"key": "evil.example", "count": 3},
        {"key": "phish.example", "count": 2},
    ]


def test_unique_counts_do_not_double_count_repeat_lookups():
    events = [event("evil.example", "block") for _ in range(5)]
    stats = summarise(events)
    assert stats["blocked"] == 5
    assert stats["unique_blocked_names"] == 1


def test_suppressed_blocks_are_counted_separately():
    """What monitor mode and staleness are holding back — the number an operator
    needs before switching enforcement on."""
    events = [
        event("a.example", "monitor", degraded_from="block"),
        event("b.example", "monitor", degraded_from="block"),
        event("c.example", "monitor"),
    ]
    assert summarise(events)["would_block"] == 2


def test_slicing_by_site_feed_and_category():
    events = [
        event("a.example", "block", site="hq", feed_id="icit-malware", category="malware"),
        event("b.example", "block", site="branch", feed_id="icit-malware", category="malware"),
        event("c.example", "block", site="hq", feed_id="community", category="phishing"),
        event("d.example", "allow", site="hq"),
    ]
    stats = summarise(events)
    assert stats["blocked_by_site"] == [{"key": "hq", "count": 2}, {"key": "branch", "count": 1}]
    assert stats["top_feeds"][0] == {"key": "icit-malware", "count": 2}
    assert {c["key"] for c in stats["top_categories"]} == {"malware", "phishing"}


def test_timeseries_includes_empty_buckets():
    """A gap must read as a gap on the chart, not as a quiet period."""
    events = [
        event("a.example", "block", ts="2026-01-01T00:10:00Z"),
        event("b.example", "block", ts="2026-01-01T03:10:00Z"),
    ]
    series = timeseries(events, bucket_seconds=3600)
    assert len(series) == 4
    assert [row["block"] for row in series] == [1, 0, 0, 1]


def test_timeseries_of_nothing_is_empty():
    assert timeseries([], bucket_seconds=3600) == []


def test_an_event_built_from_a_decision_keeps_its_provenance():
    decision = Decision(
        name="evil.example",
        action="block",
        reason="listed",
        rule_id="rule-1",
        matched_on="category:malware",
        provenance=[{"feed_id": "icit-malware", "category": "malware", "line_no": 2}],
    )
    built = event_from_decision(decision, "acme", "hq", "2026-01-01T00:00:00Z", client_key="k1")
    assert built.feed_id == "icit-malware"
    assert built.category == "malware"
    assert built.action == "block"
    assert built.client_key == "k1"


# ── posture scoring ──────────────────────────────────────────────────────────


def finding(module, severity, remediation=""):
    return Finding(
        module=module,
        target="example.com",
        severity=severity,
        title=f"{module} {severity}",
        detail="",
        evidence={"remediation": remediation} if remediation else {},
    )


def test_a_clean_email_posture_grades_a_plus():
    findings = [finding(m, "info") for m in ("spf_audit", "dkim_audit", "dmarc_audit")]
    posture = score(findings, "example.com")
    assert posture.email_score == 100
    assert posture.email_grade == "A+"
    assert posture.risk_level == "minimal"
    assert "strong" in posture.executive_summary


def test_missing_everything_grades_f_and_scores_high_risk():
    findings = [finding(m, "high") for m in ("spf_audit", "dkim_audit", "dmarc_audit")]
    posture = score(findings, "example.com")
    assert posture.email_score == 0
    assert posture.email_grade == "F"
    assert posture.risk_score == 100
    assert posture.risk_level == "critical"
    assert "immediate attention" in posture.executive_summary


def test_partial_credit_for_a_weak_but_present_control():
    findings = [
        finding("spf_audit", "medium"),  # present, permissive
        finding("dkim_audit", "info"),  # clean
        finding("dmarc_audit", "medium"),  # monitor-only
    ]
    posture = score(findings, "example.com")
    assert 0 < posture.email_score < 100
    assert posture.email_grade in ("B", "C", "D")


def test_scoring_normalises_over_the_modules_that_actually_ran():
    """Running only the DMARC check and grading F because SPF was never looked at
    would be a lie about the domain."""
    posture = score([finding("dmarc_audit", "info")], "example.com")
    assert posture.email_score == 100
    assert posture.modules_run == ["dmarc_audit"]


def test_a_scan_with_no_email_modules_says_so_rather_than_grading_f():
    posture = score([finding("dnssec_audit", "low")], "example.com")
    assert posture.email_score == 0
    assert "not assessed" in posture.executive_summary


def test_severity_counts_are_reported_in_full():
    findings = [
        finding("spf_audit", "critical"),
        finding("dkim_audit", "high"),
        finding("dns_records", "low"),
        finding("dns_records", "info"),
    ]
    counts = score(findings).findings_by_severity
    assert counts == {"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 1}


def test_quick_wins_are_the_worst_issues_that_have_a_fix():
    findings = [
        finding("dns_records", "low", "Publish a CAA record"),
        finding("spf_audit", "critical", "Replace +all with -all"),
        finding("dkim_audit", "high", "Enable DKIM signing"),
        finding("dnssec_audit", "info"),
    ]
    assert score(findings).quick_wins == [
        "Replace +all with -all",
        "Enable DKIM signing",
        "Publish a CAA record",
    ]


def test_quick_wins_are_capped_and_deduplicated():
    findings = [finding("dns_records", "high", "Same fix") for _ in range(5)]
    assert score(findings).quick_wins == ["Same fix"]


def test_risk_never_exceeds_the_scale():
    findings = [finding("spf_audit", "critical") for _ in range(20)]
    assert score(findings).risk_score == 100


# ── alert rules ──────────────────────────────────────────────────────────────


def test_an_unknown_metric_is_rejected_at_creation_rather_than_never_firing():
    with pytest.raises(ValidationError, match="unknown metric"):
        AlertRule(tenant_id="acme", name="bad", metric="vibes", threshold=1)


def test_unknown_comparators_and_severities_are_rejected():
    with pytest.raises(ValidationError):
        AlertRule(
            tenant_id="acme", name="x", metric="blocked_count", threshold=1, comparator="approx"
        )
    with pytest.raises(ValidationError):
        AlertRule(
            tenant_id="acme", name="x", metric="blocked_count", threshold=1, severity="apocalyptic"
        )


def test_metrics_are_computed_from_the_stream_and_the_feed_health():
    events = [event("a.example", "block"), event("b.example", "allow")]
    health = [{"stale": True, "failed_fetches": 3}, {"stale": False, "failed_fetches": 0}]
    metrics = compute_metrics(events, health, expiring_exceptions=2, pending_approvals=7)
    assert metrics["blocked_count"] == 1
    assert metrics["block_rate"] == 0.5
    assert metrics["stale_feeds"] == 1
    assert metrics["failed_feed_fetches"] == 3
    assert metrics["exceptions_expiring_30d"] == 2
    assert metrics["pending_approvals"] == 7


def test_a_rule_fires_and_carries_its_evidence(alerts):
    rule = alerts.create_rule(
        AlertRule(
            tenant_id="acme",
            name="Blocking spike",
            metric="blocked_count",
            threshold=10,
            comparator="gt",
            severity="high",
        ),
        "bill",
    )
    raised = alerts.evaluate("acme", {"blocked_count": 42.0}, evidence={"top": ["evil.example"]})
    assert len(raised) == 1
    assert raised[0].rule_id == rule.id
    assert raised[0].value == 42.0
    assert raised[0].evidence == {"top": ["evil.example"]}
    assert "42" in raised[0].message and "10" in raised[0].message


def test_a_rule_below_its_threshold_stays_quiet(alerts):
    alerts.create_rule(
        AlertRule(tenant_id="acme", name="x", metric="blocked_count", threshold=10), "bill"
    )
    assert alerts.evaluate("acme", {"blocked_count": 3.0}) == []


def test_a_disabled_rule_does_not_fire(alerts):
    rule = alerts.create_rule(
        AlertRule(tenant_id="acme", name="x", metric="blocked_count", threshold=1), "bill"
    )
    alerts.set_enabled("acme", rule.id, False, "bill")
    assert alerts.evaluate("acme", {"blocked_count": 99.0}) == []


def test_a_missing_metric_does_not_fire_a_rule(alerts):
    alerts.create_rule(
        AlertRule(tenant_id="acme", name="x", metric="stale_feeds", threshold=0), "bill"
    )
    assert alerts.evaluate("acme", {"blocked_count": 99.0}) == []


def test_cooldown_stops_a_persistent_condition_alerting_repeatedly(alerts, clock):
    alerts.create_rule(
        AlertRule(
            tenant_id="acme", name="x", metric="blocked_count", threshold=1, cooldown_minutes=60
        ),
        "bill",
    )
    assert len(alerts.evaluate("acme", {"blocked_count": 99.0})) == 1
    assert alerts.evaluate("acme", {"blocked_count": 99.0}) == []
    clock.advance(61 * 60)
    assert len(alerts.evaluate("acme", {"blocked_count": 99.0})) == 1


def test_resolving_an_alert_lets_the_rule_fire_again(alerts):
    alerts.create_rule(
        AlertRule(
            tenant_id="acme", name="x", metric="blocked_count", threshold=1, cooldown_minutes=600
        ),
        "bill",
    )
    first = alerts.evaluate("acme", {"blocked_count": 99.0})[0]
    alerts.resolve("acme", first.id, "bill", "over-broad rule narrowed")
    assert len(alerts.evaluate("acme", {"blocked_count": 99.0})) == 1


def test_resolving_requires_saying_what_was_done(alerts):
    alerts.create_rule(
        AlertRule(tenant_id="acme", name="x", metric="blocked_count", threshold=1), "bill"
    )
    alert = alerts.evaluate("acme", {"blocked_count": 5.0})[0]
    with pytest.raises(ValidationError, match="what was done"):
        alerts.resolve("acme", alert.id, "bill", "")


def test_acknowledging_records_who_took_it(alerts):
    alerts.create_rule(
        AlertRule(tenant_id="acme", name="x", metric="blocked_count", threshold=1), "bill"
    )
    alert = alerts.evaluate("acme", {"blocked_count": 5.0})[0]
    acknowledged = alerts.acknowledge("acme", alert.id, "ann")
    assert acknowledged.state == "acknowledged"
    assert acknowledged.acknowledged_by == "ann"


def test_alerts_and_rules_are_per_tenant(alerts):
    alerts.create_rule(
        AlertRule(tenant_id="acme", name="x", metric="blocked_count", threshold=1), "bill"
    )
    assert alerts.evaluate("globex", {"blocked_count": 99.0}) == []
    with pytest.raises(NotFoundError):
        alerts.get("globex", "alert-nope")


def test_site_scoped_rules_only_evaluate_for_their_site(alerts):
    alerts.create_rule(
        AlertRule(
            tenant_id="acme", name="hq only", metric="blocked_count", threshold=1, scope="site:hq"
        ),
        "bill",
    )
    assert alerts.evaluate("acme", {"blocked_count": 99.0}, scope="tenant") == []
    assert len(alerts.evaluate("acme", {"blocked_count": 99.0}, scope="site:hq")) == 1


def test_every_alert_lands_on_the_audit_chain(alerts, clock):
    alerts.create_rule(
        AlertRule(tenant_id="acme", name="x", metric="blocked_count", threshold=1), "bill"
    )
    alerts.evaluate("acme", {"blocked_count": 5.0})
    actions = [r.action for r in alerts.audit.records("acme")]
    assert actions == ["alertrule.create", "alert.raise"]
    assert alerts.audit.verify("acme")["valid"] is True


def test_the_default_rule_set_is_valid_and_small():
    rules = default_rules("acme")
    assert 3 <= len(rules) <= 6, "a noisy default set teaches operators to ignore the product"
    assert all(r.description for r in rules)
    assert {r.metric for r in rules} <= set(compute_metrics([]))
