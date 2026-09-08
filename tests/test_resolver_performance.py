"""Resolver performance: check the instrument before believing the measurement.

The defect this closes was the worst of the three found behind low coverage. When
every lookup failed, the module reported at **high** severity that "to most of
the internet this domain is down" — and every lookup failing is exactly what
happens when the *scanner* cannot reach 1.1.1.1 and friends, which is ordinary in
containers, in CI, and on any network that forces its own resolver.

A healthy domain was one egress rule away from being reported as down, in the
most absolute language the product uses.

Nothing here sends a query: both the benchmark and the control are injected.
"""

from __future__ import annotations

import pytest
from modules.resolver_performance import RESOLVERS, ResolverPerformance
from targets import parse_targets

HOST = "example.com"


def measurement(label, address, loss=0.0, latency=20.0):
    return {
        "resolver": label,
        "address": address,
        "queries": 15,
        "latency_avg_ms": latency,
        "latency_min_ms": latency,
        "latency_max_ms": latency,
        "loss_percent": loss,
    }


def run(results, *, answers=True):
    """`answers` decides what the control probe says: True means the resolver can
    answer for a name that certainly exists, so a failure is the domain's."""
    ordered = list(results)

    def fake_benchmark(_host, address, label, _queries):
        return next(r for r in ordered if r["address"] == address)

    control = answers if callable(answers) else (lambda _address: answers)
    return ResolverPerformance().run(
        parse_targets([HOST])[0],
        {"benchmark": fake_benchmark, "resolver_answers": control},
    )


def all_resolvers(loss=0.0, latency=20.0):
    return [measurement(label, address, loss, latency) for address, label in RESOLVERS.values()]


def titles(findings):
    return [f.title for f in findings]


def one(findings, fragment):
    matched = [f for f in findings if fragment.lower() in f.title.lower()]
    assert len(matched) == 1, f"expected one {fragment!r}, got {titles(findings)}"
    return matched[0]


# ── the defect: our egress reported as their outage ──────────────────────────


def test_a_scanner_that_cannot_reach_any_resolver_reports_nothing_about_the_domain():
    """This is the case that used to produce "to most of the internet this
    domain is down" at high severity, about a domain that was perfectly fine."""
    findings = run(all_resolvers(loss=100.0), answers=False)
    finding = one(findings, "could not be measured")
    assert finding.severity == "info"
    assert finding.confidence == "inconclusive"
    assert "says nothing about whether the domain resolves" in finding.detail
    assert not [f for f in findings if f.severity in ("high", "medium")]


def test_the_domain_is_only_called_down_when_the_resolvers_are_answering():
    """Same failing measurements, but the resolvers demonstrably answer for a
    name that exists. Now the failure really is the domain's."""
    findings = run(all_resolvers(loss=100.0), answers=True)
    finding = one(findings, "does not answer from any major resolver")
    assert finding.severity == "high"
    assert "answered for a name that certainly exists" in finding.detail


def test_resolvers_we_cannot_reach_are_excluded_rather_than_counted_against_the_domain():
    """A mixed environment: two resolvers blocked from this runner, two working
    and answering fine. The two blocked ones are not evidence of anything."""
    results = all_resolvers()
    results[0]["loss_percent"] = 100.0
    results[1]["loss_percent"] = 100.0
    blocked = {results[0]["address"], results[1]["address"]}

    findings = run(results, answers=lambda address: address not in blocked)
    assert not [f for f in findings if f.severity in ("high", "medium")]
    measured = one(findings, "performance measured")
    assert "2 did not answer this scanner and were excluded" in measured.detail


def test_a_genuine_partial_outage_is_still_reported():
    """One resolver cannot answer for the domain while answering for a name that
    exists. Visitors using it really cannot reach the client."""
    results = all_resolvers()
    results[0]["loss_percent"] = 100.0
    finding = one(run(results, answers=True), "unreachable through some major resolvers")
    assert finding.severity == "medium"
    assert "while answering for a name that certainly exists" in finding.detail


def test_the_control_is_not_consulted_for_a_resolver_that_answered():
    """A resolver that returned answers is its own proof. Asking anyway would be
    a wasted query per resolver on every scan."""
    asked = []
    run(all_resolvers(), answers=lambda address: asked.append(address) or True)
    assert asked == []


# ── the ordinary measurements ────────────────────────────────────────────────


def test_a_healthy_domain_produces_only_the_measurement():
    findings = run(all_resolvers())
    assert titles(findings) == ["Resolver performance measured"]


def test_intermittent_loss_is_reported():
    results = all_resolvers()
    results[0]["loss_percent"] = 20.0
    assert one(run(results, answers=True), "Intermittent lookup failures").severity == "low"


def test_loss_below_the_threshold_is_not_reported():
    results = all_resolvers()
    results[0]["loss_percent"] = 5.0
    assert "Intermittent lookup failures" not in titles(run(results, answers=True))


def test_slow_responses_are_reported():
    results = all_resolvers()
    results[0]["latency_avg_ms"] = 900.0
    assert one(run(results, answers=True), "Slow lookup responses").severity == "info"


def test_fast_responses_are_not_reported():
    assert "Slow lookup responses" not in titles(run(all_resolvers(latency=15.0)))


def test_the_summary_counts_only_what_was_actually_measured():
    results = all_resolvers()
    results[0]["loss_percent"] = 100.0
    blocked = {results[0]["address"]}
    measured = one(
        run(results, answers=lambda address: address not in blocked), "performance measured"
    )
    assert f"each of {len(RESOLVERS) - 1} reachable" in measured.detail


# ── shape ────────────────────────────────────────────────────────────────────


def test_every_resolver_is_measured():
    findings = run(all_resolvers())
    results = findings[-1].evidence["results"]
    assert {r["address"] for r in results} == {address for address, _ in RESOLVERS.values()}


def test_a_target_with_no_host_produces_nothing(monkeypatch):
    """The guard is on the resolved host name, not on the target object. Passing
    a bare object instead would run the real benchmark against real public
    resolvers, which is a test that quietly does live DNS."""
    from modules import resolver_performance as rp

    monkeypatch.setattr(rp, "host_of", lambda _t: "")
    assert ResolverPerformance().run(parse_targets([HOST])[0], {}) == []


@pytest.mark.parametrize("loss", [0.0, 50.0, 100.0])
def test_every_result_records_whether_it_was_usable(loss):
    results = all_resolvers(loss=loss)
    findings = run(results, answers=True)
    for result in findings[-1].evidence["results"]:
        assert "usable" in result
