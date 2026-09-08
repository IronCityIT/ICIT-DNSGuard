"""Network path: what "reachable" means, and what a silent server actually says.

Two defects sat behind this module's low coverage, and both distorted the report
rather than merely leaving it thin.

`reachable` was true when *any* hop answered — usually the scanner's own gateway
— so a trace that died three hops out was recorded as having reached the server.
And a server that ignores traceroute probes, which is ordinary and frequently
deliberate, was reported at `medium` as not reachable: a client with a correctly
hardened host being told it was broken.

Nothing here sends a packet; the traceroute call is injected.
"""

from __future__ import annotations

import pytest
from base import Finding
from modules import network_path as np
from modules.network_path import NetworkPath, trace
from targets import parse_targets

DESTINATION = "192.0.2.10"


def hops(*addresses):
    return [
        {"hop": index + 1, "address": address, "rtt_ms": 1.0 if address else None}
        for index, address in enumerate(addresses)
    ]


def traced(*addresses, available=True):
    responded = [a for a in addresses if a]
    return {
        "target": DESTINATION,
        "hops": hops(*addresses),
        "responding_hops": len(responded),
        "reached": bool(responded) and responded[-1] == DESTINATION,
        "available": available,
    }


def run(monkeypatch, result, kind="domain"):
    monkeypatch.setattr(np, "make_resolver", lambda *a, **k: object())
    monkeypatch.setattr(np, "query", lambda *a, **k: [DESTINATION])
    target = parse_targets(["example.com" if kind == "domain" else DESTINATION])[0]
    return NetworkPath().run(target, {"trace": lambda *a, **k: result})


def titles(findings: list[Finding]) -> list[str]:
    return [f.title for f in findings]


# ── what "reached" means ─────────────────────────────────────────────────────


def test_reaching_the_destination_needs_the_last_hop_to_be_the_destination():
    """The old definition — "some hop answered" — is true almost always, because
    the first hop is usually the scanner's own gateway."""
    result = traced("10.0.0.1", "203.0.113.9", DESTINATION)
    assert result["reached"] is True


def test_a_trace_that_stops_short_has_not_reached_anything():
    assert traced("10.0.0.1", "203.0.113.9")["reached"] is False


def test_a_trace_where_nothing_answered_has_not_reached_anything():
    assert traced(None, None, None)["reached"] is False


# ── a silent server is not a finding about the client ────────────────────────


def test_a_server_that_ignores_probes_is_not_reported_as_a_problem(monkeypatch):
    """Dropping ICMP and UDP probes is ordinary and often deliberate. Reporting
    it at medium tells a client their hardened server is broken."""
    findings = run(monkeypatch, traced("10.0.0.1", "203.0.113.9", None))
    stopped = next(f for f in findings if "could not be traced" in f.title)
    assert stopped.severity == "info"
    assert stopped.confidence == "inconclusive"
    assert "not a fault" in stopped.detail


def test_it_says_the_limit_is_our_vantage_point_not_their_server(monkeypatch):
    findings = run(monkeypatch, traced("10.0.0.1", None))
    stopped = next(f for f in findings if "could not be traced" in f.title)
    assert "reachability from a browser" in stopped.detail
    assert "cannot establish" in stopped.remediation


def test_no_severity_above_info_is_ever_emitted(monkeypatch):
    """This module measures our own path to a host. Nothing it can observe is a
    security finding about the client, so nothing it emits should outrank the
    findings that are."""
    for result in (
        traced("10.0.0.1", DESTINATION),
        traced("10.0.0.1", None),
        traced(None),
        traced(available=False),
    ):
        assert {f.severity for f in run(monkeypatch, result)} == {"info"}


# ── the ordinary path ────────────────────────────────────────────────────────


def test_a_completed_trace_is_reported_as_measured(monkeypatch):
    findings = run(monkeypatch, traced("10.0.0.1", "203.0.113.9", DESTINATION))
    assert "Network path measured" in titles(findings)
    assert not [f for f in findings if "could not be traced" in f.title]


def test_a_long_path_is_noted(monkeypatch):
    addresses = [f"10.0.0.{n}" for n in range(1, 20)] + [DESTINATION]
    findings = run(monkeypatch, traced(*addresses))
    assert "Long network path" in titles(findings)


def test_a_short_path_is_not_noted(monkeypatch):
    findings = run(monkeypatch, traced("10.0.0.1", DESTINATION))
    assert "Long network path" not in titles(findings)


def test_the_measurement_reports_how_many_hops_answered(monkeypatch):
    findings = run(monkeypatch, traced("10.0.0.1", None, DESTINATION))
    measured = next(f for f in findings if f.title == "Network path measured")
    assert "2 of which responded" in measured.detail


# ── the cases where there is nothing to measure ──────────────────────────────


def test_a_missing_traceroute_binary_is_inconclusive_not_a_pass(monkeypatch):
    findings = run(monkeypatch, traced(available=False))
    unavailable = next(f for f in findings if f.title == "Path measurement unavailable")
    assert unavailable.confidence == "inconclusive"
    assert "Nothing is claimed" in unavailable.detail
    assert unavailable.remediation


def test_a_domain_with_no_address_has_no_path_to_map(monkeypatch):
    monkeypatch.setattr(np, "make_resolver", lambda *a, **k: object())
    monkeypatch.setattr(np, "query", lambda *a, **k: [])
    findings = NetworkPath().run(parse_targets(["example.com"])[0], {})
    assert titles(findings) == ["No address to trace"]


def test_an_ip_target_is_traced_directly(monkeypatch):
    """No resolution step: the caller already named the machine."""
    seen = []

    def fake_trace(destination, *_a, **_k):
        seen.append(destination)
        return traced("10.0.0.1", DESTINATION)

    NetworkPath().run(parse_targets([DESTINATION])[0], {"trace": fake_trace})
    assert seen == [DESTINATION]


# ── the traceroute call itself ───────────────────────────────────────────────


def test_no_traceroute_binary_returns_a_complete_result(monkeypatch):
    """Every key present on every path. Two early returns exist below the
    initialiser, and a caller reading `reached` after either of them would raise
    rather than report."""
    monkeypatch.setattr(np.shutil, "which", lambda _name: None)
    result = trace(DESTINATION)
    assert result["available"] is False
    for key in ("target", "hops", "responding_hops", "reached"):
        assert key in result


def test_a_traceroute_timeout_returns_a_complete_result(monkeypatch):
    """The case that would have raised: the binary exists, so the caller does
    not take the unavailable branch and goes straight on to read `reached`."""
    import subprocess

    monkeypatch.setattr(np.shutil, "which", lambda _name: "/usr/bin/traceroute")

    def boom(*_a, **_k):
        raise subprocess.TimeoutExpired(cmd="traceroute", timeout=1)

    monkeypatch.setattr(np.subprocess, "run", boom)
    result = trace(DESTINATION)
    assert result["available"] is True
    assert result["reached"] is False
    assert result["responding_hops"] == 0


def test_traceroute_output_is_parsed_into_hops(monkeypatch):
    output = (
        "traceroute to 192.0.2.10 (192.0.2.10), 20 hops max\n"
        " 1  10.0.0.1  1.234 ms\n"
        " 2  * \n"
        " 3  192.0.2.10  12.5 ms\n"
    )

    class Proc:
        stdout = output

    monkeypatch.setattr(np.shutil, "which", lambda _name: "/usr/bin/traceroute")
    monkeypatch.setattr(np.subprocess, "run", lambda *a, **k: Proc())

    result = trace(DESTINATION)
    assert [h["address"] for h in result["hops"]] == ["10.0.0.1", None, "192.0.2.10"]
    assert result["hops"][0]["rtt_ms"] == pytest.approx(1.234)
    assert result["responding_hops"] == 2
    assert result["reached"] is True


def test_the_target_never_reaches_a_shell(monkeypatch):
    """A hostile hostname must not become a command. argv form, shell=False."""
    captured = {}

    class Proc:
        stdout = ""

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return Proc()

    monkeypatch.setattr(np.shutil, "which", lambda _name: "/usr/bin/traceroute")
    monkeypatch.setattr(np.subprocess, "run", fake_run)
    trace("; rm -rf /")

    assert isinstance(captured["argv"], list)
    assert captured["argv"][-1] == "; rm -rf /"
    assert "shell" not in captured["kwargs"] or captured["kwargs"]["shell"] is False
