"""Subdomain takeover verification, driven entirely off injected lookups.

The module's whole value is the distinction between "this record leads nowhere"
and "somebody else can claim what it leads to", so most of these tests are about
not getting that distinction wrong in either direction: a NODATA destination
reported as a takeover is a false alarm that costs a client's trust, and an
NXDOMAIN destination reported as absence is the real finding going unreported.

Nothing here resolves a real name.
"""

from __future__ import annotations

import pytest
from modules import alias_takeover
from modules._dns import resolution, zone_apex
from modules.alias_takeover import AliasTakeover
from targets import parse_targets


def one(value: str):
    return parse_targets([value])[0]


class FakeDns:
    """A tiny authoritative-ish fixture.

    `records` maps (name, rtype) to a list of values. A name absent from every
    rtype is NXDOMAIN; a name present under some other rtype but not the one
    asked for is NODATA. That is the same shape the real resolver reports, and
    getting it right here is what makes the NODATA-vs-NXDOMAIN tests meaningful.
    """

    def __init__(
        self,
        records: dict[tuple[str, str], list[str]],
        failing: set[str] | None = None,
        negatives: str = "nxdomain",
    ):
        self.records = {(n.lower(), t.upper()): v for (n, t), v in records.items()}
        self.failing = {n.lower() for n in (failing or set())}
        self.names = {n for (n, _) in self.records}
        #: How this resolver reports a name that does not exist. The default is
        #: correct; the other values are the non-conformant resolvers that were
        #: actually met in the wild and that the control probe exists to catch.
        self.negatives = negatives

    def query(self, _res, name, rtype):
        return list(self.records.get((name.lower(), rtype.upper()), []))

    def resolution(self, _res, name, rtype="A"):
        key = name.lower()
        if key in self.failing:
            return "error", []
        values = self.records.get((key, rtype.upper()))
        if values:
            return "ok", list(values)
        if key in self.names:
            return "nodata", []
        if self.negatives == "wildcard":
            return "ok", ["192.0.2.254"]
        return self.negatives, []


def install(monkeypatch, dns: FakeDns, candidates: set[str]):
    monkeypatch.setattr(alias_takeover, "make_resolver", lambda *a, **k: object())
    monkeypatch.setattr(alias_takeover, "query", dns.query)
    monkeypatch.setattr(alias_takeover, "resolution", dns.resolution)
    monkeypatch.setattr(alias_takeover, "_crtsh_names", lambda *a, **k: (set(candidates), "ok"))
    monkeypatch.setattr(alias_takeover, "_default_session", lambda: object())
    # zone_apex is imported into the module and calls the *module-level*
    # resolution it closed over at import time, so it is stubbed by hand.
    monkeypatch.setattr(
        alias_takeover,
        "zone_apex",
        lambda _res, name: _apex(dns, name),
    )


def _apex(dns: FakeDns, name: str) -> str:
    labels = name.rstrip(".").split(".")
    for cut in range(len(labels) - 1):
        candidate = ".".join(labels[cut:])
        if dns.resolution(None, candidate, "SOA")[0] == "ok":
            return candidate
    return ""


def run(monkeypatch, dns: FakeDns, candidates: set[str], root: str = "example.com"):
    install(monkeypatch, dns, candidates)
    return AliasTakeover().run(one(root), {"use_certificate_transparency": True})


def by_asset(findings, asset):
    return [f for f in findings if f.asset == asset and f.severity != "info"]


# ── the motivating case, in the shape it was actually found ──────────────────


def test_a_dynamic_dns_destination_is_a_confirmed_claimable_takeover(monkeypatch):
    """vpn.<domain> -> <name>.mynetgear.com, NXDOMAIN, parent served by a
    self-service provider. This is the live finding on our own domain."""
    dns = FakeDns(
        {
            ("vpn.example.com", "CNAME"): ["icit.mynetgear.com."],
            ("mynetgear.com", "SOA"): ["ns2.no-ip.com. x. 1 2 3 4 5"],
        }
    )
    findings = run(monkeypatch, dns, {"vpn.example.com"})
    found = by_asset(findings, "vpn.example.com")
    assert len(found) == 1
    f = found[0]
    assert f.severity == "critical"
    assert f.confidence == "confirmed"
    assert f.evidence["verdict"] == "claimable_service"
    assert f.evidence["service"]["zone"] == "mynetgear.com"
    assert "mynetgear.com" in f.remediation


def test_the_same_destination_on_an_untrusted_label_is_a_step_lower(monkeypatch):
    """A takeover of `blog` is an embarrassment; of `vpn`, a credential
    harvester. Same mechanism, different consequence, and the severity says so."""
    dns = FakeDns(
        {
            ("blog.example.com", "CNAME"): ["gone.mynetgear.com."],
            ("mynetgear.com", "SOA"): ["ns2.no-ip.com. x. 1 2 3 4 5"],
        }
    )
    f = by_asset(run(monkeypatch, dns, {"blog.example.com"}), "blog.example.com")[0]
    assert f.severity == "high"
    assert f.confidence == "confirmed"
    assert f.evidence["verdict"] == "claimable_service"


# ── the two mistakes that matter ─────────────────────────────────────────────


def test_a_destination_that_exists_without_an_address_is_not_a_takeover(monkeypatch):
    """NODATA. Somebody owns the destination; it simply publishes no address.
    Reporting this as claimable is a false alarm on a registered name."""
    dns = FakeDns(
        {
            ("www.example.com", "CNAME"): ["parked.partner.example.net."],
            ("parked.partner.example.net", "TXT"): ["v=spf1 -all"],
        }
    )
    f = by_asset(run(monkeypatch, dns, {"www.example.com"}), "www.example.com")[0]
    assert f.evidence["verdict"] == "no_address"
    assert f.severity == "low"
    assert "takeover" in f.detail


def test_a_failed_lookup_is_inconclusive_rather_than_either_answer(monkeypatch):
    """A timeout is not a pass and not a finding. Folding it into NXDOMAIN would
    invent takeovers every time a resolver had a bad minute."""
    dns = FakeDns(
        {("api.example.com", "CNAME"): ["backend.partner.example.net."]},
        failing={"backend.partner.example.net"},
    )
    findings = run(monkeypatch, dns, {"api.example.com"})
    row = [f for f in findings if f.asset == "api.example.com"][0]
    assert row.evidence["verdict"] == "unresolved"
    assert row.confidence == "inconclusive"
    assert row.severity == "info"


# ── the strongest case ───────────────────────────────────────────────────────


def test_an_unregistered_destination_domain_is_critical(monkeypatch):
    """No ancestor of the destination is registered, so the domain itself is
    available. This is the worst of the four verdicts and needs no provider."""
    dns = FakeDns({("shop.example.com", "CNAME"): ["store.abandoned-brand.com."]})
    f = by_asset(run(monkeypatch, dns, {"shop.example.com"}), "shop.example.com")[0]
    assert f.severity == "critical"
    assert f.confidence == "confirmed"
    assert f.evidence["verdict"] == "unregistered_domain"
    assert "certificate" in f.detail


# ── honest limits ────────────────────────────────────────────────────────────


def test_an_unknown_parent_zone_is_reported_as_unproven_not_as_safe(monkeypatch):
    """Dangling under a registered zone that is not a known self-service
    platform. The record still leads nowhere — but we have not established that
    an outsider could claim it, and the finding says so rather than either
    dropping it or overstating it."""
    dns = FakeDns(
        {
            ("old.example.com", "CNAME"): ["gone.partner-corp.example.net."],
            ("partner-corp.example.net", "SOA"): ["ns1.partner-corp.example.net. x. 1 2 3 4 5"],
        }
    )
    f = by_asset(run(monkeypatch, dns, {"old.example.com"}), "old.example.com")[0]
    assert f.evidence["verdict"] == "dangling"
    assert f.confidence == "possible"
    assert f.severity == "medium"
    assert "has not been" in f.detail


def test_a_trusted_label_raises_an_unproven_dangling_record(monkeypatch):
    dns = FakeDns(
        {
            ("sso.example.com", "CNAME"): ["gone.partner-corp.example.net."],
            ("partner-corp.example.net", "SOA"): ["ns1.partner-corp.example.net. x. 1 2 3 4 5"],
        }
    )
    f = by_asset(run(monkeypatch, dns, {"sso.example.com"}), "sso.example.com")[0]
    assert f.severity == "high"
    assert f.confidence == "possible"


def test_an_alias_that_resolves_produces_no_finding(monkeypatch):
    dns = FakeDns(
        {
            ("www.example.com", "CNAME"): ["edge.cdn.example.net."],
            ("edge.cdn.example.net", "A"): ["192.0.2.10"],
        }
    )
    findings = run(monkeypatch, dns, {"www.example.com"})
    assert by_asset(findings, "www.example.com") == []
    checked = [f for f in findings if f.title == "Alias destinations checked"][0]
    rows = [r for r in checked.evidence["checked"] if r["host"] == "www.example.com"]
    assert rows[0]["verdict"] == "resolves"
    assert rows[0]["addresses"] == ["192.0.2.10"]


def test_a_domain_with_no_aliases_at_all_produces_nothing(monkeypatch):
    dns = FakeDns({("example.com", "A"): ["192.0.2.1"]})
    assert run(monkeypatch, dns, set()) == []


# ── provider matching ────────────────────────────────────────────────────────


def test_a_regional_provider_subzone_still_matches_its_parent(monkeypatch):
    """Providers serve customers from per-region zones. The claim mechanism
    belongs to the parent, so matching only the exact apex would miss them."""
    dns = FakeDns(
        {
            ("assets.example.com", "CNAME"): ["bucket.s3.eu-west-1.amazonaws.com."],
            ("s3.eu-west-1.amazonaws.com", "SOA"): ["ns.aws.example. x. 1 2 3 4 5"],
        }
    )
    f = by_asset(run(monkeypatch, dns, {"assets.example.com"}), "assets.example.com")[0]
    assert f.evidence["verdict"] == "claimable_service"
    assert f.evidence["service"]["zone"] == "amazonaws.com"


def test_a_platform_needing_an_account_is_high_not_critical(monkeypatch):
    """Open signup is what separates "anyone, this afternoon" from "a customer
    of the same provider". Both are findings; only one is critical."""
    dns = FakeDns(
        {
            ("secure.example.com", "CNAME"): ["client.myshopify.com."],
            ("myshopify.com", "SOA"): ["ns1.shopify.example. x. 1 2 3 4 5"],
        }
    )
    f = by_asset(run(monkeypatch, dns, {"secure.example.com"}), "secure.example.com")[0]
    assert f.evidence["service"]["open"] is False
    assert f.severity == "high"


# ── reporting contract ───────────────────────────────────────────────────────


def test_every_actionable_finding_states_what_to_do(monkeypatch):
    dns = FakeDns(
        {
            ("vpn.example.com", "CNAME"): ["a.mynetgear.com."],
            ("mynetgear.com", "SOA"): ["ns2.no-ip.com. x. 1 2 3 4 5"],
            ("shop.example.com", "CNAME"): ["b.abandoned-brand.com."],
            ("old.example.com", "CNAME"): ["c.partner-corp.example.net."],
            ("partner-corp.example.net", "SOA"): ["ns1.partner-corp.example.net. x. 1 2 3 4 5"],
        }
    )
    findings = run(monkeypatch, dns, {"vpn.example.com", "shop.example.com", "old.example.com"})
    actionable = [f for f in findings if f.severity != "info"]
    assert len(actionable) == 3
    for f in actionable:
        assert f.remediation
        assert f.category == "dns"
        assert f.asset != f.target


def test_the_fingerprint_is_stable_while_the_verdict_holds(monkeypatch):
    """Change detection depends on this: a host that stays dangling week after
    week is one finding, not a new one every scan."""
    dns = FakeDns(
        {
            ("vpn.example.com", "CNAME"): ["a.mynetgear.com."],
            ("mynetgear.com", "SOA"): ["ns2.no-ip.com. x. 1 2 3 4 5"],
        }
    )
    first = by_asset(run(monkeypatch, dns, {"vpn.example.com"}), "vpn.example.com")[0]
    second = by_asset(run(monkeypatch, dns, {"vpn.example.com"}), "vpn.example.com")[0]
    assert first.fingerprint() == second.fingerprint()


def test_a_worsening_verdict_is_a_different_finding(monkeypatch):
    """dangling -> claimable is a genuine change of what is true, and should not
    be silently absorbed into the previous finding."""
    dangling = FakeDns(
        {
            ("vpn.example.com", "CNAME"): ["a.partner-corp.example.net."],
            ("partner-corp.example.net", "SOA"): ["ns1.partner-corp.example.net. x. 1 2 3 4 5"],
        }
    )
    claimable = FakeDns(
        {
            ("vpn.example.com", "CNAME"): ["a.mynetgear.com."],
            ("mynetgear.com", "SOA"): ["ns2.no-ip.com. x. 1 2 3 4 5"],
        }
    )
    a = by_asset(run(monkeypatch, dangling, {"vpn.example.com"}), "vpn.example.com")[0]
    b = by_asset(run(monkeypatch, claimable, {"vpn.example.com"}), "vpn.example.com")[0]
    assert a.fingerprint() != b.fingerprint()


# ── authorization posture ────────────────────────────────────────────────────


def test_the_module_never_contacts_the_scanned_host():
    """Recursive resolvers only. If this ever became `direct` the CLI would
    demand an authorization acknowledgement, and it should not need one."""
    assert AliasTakeover().contact == "dns"


def test_the_description_is_client_safe():
    text = AliasTakeover().description.lower()
    assert "takeover" not in text or "claim" in text
    for tool in ("nuclei", "zap", "subjack", "amass", "subfinder", "dnsrecon"):
        assert tool not in text


# ── the lookup helpers the module depends on ─────────────────────────────────


class Raiser:
    def __init__(self, exc):
        self.exc = exc

    def resolve(self, *_a, **_k):
        raise self.exc


def test_resolution_separates_the_three_ways_a_lookup_returns_nothing():
    import dns.resolver

    assert resolution(Raiser(dns.resolver.NXDOMAIN()), "x.example")[0] == "nxdomain"
    assert resolution(Raiser(dns.resolver.NoAnswer()), "x.example")[0] == "nodata"
    assert resolution(Raiser(TimeoutError("slow")), "x.example")[0] == "error"


def test_resolution_returns_the_values_on_success():
    class Ok:
        def resolve(self, *_a, **_k):
            return ['"192.0.2.1"']

    status, values = resolution(Ok(), "x.example")
    assert (status, values) == ("ok", ["192.0.2.1"])


@pytest.mark.parametrize(
    ("zones", "name", "expected"),
    [
        ({"mynetgear.com"}, "icit.mynetgear.com", "mynetgear.com"),
        ({"example.net", "sub.example.net"}, "a.sub.example.net", "sub.example.net"),
        (set(), "gone.abandoned-brand.com", ""),
    ],
)
def test_zone_apex_finds_the_closest_enclosing_zone(zones, name, expected):
    class Res:
        def resolve(self, n, _rtype):
            import dns.resolver

            if n.rstrip(".") in zones:
                return ["soa"]
            raise dns.resolver.NXDOMAIN()

    assert zone_apex(Res(), name) == expected


def test_zone_apex_never_answers_with_a_bare_tld():
    """A TLD always has an SOA, so a naive walk would report "claim .com" for
    every unregistered domain — which is not an answer anybody can act on, and
    would hide the unregistered-domain verdict behind a bogus apex."""

    class OnlyTheTld:
        def resolve(self, name, _rtype):
            import dns.resolver

            if name.rstrip(".") == "com":
                return ["soa"]
            raise dns.resolver.NXDOMAIN()

    assert zone_apex(OnlyTheTld(), "gone.abandoned-brand.com") == ""


# ── cross-module cooperation ─────────────────────────────────────────────────


def test_discovery_work_is_shared_with_the_inventory_module(monkeypatch):
    """Both modules need the same candidate set. Whichever runs first pays for
    certificate transparency; the second reuses it rather than asking again."""
    calls = []
    dns = FakeDns({("vpn.example.com", "CNAME"): ["a.mynetgear.com."]})

    def counting_crtsh(*_a, **_k):
        calls.append(1)
        return {"vpn.example.com"}, "ok"

    install(monkeypatch, dns, set())
    monkeypatch.setattr(alias_takeover, "_crtsh_names", counting_crtsh)

    ctx: dict = {}
    AliasTakeover().run(one("example.com"), ctx)
    AliasTakeover().run(one("example.com"), ctx)
    assert len(calls) == 1
    assert ctx["alias_candidates"]["root"] == "example.com"


def test_a_cache_for_another_domain_is_not_reused(monkeypatch):
    """Scanning two domains in one run must not answer the second with the
    first one's host list."""
    dns = FakeDns({("vpn.other.test", "CNAME"): ["a.mynetgear.com."]})
    install(monkeypatch, dns, {"vpn.other.test"})
    ctx = {
        "alias_candidates": {"root": "somewhere-else.test", "names": ["www.somewhere-else.test"]}
    }
    AliasTakeover().run(one("other.test"), ctx)
    assert ctx["alias_candidates"]["root"] == "other.test"


# ── the control probe: verify the instrument before trusting the measurement ──


def test_a_resolver_that_hides_nxdomain_makes_every_verdict_inconclusive(monkeypatch):
    """The defect this control exists for. A resolver that answers NODATA for
    names that do not exist would turn a live, claimable takeover into "a broken
    record, not a risk" — a false negative on the most serious thing the module
    reports. It must refuse to conclude instead."""
    dns = FakeDns(
        {
            ("vpn.example.com", "CNAME"): ["icit.mynetgear.com."],
            ("mynetgear.com", "SOA"): ["ns2.no-ip.com. x. 1 2 3 4 5"],
        },
        negatives="nodata",
    )
    findings = run(monkeypatch, dns, {"vpn.example.com"})
    row = [f for f in findings if f.asset == "vpn.example.com"][0]
    assert row.evidence["verdict"] == "unresolved"
    assert row.confidence == "inconclusive"
    assert "NXDOMAIN" in row.evidence["reason"] or "NXDOMAIN" in row.detail
    # And it must not be mistaken for a clean result.
    assert "not a pass" in row.detail


def test_a_wildcard_zone_cannot_prove_absence(monkeypatch):
    """Every name under a wildcard zone resolves, so the absence of the
    destination cannot be established from DNS at all."""
    dns = FakeDns(
        {("old.example.com", "CNAME"): ["gone.wildcarded.example.net."]},
        negatives="wildcard",
    )
    findings = run(monkeypatch, dns, {"old.example.com"})
    # The destination itself resolves under the wildcard, so there is no
    # takeover finding — and, correctly, no claim about claimability either.
    assert by_asset(findings, "old.example.com") == []
    checked = [f for f in findings if f.title == "Alias destinations checked"][0]
    row = [r for r in checked.evidence["checked"] if r["host"] == "old.example.com"][0]
    assert row["verdict"] == "resolves"


def test_a_genuine_nodata_still_reads_as_no_address_when_the_control_passes(monkeypatch):
    """The control must not make the module useless: with a faithful resolver,
    NODATA still means what it says."""
    dns = FakeDns(
        {
            ("www.example.com", "CNAME"): ["parked.partner.example.net."],
            ("parked.partner.example.net", "TXT"): ["v=spf1 -all"],
        }
    )
    f = by_asset(run(monkeypatch, dns, {"www.example.com"}), "www.example.com")[0]
    assert f.evidence["verdict"] == "no_address"


def test_the_control_is_probed_once_per_destination_zone(monkeypatch):
    """One extra lookup per distinct destination parent, not one per alias."""
    probed = []

    dns = FakeDns(
        {
            ("a.example.com", "CNAME"): ["one.mynetgear.com."],
            ("b.example.com", "CNAME"): ["two.mynetgear.com."],
            ("mynetgear.com", "SOA"): ["ns2.no-ip.com. x. 1 2 3 4 5"],
        }
    )
    real = dns.resolution

    def counting(res, name, rtype="A"):
        if name.startswith("dnsguard-control-"):
            probed.append(name)
        return real(res, name, rtype)

    install(monkeypatch, dns, {"a.example.com", "b.example.com"})
    monkeypatch.setattr(alias_takeover, "resolution", counting)
    findings = AliasTakeover().run(one("example.com"), {})

    assert len(probed) == 1
    assert probed[0].endswith(".mynetgear.com")
    assert len(by_asset(findings, "a.example.com")) == 1
    assert len(by_asset(findings, "b.example.com")) == 1


def test_the_control_name_is_unguessable(monkeypatch):
    """A fixed control label could be registered by somebody who read this
    source, which would defeat the check on exactly the zones it matters for."""
    seen = []

    dns = FakeDns(
        {
            ("vpn.example.com", "CNAME"): ["icit.mynetgear.com."],
            ("mynetgear.com", "SOA"): ["ns2.no-ip.com. x. 1 2 3 4 5"],
        }
    )
    real = dns.resolution

    def capturing(res, name, rtype="A"):
        if name.startswith("dnsguard-control-"):
            seen.append(name)
        return real(res, name, rtype)

    for _ in range(2):
        install(monkeypatch, dns, {"vpn.example.com"})
        monkeypatch.setattr(alias_takeover, "resolution", capturing)
        AliasTakeover().run(one("example.com"), {})

    assert len(seen) == 2
    assert seen[0] != seen[1]


def test_a_lookup_error_is_still_distinguished_from_an_untrustworthy_resolver(monkeypatch):
    """Both are inconclusive, but they need different remediation, so the reason
    is recorded rather than flattened."""
    dns = FakeDns(
        {("api.example.com", "CNAME"): ["backend.partner.example.net."]},
        failing={"backend.partner.example.net"},
    )
    row = [f for f in run(monkeypatch, dns, {"api.example.com"}) if f.asset == "api.example.com"][0]
    assert row.evidence["reason"] == "lookup did not complete"


# ── discovery coverage: a clean result over a smaller surface ────────────────


def test_a_failed_certificate_transparency_lookup_is_reported_not_swallowed(monkeypatch):
    """The gap this exists for: crt.sh not answering halves the discovered
    surface and used to produce an identical clean result. A check that passes
    without having checked is the failure mode this whole module is written
    against."""
    dns = FakeDns({("vpn.example.com", "CNAME"): ["a.mynetgear.com."]})
    install(monkeypatch, dns, set())
    monkeypatch.setattr(alias_takeover, "_crtsh_names", lambda *a, **k: (set(), "unavailable"))

    findings = AliasTakeover().run(one("example.com"), {})
    summary = [f for f in findings if f.title == "Alias destinations checked"][0]
    assert summary.evidence["coverage"]["certificate_transparency"] == "unavailable"
    assert "certificate transparency was unavailable" in summary.detail


def test_a_reduced_sweep_lowers_the_confidence_of_the_clean_result(monkeypatch):
    """A clean result over a reduced surface is a smaller claim than a clean
    result over the full one, and must not read as the same one."""
    dns = FakeDns({("vpn.example.com", "CNAME"): ["a.mynetgear.com."]})
    install(monkeypatch, dns, set())
    monkeypatch.setattr(alias_takeover, "_crtsh_names", lambda *a, **k: (set(), "unavailable"))
    findings = AliasTakeover().run(one("example.com"), {})
    assert [f for f in findings if f.title == "Alias destinations checked"][0].confidence == (
        "possible"
    )


def test_a_full_sweep_is_reported_as_confirmed(monkeypatch):
    dns = FakeDns({("vpn.example.com", "CNAME"): ["a.mynetgear.com."]})
    findings = run(monkeypatch, dns, {"vpn.example.com"})
    summary = [f for f in findings if f.title == "Alias destinations checked"][0]
    assert summary.confidence == "confirmed"
    assert summary.evidence["coverage"]["certificate_transparency"] == "ok"


def test_declining_certificate_transparency_is_not_the_same_as_it_failing(monkeypatch):
    """Opting out is a choice the operator made; failing is a gap they did not
    ask for. Conflating them would either nag about a deliberate setting or hide
    a real degradation."""
    dns = FakeDns({("vpn.example.com", "CNAME"): ["a.mynetgear.com."]})
    install(monkeypatch, dns, set())
    findings = AliasTakeover().run(one("example.com"), {"use_certificate_transparency": False})
    summary = [f for f in findings if f.title == "Alias destinations checked"][0]
    assert summary.evidence["coverage"]["certificate_transparency"] == "not requested"
    assert summary.confidence == "confirmed"
