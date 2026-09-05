"""Compiling a policy into resolver artifacts."""

from __future__ import annotations

import pytest

from dnsguard.clock import FrozenClock
from dnsguard.enforcement import blocked_names, compile_policy
from dnsguard.errors import ValidationError
from dnsguard.policy import PolicyVersion, Rule


def version(rules):
    return PolicyVersion(tenant_id="acme", policy_id="default", version=4, rules=rules)


def block(value, kind="domain", **kwargs):
    return Rule(
        action="block", match_kind=kind, match_value=value, justification="listed", **kwargs
    )


@pytest.fixture
def clock():
    return FrozenClock()


def test_only_explicit_names_compile_not_feed_rules():
    """Flattening a feed rule into a static file freezes a snapshot into a
    resolver config with no way to tell how old it is — the un-provenanced
    blocklist this product exists to replace."""
    rules = [
        block("evil.example"),
        block("malware", kind="category"),
        block("icit-feed", kind="feed"),
    ]
    assert blocked_names(version(rules)) == ["evil.example"]


def test_allow_and_disabled_rules_do_not_compile():
    rules = [
        block("evil.example"),
        block("off.example", enabled=False),
        Rule(action="allow", match_kind="domain", match_value="good.example"),
    ]
    assert blocked_names(version(rules)) == ["evil.example"]


def test_wildcards_compile_to_their_base_name():
    assert blocked_names(version([block("*.evil.example", kind="wildcard")])) == ["evil.example"]


def test_output_is_deterministic(clock):
    """Same version in, byte-identical artifact out — twice, and regardless of
    the order the rules happen to sit in, because a resolver config that churns
    on every compile cannot be diffed or version-controlled."""
    rules = [block("b.example"), block("a.example")]
    subject = version(rules)
    assert (
        compile_policy(subject, "rpz", clock).content
        == compile_policy(subject, "rpz", clock).content
    )

    reordered = PolicyVersion(
        tenant_id="acme", policy_id="default", version=4, rules=list(reversed(rules))
    )
    assert (
        compile_policy(subject, "rpz", clock).content.splitlines()[6:]
        == compile_policy(reordered, "rpz", clock).content.splitlines()[6:]
    )


def test_every_artifact_is_stamped_with_the_policy_that_produced_it(clock):
    """The stamp is what makes "which policy is this resolver running" answerable
    without reading the zone."""
    subject = version([block("evil.example")])
    artifact = compile_policy(subject, "rpz", clock)
    assert f"policy_hash: {artifact.policy_hash}" in artifact.content
    assert "version 4" in artifact.content
    assert artifact.policy_hash == subject.content_hash()
    assert artifact.generated_at in artifact.content


def test_rpz_blocks_the_name_and_everything_under_it(clock):
    content = compile_policy(version([block("evil.example")]), "rpz", clock).content
    assert "evil.example CNAME ." in content
    assert "*.evil.example CNAME ." in content
    assert "SOA" in content


def test_unbound_format(clock):
    content = compile_policy(version([block("evil.example")]), "unbound", clock).content
    assert content.startswith("#")
    assert 'local-zone: "evil.example" always_nxdomain' in content


def test_hosts_format(clock):
    content = compile_policy(version([block("evil.example")]), "hosts", clock).content
    assert "0.0.0.0 evil.example" in content


def test_dnsmasq_format(clock):
    content = compile_policy(version([block("evil.example")]), "dnsmasq", clock).content
    assert "address=/evil.example/" in content


def test_an_empty_policy_compiles_to_a_valid_empty_artifact(clock):
    artifact = compile_policy(version([]), "unbound", clock)
    assert artifact.rule_count == 0
    assert artifact.content.rstrip().endswith("server:")


def test_an_unknown_format_is_refused(clock):
    with pytest.raises(ValidationError, match="unknown enforcement format"):
        compile_policy(version([]), "bind9", clock)


def test_the_artifact_hash_changes_when_the_policy_does(clock):
    first = compile_policy(version([block("a.example")]), "rpz", clock)
    second = compile_policy(version([block("a.example"), block("b.example")]), "rpz", clock)
    assert first.content_hash != second.content_hash
    assert first.policy_hash != second.policy_hash
