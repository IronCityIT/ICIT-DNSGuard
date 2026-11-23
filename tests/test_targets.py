"""Target parsing is the input surface for every module. It has to accept every
shape a client types and normalise them into one classified list."""

from __future__ import annotations

import pytest
from targets import TargetError, parse_targets


def kinds(values):
    return [(t.kind, t.value) for t in parse_targets(values)]


def test_bare_domain():
    assert kinds(["Example.COM"]) == [("domain", "example.com")]


def test_url_keeps_its_scheme():
    assert kinds(["https://app.example.com/login"]) == [("url", "https://app.example.com/login")]


def test_single_label_is_a_hostname():
    assert kinds(["fileserver"]) == [("hostname", "fileserver")]


def test_ip_address():
    assert kinds(["192.0.2.10"]) == [("ip", "192.0.2.10")]


def test_cidr_expands_to_usable_hosts():
    assert kinds(["192.0.2.0/30"]) == [("ip", "192.0.2.1"), ("ip", "192.0.2.2")]


def test_comma_list_and_dedupe():
    parsed = kinds(["example.com, example.com ,192.0.2.1"])
    assert parsed == [("domain", "example.com"), ("ip", "192.0.2.1")]


def test_file_input_strips_comments_and_blanks(tmp_path):
    path = tmp_path / "targets.txt"
    path.write_text("# header\nexample.com\n\n  192.0.2.5  # inline\n")
    parsed = [(t.kind, t.value) for t in parse_targets(files=[str(path)])]
    assert parsed == [("domain", "example.com"), ("ip", "192.0.2.5")]


def test_malformed_url_is_rejected():
    with pytest.raises(ValueError):
        parse_targets(["https:///nohost"])


def test_path_without_a_scheme_is_rejected_by_name():
    with pytest.raises(TargetError, match="example.com/login"):
        parse_targets(["example.com/login"])


@pytest.mark.parametrize("token", ["10.0.0.0/8", "192.0.0.0/15", "2001:db8::/64"])
def test_oversized_range_is_rejected_before_it_is_expanded(token):
    with pytest.raises(TargetError, match="split the range") as excinfo:
        parse_targets([token])
    assert token in str(excinfo.value)


def test_largest_allowed_range_is_accepted():
    parsed = kinds(["192.0.0.0/16"])
    assert len(parsed) == 65_534
    assert parsed[0] == ("ip", "192.0.0.1")
    assert parsed[-1] == ("ip", "192.0.255.254")


@pytest.mark.parametrize("token", ["file://localhost/etc/passwd", "ftp://example.com/x"])
def test_non_web_url_scheme_is_rejected(token):
    with pytest.raises(TargetError, match="http") as excinfo:
        parse_targets([token])
    assert token in str(excinfo.value)


def test_url_scheme_is_case_insensitive_and_value_is_unchanged():
    assert kinds(["HTTPS://example.com"]) == [("url", "HTTPS://example.com")]


@pytest.mark.parametrize("token", ["https:///nohost", "http://[::1"])
def test_unparseable_url_is_a_target_error(token):
    with pytest.raises(TargetError):
        parse_targets([token])
