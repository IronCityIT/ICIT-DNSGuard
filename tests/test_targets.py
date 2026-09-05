"""Target parsing is the input surface for every module. It has to accept every
shape a client types and normalise them into one classified list."""

from __future__ import annotations

import pytest
from targets import parse_targets


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
