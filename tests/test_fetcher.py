"""The production feed transport.

A feed URL is operator-supplied and the process fetching it runs inside our
network, so most of this file is about what the fetcher refuses rather than what
it retrieves.
"""

from __future__ import annotations

import pytest

from dnsguard.errors import UpstreamError, ValidationError
from dnsguard.fetcher import HttpFetcher, is_public


class FakeResponse:
    def __init__(self, status_code=200, body=b"", headers=None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}

    def iter_content(self, chunk_size=1024):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]


class FakeSession:
    """Records requests and returns canned responses, in order or by URL."""

    def __init__(self, responses):
        self.responses = responses
        self.requests = []

    def get(self, url, headers=None, timeout=None, stream=None, allow_redirects=None):
        self.requests.append(
            {"url": url, "headers": headers or {}, "allow_redirects": allow_redirects}
        )
        if isinstance(self.responses, dict):
            for fragment, response in self.responses.items():
                if fragment in url:
                    if isinstance(response, Exception):
                        raise response
                    return response
            raise AssertionError(f"no canned response for {url}")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def fetcher(responses, **kwargs):
    kwargs.setdefault("allow_private_addresses", True)  # no DNS in these tests
    return HttpFetcher(session=FakeSession(responses), **kwargs)


# ── address classification ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
    ],
)
def test_addresses_off_the_public_internet_are_rejected(address):
    import ipaddress

    assert is_public(ipaddress.ip_address(address)) is False


@pytest.mark.parametrize("address", ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700::1111"])
def test_public_addresses_are_accepted(address):
    import ipaddress

    assert is_public(ipaddress.ip_address(address)) is True


def test_the_cloud_metadata_endpoint_is_specifically_covered():
    """The one address an SSRF guard exists for. is_global alone permits it."""
    import ipaddress

    assert is_public(ipaddress.ip_address("169.254.169.254")) is False


# ── the guard ────────────────────────────────────────────────────────────────


def test_a_private_address_literal_is_refused():
    guard = HttpFetcher(session=FakeSession([]))
    with pytest.raises(ValidationError, match="not on the public internet"):
        guard.check("https://169.254.169.254/latest/meta-data/")


def test_a_loopback_url_is_refused():
    guard = HttpFetcher(session=FakeSession([]))
    with pytest.raises(ValidationError, match="not on the public internet"):
        guard.check("https://127.0.0.1:8080/admin")


def test_plain_http_is_refused_by_default():
    guard = HttpFetcher(session=FakeSession([]), allow_private_addresses=True)
    with pytest.raises(ValidationError, match="plain http"):
        guard.check("http://feeds.example/list.txt")


def test_plain_http_can_be_permitted_deliberately():
    guard = HttpFetcher(session=FakeSession([]), allow_private_addresses=True, allow_insecure=True)
    guard.check("http://feeds.example/list.txt")


@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "gopher://x/", "ftp://x/y", "/relative/path"]
)
def test_non_http_schemes_are_refused(url):
    guard = HttpFetcher(session=FakeSession([]), allow_private_addresses=True)
    with pytest.raises(ValidationError, match="must be http"):
        guard.check(url)


def test_a_url_with_no_host_is_refused():
    guard = HttpFetcher(session=FakeSession([]), allow_private_addresses=True)
    with pytest.raises(ValidationError, match="no host"):
        guard.check("https:///list.txt")


def test_an_unresolvable_host_is_an_upstream_error_not_a_pass():
    guard = HttpFetcher(session=FakeSession([]))
    with pytest.raises(UpstreamError, match="could not resolve"):
        guard.check("https://this-name-does-not-exist.invalid/list.txt")


# ── fetching ─────────────────────────────────────────────────────────────────


def test_a_successful_fetch_returns_the_body_and_etag():
    get = fetcher([FakeResponse(200, b"evil.example\n", {"ETag": "v1"})])
    response = get("https://feeds.example/list.txt")
    assert response.status_code == 200
    assert response.body == "evil.example\n"
    assert response.etag == "v1"


def test_the_previous_etag_is_sent_as_a_conditional_request():
    session = FakeSession([FakeResponse(304, b"", {"ETag": "v1"})])
    get = HttpFetcher(session=session, allow_private_addresses=True)
    response = get("https://feeds.example/list.txt", etag="v1")
    assert session.requests[0]["headers"]["If-None-Match"] == "v1"
    assert response.status_code == 304
    assert response.body == ""


def test_no_conditional_header_is_sent_without_an_etag():
    session = FakeSession([FakeResponse(200, b"x.example\n")])
    HttpFetcher(session=session, allow_private_addresses=True)("https://feeds.example/l.txt")
    assert "If-None-Match" not in session.requests[0]["headers"]


def test_a_body_over_the_cap_is_refused_rather_than_buffered():
    get = fetcher([FakeResponse(200, b"x" * 5000)], max_bytes=1000)
    with pytest.raises(UpstreamError, match="exceeded the 1000 byte limit"):
        get("https://feeds.example/huge.txt")


def test_a_body_at_the_cap_is_accepted():
    get = fetcher([FakeResponse(200, b"x" * 1000)], max_bytes=1000)
    assert len(get("https://feeds.example/list.txt").body) == 1000


def test_a_non_200_is_returned_rather_than_raised():
    """The registry turns this into a failed snapshot; raising here would lose
    the status code that explains why."""
    response = fetcher([FakeResponse(429, b"slow down")])("https://feeds.example/l.txt")
    assert response.status_code == 429
    assert response.body == ""


def test_a_transport_failure_becomes_an_upstream_error():
    get = fetcher([ConnectionResetError("reset by peer")])
    with pytest.raises(UpstreamError, match="reset by peer"):
        get("https://feeds.example/l.txt")


def test_invalid_utf8_is_replaced_rather_than_failing_the_fetch():
    response = fetcher([FakeResponse(200, b"evil.example\n\xff\xfe\n")])(
        "https://feeds.example/l.txt"
    )
    assert "evil.example" in response.body


# ── redirects ────────────────────────────────────────────────────────────────


def test_redirects_are_followed_by_hand():
    session = FakeSession(
        [
            FakeResponse(302, b"", {"Location": "https://cdn.example/list.txt"}),
            FakeResponse(200, b"evil.example\n"),
        ]
    )
    get = HttpFetcher(session=session, allow_private_addresses=True)
    assert get("https://feeds.example/list.txt").body == "evil.example\n"
    assert [r["url"] for r in session.requests] == [
        "https://feeds.example/list.txt",
        "https://cdn.example/list.txt",
    ]
    assert all(r["allow_redirects"] is False for r in session.requests)


def test_every_redirect_hop_is_re_checked():
    """The whole reason redirects are followed by hand: letting requests follow
    them would skip the address guard on every hop after the first.

    Addressed by public IP literal so the test needs no DNS — the guard is ON
    here, which is the point."""
    session = FakeSession([FakeResponse(302, b"", {"Location": "https://169.254.169.254/"})])
    get = HttpFetcher(session=session)
    with pytest.raises(ValidationError, match="not on the public internet"):
        get("https://93.184.216.34/list.txt")


def test_a_downgrade_to_plain_http_is_refused():
    session = FakeSession([FakeResponse(302, b"", {"Location": "http://feeds.example/list.txt"})])
    get = HttpFetcher(session=session, allow_private_addresses=True)
    with pytest.raises(ValidationError, match="refusing redirect"):
        get("https://feeds.example/list.txt")


def test_a_relative_redirect_resolves_against_the_current_url():
    session = FakeSession(
        [
            FakeResponse(301, b"", {"Location": "/v2/list.txt"}),
            FakeResponse(200, b"evil.example\n"),
        ]
    )
    HttpFetcher(session=session, allow_private_addresses=True)("https://feeds.example/v1/list.txt")
    assert session.requests[1]["url"] == "https://feeds.example/v2/list.txt"


def test_a_redirect_loop_terminates():
    session = FakeSession({"": FakeResponse(302, b"", {"Location": "https://feeds.example/l.txt"})})
    get = HttpFetcher(session=session, allow_private_addresses=True, max_redirects=2)
    with pytest.raises(UpstreamError, match="redirected more than 2 times"):
        get("https://feeds.example/l.txt")


def test_the_conditional_header_is_not_replayed_after_a_redirect():
    """The etag belongs to the original resource, not whatever it points at."""
    session = FakeSession(
        [
            FakeResponse(302, b"", {"Location": "https://cdn.example/list.txt"}),
            FakeResponse(200, b"evil.example\n"),
        ]
    )
    HttpFetcher(session=session, allow_private_addresses=True)(
        "https://feeds.example/list.txt", etag="v1"
    )
    assert "If-None-Match" in session.requests[0]["headers"]
    assert "If-None-Match" not in session.requests[1]["headers"]


def test_a_useful_user_agent_identifies_us_to_publishers():
    session = FakeSession([FakeResponse(200, b"x.example\n")])
    HttpFetcher(session=session, allow_private_addresses=True)("https://feeds.example/l.txt")
    assert "DNSGuard" in session.requests[0]["headers"]["User-Agent"]


def test_a_nonsense_size_cap_is_rejected_at_construction():
    with pytest.raises(ValidationError):
        HttpFetcher(session=FakeSession([]), max_bytes=0)
