"""The production HTTP transport for threat feeds.

`FeedFetcher` takes its transport as an injection, which is what makes the feeds
subsystem testable — and, until now, meant nothing in this repository could
actually fetch a feed. This is that missing half.

It is not a thin wrapper around `requests.get`, because a feed URL is not
trusted input. Feed registration is an ordinary operator action, so the URL
arrives from a person who may be careless or hostile, and the process that
fetches it runs inside our own network with an instance metadata endpoint one
request away. Four things follow from that:

  * **Only https.** Plain http is opt-in per fetcher and off by default: a feed
    fetched over http can be rewritten in transit, and the whole point of the
    provenance chain is that we can say where an indicator came from.
  * **No private address space.** Every hop is resolved and every resolved
    address is checked before the connection is made, so a feed URL cannot be
    pointed at 169.254.169.254, a loopback admin port, or an internal subnet.
  * **Redirects are followed by hand.** `requests` would follow them for us and
    silently skip the check above on every hop after the first, which is exactly
    how an SSRF guard gets bypassed.
  * **Responses are capped and streamed.** A publisher who serves an endless
    body should cost us a bounded amount of memory and then an error, not the
    runner.

Conditional requests are supported because feed publishers expect them: sending
the previous ETag turns an unchanged daily list into a 304 and keeps us inside
their rate limits.

Residual, stated rather than hidden: the address check and the connection are
two separate steps, so a name that resolves differently between them (DNS
rebinding) is not defeated by this. Closing that needs connection-level pinning,
which `requests` does not expose. The guard stops the careless and the
opportunistic; it is not a substitute for egress filtering on the runner.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from .errors import UpstreamError, ValidationError
from .feeds import FetchResponse

USER_AGENT = "IronCity-DNSGuard/1.0 (+https://ironcityit.com)"

DEFAULT_TIMEOUT = 20.0
DEFAULT_MAX_BYTES = 32 * 1024 * 1024  # 32 MiB — larger than any real domain list
DEFAULT_MAX_REDIRECTS = 3
CHUNK = 64 * 1024


def _addresses_for(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Every address the host resolves to. All of them are checked, not just the
    first, because a name with one public and one private A record would
    otherwise pass the guard and then connect to whichever the stack picked."""
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return [literal]

    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UpstreamError(f"could not resolve feed host {host}: {exc}") from exc

    found = []
    for info in infos:
        try:
            found.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    if not found:
        raise UpstreamError(f"feed host {host} resolved to no usable address")
    return found


def is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Whether an address is somewhere on the public internet.

    `is_global` alone is not enough: it accepts some ranges we still do not want
    a fetch pointed at, and the link-local range that carries cloud instance
    metadata is the one that matters most here.
    """
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


@dataclass
class HttpFetcher:
    """Fetches a feed over HTTP, safely. Satisfies the `HttpFetch` contract."""

    timeout: float = DEFAULT_TIMEOUT
    max_bytes: int = DEFAULT_MAX_BYTES
    max_redirects: int = DEFAULT_MAX_REDIRECTS
    allow_insecure: bool = False
    allow_private_addresses: bool = False  # tests and on-premise mirrors only
    session: Any = None
    extra_headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.session is None:
            import requests

            self.session = requests.Session()
        if self.max_bytes < 1:
            raise ValidationError("max_bytes must be positive")

    # ── the contract ────────────────────────────────────────────────────────

    def __call__(self, url: str, etag: str = "") -> FetchResponse:
        current = url
        for hop in range(self.max_redirects + 1):
            self.check(current)
            response = self._request(current, etag if hop == 0 else "")

            location = response.headers.get("Location", "") if hasattr(response, "headers") else ""
            if response.status_code in (301, 302, 303, 307, 308) and location:
                current = self._resolve_redirect(current, location)
                continue

            return self._read(response, current)

        raise UpstreamError(f"feed at {url} redirected more than {self.max_redirects} times")

    # ── the guard ───────────────────────────────────────────────────────────

    def check(self, url: str) -> None:
        """Refuse a URL before any connection is attempted."""
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()

        if scheme not in ("https", "http"):
            raise ValidationError(f"feed url must be http(s), not {scheme or 'a relative path'!r}")
        if scheme == "http" and not self.allow_insecure:
            raise ValidationError(
                f"refusing to fetch {url} over plain http: a feed rewritten in transit "
                "would poison the provenance chain. Set allow_insecure to override."
            )
        if not parsed.hostname:
            raise ValidationError(f"feed url has no host: {url}")

        if self.allow_private_addresses:
            return

        for address in _addresses_for(parsed.hostname):
            if not is_public(address):
                raise ValidationError(
                    f"refusing to fetch {url}: {parsed.hostname} resolves to {address}, "
                    "which is not on the public internet"
                )

    def _resolve_redirect(self, current: str, location: str) -> str:
        from urllib.parse import urljoin

        target = urljoin(current, location)
        # A redirect from https to http is a downgrade, and following it would
        # undo the scheme check that already passed.
        if urlparse(current).scheme == "https" and urlparse(target).scheme == "http":
            raise ValidationError(f"refusing redirect from {current} to plain http at {target}")
        return target

    # ── transport ───────────────────────────────────────────────────────────

    def _request(self, url: str, etag: str) -> Any:
        headers = {"User-Agent": USER_AGENT, "Accept": "text/plain, */*", **self.extra_headers}
        if etag:
            headers["If-None-Match"] = etag
        try:
            return self.session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                stream=True,
                allow_redirects=False,  # followed by hand so every hop is checked
            )
        except Exception as exc:  # noqa: BLE001 - any transport failure is upstream
            raise UpstreamError(f"fetching {url} failed: {exc}") from exc

    def _read(self, response: Any, url: str) -> FetchResponse:
        status = int(response.status_code)
        etag = response.headers.get("ETag", "") if hasattr(response, "headers") else ""

        # 304 carries no body by definition, and the caller must not read the
        # empty one as "the publisher removed every entry".
        if status == 304:
            return FetchResponse(body="", etag=etag, status_code=304)

        if status != 200:
            return FetchResponse(body="", etag=etag, status_code=status)

        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=CHUNK):
            if not chunk:
                continue
            total += len(chunk)
            if total > self.max_bytes:
                raise UpstreamError(
                    f"feed at {url} exceeded the {self.max_bytes} byte limit; refusing to buffer it"
                )
            chunks.append(chunk)

        return FetchResponse(
            body=b"".join(chunks).decode("utf-8", errors="replace"),
            etag=etag,
            status_code=200,
        )
