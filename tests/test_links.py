"""Signed scan links: what a stranger holding a URL is allowed to see.

The free-scan funnel hands a result to somebody with no account who will never
have one, so the permission has to travel in the URL. Doing that safely is
entirely about what the token cannot be talked into.

Every test here is an attempt to get more than one scan, or to get one for
longer than was granted.
"""

from __future__ import annotations

import base64
import json

import pytest

from dnsguard.errors import ValidationError
from dnsguard.links import DEFAULT_TTL_SECONDS, REFUSED, VERSION, sign, verify

SECRET = "a-link-secret-" + "long-enough-for-hmac"
OTHER_SECRET = "a-different-" + "secret-entirely-here"
NOW = 1_700_000_000.0


def token(tenant="acme", scan="scan-1", secret=SECRET, issued_at=NOW, ttl=None):
    return sign(tenant, scan, secret, issued_at, ttl)


def body_of(tok: str) -> dict:
    body = tok.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


def retoken(payload: dict, secret: str = SECRET) -> str:
    """Re-encode a payload and sign it. Used to prove that editing the payload
    without the secret does not work — and that editing it *with* the secret
    does, which is what makes the first result meaningful."""
    import hashlib
    import hmac

    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    mac = hmac.new(secret.encode(), encoded.encode(), hashlib.sha256).digest()
    return f"{encoded}.{base64.urlsafe_b64encode(mac).decode().rstrip('=')}"


# ── the happy path, so the refusals below mean something ─────────────────────


def test_a_freshly_minted_link_grants_exactly_what_it_names():
    link = verify(token(), SECRET, NOW)
    assert (link.tenant_id, link.scan_id) == ("acme", "scan-1")
    assert link.expires_at == int(NOW) + DEFAULT_TTL_SECONDS


def test_the_secret_never_appears_in_the_token():
    """A leaked link is one scan. It must not also be the ability to mint more."""
    assert SECRET not in token()


def test_two_scans_get_different_tokens():
    assert token(scan="scan-1") != token(scan="scan-2")


# ── the token cannot be repointed ────────────────────────────────────────────


def test_editing_the_scan_id_invalidates_the_token():
    """The obvious attack: hold one link, change one character, read somebody
    else's scan."""
    payload = body_of(token())
    payload["s"] = "scan-2"
    with pytest.raises(ValidationError):
        verify(retoken(payload, secret="not-the-secret-at-all-here"), SECRET, NOW)


def test_editing_the_tenant_invalidates_the_token():
    payload = body_of(token())
    payload["t"] = "globex"
    with pytest.raises(ValidationError):
        verify(retoken(payload, secret="not-the-secret-at-all-here"), SECRET, NOW)


def test_extending_the_expiry_invalidates_the_token():
    payload = body_of(token())
    payload["e"] = payload["e"] + 10_000_000
    with pytest.raises(ValidationError):
        verify(retoken(payload, secret="not-the-secret-at-all-here"), SECRET, NOW)


def test_the_same_edits_work_when_you_do_hold_the_secret():
    """The control for the three tests above. If re-signing did not work, they
    would pass for the wrong reason — a broken re-encoder rather than a working
    signature."""
    payload = body_of(token())
    payload["s"] = "scan-2"
    assert verify(retoken(payload, SECRET), SECRET, NOW).scan_id == "scan-2"


def test_a_token_signed_with_another_secret_is_refused():
    with pytest.raises(ValidationError):
        verify(token(secret=OTHER_SECRET), SECRET, NOW)


# ── expiry ───────────────────────────────────────────────────────────────────


def test_a_token_past_its_expiry_is_refused():
    """A link sitting in a mailbox is a permission granted for as long as the
    mailbox exists, unless it stops working."""
    tok = token(ttl=3600)
    assert verify(tok, SECRET, NOW + 3599)
    with pytest.raises(ValidationError):
        verify(tok, SECRET, NOW + 3601)


def test_a_token_expiring_exactly_now_is_refused():
    """Boundaries decided deliberately rather than by whichever comparison got
    typed: at the moment of expiry, it has expired."""
    tok = token(ttl=100)
    with pytest.raises(ValidationError):
        verify(tok, SECRET, NOW + 100)


def test_the_default_lifetime_is_bounded_and_not_absurd():
    assert 0 < DEFAULT_TTL_SECONDS <= 365 * 24 * 3600


# ── malformed input is refused, not crashed on ───────────────────────────────


@pytest.mark.parametrize(
    "bad",
    [
        "",
        ".",
        "onlybody",
        "body.",
        ".signature",
        "!!!!.!!!!",
        "a.b.c",
        "x" * 5000,
    ],
)
def test_junk_is_refused_rather_than_raising_something_else(bad):
    with pytest.raises(ValidationError):
        verify(bad, SECRET, NOW)


def test_a_token_whose_payload_is_not_json_is_refused():
    encoded = base64.urlsafe_b64encode(b"not json at all").decode().rstrip("=")
    with pytest.raises(ValidationError):
        verify(
            retoken({"junk": True}).replace(retoken({"junk": True}).split(".")[0], encoded),
            SECRET,
            NOW,
        )


def test_a_token_from_an_older_payload_shape_is_refused():
    """Rejected outright rather than read as a current token with fields
    missing, which is how a version bump silently loosens a check."""
    payload = body_of(token())
    payload["v"] = VERSION - 1
    with pytest.raises(ValidationError):
        verify(retoken(payload, SECRET), SECRET, NOW)


@pytest.mark.parametrize("field", ["t", "s", "e"])
def test_a_token_missing_a_field_is_refused(field):
    payload = body_of(token())
    del payload[field]
    with pytest.raises(ValidationError):
        verify(retoken(payload, SECRET), SECRET, NOW)


def test_a_non_integer_expiry_is_refused():
    payload = body_of(token())
    payload["e"] = "whenever"
    with pytest.raises(ValidationError):
        verify(retoken(payload, SECRET), SECRET, NOW)


# ── every refusal says the same thing ────────────────────────────────────────


def test_no_refusal_says_why():
    """Distinguishable messages turn a link checker into an oracle: a caller
    could learn whether a scan exists, or whether a token merely expired, by
    reading the difference."""
    payload = body_of(token())
    payload["s"] = "scan-2"

    attempts = [
        lambda: verify("garbage", SECRET, NOW),
        lambda: verify(token(secret=OTHER_SECRET), SECRET, NOW),
        lambda: verify(token(ttl=1), SECRET, NOW + 100),
        lambda: verify(retoken(payload, "wrong-secret-here-padding"), SECRET, NOW),
    ]
    messages = set()
    for attempt in attempts:
        with pytest.raises(ValidationError) as excinfo:
            attempt()
        messages.add(str(excinfo.value))
    assert messages == {REFUSED}


# ── fail closed ──────────────────────────────────────────────────────────────


def test_nothing_can_be_signed_without_a_secret():
    with pytest.raises(ValidationError, match="DNSGUARD_LINK_SECRET"):
        sign("acme", "scan-1", "", NOW)


def test_nothing_can_be_verified_without_a_secret():
    """The dangerous default would be to skip verification when unconfigured,
    which turns every token into a valid one."""
    with pytest.raises(ValidationError, match="DNSGUARD_LINK_SECRET"):
        verify(token(), "", NOW)


@pytest.mark.parametrize(("tenant", "scan"), [("", "scan-1"), ("acme", ""), ("", "")])
def test_a_link_must_point_at_something(tenant, scan):
    with pytest.raises(ValidationError):
        sign(tenant, scan, SECRET, NOW)
