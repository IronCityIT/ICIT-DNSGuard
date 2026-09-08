"""Starting a free scan: the only route where a stranger can spend our resources.

Every other endpoint in this product requires a credential. This one cannot,
because the person using it has no account and the whole point of the funnel is
that they never need one — so a stranger can cause a record to be written and a
CI pipeline to run for a couple of minutes against a domain they chose.

The version this replaces has no rate limiting that could be found anywhere in
the repository. Most of what follows is about not carrying that across.

Nothing here dispatches a real pipeline: the dispatch is injected.
"""

from __future__ import annotations

import pytest

from dnsguard.audit import AuditLog
from dnsguard.clock import FrozenClock
from dnsguard.errors import ValidationError
from dnsguard.scans import ScanService
from dnsguard.store import MemoryStore
from dnsguard.trigger import (
    DEFAULT_LIMIT,
    RATE_COLLECTION,
    RateLimitError,
    ScanTrigger,
    check_email,
    normalise_domain,
)

EMAIL = "someone@acme.example"


@pytest.fixture
def clock():
    return FrozenClock()


@pytest.fixture
def store():
    return MemoryStore()


@pytest.fixture
def dispatched():
    return []


@pytest.fixture
def trigger(store, clock, dispatched):
    return ScanTrigger(
        scans=ScanService(store=store, audit=AuditLog(store, clock), clock=clock),
        store=store,
        dispatch=lambda domain, scan_id: dispatched.append((domain, scan_id)),
        clock=clock,
    )


# ── the ordinary request ─────────────────────────────────────────────────────


def test_a_request_records_a_queued_scan_and_starts_the_pipeline(trigger, dispatched):
    accepted = trigger.request(EMAIL, "acme.example", source="203.0.113.7")
    assert accepted["status"] == "queued"
    assert dispatched == [("acme.example", accepted["scan_id"])]

    stored = trigger.scans.get(trigger.tenant_id, accepted["scan_id"])
    assert stored["status"] == "queued"
    assert stored["target"] == "acme.example"


def test_the_submitters_address_does_not_end_up_on_the_scan(trigger):
    """It is stored, in its own collection, and the scan is the thing that gets
    read and rendered."""
    accepted = trigger.request(EMAIL, "acme.example")
    stored = trigger.scans.get(trigger.tenant_id, accepted["scan_id"])
    assert EMAIL not in str(stored)
    assert trigger.scans.submitter(trigger.tenant_id, accepted["scan_id"])["email"] == EMAIL


def test_two_requests_get_different_scan_ids(trigger):
    first = trigger.request(EMAIL, "acme.example")["scan_id"]
    second = trigger.request(EMAIL, "other.example")["scan_id"]
    assert first != second


# ── rate limiting: per submitter AND per source ──────────────────────────────


def test_one_address_cannot_start_unlimited_scans(trigger):
    for _ in range(DEFAULT_LIMIT):
        trigger.request(EMAIL, "acme.example", source="203.0.113.7")
    with pytest.raises(RateLimitError):
        trigger.request(EMAIL, "acme.example", source="203.0.113.7")


def test_one_address_from_many_hosts_is_still_limited(trigger):
    """Limiting only by source would be evaded by a botnet, which is the easy
    half of the problem."""
    for n in range(DEFAULT_LIMIT):
        trigger.request(EMAIL, "acme.example", source=f"203.0.113.{n}")
    with pytest.raises(RateLimitError):
        trigger.request(EMAIL, "acme.example", source="203.0.113.99")


def test_many_addresses_from_one_host_are_still_limited(trigger):
    """Limiting only by address would be evaded by typing a different one, which
    is the easier half."""
    for n in range(DEFAULT_LIMIT):
        trigger.request(f"user{n}@acme.example", "acme.example", source="203.0.113.7")
    with pytest.raises(RateLimitError):
        trigger.request("someone-else@acme.example", "acme.example", source="203.0.113.7")


def test_the_limit_lifts_when_the_window_passes(trigger, clock):
    for _ in range(DEFAULT_LIMIT):
        trigger.request(EMAIL, "acme.example", source="203.0.113.7")
    clock.advance(trigger.window_seconds + 1)
    assert trigger.request(EMAIL, "acme.example", source="203.0.113.7")["status"] == "queued"


def test_a_refusal_says_how_long_to_wait(trigger):
    """A caller over the limit should be able to tell that from a caller who
    broke something."""
    for _ in range(DEFAULT_LIMIT):
        trigger.request(EMAIL, "acme.example", source="203.0.113.7")
    with pytest.raises(RateLimitError, match="seconds"):
        trigger.request(EMAIL, "acme.example", source="203.0.113.7")


def test_the_refusal_carries_a_429(trigger):
    for _ in range(DEFAULT_LIMIT):
        trigger.request(EMAIL, "acme.example")
    with pytest.raises(RateLimitError) as excinfo:
        trigger.request(EMAIL, "acme.example")
    assert excinfo.value.status_code == 429


def test_a_rate_limited_request_starts_nothing(trigger, dispatched):
    """The check happens before anything is written or dispatched, so a refused
    request costs nothing beyond the check itself."""
    for _ in range(DEFAULT_LIMIT):
        trigger.request(EMAIL, "acme.example")
    started = len(dispatched)
    with pytest.raises(RateLimitError):
        trigger.request(EMAIL, "acme.example")
    assert len(dispatched) == started


def test_the_counter_survives_a_restart(store, clock, dispatched):
    """Counted in the store, not in the process. A restart that resets
    everybody's budget is not a limit."""

    def build():
        return ScanTrigger(
            scans=ScanService(store=store, audit=AuditLog(store, clock), clock=clock),
            store=store,
            dispatch=lambda d, s: dispatched.append((d, s)),
            clock=clock,
        )

    for _ in range(DEFAULT_LIMIT):
        build().request(EMAIL, "acme.example", source="203.0.113.7")
    with pytest.raises(RateLimitError):
        build().request(EMAIL, "acme.example", source="203.0.113.7")


def test_the_counter_does_not_store_the_address_it_counts(trigger, store):
    """A counter needs to know whether it has seen somebody before, not who they
    are. Both the address and the source address are personal data."""
    trigger.request(EMAIL, "acme.example", source="203.0.113.7")
    records = store.list(trigger.tenant_id, RATE_COLLECTION)
    assert records
    assert EMAIL not in str(records)
    assert "203.0.113.7" not in str(records)


# ── validation ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("acme.example", "acme.example"),
        ("ACME.example", "acme.example"),
        ("https://acme.example", "acme.example"),
        ("http://www.acme.example", "acme.example"),
        ("www.acme.example/path?x=1", "acme.example"),
        ("  acme.example  ", "acme.example"),
    ],
)
def test_what_people_actually_paste_is_normalised(raw, expected):
    assert normalise_domain(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "not a domain",
        "acme",
        "-acme.example",
        "acme.example;rm -rf /",
        "acme.example`whoami`",
        "$(id).example",
        "a" * 300 + ".example",
        "acme..example",
        "http://",
    ],
)
def test_anything_that_is_not_a_hostname_is_refused(raw):
    """This value reaches a workflow input and then a command line. Stripping is
    not validation — the check runs last, on the value that will be used."""
    with pytest.raises(ValidationError):
        normalise_domain(raw)


@pytest.mark.parametrize("raw", ["", "not-an-email", "a@b", "@acme.example", "someone@"])
def test_a_malformed_address_is_refused(raw):
    with pytest.raises(ValidationError):
        check_email(raw)


@pytest.mark.parametrize("provider", ["gmail.com", "outlook.com", "proton.me"])
def test_free_mail_is_refused(provider):
    with pytest.raises(ValidationError, match="work email"):
        check_email(f"someone@{provider}")


def test_a_work_address_is_accepted():
    assert check_email("Someone@Acme.Example") == "someone@acme.example"


def test_validation_happens_before_anything_is_written(trigger, dispatched, store):
    with pytest.raises(ValidationError):
        trigger.request(EMAIL, "not a domain")
    assert dispatched == []
    assert store.list(trigger.tenant_id, "scans") == []


# ── when the pipeline cannot be started ──────────────────────────────────────


def test_a_dispatch_failure_closes_the_scan_rather_than_leaving_it_queued(store, clock):
    """A record left queued forever is a page that spins until the browser gives
    up, which reads to the client as "still running" rather than "failed"."""

    def broken(_domain, _scan_id):
        raise OSError("the pipeline is unreachable")

    trigger = ScanTrigger(
        scans=ScanService(store=store, audit=AuditLog(store, clock), clock=clock),
        store=store,
        dispatch=broken,
        clock=clock,
    )
    with pytest.raises(ValidationError, match="could not be started"):
        trigger.request(EMAIL, "acme.example")

    scans = trigger.scans.list(trigger.tenant_id)
    assert len(scans) == 1
    assert scans[0]["status"] == "failed"
    assert scans[0]["error"]["stage"] == "dispatch"


def test_a_dispatch_failure_does_not_leak_the_underlying_error(store, clock):
    """What went wrong upstream is an operational detail. The person who typed
    their email address gets something they can act on."""

    def broken(_domain, _scan_id):
        raise OSError("connection refused to internal-ci.example:8080")

    trigger = ScanTrigger(
        scans=ScanService(store=store, audit=AuditLog(store, clock), clock=clock),
        store=store,
        dispatch=broken,
        clock=clock,
    )
    with pytest.raises(ValidationError) as excinfo:
        trigger.request(EMAIL, "acme.example")
    assert "internal-ci.example" not in str(excinfo.value)


# ── it is audited ────────────────────────────────────────────────────────────


def test_a_free_scan_is_audited_as_such(trigger):
    accepted = trigger.request(EMAIL, "acme.example")
    records = trigger.scans.audit.records(trigger.tenant_id)
    ingested = [r for r in records if r.subject == f"scan/{accepted['scan_id']}"]
    assert ingested
    assert ingested[0].actor == "free-scan"
