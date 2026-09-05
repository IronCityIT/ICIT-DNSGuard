"""Retry and circuit-breaking behaviour, driven with a frozen clock so the tests
assert the backoff *shape* without waiting for it."""

from __future__ import annotations

import pytest

from dnsguard.clock import FrozenClock
from dnsguard.errors import CircuitOpenError, UpstreamError
from dnsguard.resilience import (
    BreakerRegistry,
    CircuitBreaker,
    RetryPolicy,
    resilient_call,
    try_call,
)


class Flaky:
    """Fails the first `failures` calls, then succeeds."""

    def __init__(self, failures: int, value: str = "ok") -> None:
        self.failures = failures
        self.value = value
        self.calls = 0

    def __call__(self) -> str:
        self.calls += 1
        if self.calls <= self.failures:
            raise ConnectionError(f"attempt {self.calls} failed")
        return self.value


# ── RetryPolicy ──────────────────────────────────────────────────────────────


def test_backoff_grows_exponentially_and_is_capped():
    policy = RetryPolicy(attempts=6, base_delay=1.0, multiplier=2.0, max_delay=8.0, jitter=False)
    assert [policy.delay_for(n) for n in range(1, 6)] == [1.0, 2.0, 4.0, 8.0, 8.0]


def test_full_jitter_stays_within_the_cap():
    policy = RetryPolicy(base_delay=1.0, multiplier=2.0, max_delay=10.0, jitter=True)
    assert policy.delay_for(3, rand=lambda: 0.0) == 0.0
    assert policy.delay_for(3, rand=lambda: 1.0) == 4.0
    assert policy.delay_for(3, rand=lambda: 0.5) == 2.0


def test_a_policy_must_allow_at_least_one_attempt():
    with pytest.raises(ValueError):
        RetryPolicy(attempts=0)


# ── resilient_call ───────────────────────────────────────────────────────────


def test_transient_failure_is_retried_and_succeeds():
    clock = FrozenClock()
    flaky = Flaky(failures=2)
    assert resilient_call(flaky, policy=RetryPolicy(attempts=3, jitter=False), clock=clock) == "ok"
    assert flaky.calls == 3
    assert clock.slept == [0.5, 1.0]


def test_exhausted_attempts_raise_upstream_error():
    clock = FrozenClock()
    flaky = Flaky(failures=99)
    with pytest.raises(UpstreamError) as excinfo:
        resilient_call(flaky, policy=RetryPolicy(attempts=3, jitter=False), clock=clock)
    assert flaky.calls == 3
    assert "3 attempt(s)" in str(excinfo.value)


def test_no_sleep_after_the_final_attempt():
    clock = FrozenClock()
    with pytest.raises(UpstreamError):
        resilient_call(Flaky(99), policy=RetryPolicy(attempts=2, jitter=False), clock=clock)
    assert len(clock.slept) == 1


def test_errors_outside_retry_on_propagate_immediately():
    def boom():
        raise KeyError("not retryable")

    with pytest.raises(KeyError):
        resilient_call(boom, retry_on=(ConnectionError,), clock=FrozenClock())


# ── CircuitBreaker ───────────────────────────────────────────────────────────


def test_breaker_opens_after_the_threshold_and_sheds_calls():
    clock = FrozenClock()
    breaker = CircuitBreaker("feeds", failure_threshold=3, reset_timeout=60, clock=clock)
    for _ in range(3):
        breaker.record_failure()
    assert breaker.state == "open"
    assert breaker.allows() is False


def test_breaker_half_opens_after_the_cooldown():
    clock = FrozenClock()
    breaker = CircuitBreaker("feeds", failure_threshold=1, reset_timeout=60, clock=clock)
    breaker.record_failure()
    assert breaker.state == "open"
    clock.advance(59)
    assert breaker.state == "open"
    clock.advance(2)
    assert breaker.state == "half_open"
    assert breaker.allows() is True


def test_a_failed_probe_reopens_the_circuit():
    clock = FrozenClock()
    breaker = CircuitBreaker("feeds", failure_threshold=2, reset_timeout=10, clock=clock)
    breaker.record_failure()
    breaker.record_failure()
    clock.advance(11)
    assert breaker.state == "half_open"
    breaker.record_failure()
    assert breaker.state == "open"


def test_success_closes_the_circuit_and_clears_the_count():
    clock = FrozenClock()
    breaker = CircuitBreaker("feeds", failure_threshold=2, reset_timeout=10, clock=clock)
    breaker.record_failure()
    breaker.record_success()
    breaker.record_failure()
    assert breaker.state == "closed"


def test_open_circuit_rejects_before_calling_the_dependency():
    clock = FrozenClock()
    breaker = CircuitBreaker("feeds", failure_threshold=1, reset_timeout=60, clock=clock)
    breaker.record_failure()
    flaky = Flaky(0)
    with pytest.raises(CircuitOpenError):
        resilient_call(flaky, breaker=breaker, clock=clock)
    assert flaky.calls == 0, "an open circuit must not touch the dependency"


def test_retries_stop_early_once_they_trip_the_breaker():
    clock = FrozenClock()
    breaker = CircuitBreaker("feeds", failure_threshold=2, reset_timeout=60, clock=clock)
    flaky = Flaky(99)
    with pytest.raises(CircuitOpenError):
        resilient_call(
            flaky, policy=RetryPolicy(attempts=10, jitter=False), breaker=breaker, clock=clock
        )
    assert flaky.calls == 2


# ── try_call ─────────────────────────────────────────────────────────────────


def test_try_call_reports_success_with_attempt_count():
    result = try_call(Flaky(1), policy=RetryPolicy(attempts=3, jitter=False), clock=FrozenClock())
    assert result.ok is True
    assert result.value == "ok"
    assert result.attempts == 2
    assert result.degraded is False


def test_try_call_degrades_to_a_fallback_instead_of_raising():
    result = try_call(
        Flaky(99), fallback=[], policy=RetryPolicy(attempts=2, jitter=False), clock=FrozenClock()
    )
    assert result.ok is False
    assert result.degraded is True
    assert result.value == []
    assert "failed" in result.error


def test_try_call_surfaces_the_circuit_state_for_health_reporting():
    clock = FrozenClock()
    breaker = CircuitBreaker("vendor", failure_threshold=1, reset_timeout=60, clock=clock)
    breaker.record_failure()
    result = try_call(Flaky(0), fallback="none", breaker=breaker, clock=clock)
    assert result.degraded is True
    assert result.circuit_state == "open"


def test_registry_hands_out_one_breaker_per_dependency():
    registry = BreakerRegistry(clock=FrozenClock())
    assert registry.get("feeds") is registry.get("feeds")
    assert registry.get("feeds") is not registry.get("reputation")
    registry.get("feeds").record_failure()
    snapshot = {b["name"]: b for b in registry.snapshot()}
    assert snapshot["feeds"]["consecutive_failures"] == 1
    assert snapshot["reputation"]["state"] == "closed"
