"""Retry, backoff and circuit breaking for calls the product does not control.

Threat feeds, reputation providers and the results endpoint all fail in the same
three ways: slow, intermittently, or completely. Each needs a different response
and the difference matters — retrying a dead dependency turns one outage into a
queue of stalled scans, while giving up on one dropped packet loses a scan.

  RetryPolicy    bounded attempts, exponential backoff, full jitter.
  CircuitBreaker sheds calls to a dependency that is failing, and probes it
                 again after a cooldown instead of hammering it.
  resilient_call composes the two, plus a deadline.

The clock and the RNG are injected so the behaviour is testable without waiting.
"""

from __future__ import annotations

import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeVar

from .clock import Clock
from .errors import CircuitOpenError, UpstreamError

T = TypeVar("T")


@dataclass(frozen=True)
class RetryPolicy:
    attempts: int = 3
    base_delay: float = 0.5
    max_delay: float = 30.0
    multiplier: float = 2.0
    jitter: bool = True

    def __post_init__(self) -> None:
        if self.attempts < 1:
            raise ValueError("attempts must be at least 1")
        if self.base_delay < 0 or self.max_delay < 0:
            raise ValueError("delays must not be negative")

    def delay_for(self, attempt: int, rand: Callable[[], float] = random.random) -> float:
        """Delay before `attempt` (1-based). Full jitter: uniform over [0, cap].

        Full jitter rather than fixed backoff because every scan runner retries
        on the same schedule otherwise, and a feed that just came back up gets
        the whole fleet at once.
        """
        cap = min(self.max_delay, self.base_delay * (self.multiplier ** max(0, attempt - 1)))
        return cap * rand() if self.jitter else cap


class CircuitBreaker:
    """closed -> open -> half_open -> closed.

    Opens after `failure_threshold` consecutive failures. While open every call
    is rejected immediately (that is the point: shed load, do not queue it).
    After `reset_timeout` one probe call is allowed; success closes the circuit,
    failure re-opens it for another cooldown.
    """

    def __init__(
        self,
        name: str = "dependency",
        failure_threshold: int = 5,
        reset_timeout: float = 60.0,
        clock: Clock | None = None,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be at least 1")
        self.name = name
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self._clock = clock or Clock()
        self._failures = 0
        self._state = "closed"
        self._opened_at = 0.0

    @property
    def state(self) -> str:
        if (
            self._state == "open"
            and self._clock.monotonic() - self._opened_at >= self.reset_timeout
        ):
            self._state = "half_open"
        return self._state

    def allows(self) -> bool:
        return self.state in ("closed", "half_open")

    def record_success(self) -> None:
        self._failures = 0
        self._state = "closed"

    def record_failure(self) -> None:
        self._failures += 1
        if self._state == "half_open" or self._failures >= self.failure_threshold:
            self._state = "open"
            self._opened_at = self._clock.monotonic()

    def snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state,
            "consecutive_failures": self._failures,
            "failure_threshold": self.failure_threshold,
            "reset_timeout_seconds": self.reset_timeout,
        }


@dataclass
class CallResult:
    """What happened, in enough detail to explain a degraded response to a user."""

    ok: bool
    value: Any = None
    attempts: int = 0
    error: str = ""
    circuit_state: str = "closed"
    degraded: bool = False


def resilient_call(
    fn: Callable[[], T],
    *,
    policy: RetryPolicy | None = None,
    breaker: CircuitBreaker | None = None,
    retry_on: Sequence[type[BaseException]] = (Exception,),
    clock: Clock | None = None,
    rand: Callable[[], float] = random.random,
) -> T:
    """Call fn with retry and circuit breaking. Raises on final failure."""
    policy = policy or RetryPolicy()
    clock = clock or Clock()

    if breaker is not None and not breaker.allows():
        raise CircuitOpenError(f"{breaker.name} is unavailable; calls are being shed")

    last: BaseException | None = None
    for attempt in range(1, policy.attempts + 1):
        try:
            value = fn()
        except tuple(retry_on) as exc:
            last = exc
            if breaker is not None:
                breaker.record_failure()
                if not breaker.allows():
                    raise CircuitOpenError(
                        f"{breaker.name} is unavailable; calls are being shed"
                    ) from exc
            if attempt < policy.attempts:
                clock.sleep(policy.delay_for(attempt, rand))
        else:
            if breaker is not None:
                breaker.record_success()
            return value

    raise UpstreamError(f"call failed after {policy.attempts} attempt(s): {last}") from last


def try_call(
    fn: Callable[[], T],
    *,
    fallback: T | None = None,
    policy: RetryPolicy | None = None,
    breaker: CircuitBreaker | None = None,
    clock: Clock | None = None,
    rand: Callable[[], float] = random.random,
) -> CallResult:
    """Non-raising variant: returns a CallResult describing the outcome.

    This is what the API uses for optional data. A dashboard panel whose feed is
    down should render "unavailable", not take the whole page down with it, and
    the caller needs to know which of those happened — hence `degraded`.
    """
    policy = policy or RetryPolicy()
    attempts_used = 0

    def counting() -> T:
        nonlocal attempts_used
        attempts_used += 1
        return fn()

    try:
        value = resilient_call(counting, policy=policy, breaker=breaker, clock=clock, rand=rand)
    except Exception as exc:
        return CallResult(
            ok=False,
            value=fallback,
            attempts=attempts_used,
            error=str(exc),
            circuit_state=breaker.state if breaker else "closed",
            degraded=True,
        )
    return CallResult(
        ok=True,
        value=value,
        attempts=attempts_used,
        circuit_state=breaker.state if breaker else "closed",
    )


@dataclass
class BreakerRegistry:
    """Named breakers, so /healthz can report which dependencies are shedding."""

    failure_threshold: int = 5
    reset_timeout: float = 60.0
    clock: Clock = field(default_factory=Clock)
    _breakers: dict[str, CircuitBreaker] = field(default_factory=dict, init=False)

    def get(self, name: str) -> CircuitBreaker:
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(
                name=name,
                failure_threshold=self.failure_threshold,
                reset_timeout=self.reset_timeout,
                clock=self.clock,
            )
        return self._breakers[name]

    def snapshot(self) -> list[dict[str, Any]]:
        return [b.snapshot() for b in sorted(self._breakers.values(), key=lambda b: b.name)]
