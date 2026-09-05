"""One source of time, injectable.

Everything in the control plane timestamps, expires or ages something — feed
snapshots, approvals, exceptions, alert windows. Tests that cannot control time
end up either slow or flaky, so time is a dependency here rather than a global.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

UTC = timezone.utc


class Clock:
    """Real time."""

    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class FrozenClock(Clock):
    """Time that only moves when a test moves it."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 1, 1, tzinfo=UTC)
        self._mono = 0.0
        self.slept: list[float] = []

    def now(self) -> datetime:
        return self._now

    def monotonic(self) -> float:
        return self._mono

    def sleep(self, seconds: float) -> None:
        # Record rather than block: a test asserting backoff shape should not
        # actually wait for it.
        self.slept.append(seconds)
        self.advance(seconds)

    def advance(self, seconds: float) -> None:
        self._now = self._now + timedelta(seconds=seconds)
        self._mono += seconds


def iso(moment: datetime) -> str:
    """Canonical timestamp format: UTC, second precision, trailing Z."""
    return moment.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    text = value.replace("Z", "+00:00")
    moment = datetime.fromisoformat(text)
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)
