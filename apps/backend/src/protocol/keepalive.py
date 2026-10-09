"""P-11 Contract-governed SSE keep-alive scheduler.

Emits standard comment keepalives (: keep-alive\\n\\n) during long waits, enforces
an unextendable absolute deadline, and terminates cleanly without post-termination emissions.
"""

from __future__ import annotations

import time

from infra.errors import SafetyCode, SafetyError

DEFAULT_KEEPALIVE_INTERVAL = 15.0  # seconds
DEFAULT_ABSOLUTE_DEADLINE = 120.0  # seconds


class SseKeepAliveScheduler:
    """Schedules SSE comment keepalives and strictly enforces absolute deadlines (P-11)."""

    def __init__(
        self,
        interval_seconds: float = DEFAULT_KEEPALIVE_INTERVAL,
        deadline_seconds: float = DEFAULT_ABSOLUTE_DEADLINE,
        start_time: float | None = None,
    ) -> None:
        if interval_seconds <= 0 or deadline_seconds <= 0:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "interval and deadline must be positive")
        if interval_seconds >= deadline_seconds:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "interval must be strictly less than deadline")

        self.interval_seconds = interval_seconds
        self.deadline_seconds = deadline_seconds
        self.start_time = time.monotonic() if start_time is None else start_time
        self.last_activity = self.start_time
        self._terminated = False

    def record_activity(self, now: float | None = None) -> None:
        """Record real event traffic on the stream, resetting keep-alive timer."""
        current = time.monotonic() if now is None else now
        self.check_deadline(current)
        if not self._terminated:
            self.last_activity = current

    def should_emit_keepalive(self, now: float | None = None) -> bool:
        """Check if interval has elapsed since last activity without exceeding deadline."""
        if self._terminated:
            return False
        current = time.monotonic() if now is None else now
        self.check_deadline(current)
        return (current - self.last_activity) >= self.interval_seconds

    def emit_keepalive(self, now: float | None = None) -> str:
        """Emit a standard SSE comment keepalive if permitted. Resets last_activity."""
        if self._terminated:
            return ""
        current = time.monotonic() if now is None else now
        self.check_deadline(current)
        self.last_activity = current
        return ": keep-alive\n\n"

    def check_deadline(self, now: float | None = None) -> None:
        """Strictly enforce immutable absolute deadline. Cannot be extended by keepalives."""
        current = time.monotonic() if now is None else now
        if current - self.start_time >= self.deadline_seconds:
            self._terminated = True
            raise SafetyError(
                SafetyCode.CONTRACT_VIOLATION,
                f"SSE absolute deadline of {self.deadline_seconds}s exceeded",
            )

    def terminate(self) -> None:
        """Mark stream terminated; no further keepalives will be emitted."""
        self._terminated = True
