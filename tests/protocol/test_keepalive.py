"""Tests for P-11 contract-governed SSE keep-alive scheduler."""

from __future__ import annotations

import unittest

from infra.errors import SafetyCode, SafetyError
from protocol.keepalive import SseKeepAliveScheduler


class TestSseKeepAlive(unittest.TestCase):
    def test_keepalive_emitted_after_idle_interval(self) -> None:
        """P-11: Comment keepalive emitted when elapsed time >= interval."""
        start = 100.0
        scheduler = SseKeepAliveScheduler(interval_seconds=5.0, deadline_seconds=30.0, start_time=start)

        # At t=104.0 (4s elapsed), no keepalive needed
        self.assertFalse(scheduler.should_emit_keepalive(now=104.0))

        # At t=105.0 (5s elapsed), keepalive is needed
        self.assertTrue(scheduler.should_emit_keepalive(now=105.0))
        msg = scheduler.emit_keepalive(now=105.0)
        self.assertEqual(": keep-alive\n\n", msg)

        # After emission, timer is reset
        self.assertFalse(scheduler.should_emit_keepalive(now=106.0))

    def test_real_activity_resets_keepalive_timer(self) -> None:
        """P-11: Data activity resets idle timer."""
        start = 100.0
        scheduler = SseKeepAliveScheduler(interval_seconds=5.0, deadline_seconds=30.0, start_time=start)

        # At t=104.0, real data event occurs
        scheduler.record_activity(now=104.0)

        # At t=106.0 (2s after activity, 6s after start), no keepalive needed yet
        self.assertFalse(scheduler.should_emit_keepalive(now=106.0))

        # At t=109.0 (5s after activity), keepalive needed
        self.assertTrue(scheduler.should_emit_keepalive(now=109.0))

    def test_absolute_deadline_cannot_be_extended(self) -> None:
        """P-11: Keepalives do NOT extend the absolute deadline."""
        start = 100.0
        scheduler = SseKeepAliveScheduler(interval_seconds=5.0, deadline_seconds=20.0, start_time=start)

        # Multiple keepalives emitted
        scheduler.emit_keepalive(now=105.0)
        scheduler.emit_keepalive(now=110.0)
        scheduler.emit_keepalive(now=115.0)

        # At t=120.0 (20s elapsed), absolute deadline is reached and fails closed!
        with self.assertRaises(SafetyError) as exc_info:
            scheduler.check_deadline(now=120.0)
        self.assertEqual(SafetyCode.CONTRACT_VIOLATION, exc_info.exception.code)

    def test_termination_halts_all_emissions(self) -> None:
        """P-11: Terminated stream emits zero keepalives."""
        start = 100.0
        scheduler = SseKeepAliveScheduler(interval_seconds=5.0, deadline_seconds=30.0, start_time=start)

        scheduler.terminate()
        self.assertFalse(scheduler.should_emit_keepalive(now=110.0))
        self.assertEqual("", scheduler.emit_keepalive(now=110.0))


if __name__ == "__main__":
    unittest.main()
