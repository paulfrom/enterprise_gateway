"""Admission limiter tests: token budgeting, concurrency limits, and request throttling.

All fixtures are synthetic and built in memory. gzip inputs are real
``gzip.compress`` payloads; the gzip-bomb cases use genuinely highly
compressible data so a small raw body decompresses far beyond the limit.
Concurrency tests use real threads and real condition-variable waits — no
mocked clocks — with generous join budgets so slow CI machines stay green.
"""

from __future__ import annotations

import gzip
import math
import random
import sys
import threading
import time
import unittest

from protocol.admission import (
    DIMENSION_BODY_BYTES,
    DIMENSION_CONCURRENCY,
    DIMENSION_DECOMPRESSED_BYTES,
    DIMENSION_EXPANSION_RATIO,
    DIMENSION_HISTORY_MESSAGES,
    DIMENSION_TEXT_CHARS,
    AdmissionLimiter,
    AdmissionMeasurement,
    _OccurrenceCounter,
)
from infra.errors import SafetyCode, SafetyError

CANARY = "p16-canary-7d2e91af"  # synthetic marker; must never appear in public messages

_BOMB = b"\x00" * (1024 * 1024)  # 1 MiB of zeros: tiny when gzip-compressed


def _gzip(data: bytes) -> bytes:
    return gzip.compress(data)


def _expected_limit_message(dimension: str) -> str:
    return f"{SafetyCode.ADMISSION_LIMIT_EXCEEDED.value} ({dimension})"


class _AcquireThread(threading.Thread):
    """Run one blocking acquire on a side thread and capture its outcome."""

    def __init__(self, limiter: AdmissionLimiter, *, timeout: float | None):
        super().__init__(daemon=True)
        self._limiter = limiter
        self._timeout = timeout
        self.outcome = None

    def run(self) -> None:
        try:
            permit = self._limiter.acquire(timeout=self._timeout)
        except BaseException as exc:  # noqa: BLE001
            self.outcome = ("raise", exc)
        else:
            self.outcome = ("permit", permit)


def _wait_for(predicate, timeout=15.0, interval=0.02) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


class BodyBytesTests(unittest.TestCase):
    def test_body_bytes_exactly_at_limit_passes(self) -> None:
        limiter = AdmissionLimiter(max_body_bytes=256)
        measurement = limiter.admit(b"x" * 256)
        self.assertEqual(measurement.body_bytes, 256)
        self.assertIsInstance(measurement, AdmissionMeasurement)

    def test_body_bytes_one_over_limit_rejected(self) -> None:
        limiter = AdmissionLimiter(max_body_bytes=256)
        with self.assertRaises(SafetyError) as caught:
            limiter.admit(b"x" * 257)
        self.assertEqual(caught.exception.code, SafetyCode.ADMISSION_LIMIT_EXCEEDED)
        self.assertEqual(str(caught.exception), _expected_limit_message(DIMENSION_BODY_BYTES))

    def test_body_bytes_empty_body_against_zero_limit_passes(self) -> None:
        limiter = AdmissionLimiter(max_body_bytes=0)
        self.assertEqual(limiter.admit(b"").body_bytes, 0)

    def test_body_accepts_bytes_like_objects(self) -> None:
        limiter = AdmissionLimiter(max_body_bytes=4)
        self.assertEqual(limiter.admit(bytearray(b"abcd")).body_bytes, 4)
        self.assertEqual(limiter.admit(memoryview(b"abcd")).body_bytes, 4)

    def test_body_rejects_non_bytes(self) -> None:
        limiter = AdmissionLimiter()
        with self.assertRaises(TypeError):
            limiter.admit("text is not a resource body")  # type: ignore[arg-type]


class GzipAdmissionTests(unittest.TestCase):
    def test_decompressed_bytes_exactly_at_limit_passes(self) -> None:
        payload = bytes(range(256)) * 20  # 5120 bytes, incompressible-ish
        compressed = _gzip(payload)
        limiter = AdmissionLimiter(max_decompressed_bytes=len(payload))
        measurement = limiter.admit(compressed)
        self.assertEqual(measurement.decompressed_bytes, len(payload))
        self.assertAlmostEqual(
            measurement.expansion_ratio, len(payload) / len(compressed), places=12
        )

    def test_small_body_with_huge_decompressed_rejected(self) -> None:
        compressed = _gzip(_BOMB)
        self.assertLess(len(compressed), 4096)  # genuinely small on the wire
        limiter = AdmissionLimiter(max_decompressed_bytes=65536)
        with self.assertRaises(SafetyError) as caught:
            limiter.admit(compressed)
        self.assertEqual(caught.exception.code, SafetyCode.ADMISSION_LIMIT_EXCEEDED)
        self.assertEqual(
            str(caught.exception), _expected_limit_message(DIMENSION_DECOMPRESSED_BYTES)
        )

    def test_expansion_ratio_at_limit_passes(self) -> None:
        compressed = _gzip(_BOMB)
        # A huge finite limit triggers measurement without ever rejecting.
        measured = AdmissionLimiter(max_expansion_ratio=sys.float_info.max).admit(compressed)
        self.assertIsNotNone(measured.expansion_ratio)
        limiter = AdmissionLimiter(max_expansion_ratio=measured.expansion_ratio)
        measurement = limiter.admit(compressed)  # exactly at the limit passes
        self.assertEqual(measurement.expansion_ratio, measured.expansion_ratio)

    def test_expansion_ratio_one_ulp_below_limit_rejected(self) -> None:
        compressed = _gzip(_BOMB)
        measured = AdmissionLimiter(max_expansion_ratio=sys.float_info.max).admit(compressed)
        just_below = math.nextafter(measured.expansion_ratio, 0.0)
        limiter = AdmissionLimiter(max_expansion_ratio=just_below)
        with self.assertRaises(SafetyError) as caught:
            limiter.admit(compressed)
        self.assertEqual(
            str(caught.exception), _expected_limit_message(DIMENSION_EXPANSION_RATIO)
        )

    def test_ratio_alone_rejects_bomb_without_decompressed_limit(self) -> None:
        limiter = AdmissionLimiter(max_expansion_ratio=2.0)
        with self.assertRaises(SafetyError) as caught:
            limiter.admit(_gzip(_BOMB))
        self.assertEqual(
            str(caught.exception), _expected_limit_message(DIMENSION_EXPANSION_RATIO)
        )

    def test_decompression_limits_do_not_apply_to_plain_bodies(self) -> None:
        limiter = AdmissionLimiter(max_decompressed_bytes=1, max_expansion_ratio=1.0)
        measurement = limiter.admit(b"plain text, definitely not gzip")
        self.assertIsNone(measurement.decompressed_bytes)
        self.assertIsNone(measurement.expansion_ratio)

    def test_gzip_body_without_size_limits_is_not_decompressed(self) -> None:
        # No decompression-dependent dimension is configured, so the body is
        # never decompressed: the measurement reports None, and a body that
        # would explode stays untouched.
        limiter = AdmissionLimiter(max_body_bytes=1 << 20)
        measurement = limiter.admit(_gzip(_BOMB))
        self.assertIsNone(measurement.decompressed_bytes)
        self.assertIsNone(measurement.expansion_ratio)

    def test_truncated_gzip_rejected_with_controlled_error(self) -> None:
        truncated = _gzip(b"x" * 100)[:10]
        limiter = AdmissionLimiter(max_decompressed_bytes=1 << 20)
        with self.assertRaises(SafetyError) as caught:
            limiter.admit(truncated)
        error = caught.exception
        self.assertEqual(error.code, SafetyCode.INVALID_PAYLOAD)
        self.assertEqual(str(error), f"{SafetyCode.INVALID_PAYLOAD.value} (gzip_stream)")
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        # Fail closed, nothing executed: no slot was taken and the limiter
        # keeps serving well-formed requests.
        self.assertEqual(limiter.in_use, 0)
        self.assertEqual(limiter.admit(b"plain").body_bytes, 5)

    def test_corrupt_deflate_data_rejected_with_controlled_error(self) -> None:
        # Non-truncation corruption: flip bytes inside the deflate payload
        # region (past the 10-byte header). Decoding then fails mid-stream
        # (zlib.error) or at the end-of-stream CRC check (BadGzipFile);
        # either native failure maps to the same controlled rejection.
        corrupted = bytearray(_gzip(bytes(range(256)) * 20))
        for index in (12, 25, 40):
            corrupted[index] ^= 0xFF
        limiter = AdmissionLimiter(max_decompressed_bytes=1 << 20)
        with self.assertRaises(SafetyError) as caught:
            limiter.admit(bytes(corrupted))
        error = caught.exception
        self.assertEqual(error.code, SafetyCode.INVALID_PAYLOAD)
        self.assertEqual(str(error), f"{SafetyCode.INVALID_PAYLOAD.value} (gzip_stream)")
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        self.assertEqual(limiter.in_use, 0)

    def test_history_counted_on_decompressed_stream_for_gzip(self) -> None:
        payload = b'{"role": "user", "content": "hi"}' * 8  # 8 occurrences
        compressed = _gzip(payload)
        limiter = AdmissionLimiter(max_history_messages=8)
        measurement = limiter.admit(compressed)
        self.assertEqual(measurement.history_messages, 8)
        with self.assertRaises(SafetyError) as caught:
            AdmissionLimiter(max_history_messages=7).admit(compressed)
        self.assertEqual(
            str(caught.exception), _expected_limit_message(DIMENSION_HISTORY_MESSAGES)
        )


class OccurrenceCounterTests(unittest.TestCase):
    """White-box: the streaming count must equal bytes.count for every split."""

    _NEEDLE = b'"role"'

    def _assert_split_invariant(self, payload: bytes) -> None:
        expected = payload.count(self._NEEDLE)
        for size in (1, 2, 3, 5, 8, 64, 4096):
            counter = _OccurrenceCounter(self._NEEDLE)
            for i in range(0, len(payload), size):
                counter.feed(payload[i : i + size])
            self.assertEqual(counter.count, expected, f"chunk size {size}")

    def test_streaming_matches_whole_buffer_on_adversarial_payload(self) -> None:
        crafted = (
            b'"role"' * 3
            + b'"rol'
            + b'e"'
            + b'"role"role"rol'
            + b'e"role"'
            + b'"rolerole"'
        )
        self._assert_split_invariant(crafted)

    def test_streaming_matches_whole_buffer_on_random_payload(self) -> None:
        rng = random.Random(20261004)
        alphabet = b'"role x'
        payload = bytes(rng.choice(alphabet) for _ in range(5000))
        self._assert_split_invariant(payload)


class HistoryAndTextTests(unittest.TestCase):
    def test_history_structured_count_at_limit_passes(self) -> None:
        limiter = AdmissionLimiter(max_history_messages=12)
        measurement = limiter.admit(b"ignored body", history_messages=12)
        self.assertEqual(measurement.history_messages, 12)

    def test_history_structured_count_over_limit_rejected(self) -> None:
        limiter = AdmissionLimiter(max_history_messages=12)
        with self.assertRaises(SafetyError) as caught:
            limiter.admit(b"ignored body", history_messages=13)
        self.assertEqual(
            str(caught.exception), _expected_limit_message(DIMENSION_HISTORY_MESSAGES)
        )

    def test_history_structured_count_wins_over_heuristic(self) -> None:
        body = b'{"role": "x"}' * 50  # heuristic would count 50
        limiter = AdmissionLimiter(max_history_messages=2)
        measurement = limiter.admit(body, history_messages=2)
        self.assertEqual(measurement.history_messages, 2)

    def test_history_lightweight_count_on_raw_bytes(self) -> None:
        body = b'{"role": "user", "content": "a"}' * 7  # 7 occurrences
        limiter = AdmissionLimiter(max_history_messages=7)
        self.assertEqual(limiter.admit(body).history_messages, 7)
        with self.assertRaises(SafetyError) as caught:
            AdmissionLimiter(max_history_messages=6).admit(body)
        self.assertEqual(
            str(caught.exception), _expected_limit_message(DIMENSION_HISTORY_MESSAGES)
        )

    def test_history_unconfigured_not_measured(self) -> None:
        measurement = AdmissionLimiter().admit(b'{"role": "x"}' * 9)
        self.assertIsNone(measurement.history_messages)

    def test_history_rejects_non_int_and_negative(self) -> None:
        limiter = AdmissionLimiter()
        with self.assertRaises(TypeError):
            limiter.admit(b"body", history_messages=True)
        with self.assertRaises(TypeError):
            limiter.admit(b"body", history_messages="3")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            limiter.admit(b"body", history_messages=-1)

    def test_text_chars_at_limit_passes(self) -> None:
        limiter = AdmissionLimiter(max_text_chars=1000)
        measurement = limiter.admit(b"body", text_chars=1000)
        self.assertEqual(measurement.text_chars, 1000)

    def test_text_chars_over_limit_rejected(self) -> None:
        limiter = AdmissionLimiter(max_text_chars=1000)
        with self.assertRaises(SafetyError) as caught:
            limiter.admit(b"body", text_chars=1001)
        self.assertEqual(
            str(caught.exception), _expected_limit_message(DIMENSION_TEXT_CHARS)
        )

    def test_text_chars_required_when_configured(self) -> None:
        limiter = AdmissionLimiter(max_text_chars=1000)
        with self.assertRaises(TypeError):
            limiter.admit(b"body")

    def test_text_chars_optional_when_unconfigured(self) -> None:
        measurement = AdmissionLimiter().admit(b"body")
        self.assertIsNone(measurement.text_chars)


class DimensionOrderTests(unittest.TestCase):
    def test_first_exceeding_dimension_is_body_bytes(self) -> None:
        limiter = AdmissionLimiter(
            max_body_bytes=10,
            max_decompressed_bytes=10,
            max_expansion_ratio=1.0,
            max_history_messages=0,
            max_text_chars=0,
        )
        with self.assertRaises(SafetyError) as caught:
            limiter.admit(
                _gzip(_BOMB), history_messages=99, text_chars=99
            )
        self.assertEqual(str(caught.exception), _expected_limit_message(DIMENSION_BODY_BYTES))

    def test_decompressed_reported_before_ratio(self) -> None:
        limiter = AdmissionLimiter(
            max_decompressed_bytes=100, max_expansion_ratio=1.0
        )
        with self.assertRaises(SafetyError) as caught:
            limiter.admit(_gzip(_BOMB))
        self.assertEqual(
            str(caught.exception), _expected_limit_message(DIMENSION_DECOMPRESSED_BYTES)
        )

    def test_ratio_reported_when_absolute_size_allows(self) -> None:
        limiter = AdmissionLimiter(
            max_decompressed_bytes=1 << 20, max_expansion_ratio=1.0
        )
        with self.assertRaises(SafetyError) as caught:
            limiter.admit(_gzip(_BOMB))
        self.assertEqual(
            str(caught.exception), _expected_limit_message(DIMENSION_EXPANSION_RATIO)
        )

    def test_history_reported_before_text(self) -> None:
        limiter = AdmissionLimiter(max_history_messages=1, max_text_chars=1)
        body = b'{"role": "x"}' * 5
        with self.assertRaises(SafetyError) as caught:
            limiter.admit(body, text_chars=99)
        self.assertEqual(
            str(caught.exception), _expected_limit_message(DIMENSION_HISTORY_MESSAGES)
        )


class AllDimensionsWithinLimitsTests(unittest.TestCase):
    def test_every_dimension_exactly_at_limit_passes_together(self) -> None:
        payload = _gzip(b'{"role": "m"}' * 4)  # 4 history occurrences, incompressible-ish
        limiter = AdmissionLimiter(
            max_body_bytes=len(payload),
            max_decompressed_bytes=4 * len(b'{"role": "m"}'),
            max_expansion_ratio=len(b'{"role": "m"}' * 4) / len(payload),
            max_history_messages=4,
            max_text_chars=300,
        )
        measurement = limiter.admit(payload, text_chars=300)
        self.assertEqual(measurement.body_bytes, len(payload))
        self.assertEqual(measurement.decompressed_bytes, 4 * len(b'{"role": "m"}'))
        self.assertEqual(measurement.history_messages, 4)
        self.assertEqual(measurement.text_chars, 300)


class ConcurrencyTests(unittest.TestCase):
    def test_slots_acquired_released_and_reused(self) -> None:
        limiter = AdmissionLimiter(max_concurrency=2)
        p1 = limiter.acquire()
        p2 = limiter.acquire()
        self.assertEqual(limiter.snapshot(), (2, 0))
        p1.release()
        self.assertEqual(limiter.in_use, 1)
        p3 = limiter.acquire()  # released slot is immediately reusable
        self.assertTrue(p3.active)
        p2.release()
        p3.release()
        self.assertEqual(limiter.snapshot(), (0, 0))

    def test_full_pool_rejects_immediately_by_default(self) -> None:
        limiter = AdmissionLimiter(max_concurrency=1)
        permit = limiter.acquire()
        started = time.monotonic()
        with self.assertRaises(SafetyError) as caught:
            limiter.acquire()
        # Immediate rejection: nowhere near any wait budget.
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(caught.exception.code, SafetyCode.ADMISSION_LIMIT_EXCEEDED)
        self.assertEqual(
            str(caught.exception), _expected_limit_message(DIMENSION_CONCURRENCY)
        )
        self.assertEqual(limiter.snapshot(), (1, 0))  # holder unaffected
        permit.release()
        self.assertEqual(limiter.in_use, 0)

    def test_bounded_wait_acquires_slot_after_release(self) -> None:
        limiter = AdmissionLimiter(
            max_concurrency=1, wait_timeout=10.0, max_waiters=1
        )
        holder = limiter.acquire()
        waiter = _AcquireThread(limiter, timeout=10.0)
        waiter.start()
        self.assertTrue(
            _wait_for(lambda: limiter.snapshot() == (1, 1)),
            "waiter did not register while the pool was full",
        )
        holder.release()
        waiter.join(timeout=20)
        self.assertFalse(waiter.is_alive())
        status, permit = waiter.outcome
        self.assertEqual(status, "permit")
        self.assertTrue(permit.active)
        self.assertEqual(limiter.in_use, 1)
        permit.release()
        self.assertEqual(limiter.snapshot(), (0, 0))

    def test_bounded_wait_rejects_after_timeout(self) -> None:
        limiter = AdmissionLimiter(
            max_concurrency=1, wait_timeout=0.25, max_waiters=1
        )
        holder = limiter.acquire()
        waiter = _AcquireThread(limiter, timeout=0.25)
        waiter.start()
        waiter.join(timeout=20)
        self.assertFalse(waiter.is_alive(), "waiter did not finish within join budget")
        status, error = waiter.outcome
        self.assertEqual(status, "raise")
        self.assertIsInstance(error, SafetyError)
        self.assertEqual(error.code, SafetyCode.ADMISSION_LIMIT_EXCEEDED)
        self.assertEqual(str(error), _expected_limit_message(DIMENSION_CONCURRENCY))
        self.assertEqual(limiter.snapshot(), (1, 0))  # no waiter left behind
        holder.release()
        self.assertEqual(limiter.in_use, 0)

    def test_waiters_are_bounded(self) -> None:
        limiter = AdmissionLimiter(max_concurrency=1, wait_timeout=10.0, max_waiters=1)
        holder = limiter.acquire()
        waiter = _AcquireThread(limiter, timeout=10.0)
        waiter.start()
        self.assertTrue(
            _wait_for(lambda: limiter.snapshot() == (1, 1)),
            "first waiter did not register",
        )
        # The waiter pool is full: extra callers are rejected immediately.
        started = time.monotonic()
        with self.assertRaises(SafetyError) as caught:
            limiter.acquire(timeout=10.0)
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual(
            str(caught.exception), _expected_limit_message(DIMENSION_CONCURRENCY)
        )
        holder.release()
        waiter.join(timeout=20)
        self.assertFalse(waiter.is_alive())
        status, permit = waiter.outcome
        self.assertEqual(status, "permit")
        permit.release()
        self.assertEqual(limiter.snapshot(), (0, 0))

    def test_context_manager_releases_on_exception(self) -> None:
        limiter = AdmissionLimiter(max_concurrency=1)
        with self.assertRaises(RuntimeError):
            with limiter.acquire():
                self.assertEqual(limiter.in_use, 1)
                raise RuntimeError("work failed")
        self.assertEqual(limiter.in_use, 0)  # exception path still released

    def test_release_is_idempotent_and_does_not_corrupt_pool(self) -> None:
        limiter = AdmissionLimiter(max_concurrency=1)
        permit = limiter.acquire()
        permit.release()
        permit.release()  # second release is a no-op, not a negative count
        self.assertFalse(permit.active)
        self.assertEqual(limiter.snapshot(), (0, 0))
        again = limiter.acquire()
        again.release()
        self.assertEqual(limiter.in_use, 0)

    def test_repeated_cycles_leave_no_slot_leak(self) -> None:
        limiter = AdmissionLimiter(max_concurrency=3)
        for _ in range(50):
            permits = [limiter.acquire() for _ in range(3)]
            for permit in permits:
                permit.release()
        self.assertEqual(limiter.snapshot(), (0, 0))

    def test_permit_reusable_across_threads(self) -> None:
        limiter = AdmissionLimiter(max_concurrency=1)
        permit = limiter.acquire()
        releaser = threading.Thread(target=permit.release)
        releaser.start()
        releaser.join(timeout=10)
        self.assertFalse(releaser.is_alive())
        self.assertEqual(limiter.in_use, 0)

    def test_acquire_argument_validation(self) -> None:
        limiter = AdmissionLimiter()
        with self.assertRaises(TypeError):
            limiter.acquire(timeout="1")
        with self.assertRaises(ValueError):
            limiter.acquire(timeout=-0.5)
        with self.assertRaises(ValueError):
            limiter.acquire(timeout=float("nan"))
        with self.assertRaises(ValueError):
            limiter.acquire(timeout=float("inf"))
        limiter.acquire().release()

    def test_constructor_validation(self) -> None:
        with self.assertRaises(ValueError):
            AdmissionLimiter(max_concurrency=0)
        with self.assertRaises(TypeError):
            AdmissionLimiter(max_concurrency=True)
        with self.assertRaises(TypeError):
            AdmissionLimiter(max_concurrency="2")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            AdmissionLimiter(max_body_bytes=-1)
        with self.assertRaises(TypeError):
            AdmissionLimiter(max_body_bytes=True)
        with self.assertRaises(ValueError):
            AdmissionLimiter(max_decompressed_bytes=-1)
        with self.assertRaises(ValueError):
            AdmissionLimiter(max_history_messages=-1)
        with self.assertRaises(ValueError):
            AdmissionLimiter(max_text_chars=-1)
        with self.assertRaises(TypeError):
            AdmissionLimiter(max_expansion_ratio="2")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            AdmissionLimiter(max_expansion_ratio=-0.5)
        with self.assertRaises(ValueError):
            AdmissionLimiter(max_expansion_ratio=float("nan"))
        with self.assertRaises(ValueError):
            AdmissionLimiter(wait_timeout=-1)
        with self.assertRaises(ValueError):
            AdmissionLimiter(max_waiters=-1)


class CanaryAndDeterminismTests(unittest.TestCase):
    def test_public_message_is_code_plus_static_dimension_only(self) -> None:
        cases = [
            (AdmissionLimiter(max_body_bytes=1), b"xx", DIMENSION_BODY_BYTES),
            (
                AdmissionLimiter(max_decompressed_bytes=1),
                _gzip(b"xx"),
                DIMENSION_DECOMPRESSED_BYTES,
            ),
            (
                AdmissionLimiter(max_expansion_ratio=1.0),
                _gzip(_BOMB),
                DIMENSION_EXPANSION_RATIO,
            ),
            (
                AdmissionLimiter(max_history_messages=0),
                b'{"role": "x"}',
                DIMENSION_HISTORY_MESSAGES,
            ),
            (
                AdmissionLimiter(max_text_chars=0),
                None,
                DIMENSION_TEXT_CHARS,
            ),
        ]
        for limiter, body, dimension in cases:
            with self.subTest(dimension=dimension):
                with self.assertRaises(SafetyError) as caught:
                    if body is None:
                        limiter.admit(b"", text_chars=1)
                    else:
                        limiter.admit(body)
                self.assertEqual(
                    str(caught.exception), _expected_limit_message(dimension)
                )

    def test_no_business_text_or_canary_in_public_message(self) -> None:
        business = f"机密 {CANARY} 内容"
        body = business.encode("utf-8") * 64
        with self.assertRaises(SafetyError) as caught:
            AdmissionLimiter(max_body_bytes=1).admit(body)
        self.assertNotIn(CANARY, str(caught.exception))
        self.assertNotIn("机密", str(caught.exception))
        # History heuristic path: canary hidden in business content.
        history_body = (f'{{"role": "user", "content": "{CANARY}"}}').encode("utf-8") * 4
        with self.assertRaises(SafetyError) as caught_hist:
            AdmissionLimiter(max_history_messages=1).admit(history_body)
        self.assertNotIn(CANARY, str(caught_hist.exception))
        # Concurrency path: message is exactly code + static dimension name.
        limiter = AdmissionLimiter(max_concurrency=1)
        permit = limiter.acquire()
        with self.assertRaises(SafetyError) as caught_conc:
            limiter.acquire()
        self.assertEqual(
            str(caught_conc.exception), _expected_limit_message(DIMENSION_CONCURRENCY)
        )
        permit.release()

    def test_limit_errors_carry_no_exception_chain(self) -> None:
        attempts = [
            lambda: AdmissionLimiter(max_body_bytes=1).admit(b"xx"),
            lambda: AdmissionLimiter(max_decompressed_bytes=1).admit(_gzip(b"xx")),
            lambda: AdmissionLimiter(max_history_messages=0).admit(b'{"role": "x"}'),
            lambda: AdmissionLimiter(max_text_chars=0).admit(b"", text_chars=1),
        ]
        holder = AdmissionLimiter(max_concurrency=1)
        permit = holder.acquire()
        attempts.append(lambda: holder.acquire())
        for attempt in attempts:
            with self.assertRaises(SafetyError) as caught:
                attempt()
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)
        permit.release()

    def test_admission_verdicts_are_deterministic(self) -> None:
        payload = _gzip(('{"role": "m"}' * 4).encode("utf-8"))
        limiter = AdmissionLimiter(
            max_body_bytes=len(payload),
            max_decompressed_bytes=64,
            max_history_messages=4,
            max_text_chars=64,
        )
        first = limiter.admit(payload, text_chars=64)
        second = limiter.admit(payload, text_chars=64)
        self.assertEqual(first, second)
        rejecting = AdmissionLimiter(max_body_bytes=1)
        messages = set()
        for _ in range(3):
            with self.assertRaises(SafetyError) as caught:
                rejecting.admit(b"xx")
            messages.add(str(caught.exception))
        self.assertEqual(len(messages), 1)


if __name__ == "__main__":
    unittest.main()
