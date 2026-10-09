"""P-16 request admission limiter: bounded resource-dimension gate.

The limiter is the resource-dimension gate a request crosses before it may
enter the detection pipeline. It judges *resources only* — raw body size,
decompressed size, compression expansion, message count, business text
volume, and concurrency slots. It never parses protocol structure or
business fields; strict protocol validation is the P-04 ingress contract,
and the two gates compose instead of overlapping.

All limits are constructor-injected; ``None`` disables a dimension:

- ``max_body_bytes``: raw request body bytes.
- ``max_decompressed_bytes``: decompressed byte count of a gzip-compressed
  body (not applied to uncompressed input).
- ``max_expansion_ratio``: decompressed/raw byte ratio of a gzip-compressed
  body (not applied to uncompressed input).
- ``max_history_messages``: message/history count. Structured counted input
  is supplied by the caller; when absent the documented lightweight
  heuristic counts non-overlapping occurrences of ``b'"role"'`` in the raw
  (or decompressed) body. The heuristic is a resource measurement, not a
  protocol parse — P-04 remains authoritative for protocol semantics.
- ``max_text_chars``: total business text characters. Always a structured
  caller-measured count (e.g. summed fragment lengths downstream of P-04);
  mandatory when the dimension is configured.
- ``max_concurrency``: admission slots (default 1).
- ``wait_timeout`` / ``max_waiters``: bounded-wait policy for slots
  (default ``0.0`` / ``0``).

Verdict semantics: a measured value exactly at its limit passes; any value
above it rejects the request with
``SafetyError(SafetyCode.ADMISSION_LIMIT_EXCEEDED, "<static dimension name>")``.
There is no truncation, no degradation, and no bypass — a rejected request
is never executed. Dimension checks run in a fixed, documented order and the
first exceeding dimension is reported, so equal inputs always produce equal
verdicts and equal public messages.

Compression: a body starting with the gzip magic bytes is measured by
streaming decompression in fixed-size chunks — the decompressed content is
never fully materialized in memory, counting stops at the first chunk that
exceeds ``max_decompressed_bytes`` (immediate rejection), and the expansion
ratio is ``decompressed_bytes / len(body)``. A malformed or truncated gzip
body cannot be measured to completion; per ADR-0004 (unified controlled
errors) the native ``gzip``/``zlib`` failure — ``OSError``/``BadGzipFile``,
``EOFError``, ``zlib.error`` — is mapped to
``SafetyError(SafetyCode.INVALID_PAYLOAD, "gzip_stream")`` with no exception
chain. Well-formedness of compressed payloads is not a resource dimension,
but admission fails closed all the same: an unmeasurable stream never
reaches a verdict and nothing downstream runs.

Concurrency semantics (chosen policy, written down): when every slot is
held, :meth:`AdmissionLimiter.acquire` **rejects immediately** by default —
the default queue depth is zero and waiting callers are bounded by
construction. Bounded waiting is opt-in: with ``max_waiters >= 1`` a caller
may block up to ``wait_timeout`` seconds for a slot; if no slot frees within
the budget, the acquisition is rejected with the same controlled error. The
number of concurrently waiting callers never exceeds ``max_waiters`` —
there is no unbounded request queue anywhere in this component. A granted
slot is held by an :class:`AdmissionPermit`: released via ``release()``
(idempotent) or the context manager, which also releases on exception paths.
Released slots are immediately reusable.

D-10 alignment: one admission permit authorizes occupying one compute slot
of the bounded inference executor. Wire ``max_concurrency`` equal to the
executor's ``max_workers`` (and the executor's ``max_pending=0``) so that
queueing happens here — bounded by ``max_waiters`` — instead of piling up
inside the executor. The limiter never imports or drives the executor; the
orchestration (D-12/P-18) composes the two.

Determinism: dimension verdicts are pure functions of the measured values.
Concurrency verdicts are timing-dependent by nature, but every outcome is
bounded and controlled: immediate rejection, acquisition within the wait
budget, or rejection when the budget expires. Nothing here runs work.
"""

from __future__ import annotations

import gzip
import io
import threading
import time
import zlib
from dataclasses import dataclass

from infra.errors import SafetyCode, SafetyError

__all__ = [
    "AdmissionLimiter",
    "AdmissionPermit",
    "AdmissionMeasurement",
    "DIMENSION_BODY_BYTES",
    "DIMENSION_DECOMPRESSED_BYTES",
    "DIMENSION_EXPANSION_RATIO",
    "DIMENSION_HISTORY_MESSAGES",
    "DIMENSION_TEXT_CHARS",
    "DIMENSION_CONCURRENCY",
]

DIMENSION_BODY_BYTES = "body_bytes"
DIMENSION_DECOMPRESSED_BYTES = "decompressed_bytes"
DIMENSION_EXPANSION_RATIO = "expansion_ratio"
DIMENSION_HISTORY_MESSAGES = "history_messages"
DIMENSION_TEXT_CHARS = "text_chars"
DIMENSION_CONCURRENCY = "concurrency"

_GZIP_MAGIC = b"\x1f\x8b"
_READ_CHUNK = 64 * 1024
_HISTORY_NEEDLE = b'"role"'
# Static detail for the ADR-0004 controlled mapping of an unmeasurable
# compressed stream; never carries submitted content.
_DETAIL_GZIP_STREAM = "gzip_stream"


class _OccurrenceCounter:
    """Streaming non-overlapping byte-substring count.

    Feeding every chunk of a stream in any split yields the same total as
    ``concatenated.count(needle)``; at most ``len(needle) - 1`` bytes of the
    stream are retained. The scan position after the last accepted match is
    carried across chunk boundaries so split-invariance holds exactly, not
    approximately.
    """

    __slots__ = ("_needle", "_carry", "_scan_from", "count")

    def __init__(self, needle: bytes) -> None:
        if not needle:
            raise ValueError("needle must not be empty")
        self._needle = needle
        self._carry = b""
        self._scan_from = 0
        self.count = 0

    def feed(self, chunk: bytes) -> None:
        window = self._carry + chunk
        needle = self._needle
        n = len(needle)
        i = self._scan_from
        last_end: int | None = None
        while True:
            j = window.find(needle, i)
            if j < 0:
                break
            self.count += 1
            i = j + n
            last_end = i
        keep = n - 1
        split = len(window) - keep
        if split <= 0:
            # The whole window is smaller than the carry budget; keep it.
            # The scan constraint is the end of the last accepted match
            # (which may predate this feed), remapped into the kept window.
            self._carry = window
            self._scan_from = last_end if last_end is not None else self._scan_from
            return
        self._carry = window[split:]
        # A match may not start before the end of the last accepted match,
        # whenever that match happened; remap that absolute position into
        # the new window. With no match on record the next window is
        # scanned from the beginning.
        if last_end is not None:
            self._scan_from = max(0, last_end - split)
        else:
            self._scan_from = max(0, self._scan_from - split)


@dataclass(frozen=True, slots=True)
class AdmissionMeasurement:
    """What :meth:`AdmissionLimiter.admit` measured and checked.

    ``decompressed_bytes``/``expansion_ratio`` are ``None`` for uncompressed
    input (the dimensions do not apply). ``history_messages`` is ``None``
    when neither a structured count was supplied nor the dimension is
    configured. ``text_chars`` is ``None`` when no structured count was
    supplied. A field being present never means a check ran: only configured
    limits are enforced.
    """

    body_bytes: int
    decompressed_bytes: int | None
    expansion_ratio: float | None
    history_messages: int | None
    text_chars: int | None


def _checked_optional_int(name: str, value: int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int or None")
    if value < 0:
        raise ValueError(f"{name} must be >= 0")
    return value


def _checked_finite_number(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a number")
    result = float(value)
    if result != result or result in (float("inf"), float("-inf")):
        raise ValueError(f"{name} must be finite")
    return result


def _checked_count(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int")
    if value < 0:
        raise ValueError(f"{name} must be >= 0")
    return value


class AdmissionPermit:
    """Handle for one held admission slot.

    Use as a context manager so the slot is released on every exit path,
    including exceptions. ``release()`` is idempotent; a released permit
    stays released. A permit may be released from a different thread than
    the one that acquired it.
    """

    __slots__ = ("_limiter", "_lock", "_released")

    def __init__(self, limiter: AdmissionLimiter) -> None:
        self._limiter = limiter
        self._lock = threading.Lock()
        self._released = False

    @property
    def active(self) -> bool:
        with self._lock:
            return not self._released

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
        self._limiter._release_slot()

    def __enter__(self) -> AdmissionPermit:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()


class AdmissionLimiter:
    """Resource-dimension admission gate with bounded concurrency slots.

    Parameters
    ----------
    max_body_bytes, max_decompressed_bytes, max_history_messages, max_text_chars:
        Optional integer limits; ``None`` (default) disables the dimension.
    max_expansion_ratio:
        Optional float limit on decompressed/raw byte ratio of compressed
        input; ``None`` (default) disables the dimension.
    max_concurrency:
        Number of admission slots (default 1, must be >= 1).
    wait_timeout:
        Default per-acquisition wait budget in seconds (default ``0.0`` =
        never wait: a full slot pool rejects immediately).
    max_waiters:
        Maximum number of callers concurrently waiting for a slot
        (default ``0``: waiting is disabled entirely, so the default policy
        rejects the moment all slots are held).

    The limiter owns no threads, no background tasks, and no unbounded
    buffer. ``admit`` is a pure measurement-plus-check and is safe to call
    concurrently; slots are guarded by a single condition variable.
    """

    def __init__(
        self,
        *,
        max_body_bytes: int | None = None,
        max_decompressed_bytes: int | None = None,
        max_expansion_ratio: float | None = None,
        max_history_messages: int | None = None,
        max_text_chars: int | None = None,
        max_concurrency: int = 1,
        wait_timeout: float = 0.0,
        max_waiters: int = 0,
    ) -> None:
        self._max_body_bytes = _checked_optional_int("max_body_bytes", max_body_bytes)
        self._max_decompressed_bytes = _checked_optional_int(
            "max_decompressed_bytes", max_decompressed_bytes
        )
        if max_expansion_ratio is None:
            self._max_expansion_ratio: float | None = None
        else:
            ratio = _checked_finite_number("max_expansion_ratio", max_expansion_ratio)
            if ratio < 0:
                raise ValueError("max_expansion_ratio must be >= 0")
            self._max_expansion_ratio = ratio
        self._max_history_messages = _checked_optional_int(
            "max_history_messages", max_history_messages
        )
        self._max_text_chars = _checked_optional_int("max_text_chars", max_text_chars)
        if isinstance(max_concurrency, bool) or not isinstance(max_concurrency, int):
            raise TypeError("max_concurrency must be an int")
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        self._max_concurrency = max_concurrency
        wait = _checked_finite_number("wait_timeout", wait_timeout)
        if wait < 0:
            raise ValueError("wait_timeout must be >= 0")
        self._wait_timeout = wait
        if isinstance(max_waiters, bool) or not isinstance(max_waiters, int):
            raise TypeError("max_waiters must be an int")
        if max_waiters < 0:
            raise ValueError("max_waiters must be >= 0")
        self._max_waiters = max_waiters
        self._cond = threading.Condition()
        self._in_use = 0
        self._waiters = 0

    @property
    def max_concurrency(self) -> int:
        return self._max_concurrency

    @property
    def in_use(self) -> int:
        with self._cond:
            return self._in_use

    def snapshot(self) -> tuple[int, int]:
        """Return ``(slots_in_use, waiters)`` (test/observability hook)."""
        with self._cond:
            return (self._in_use, self._waiters)

    # -- dimension checks ---------------------------------------------------

    def _check(self, dimension: str, measured: float, limit: float | None) -> None:
        if limit is not None and measured > limit:
            raise SafetyError(SafetyCode.ADMISSION_LIMIT_EXCEEDED, dimension) from None

    def admit(
        self,
        body: bytes | bytearray | memoryview,
        *,
        history_messages: int | None = None,
        text_chars: int | None = None,
    ) -> AdmissionMeasurement:
        """Measure and check the configured dimensions of one request body.

        Checks run in the fixed order ``body_bytes`` → ``decompressed_bytes``
        → ``expansion_ratio`` → ``history_messages`` → ``text_chars``; the
        first exceeding dimension raises. A value exactly at its limit
        passes. Returns the measured values. Limit violations raise
        ``SafetyError(ADMISSION_LIMIT_EXCEEDED, "<dimension name>")``; a
        compressed body whose stream cannot be measured to completion raises
        ``SafetyError(INVALID_PAYLOAD, "gzip_stream")`` (see module
        docstring).

        ``history_messages``/``text_chars`` are structured counts supplied by
        the caller. When ``max_history_messages`` is configured and no
        structured count is given, the documented lightweight heuristic is
        measured on the raw (or decompressed) body. When ``max_text_chars``
        is configured a structured ``text_chars`` count is mandatory —
        omitting it is a caller error (``TypeError``), never a silent skip.
        """
        if not isinstance(body, (bytes, bytearray, memoryview)):
            raise TypeError("body must be a bytes-like object")
        body = bytes(body)
        body_bytes = len(body)
        self._check(DIMENSION_BODY_BYTES, body_bytes, self._max_body_bytes)

        compressed = body[:2] == _GZIP_MAGIC
        history_structured = (
            None
            if history_messages is None
            else _checked_count("history_messages", history_messages)
        )
        text_structured = (
            None if text_chars is None else _checked_count("text_chars", text_chars)
        )

        wants_size = (
            self._max_decompressed_bytes is not None
            or self._max_expansion_ratio is not None
        )
        needs_history_stream = (
            self._max_history_messages is not None and history_structured is None
        )
        decompressed: int | None = None
        ratio: float | None = None
        history: int | None = history_structured
        if compressed and (wants_size or needs_history_stream):
            counter = _OccurrenceCounter(_HISTORY_NEEDLE) if needs_history_stream else None
            decompressed = self._stream_gzip(body, counter)
            if self._max_decompressed_bytes is not None:
                self._check(
                    DIMENSION_DECOMPRESSED_BYTES, decompressed, self._max_decompressed_bytes
                )
            ratio = decompressed / body_bytes
            self._check(DIMENSION_EXPANSION_RATIO, ratio, self._max_expansion_ratio)
            if history is None and counter is not None:
                history = counter.count
        elif needs_history_stream:
            # Uncompressed input: identical counting semantics to the
            # streaming path (one whole-buffer feed).
            history = body.count(_HISTORY_NEEDLE)

        # A configured dimension is always measured by construction above;
        # the ``-1`` sentinel only guards the impossible "configured but
        # unmeasured" state into a rejection instead of a silent pass.
        self._check(
            DIMENSION_HISTORY_MESSAGES,
            -1 if history is None else history,
            self._max_history_messages,
        )
        if text_structured is None and self._max_text_chars is not None:
            raise TypeError(
                "text_chars structured count is required when max_text_chars is configured"
            )
        self._check(
            DIMENSION_TEXT_CHARS,
            -1 if text_structured is None else text_structured,
            self._max_text_chars,
        )

        return AdmissionMeasurement(
            body_bytes=body_bytes,
            decompressed_bytes=decompressed,
            expansion_ratio=ratio,
            history_messages=history,
            text_chars=text_structured,
        )

    def _stream_gzip(self, body: bytes, counter: _OccurrenceCounter | None) -> int:
        """Stream-decompress ``body`` for measurement only; return the count.

        Counting stops at the first chunk whose cumulative size exceeds
        ``max_decompressed_bytes`` — the stream is abandoned immediately,
        which is the early-rejection guarantee: decompressed content is never
        fully materialized and a limit breach is reported as soon as it is
        provable. A stream the gzip/zlib layer cannot decode to completion
        (truncation, header/flag corruption, deflate or CRC failure) cannot
        be measured, so admission fails closed: the native error is mapped to
        ``SafetyError(SafetyCode.INVALID_PAYLOAD, "gzip_stream")``. The
        mapping is raised *outside* the ``except`` block (ADR-0004), so the
        ``SafetyError`` carries neither ``__cause__`` nor ``__context__``.
        The limit-breach ``SafetyError`` raised inside the loop is not part
        of the mapping — it propagates unchanged.
        """
        decompressed = 0
        unmeasurable = False
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(body), mode="rb") as stream:
                while True:
                    chunk = stream.read(_READ_CHUNK)
                    if not chunk:
                        break
                    decompressed += len(chunk)
                    if counter is not None:
                        counter.feed(chunk)
                    if (
                        self._max_decompressed_bytes is not None
                        and decompressed > self._max_decompressed_bytes
                    ):
                        raise SafetyError(
                            SafetyCode.ADMISSION_LIMIT_EXCEEDED, DIMENSION_DECOMPRESSED_BYTES
                        ) from None
        except (OSError, EOFError, zlib.error):
            # gzip.BadGzipFile is an OSError subclass; truncated streams
            # raise EOFError; corrupt deflate data raises zlib.error. Any of
            # them means the compressed payload is unmeasurable. Only the
            # flag escapes the handler — the controlled raise below happens
            # with no active exception, keeping the chain empty.
            unmeasurable = True
        if unmeasurable:
            raise SafetyError(SafetyCode.INVALID_PAYLOAD, _DETAIL_GZIP_STREAM) from None
        return decompressed

    # -- concurrency slots ---------------------------------------------------

    def acquire(self, *, timeout: float | None = None) -> AdmissionPermit:
        """Acquire one admission slot, or reject in a controlled way.

        ``timeout`` overrides the constructor ``wait_timeout`` for this call;
        ``None`` uses the configured default. With the default policy
        (``wait_timeout=0`` or ``max_waiters=0``) a full pool rejects
        immediately. Otherwise the call waits at most ``timeout`` seconds
        for a slot; on expiry it rejects. Waiting callers never exceed
        ``max_waiters`` — excess callers are rejected immediately.

        Raises
        ------
        SafetyError(ADMISSION_LIMIT_EXCEEDED)
            Detail is the static dimension name ``concurrency``.
        """
        wait = self._wait_timeout if timeout is None else _checked_finite_number("timeout", timeout)
        if wait < 0:
            raise ValueError("timeout must be >= 0")
        deadline = time.monotonic() + wait
        with self._cond:
            if self._in_use < self._max_concurrency:
                self._in_use += 1
                return AdmissionPermit(self)
            if wait <= 0 or self._waiters >= self._max_waiters:
                raise SafetyError(
                    SafetyCode.ADMISSION_LIMIT_EXCEEDED, DIMENSION_CONCURRENCY
                ) from None
            self._waiters += 1
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise SafetyError(
                            SafetyCode.ADMISSION_LIMIT_EXCEEDED, DIMENSION_CONCURRENCY
                        ) from None
                    self._cond.wait(remaining)
                    if self._in_use < self._max_concurrency:
                        self._in_use += 1
                        return AdmissionPermit(self)
            finally:
                self._waiters -= 1

    def _release_slot(self) -> None:
        with self._cond:
            if self._in_use > 0:
                self._in_use -= 1
                self._cond.notify(1)
