"""P-07 SSE incremental parser and state machine.

Implements byte-level incremental chunk buffering, UTF-8 boundary handling,
CRLF/LF line normalization, multi-line `data:` concatenation, comment ignoring,
and typed SSE event dispatching.
Fails closed with SafetyError on unrecoverable stream corruption.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from infra.errors import SafetyCode, SafetyError


@dataclass(frozen=True, slots=True)
class ServerSentEvent:
    """A fully framed and parsed Server-Sent Event."""

    event: str = "message"
    data: str = ""
    id: str | None = None
    retry: int | None = None
    is_comment: bool = False
    comment: str | None = None


class SseIncrementalParser:
    """Incremental byte-level Server-Sent Events parser (P-07).

    Accepts arbitrary byte chunks, handles partial UTF-8 sequences at chunk
    boundaries, splits lines on \\r\\n, \\r, or \\n, and accumulates fields
    until an empty line dispatches a ServerSentEvent.
    """

    def __init__(self, max_buffer_bytes: int = 1024 * 1024) -> None:
        if type(max_buffer_bytes) is not int or max_buffer_bytes <= 0:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "invalid SSE buffer budget")
        self.max_buffer_bytes = max_buffer_bytes
        self._byte_buffer = bytearray()
        self._current_event_type: str = "message"
        self._current_data_lines: list[str] = []
        self._current_id: str | None = None
        self._current_retry: int | None = None
        self._event_bytes = 0

    def feed(self, chunk: bytes | str) -> Iterator[ServerSentEvent]:
        """Consume arbitrary transport chunks without treating them as events.

        Copy only a bounded piece into the incomplete-line buffer, draining
        complete lines/events before accepting the next piece. The event cap
        continues to apply across pieces and across transport reads.
        """
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        if not isinstance(chunk, (bytes, bytearray)):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "chunk must be bytes or string")
        offset = 0
        while offset < len(chunk):
            allowance = self.max_buffer_bytes - self._event_bytes - len(self._byte_buffer)
            # One delimiter lookahead distinguishes CRLF from standalone CR.
            # The following LF is not extra event content; rejecting it would
            # make a boundary-sized CR frame depend on transport splitting.
            if allowance == 0 and self._byte_buffer.endswith(b"\r"):
                allowance = 1
            if allowance <= 0:
                raise SafetyError(SafetyCode.ADMISSION_LIMIT_EXCEEDED, "SSE incomplete line or event limit exceeded")
            piece = bytes(chunk[offset:offset + min(allowance, 65536)])
            offset += len(piece)
            yield from self._feed_piece(piece)

    def _feed_piece(self, chunk: bytes) -> Iterator[ServerSentEvent]:
        if len(self._byte_buffer) + len(chunk) > self.max_buffer_bytes:
            raise SafetyError(SafetyCode.ADMISSION_LIMIT_EXCEEDED, "SSE stream buffer limit exceeded")

        self._byte_buffer.extend(chunk)

        # Process lines from _byte_buffer
        while True:
            line_bytes, has_line = self._extract_next_line()
            if not has_line:
                break
            self._event_bytes += len(line_bytes) + 1
            if self._event_bytes > self.max_buffer_bytes:
                raise SafetyError(SafetyCode.ADMISSION_LIMIT_EXCEEDED, "SSE event limit exceeded")

            # Decode line to text
            try:
                line = line_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SafetyError(SafetyCode.INVALID_UTF8, "corrupted UTF-8 in SSE stream") from exc

            # Dispatch on empty line
            if not line:
                self._event_bytes = 0
                if self._current_data_lines or self._current_event_type != "message" or self._current_id is not None:
                    event = ServerSentEvent(
                        event=self._current_event_type,
                        data="\n".join(self._current_data_lines),
                        id=self._current_id,
                        retry=self._current_retry,
                    )
                    # Reset event state
                    self._current_event_type = "message"
                    self._current_data_lines = []
                    self._current_id = None
                    self._current_retry = None
                    yield event
                else:
                    self._current_retry = None
                continue

            # Comment line
            if line.startswith(":"):
                yield ServerSentEvent(is_comment=True, comment=line[1:].lstrip())
                continue

            # Field parsing
            if ":" in line:
                field, value = line.split(":", 1)
                if value.startswith(" "):
                    value = value[1:]
            else:
                field, value = line, ""

            if field == "event":
                self._current_event_type = value
            elif field == "data":
                self._current_data_lines.append(value)
            elif field == "id":
                if "\x00" in value:
                    raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "invalid SSE id")
                self._current_id = value
            elif field == "retry":
                try:
                    self._current_retry = int(value.strip())
                except ValueError:
                    pass  # Non-integer retry is ignored per WHATWG spec

    def flush(self) -> Iterator[ServerSentEvent]:
        """Reject incomplete application frames at EOF; no synthetic dispatch."""
        # A final CR is a valid line terminator, even without a following LF.
        if self._byte_buffer.endswith(b"\r"):
            yield from self._feed_piece(b"\n")
        if self._byte_buffer:
            try:
                self._byte_buffer.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SafetyError(SafetyCode.INVALID_UTF8, "incomplete UTF-8 at stream end") from exc
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "truncated SSE frame")
        if self._current_data_lines or self._current_event_type != "message" or self._current_id is not None:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "truncated SSE event")
        yield from ()
        self._current_event_type = "message"
        self._current_data_lines = []
        self._current_id = None
        self._current_retry = None

    def cancel(self) -> None:
        self._byte_buffer.clear()
        self._current_data_lines.clear()
        self._current_event_type = "message"
        self._current_id = None
        self._current_retry = None
        self._event_bytes = 0

    def _extract_next_line(self) -> tuple[bytes, bool]:
        """Extract a single line terminated by \\r\\n, \\n, or \\r."""
        buf = self._byte_buffer
        length = len(buf)
        if length == 0:
            return b"", False

        for i in range(length):
            byte = buf[i]
            if byte == ord("\n"):
                line = bytes(buf[:i])
                del buf[: i + 1]
                return line, True
            elif byte == ord("\r"):
                # Check for CRLF
                if i + 1 < length:
                    if buf[i + 1] == ord("\n"):
                        line = bytes(buf[:i])
                        del buf[: i + 2]
                        return line, True
                    else:
                        line = bytes(buf[:i])
                        del buf[: i + 1]
                        return line, True
                else:
                    # Incomplete trailing \r, wait for next byte
                    return b"", False

        return b"", False
