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
        self.max_buffer_bytes = max_buffer_bytes
        self._byte_buffer = bytearray()
        self._current_event_type: str = "message"
        self._current_data_lines: list[str] = []
        self._current_id: str | None = None
        self._current_retry: int | None = None

    def feed(self, chunk: bytes | str) -> Iterator[ServerSentEvent]:
        """Feed a chunk of bytes or string and yield any completed SSE events."""
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        if not isinstance(chunk, (bytes, bytearray)):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "chunk must be bytes or string")

        if len(self._byte_buffer) + len(chunk) > self.max_buffer_bytes:
            raise SafetyError(SafetyCode.ADMISSION_LIMIT_EXCEEDED, "SSE stream buffer limit exceeded")

        self._byte_buffer.extend(chunk)

        # Process lines from _byte_buffer
        while True:
            line_bytes, has_line = self._extract_next_line()
            if not has_line:
                break

            # Decode line to text
            try:
                line = line_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SafetyError(SafetyCode.INVALID_UTF8, "corrupted UTF-8 in SSE stream") from exc

            # Dispatch on empty line
            if not line:
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
                self._current_id = value
            elif field == "retry":
                try:
                    self._current_retry = int(value.strip())
                except ValueError:
                    pass  # Non-integer retry is ignored per WHATWG spec

    def flush(self) -> Iterator[ServerSentEvent]:
        """Flush remaining buffer at stream end."""
        if self._byte_buffer:
            try:
                line = self._byte_buffer.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SafetyError(SafetyCode.INVALID_UTF8, "incomplete UTF-8 at stream end") from exc
            self._byte_buffer.clear()
            if line:
                if line.startswith("data:"):
                    v = line[5:]
                    if v.startswith(" "):
                        v = v[1:]
                    self._current_data_lines.append(v)
                if self._current_data_lines:
                    yield ServerSentEvent(
                        event=self._current_event_type,
                        data="\n".join(self._current_data_lines),
                        id=self._current_id,
                        retry=self._current_retry,
                    )
        self._current_event_type = "message"
        self._current_data_lines = []
        self._current_id = None
        self._current_retry = None

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
