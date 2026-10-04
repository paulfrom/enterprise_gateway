"""Tests for P-07 SSE incremental parser and state machine."""

from __future__ import annotations

import unittest

from infra.errors import SafetyCode, SafetyError
from protocol.sse import ServerSentEvent, SseIncrementalParser


class TestSseIncrementalParser(unittest.TestCase):
    def test_exact_event_budget_cr_eof_and_split_crlf(self):
        for raw in (b"data:" + b"x" * 93 + b"\r\r", b"data:" + b"x" * 93 + b"\r\n\r\n"):
            for cut in range(len(raw) + 1):
                parser = SseIncrementalParser(max_buffer_bytes=100)
                events = list(parser.feed(raw[:cut])) + list(parser.feed(raw[cut:])) + list(parser.flush())
                self.assertEqual(["x" * 93], [event.data for event in events])

    def test_accumulated_multiline_event_budget_and_eof_truncation(self):
        parser = SseIncrementalParser(max_buffer_bytes=40)
        list(parser.feed(b"data: " + b"x" * 15 + b"\n"))
        with self.assertRaises(SafetyError):
            list(parser.feed(b"data: " + b"y" * 15 + b"\n"))
        for content in (b"data: incomplete", b"data: complete\n", b"data: \xe4"):
            parser = SseIncrementalParser()
            list(parser.feed(content))
            with self.assertRaises(SafetyError):
                list(parser.flush())

    def test_every_byte_crlf_multiline_and_utf8_corruption(self):
        parser = SseIncrementalParser()
        result = []
        for byte in "data: 公司甲\r\ndata: second\r\n\r\n".encode():
            result.extend(parser.feed(bytes([byte])))
        self.assertEqual(["公司甲\nsecond"], [item.data for item in result])
        self.assertEqual([], list(parser.flush()))
        parser = SseIncrementalParser()
        list(parser.feed(b"data: \xe4"))
        with self.assertRaises(SafetyError):
            list(parser.feed(b"\xff\n\n"))

    def test_standard_message_dispatch(self) -> None:
        """Parses standard SSE message blocks."""
        parser = SseIncrementalParser()
        raw = b"event: update\ndata: {\"text\": \"hello\"}\nid: 1\n\n"
        events = list(parser.feed(raw))
        self.assertEqual(1, len(events))
        ev = events[0]
        self.assertEqual("update", ev.event)
        self.assertEqual('{"text": "hello"}', ev.data)
        self.assertEqual("1", ev.id)
        self.assertFalse(ev.is_comment)

    def test_crlf_and_cr_line_endings(self) -> None:
        """Handles CRLF, LF, and standalone CR transparently."""
        parser = SseIncrementalParser()
        raw = b"event: msg1\r\ndata: crlf\r\n\r\nevent: msg2\rdata: cr\r\revent: msg3\ndata: lf\n\n"
        events = list(parser.feed(raw))
        self.assertEqual(3, len(events))
        self.assertEqual("crlf", events[0].data)
        self.assertEqual("cr", events[1].data)
        self.assertEqual("lf", events[2].data)

    def test_multi_line_data_concatenation(self) -> None:
        """Multiple consecutive data fields in one event are joined by newline."""
        parser = SseIncrementalParser()
        raw = b"data: first line\ndata: second line\ndata: third line\n\n"
        events = list(parser.feed(raw))
        self.assertEqual(1, len(events))
        self.assertEqual("first line\nsecond line\nthird line", events[0].data)

    def test_arbitrary_single_byte_chunk_streaming(self) -> None:
        """Feed bytes one-by-one, including splitting multi-byte UTF-8 Chinese characters."""
        parser = SseIncrementalParser()
        text = "event: chat\ndata: 深度求索与克劳德正在进行安全对话\n\n"
        raw = text.encode("utf-8")

        events: list[ServerSentEvent] = []
        for byte in raw:
            events.extend(parser.feed(bytes([byte])))

        self.assertEqual(1, len(events))
        self.assertEqual("chat", events[0].event)
        self.assertEqual("深度求索与克劳德正在进行安全对话", events[0].data)

    def test_sse_comment_handling(self) -> None:
        """Comment lines starting with colon are tagged as comments."""
        parser = SseIncrementalParser()
        raw = b": keep-alive\n\ndata: real data\n\n"
        events = list(parser.feed(raw))
        self.assertEqual(2, len(events))
        self.assertTrue(events[0].is_comment)
        self.assertEqual("keep-alive", events[0].comment)
        self.assertFalse(events[1].is_comment)
        self.assertEqual("real data", events[1].data)

    def test_invalid_utf8_fails_closed(self) -> None:
        """Invalid UTF-8 sequence raises SafetyError(INVALID_UTF8)."""
        parser = SseIncrementalParser()
        bad_bytes = b"data: \xff\xfe\xfd\n\n"
        with self.assertRaises(SafetyError) as exc_info:
            list(parser.feed(bad_bytes))
        self.assertEqual(SafetyCode.INVALID_UTF8, exc_info.exception.code)

    def test_buffer_limit_exceeded_fails_closed(self) -> None:
        """Exceeding max buffer bytes raises ADMISSION_LIMIT_EXCEEDED."""
        parser = SseIncrementalParser(max_buffer_bytes=100)
        oversized = b"data: " + b"x" * 200 + b"\n\n"
        with self.assertRaises(SafetyError) as exc_info:
            list(parser.feed(oversized))
        self.assertEqual(SafetyCode.ADMISSION_LIMIT_EXCEEDED, exc_info.exception.code)


if __name__ == "__main__":
    unittest.main()
