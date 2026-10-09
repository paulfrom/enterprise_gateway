"""Executable span-union contracts, not evidence of a working detector."""

import itertools
import unittest

from infra.errors import SafetyCode, SafetyError
from masking.mapping import MappingContext
from detection.spans import Span, merge_spans, redact_text


KEY = bytes(range(32))


class SpanTests(unittest.TestCase):
    def test_union_never_loses_detected_character_coverage(self):
        ranges = [(start, end) for start in range(5) for end in range(start + 1, 6)]
        for first, second in itertools.product(ranges, repeat=2):
            spans = [Span(*first, "ORG", 3), Span(*second, "ID", 1)]
            merged = merge_spans(spans, text_length=5)
            expected = set(range(*first)) | set(range(*second))
            actual = {index for span in merged for index in range(span.start, span.end)}
            self.assertEqual(expected, actual)

    def test_nested_high_priority_span_does_not_shrink_coverage(self):
        result = merge_spans([Span(0, 10, "ORG", 3), Span(3, 5, "ID", 1)], text_length=10)
        self.assertEqual((Span(0, 10, "MIXED", 1),), result)

    def test_crossing_union_is_order_independent(self):
        spans = [Span(1, 5, "ORG", 2), Span(4, 8, "PERSON", 3), Span(7, 11, "ID", 1)]
        for order in itertools.permutations(spans):
            self.assertEqual((Span(1, 11, "MIXED", 1),), merge_spans(order, text_length=12))

    def test_adjacent_spans_remain_separate_and_unicode_offsets_roundtrip(self):
        text = "甲公司张三"
        spans = [Span(0, 3, "ORG", 2), Span(3, 5, "PERSON", 3)]
        self.assertEqual(tuple(spans), merge_spans(spans, text_length=len(text)))
        with MappingContext("domain", "v1", KEY) as context:
            masked = redact_text(text, spans, context)
            self.assertNotIn("甲公司", masked)
            self.assertNotIn("张三", masked)
            self.assertEqual(text, context.restore(masked))

    def test_secret_anywhere_blocks_before_mapping(self):
        with MappingContext("domain", "v1", KEY) as context:
            with self.assertRaisesRegex(SafetyError, "SECRET_DETECTED"):
                redact_text("abcdefghij", [Span(0, 10, "ORG", 2), Span(4, 5, "SECRET", 0)], context)
            self.assertEqual(0, context.entry_count)

    def test_invalid_span_fails_closed(self):
        for span in (Span(-1, 2, "ORG"), Span(1, 1, "ORG"), Span(0, 11, "ORG"), Span(0, 2, "ORG", 4)):
            with self.assertRaisesRegex(SafetyError, "INVALID_SPAN"):
                merge_spans([span], text_length=10)

    def test_redact_preserves_lookalike_literals_and_roundtrips(self):
        prefix = "联系<<ent或<ENT处理，主体"
        text = prefix + "甲公司"
        spans = [Span(len(prefix), len(text), "ORG", 3)]
        with MappingContext("domain", "v1", KEY) as context:
            masked = redact_text(text, spans, context)
            self.assertIn("<<ent", masked)
            self.assertIn("<ENT", masked)
            self.assertNotIn("甲公司", masked)
            self.assertEqual(text, context.restore(masked))
            self.assertEqual(1, context.entry_count)

    def test_redact_rejects_reserved_literal_text_without_echoing_content(self):
        canary = "CNRY-spans-redact-4884"
        with MappingContext("domain", "v1", KEY) as context:
            with self.assertRaises(SafetyError) as failure:
                redact_text(f"前文{canary}<<ENT后文", [Span(0, 2, "ORG", 3)], context)
            self.assertEqual(SafetyCode.RESERVED_TOKEN_LITERAL, failure.exception.code)
            self.assertNotIn(canary, str(failure.exception))
            self.assertNotIn(canary, repr(failure.exception))
            self.assertIsNone(failure.exception.__cause__)
            self.assertIsNone(failure.exception.__context__)
            self.assertEqual(0, context.entry_count)


if __name__ == "__main__":
    unittest.main()
