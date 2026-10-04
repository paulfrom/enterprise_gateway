"""Executable contracts for deterministic candidate-conflict resolution."""

import itertools
import unittest

from infra.errors import SafetyCode, SafetyError
from detection.ner_windowing import EntitySpan
from detection.span_resolver import (
    DetectionCandidate,
    ResolvedSpan,
    candidate_from,
    resolve_spans,
)
from detection.spans import Span


def _candidate(start, end, entity_type="ORG", priority=3, source="rule:phone"):
    return DetectionCandidate(start, end, entity_type, priority, source)


class CandidateValidationTests(unittest.TestCase):
    def test_out_of_bounds_and_inverted_candidates_fail_closed(self):
        bad = [
            _candidate(-1, 2),
            _candidate(2, 1),
            _candidate(3, 3),
            _candidate(0, 11),
        ]
        for candidate in bad:
            with self.subTest(candidate=candidate):
                with self.assertRaisesRegex(SafetyError, "INVALID_SPAN"):
                    resolve_spans([candidate], text_length=10)

    def test_invalid_entity_type_priority_and_source_fail_closed(self):
        bad = [
            _candidate(0, 2, entity_type="person"),
            _candidate(0, 2, entity_type=""),
            _candidate(0, 2, entity_type="A" * 33),
            _candidate(0, 2, priority=4),
            _candidate(0, 2, priority=-1),
            _candidate(0, 2, priority=True),
            _candidate(0, 2, priority="1"),
            _candidate(0, 2, source=""),
            _candidate(0, 2, source=None),
            _candidate(0, 2, source=123),
        ]
        for candidate in bad:
            with self.subTest(candidate=candidate):
                with self.assertRaisesRegex(SafetyError, "INVALID_SPAN"):
                    resolve_spans([candidate], text_length=10)

    def test_non_candidate_objects_fail_closed(self):
        for item in (Span(0, 2, "ORG"), (0, 2, "ORG"), None, "ORG"):
            with self.subTest(item=item):
                with self.assertRaisesRegex(SafetyError, "INVALID_SPAN"):
                    resolve_spans([item], text_length=10)

    def test_invalid_text_length_fails_closed(self):
        for text_length in (-1, 1.5, "10", None):
            with self.subTest(text_length=text_length):
                with self.assertRaisesRegex(SafetyError, "INVALID_TEXT_LENGTH"):
                    resolve_spans([], text_length=text_length)

    def test_error_is_chainless_and_message_carries_no_business_text(self):
        with self.assertRaises(SafetyError) as failure:
            resolve_spans([_candidate(0, 2, source="rule:super-secret-detector")], text_length=1)
        self.assertEqual(SafetyCode.INVALID_SPAN, failure.exception.code)
        self.assertEqual(str(failure.exception), "INVALID_SPAN")
        self.assertIsNone(failure.exception.__cause__)
        self.assertIsNone(failure.exception.__context__)


class SecretBlockingTests(unittest.TestCase):
    def test_priority_zero_anywhere_blocks_for_every_permutation(self):
        base = [
            _candidate(0, 3, "ORG", 3, "dict"),
            _candidate(2, 5, "PERSON", 2, "ner"),
            _candidate(5, 8, "ID", 1, "rule:id"),
        ]
        for position in range(4):
            secret = _candidate(position * 2, position * 2 + 1, "SECRET", 0, "rule:secret")
            group = base[:position] + [secret] + base[position:]
            for order in itertools.permutations(group):
                with self.subTest(position=position, order=order):
                    with self.assertRaisesRegex(SafetyError, "SECRET_DETECTED"):
                        resolve_spans(order, text_length=12)

    def test_validation_precedes_secret_blocking(self):
        with self.assertRaisesRegex(SafetyError, "INVALID_SPAN"):
            resolve_spans([_candidate(0, 99, "SECRET", 0)], text_length=10)


class MergeSemanticsTests(unittest.TestCase):
    def test_nested_candidate_merges_into_single_mixed_span(self):
        result = resolve_spans(
            [_candidate(0, 10, "ORG", 3, "rule:org"), _candidate(3, 5, "ID", 1, "dict")],
            text_length=10,
        )
        self.assertEqual(
            (ResolvedSpan(0, 10, "MIXED", 1, ("dict", "rule:org")),),
            result,
        )

    def test_crossing_candidates_merge_into_union_range(self):
        result = resolve_spans(
            [_candidate(1, 5, "ORG", 2, "rule:org"), _candidate(4, 8, "PERSON", 3, "ner")],
            text_length=12,
        )
        self.assertEqual((ResolvedSpan(1, 8, "MIXED", 2, ("ner", "rule:org")),), result)

    def test_adjacent_candidates_remain_separate(self):
        candidates = [_candidate(0, 3, "ORG", 2, "rule:org"), _candidate(3, 5, "PERSON", 3, "ner")]
        result = resolve_spans(candidates, text_length=5)
        self.assertEqual(
            (
                ResolvedSpan(0, 3, "ORG", 2, ("rule:org",)),
                ResolvedSpan(3, 5, "PERSON", 3, ("ner",)),
            ),
            result,
        )

    def test_same_type_overlap_keeps_entity_type(self):
        result = resolve_spans(
            [_candidate(0, 4, "PERSON", 3, "ner"), _candidate(2, 6, "PERSON", 2, "rule:name")],
            text_length=8,
        )
        self.assertEqual((ResolvedSpan(0, 6, "PERSON", 2, ("ner", "rule:name")),), result)

    def test_chain_of_crossings_collapses_into_one_span(self):
        candidates = [
            _candidate(1, 5, "ORG", 2, "rule:org"),
            _candidate(4, 8, "PERSON", 3, "ner"),
            _candidate(7, 11, "ID", 1, "rule:id"),
        ]
        result = resolve_spans(candidates, text_length=12)
        self.assertEqual((ResolvedSpan(1, 11, "MIXED", 1, ("ner", "rule:id", "rule:org")),), result)

    def test_empty_candidate_set_resolves_empty(self):
        self.assertEqual((), resolve_spans([], text_length=0))


class DeterminismTests(unittest.TestCase):
    def test_conflicting_group_is_permutation_invariant(self):
        group = [
            _candidate(0, 6, "ORG", 3, "dict"),
            _candidate(2, 4, "ID", 1, "rule:id"),
            _candidate(5, 9, "PERSON", 2, "ner"),
            _candidate(8, 12, "ORG", 3, "rule:org"),
            _candidate(20, 24, "LOC", 3, "ner"),
        ]
        expected = resolve_spans(group, text_length=30)
        self.assertGreater(len(list(itertools.permutations(group))), 100)
        for order in itertools.permutations(group):
            with self.subTest(order=order):
                self.assertEqual(expected, resolve_spans(order, text_length=30))

    def test_union_coverage_equals_candidate_coverage_and_outputs_disjoint(self):
        ranges = [(start, end) for start in range(5) for end in range(start + 1, 6)]
        sources = ("dict", "ner", "rule:phone")
        for index, (first, second) in enumerate(itertools.product(ranges, repeat=2)):
            candidates = [
                DetectionCandidate(*first, "ORG", 3, sources[index % 3]),
                DetectionCandidate(*second, "ID", 1, sources[(index + 1) % 3]),
            ]
            for order in itertools.permutations(candidates):
                resolved = resolve_spans(order, text_length=5)
                expected_coverage = set(range(*first)) | set(range(*second))
                actual_coverage = {i for span in resolved for i in range(span.start, span.end)}
                self.assertEqual(expected_coverage, actual_coverage)
                for left, right in zip(resolved, resolved[1:]):
                    self.assertGreaterEqual(right.start, left.end)


class ProvenanceTests(unittest.TestCase):
    def test_every_resolved_span_traces_to_sorted_source_set(self):
        candidates = [
            _candidate(0, 4, "ORG", 3, "rule:org"),
            _candidate(1, 3, "ORG", 2, "dict"),
            _candidate(6, 9, "ID", 1, "rule:id"),
        ]
        resolved = resolve_spans(candidates, text_length=10)
        self.assertEqual(("dict", "rule:org"), resolved[0].sources)
        self.assertEqual(("rule:id",), resolved[1].sources)
        for span in resolved:
            self.assertEqual(tuple(sorted(span.sources)), span.sources)
            self.assertTrue(span.sources)


class AdapterTests(unittest.TestCase):
    def test_candidate_from_accepts_span_and_entity_span_outputs(self):
        from_span = candidate_from(Span(1, 4, "ORG", 2), source="dict")
        self.assertEqual(DetectionCandidate(1, 4, "ORG", 2, "dict"), from_span)
        from_ner = candidate_from(EntitySpan(2, 6, "PER"), source="ner")
        self.assertEqual(DetectionCandidate(2, 6, "PER", 3, "ner"), from_ner)
        overridden = candidate_from(Span(1, 4, "ORG", 2), source="dict", priority=1)
        self.assertEqual(DetectionCandidate(1, 4, "ORG", 1, "dict"), overridden)

    def test_candidate_from_rejects_bad_inputs_and_sources(self):
        with self.assertRaisesRegex(SafetyError, "INVALID_SPAN"):
            candidate_from(object(), source="ner")
        with self.assertRaisesRegex(SafetyError, "INVALID_SPAN"):
            candidate_from(Span(1, 4, "ORG"), source="")
        with self.assertRaisesRegex(SafetyError, "INVALID_SPAN"):
            candidate_from(_candidate(0, 2), source="other")

    def test_adapted_detection_outputs_resolve(self):
        candidates = [
            candidate_from(Span(0, 3, "ORG", 2), source="dict"),
            candidate_from(EntitySpan(1, 5, "ORG"), source="ner"),
        ]
        resolved = resolve_spans(candidates, text_length=8)
        self.assertEqual((ResolvedSpan(0, 5, "ORG", 2, ("dict", "ner")),), resolved)


if __name__ == "__main__":
    unittest.main()
