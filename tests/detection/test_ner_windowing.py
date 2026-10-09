"""Sliding-window NER offset recovery and inference tests.

Mock-level tests drive the merger with the real mini-valid-package tokenizer
plus a fake ONNX session returning controlled per-window label sequences, so
windowing, core-region trust, merging and blocking are exercised exactly.
Offset-poisoning tests inject a fake tokenizer with out-of-range, inverted or
non-monotonic offsets. One positive path runs the fully real
``load_model_package`` pipeline (random-weight mini model) and asserts
pipeline and offset semantics only, never recognition quality. All fixture
text is synthetic ASCII / generated in-test; no real names or institutions.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace

import numpy as np

from infra.errors import SafetyCode, SafetyError
from detection.ner_model import load_model_package
from detection.ner_windowing import (
    _INFERENCE_BATCH_SIZE,
    DEFAULT_STRIDE,
    DEFAULT_WINDOW_LENGTH,
    EntitySpan,
    NerWindowMerger,
    plan_windows,
)

NER_FIXTURES = Path(__file__).parent / "fixtures" / "ner"
MINI_PACKAGE = NER_FIXTURES / "mini-valid-package"
SYNTH_LONG_TEXT = NER_FIXTURES / "synth-long-text.txt"

# mini-valid-package label layout (see D-08 fixture config.json).
LABEL_IDS = {
    "O": 0,
    "B-PER": 1,
    "I-PER": 2,
    "B-ORG": 3,
    "I-ORG": 4,
    "B-LOC": 5,
    "I-LOC": 6,
    "B-TIME": 7,
    "I-TIME": 8,
}
NUM_LABELS = len(LABEL_IDS)
ID2LABEL = {index: label for label, index in LABEL_IDS.items()}

_LOADED = None


def loaded_package():
    global _LOADED
    if _LOADED is None:
        _LOADED = load_model_package(MINI_PACKAGE)
    return _LOADED


def mini_tokenizer():
    return loaded_package().tokenizer


def mini_id2label():
    return loaded_package().id2label


def encode(text):
    return mini_tokenizer().encode(text, add_special_tokens=False)


def token_offsets(encoding, first, last):
    return encoding.offsets[first][0], encoding.offsets[last][1]


def build_labels(token_count, specs):
    """Full-sequence label ids from (first_token, last_token, type) specs."""
    labels = [LABEL_IDS["O"]] * token_count
    for first, last, entity_type in specs:
        labels[first] = LABEL_IDS[f"B-{entity_type}"]
        for index in range(first + 1, last + 1):
            labels[index] = LABEL_IDS[f"I-{entity_type}"]
    return labels


def build_queue(encoding, specs, windows):
    """Per-window content label slices matching the deterministic plan."""
    full = build_labels(len(encoding.ids), specs)
    return [full[start:end] for start, end in windows]


class FakeSession:
    """ONNX session stub returning controlled per-window label sequences.

    Batch-aware: one queued content-label row is consumed per batch row,
    with each row's real sequence length recovered from the attention mask.
    """

    def __init__(self, queues, num_labels=NUM_LABELS):
        self._queues = [list(queue) for queue in queues]
        self._num_labels = num_labels
        self.calls = 0

    def run(self, output_names, feed):
        if output_names != ["logits"]:
            raise AssertionError(f"unexpected outputs: {output_names}")
        batch = np.asarray(feed["input_ids"])
        mask = np.asarray(feed["attention_mask"])
        rows, width = batch.shape
        if len(self._queues) < rows:
            raise AssertionError("unexpected extra inference call")
        logits = np.full((rows, width, self._num_labels), -10.0, dtype=np.float32)
        for row in range(rows):
            real = int(mask[row].sum())
            content = self._queues.pop(0)
            if len(content) != real - 2:
                raise AssertionError("window content length mismatch")
            labels = [LABEL_IDS["O"], *content, LABEL_IDS["O"]]
            labels += [LABEL_IDS["O"]] * (width - real)
            logits[row, np.arange(width), labels] = 10.0
        self.calls += 1
        return [logits]


class FakeTokenizer:
    """Tokenizer stub with explicit ids/offsets (for offset poisoning)."""

    def __init__(self, ids, offsets):
        self._ids = list(ids)
        self._offsets = offsets

    def encode(self, text, add_special_tokens=False):
        if add_special_tokens:
            raise AssertionError("merger must encode without special tokens")
        return SimpleNamespace(ids=list(self._ids), offsets=self._offsets)

    def token_to_id(self, token):
        return {"[CLS]": 2, "[SEP]": 3}.get(token)


class CountingSession:
    """Delegates to a real session while counting inference calls."""

    def __init__(self, inner):
        self._inner = inner
        self.calls = 0

    def run(self, output_names, feed):
        self.calls += 1
        return self._inner.run(output_names, feed)


def assert_blocked(testcase, ctx, detail, *body_fragments):
    exc = ctx.exception
    testcase.assertEqual(exc.code, SafetyCode.NER_OFFSET_UNRECOVERABLE)
    testcase.assertEqual(str(exc), f"NER_OFFSET_UNRECOVERABLE ({detail})")
    testcase.assertIsNone(exc.__cause__)
    testcase.assertIsNone(exc.__context__)
    for fragment in body_fragments:
        testcase.assertNotIn(fragment, str(exc))
    return exc


class WindowPlanTests(unittest.TestCase):
    def test_short_text_yields_single_full_window(self):
        self.assertEqual(plan_windows(6, 6, 2), ((0, 6),))
        self.assertEqual(plan_windows(3, 6, 2), ((0, 3),))
        self.assertEqual(plan_windows(0, 6, 2), ())

    def test_last_window_realigns_to_text_end(self):
        self.assertEqual(plan_windows(10, 6, 2), ((0, 6), (2, 8), (4, 10)))
        self.assertEqual(
            plan_windows(12, 6, 2), ((0, 6), (2, 8), (4, 10), (6, 12))
        )
        self.assertEqual(
            plan_windows(16, 6, 4), ((0, 6), (4, 10), (8, 14), (10, 16))
        )

    def test_plan_covers_every_token(self):
        for token_count, capacity, stride in [(10, 6, 2), (40, 22, 6), (300, 126, 32)]:
            windows = plan_windows(token_count, capacity, stride)
            self.assertEqual(windows[0][0], 0)
            self.assertEqual(windows[-1][1], token_count)
            for previous, current in zip(windows, windows[1:]):
                self.assertLess(previous[0], current[0])
                self.assertLess(previous[1], current[1])
            covered = set()
            for start, end in windows:
                self.assertLessEqual(end - start, capacity)
                covered.update(range(start, end))
            self.assertEqual(covered, set(range(token_count)))

    def test_production_defaults_make_multiple_windows(self):
        windows = plan_windows(300, DEFAULT_WINDOW_LENGTH - 2, DEFAULT_STRIDE)
        self.assertEqual(len(windows), 7)
        self.assertEqual(windows[-1], (174, 300))

    def test_plan_rejects_invalid_parameters(self):
        for args in [(6, 0, 1), (6, 6, 0), (-1, 6, 2), (10, 6, 7), (6, 6, True)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                plan_windows(*args)


class MergerConstructorTests(unittest.TestCase):
    def make(self, **overrides):
        kwargs = {
            "tokenizer": mini_tokenizer(),
            "session": FakeSession([]),
            "id2label": mini_id2label(),
        }
        kwargs.update(overrides)
        return NerWindowMerger(**kwargs)

    def test_valid_mini_package_components_accepted(self):
        merger = self.make()
        self.assertEqual(merger.extract(""), ())

    def test_rejects_bad_window_geometry(self):
        for kwargs in [
            {"window_length": 2},
            {"window_length": True},
            {"window_length": "128"},
            {"stride": 0},
            {"stride": -1},
            {"stride": 200},
            {"stride": True},
        ]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.make(**kwargs)

    def test_rejects_bad_id2label(self):
        for id2label in [
            {},
            {0: "O", 2: "B-PER"},
            {0: "O", 1: "PER"},
            {0: "O", 1: "B-per"},
        ]:
            with self.subTest(id2label=id2label), self.assertRaises(ValueError):
                self.make(id2label=id2label)

    def test_rejects_tokenizer_without_special_tokens(self):
        with self.assertRaises(ValueError):
            self.make(tokenizer=SimpleNamespace(encode=lambda *a, **k: None))
        with self.assertRaises(ValueError):
            self.make(
                tokenizer=SimpleNamespace(
                    encode=lambda *a, **k: None, token_to_id=lambda token: None
                )
            )

    def test_rejects_session_without_run(self):
        with self.assertRaises(ValueError):
            self.make(session=SimpleNamespace())

    def test_rejects_non_string_text(self):
        merger = self.make()
        with self.assertRaises(ValueError):
            merger.extract(None)
        with self.assertRaises(ValueError):
            merger.extract(123)


class MergerMockTests(unittest.TestCase):
    """Exact span expectations against controlled per-window label sequences."""

    def make_merger(self, encoding, specs, window_length, stride, queue=None):
        windows = plan_windows(len(encoding.ids), window_length - 2, stride)
        session = FakeSession(queue if queue is not None else build_queue(encoding, specs, windows))
        merger = NerWindowMerger(
            mini_tokenizer(),
            session,
            mini_id2label(),
            window_length=window_length,
            stride=stride,
        )
        return merger, session, windows

    def test_short_text_single_window_direct(self):
        encoding = encode("abcd")
        self.assertEqual(len(encoding.ids), 4)
        merger, session, windows = self.make_merger(encoding, [(1, 2, "PER")], 8, 2)
        self.assertEqual(windows, ((0, 4),))
        result = merger.extract("abcd")
        self.assertEqual(result, (EntitySpan(1, 3, "PER"),))
        self.assertEqual("abcd"[1:3], "bc")
        self.assertEqual(session.calls, 1)

    def test_adjacent_entities_kept_separate(self):
        text = "abcd efgh"
        encoding = encode(text)
        self.assertEqual(len(encoding.ids), 8)
        merger, session, _ = self.make_merger(
            encoding, [(0, 1, "PER"), (2, 3, "ORG")], 8, 2
        )
        result = merger.extract(text)
        per_span = token_offsets(encoding, 0, 1)
        org_span = token_offsets(encoding, 2, 3)
        self.assertEqual(
            result,
            (
                EntitySpan(per_span[0], per_span[1], "PER"),
                EntitySpan(org_span[0], org_span[1], "ORG"),
            ),
        )
        self.assertEqual(text[per_span[0] : per_span[1]], "ab")
        self.assertEqual(text[org_span[0] : org_span[1]], "cd")
        self.assertEqual(session.calls, 1)  # both windows ride one batch

    def test_chinese_entity_exact_offsets(self):
        text = "张三在北京"
        encoding = encode(text)
        self.assertEqual(len(encoding.ids), 1)
        self.assertEqual(encoding.offsets[0], (0, 5))
        merger, _, _ = self.make_merger(encoding, [(0, 0, "LOC")], 8, 2)
        result = merger.extract(text)
        self.assertEqual(result, (EntitySpan(0, 5, "LOC"),))
        self.assertEqual(text[0:5], "张三在北京")

    def test_mixed_chinese_ascii_adjacent_entities(self):
        text = "aa 北京 bb"
        encoding = encode(text)
        self.assertEqual(encoding.ids[2], 1)  # [UNK] run covering the Chinese text
        self.assertEqual(encoding.offsets[2], (3, 5))
        merger, _, _ = self.make_merger(
            encoding, [(0, 1, "PER"), (2, 2, "ORG"), (3, 4, "LOC")], 8, 2
        )
        result = merger.extract(text)
        self.assertEqual(
            result,
            (EntitySpan(0, 2, "PER"), EntitySpan(3, 5, "ORG"), EntitySpan(6, 8, "LOC")),
        )
        self.assertEqual(text[0:2], "aa")
        self.assertEqual(text[3:5], "北京")
        self.assertEqual(text[6:8], "bb")

    def test_single_character_entity(self):
        encoding = encode("abcd")
        merger, _, _ = self.make_merger(encoding, [(2, 2, "TIME")], 8, 2)
        result = merger.extract("abcd")
        self.assertEqual(result, (EntitySpan(2, 3, "TIME"),))
        self.assertEqual("abcd"[2:3], "c")

    def test_cross_window_entity_merged_to_exact_source_span(self):
        text = "aa bb cc dd ee ff gg hh"
        encoding = encode(text)
        self.assertEqual(len(encoding.ids), 16)
        merger, session, windows = self.make_merger(encoding, [(9, 12, "PER")], 13, 3)
        self.assertEqual(windows, ((0, 11), (3, 14), (5, 16)))
        start, end = token_offsets(encoding, 9, 12)
        self.assertEqual((start, end), (13, 19))
        result = merger.extract(text)
        self.assertEqual(result, (EntitySpan(start, end, "PER"),))
        self.assertEqual((start, end), (13, 19))
        self.assertEqual(text[start:end], "e ff g")
        self.assertEqual(session.calls, 1)  # three windows, one batch

    def test_repeated_calls_are_deterministic(self):
        text = "aa bb cc dd ee ff gg hh"
        encoding = encode(text)
        windows = plan_windows(len(encoding.ids), 11, 3)
        queue = build_queue(encoding, [(9, 12, "PER")], windows)
        merger1, _, _ = self.make_merger(encoding, [], 13, 3, queue=queue + queue)
        merger2, _, _ = self.make_merger(encoding, [(9, 12, "PER")], 13, 3)
        first = merger1.extract(text)
        second = merger1.extract(text)
        third = merger2.extract(text)
        self.assertEqual(first, second)
        self.assertEqual(first, third)

    def test_empty_text_returns_no_spans_without_inference(self):
        merger, session, _ = self.make_merger(encode("abcd"), [], 8, 2)
        self.assertEqual(merger.extract(""), ())
        self.assertEqual(session.calls, 0)


class MergerBlockTests(unittest.TestCase):
    def make_merger(self, encoding, specs, window_length=8, stride=2, queue=None):
        windows = plan_windows(len(encoding.ids), window_length - 2, stride)
        session = FakeSession(queue if queue is not None else build_queue(encoding, specs, windows))
        merger = NerWindowMerger(
            mini_tokenizer(),
            session,
            mini_id2label(),
            window_length=window_length,
            stride=stride,
        )
        return merger, windows

    def test_entity_at_window_boundaries_emits_union_envelope(self):
        text = "aa bb cc dd ee"
        encoding = encode(text)
        self.assertEqual(len(encoding.ids), 10)
        merger, _ = self.make_merger(encoding, [(5, 6, "PER")])
        start, end = token_offsets(encoding, 5, 6)
        self.assertEqual(merger.extract(text), (EntitySpan(start, end, "PER"),))

    def test_entity_longer_than_core_region_emits_union_envelope(self):
        text = "aa bb cc dd ee"
        encoding = encode(text)
        merger, _ = self.make_merger(encoding, [(2, 7, "ORG")])
        start, end = token_offsets(encoding, 2, 7)
        self.assertEqual(merger.extract(text), (EntitySpan(start, end, "ORG"),))

    def test_contradictory_labels_across_windows_block(self):
        text = "aa bb cc d"
        encoding = encode(text)
        self.assertEqual(len(encoding.ids), 7)
        windows = plan_windows(7, 6, 2)
        self.assertEqual(windows, ((0, 6), (1, 7)))
        queue = [
            [0, 0, 0, LABEL_IDS["B-PER"], 0, 0],
            [0, 0, LABEL_IDS["B-ORG"], 0, 0, 0],
        ]
        merger, _ = self.make_merger(encoding, [], queue=queue)
        with self.assertRaises(SafetyError) as ctx:
            merger.extract(text)
        assert_blocked(self, ctx, "contradictory_span_labels", "aa", "bb", "cc")

    def test_offset_out_of_range_blocks(self):
        tokenizer = FakeTokenizer([5, 6, 7], [(0, 1), (1, 2), (2, 9)])
        merger = NerWindowMerger(tokenizer, FakeSession([[0, 0, 0]]), ID2LABEL, window_length=8, stride=2)
        with self.assertRaises(SafetyError) as ctx:
            merger.extract("abcdef")
        assert_blocked(self, ctx, "offset_out_of_range", "abcdef")

    def test_offset_inverted_blocks(self):
        tokenizer = FakeTokenizer([5, 6, 7], [(0, 1), (1, 2), (4, 3)])
        merger = NerWindowMerger(tokenizer, FakeSession([[0, 0, 0]]), ID2LABEL, window_length=8, stride=2)
        with self.assertRaises(SafetyError) as ctx:
            merger.extract("abcdef")
        assert_blocked(self, ctx, "offset_inverted", "abcdef")

    def test_offset_non_monotonic_blocks(self):
        tokenizer = FakeTokenizer([5, 6, 7], [(0, 4), (2, 3), (3, 6)])
        merger = NerWindowMerger(tokenizer, FakeSession([[0, 0, 0]]), ID2LABEL, window_length=8, stride=2)
        with self.assertRaises(SafetyError) as ctx:
            merger.extract("abcdef")
        assert_blocked(self, ctx, "offset_non_monotonic", "abcdef")

    def test_offset_coverage_incomplete_blocks(self):
        tokenizer = FakeTokenizer([5, 6], [(1, 2), (2, 6)])
        merger = NerWindowMerger(tokenizer, FakeSession([[0, 0]]), ID2LABEL, window_length=8, stride=2)
        with self.assertRaises(SafetyError) as ctx:
            merger.extract("abcdef")
        assert_blocked(self, ctx, "offset_coverage_incomplete", "abcdef")

    def test_malformed_offsets_block(self):
        tokenizer = FakeTokenizer([5, 6], None)
        merger = NerWindowMerger(tokenizer, FakeSession([[0, 0]]), ID2LABEL, window_length=8, stride=2)
        with self.assertRaises(SafetyError) as ctx:
            merger.extract("abcdef")
        assert_blocked(self, ctx, "offsets_unavailable", "abcdef")

        bad = FakeTokenizer([5, 6], [(0, 1), (1, "x")])
        merger = NerWindowMerger(bad, FakeSession([[0, 0]]), ID2LABEL, window_length=8, stride=2)
        with self.assertRaises(SafetyError) as ctx:
            merger.extract("abcdef")
        assert_blocked(self, ctx, "offset_malformed", "abcdef")

        short = FakeTokenizer([5, 6, 7], [(0, 1), (1, 6)])
        merger = NerWindowMerger(short, FakeSession([[0, 0, 0]]), ID2LABEL, window_length=8, stride=2)
        with self.assertRaises(SafetyError) as ctx:
            merger.extract("abcdef")
        assert_blocked(self, ctx, "offset_malformed", "abcdef")

    def test_logits_shape_mismatch_blocks(self):
        class BadShapeSession:
            def run(self, output_names, feed):
                return [np.zeros((1, 3, NUM_LABELS), dtype=np.float32)]

        merger = NerWindowMerger(
            mini_tokenizer(), BadShapeSession(), mini_id2label(), window_length=8, stride=2
        )
        with self.assertRaises(SafetyError) as ctx:
            merger.extract("abcd")
        assert_blocked(self, ctx, "logits_shape_mismatch", "abcd")

    def test_empty_tokenization_of_non_empty_text_blocks(self):
        tokenizer = FakeTokenizer([], [])
        merger = NerWindowMerger(tokenizer, FakeSession([]), ID2LABEL, window_length=8, stride=2)
        with self.assertRaises(SafetyError) as ctx:
            merger.extract("abcdef")
        assert_blocked(self, ctx, "offset_malformed", "abcdef")


class MergerRealPackageTests(unittest.TestCase):
    """Full pipeline through load_model_package; structural asserts only."""

    def assert_valid_result(self, result, text):
        self.assertEqual(
            result, tuple(sorted(result, key=lambda s: (s.start, s.end, s.entity_type)))
        )
        seen = set()
        allowed_types = loaded_package().entity_types
        for span in result:
            self.assertIsInstance(span, EntitySpan)
            self.assertTrue(0 <= span.start < span.end <= len(text))
            self.assertIsNotNone(span.entity_type)
            self.assertIn(span.entity_type, allowed_types)
            key = (span.entity_type, span.start, span.end)
            self.assertNotIn(key, seen)
            seen.add(key)

    def test_real_package_short_text_runs_full_pipeline(self):
        merger = NerWindowMerger(
            loaded_package().tokenizer,
            CountingSession(loaded_package().session),
            loaded_package().id2label,
        )
        first = merger.extract("abcd")
        second = merger.extract("abcd")
        self.assertEqual(first, second)
        self.assert_valid_result(first, "abcd")

    def test_real_package_long_text_multi_window_call_count(self):
        text = SYNTH_LONG_TEXT.read_text(encoding="utf-8").strip()
        encoding = encode(text)
        # The mini fixture model rejects near-128-token inputs, so the real
        # multi-window path runs with a small window; windowing geometry
        # itself is covered by the mock tests and the plan tests above.
        window_length, stride = 8, 2
        self.assertGreater(len(encoding.ids), window_length - 2)
        counter = CountingSession(loaded_package().session)
        merger = NerWindowMerger(
            loaded_package().tokenizer,
            counter,
            loaded_package().id2label,
            window_length=window_length,
            stride=stride,
        )
        expected_windows = plan_windows(
            len(encoding.ids), window_length - 2, stride
        )
        self.assertGreater(len(expected_windows), 1)
        try:
            first = merger.extract(text)
        except SafetyError as exc:
            # Random-weight fixture models can label windows inconsistently;
            # blocking is the specified fail-closed outcome and must be
            # deterministic and text-free.
            self.assertEqual(exc.code, SafetyCode.NER_OFFSET_UNRECOVERABLE)
            self.assertTrue(str(exc).startswith("NER_OFFSET_UNRECOVERABLE ("))
            for fragment in ("aa", "bb", "cc", "dd"):
                self.assertNotIn(fragment, str(exc))
            with self.assertRaises(SafetyError) as second:
                merger.extract(text)
            self.assertEqual(str(second.exception), str(exc))
            return
        second = merger.extract(text)
        self.assertEqual(first, second)
        expected_calls = -(-len(expected_windows) // _INFERENCE_BATCH_SIZE)
        self.assertEqual(counter.calls, 2 * expected_calls)
        self.assert_valid_result(first, text)

    def test_real_package_results_repeat_across_instances(self):
        text = SYNTH_LONG_TEXT.read_text(encoding="utf-8").strip()
        merger_a = NerWindowMerger(
            loaded_package().tokenizer,
            loaded_package().session,
            loaded_package().id2label,
            window_length=8,
            stride=2,
        )
        merger_b = NerWindowMerger(
            loaded_package().tokenizer,
            loaded_package().session,
            loaded_package().id2label,
            window_length=8,
            stride=2,
        )
        try:
            result_a = merger_a.extract(text)
        except SafetyError:
            with self.assertRaises(SafetyError) as ctx:
                merger_b.extract(text)
            self.assertIn("NER_OFFSET_UNRECOVERABLE (", str(ctx.exception))
            return
        self.assertEqual(result_a, merger_b.extract(text))


class MergerBatchTests(unittest.TestCase):
    """Window inference is batched; results match the per-window plan."""

    def make_merger(self, encoding, specs, window_length, stride):
        windows = plan_windows(len(encoding.ids), window_length - 2, stride)
        session = FakeSession(build_queue(encoding, specs, windows))
        merger = NerWindowMerger(
            mini_tokenizer(), session, mini_id2label(),
            window_length=window_length, stride=stride,
        )
        return merger, session, windows

    def test_windows_infer_in_fixed_size_batches(self):
        text = " ".join(["aa"] * 120)
        encoding = encode(text)
        merger, session, windows = self.make_merger(encoding, [], 8, 2)
        self.assertGreater(len(windows), _INFERENCE_BATCH_SIZE)
        self.assertEqual(merger.extract(text), ())
        self.assertEqual(session.calls, -(-len(windows) // _INFERENCE_BATCH_SIZE))

    def test_batched_spans_match_window_plan(self):
        text = "aa bb cc dd ee ff gg hh"
        encoding = encode(text)
        merger, session, _ = self.make_merger(encoding, [(9, 12, "PER")], 13, 3)
        start, end = token_offsets(encoding, 9, 12)
        self.assertEqual(merger.extract(text), (EntitySpan(start, end, "PER"),))
        self.assertEqual(session.calls, 1)


class MergerCoverageToleranceTests(unittest.TestCase):
    """Tokenizer-dropped head/tail whitespace must not block extraction."""

    def make_merger(self, ids, offsets):
        queue = [[LABEL_IDS["O"]] * len(ids)] if ids else []
        return NerWindowMerger(
            FakeTokenizer(ids, offsets), FakeSession(queue), ID2LABEL,
            window_length=8, stride=2,
        )

    def test_trailing_whitespace_uncovered_accepted(self):
        merger = self.make_merger([5, 6], [(0, 1), (1, 2)])
        self.assertEqual(merger.extract("ab\n"), ())

    def test_leading_whitespace_uncovered_accepted(self):
        merger = self.make_merger([5, 6], [(1, 2), (2, 3)])
        self.assertEqual(merger.extract("\nab"), ())

    def test_whitespace_only_text_returns_no_spans(self):
        merger = self.make_merger([5, 5], [(0, 0), (0, 0)])
        self.assertEqual(merger.extract("  "), ())

    def test_trailing_non_whitespace_uncovered_still_blocks(self):
        merger = self.make_merger([5, 6], [(0, 1), (1, 2)])
        with self.assertRaises(SafetyError) as ctx:
            merger.extract("abc")
        assert_blocked(self, ctx, "offset_coverage_incomplete", "abc")

    def test_leading_non_whitespace_uncovered_still_blocks(self):
        merger = self.make_merger([5, 6], [(1, 2), (2, 3)])
        with self.assertRaises(SafetyError) as ctx:
            merger.extract("zab")
        assert_blocked(self, ctx, "offset_coverage_incomplete", "zab")

    def test_real_tokenizer_trailing_newline_accepted(self):
        encoding = encode("ab\n")
        windows = plan_windows(len(encoding.ids), 6, 2)
        session = FakeSession(build_queue(encoding, [], windows))
        merger = NerWindowMerger(
            mini_tokenizer(), session, mini_id2label(), window_length=8, stride=2
        )
        self.assertEqual(merger.extract("ab\n"), ())


class MergerCompositionTests(unittest.TestCase):
    """Split/join labeling variants of one mention across windows.

    Core-region trust plus union-envelope merge: a boundary-straddling
    mention trusted in split form and sighted in joined form at window
    edges emits the union envelope (over-masking boundary noise is the
    safe direction); components never confirmed by any core still block.
    """

    TOKEN_COUNT = 30

    def make_merger(self, queue):
        ids = list(range(100, 100 + self.TOKEN_COUNT))
        offsets = [(i, i + 1) for i in range(self.TOKEN_COUNT)]
        merger = NerWindowMerger(
            FakeTokenizer(ids, offsets), FakeSession(queue), ID2LABEL,
            window_length=12, stride=2,
        )
        return merger

    def base_queue(self):
        windows = plan_windows(self.TOKEN_COUNT, 10, 2)
        assert len(windows) == 11 and windows[3] == (6, 16) and windows[5] == (10, 20)
        return [[LABEL_IDS["O"]] * (end - start) for start, end in windows]

    @staticmethod
    def mark(queue, window_index, specs):
        for first, last, entity_type in specs:
            queue[window_index][first] = LABEL_IDS[f"B-{entity_type}"]
            for index in range(first + 1, last + 1):
                queue[window_index][index] = LABEL_IDS[f"I-{entity_type}"]

    def test_joined_edge_sighting_unions_with_trusted_split_parts(self):
        queue = self.base_queue()
        # Mention at tokens 10-13 (chars [10,14)); the core boundary at
        # token 12 splits it into trusted parts (10,12) and (12,14), while
        # an edge window sights the joined form (10,14).
        self.mark(queue, 3, [(4, 5, "PER"), (6, 7, "PER")])  # window (6,16): part1 trusted
        self.mark(queue, 4, [(2, 3, "PER"), (4, 5, "PER")])  # window (8,18): part2 trusted
        self.mark(queue, 5, [(0, 3, "PER")])                 # window (10,20): joined, edge only
        merger = self.make_merger(queue)
        self.assertEqual(
            merger.extract("x" * self.TOKEN_COUNT),
            (EntitySpan(10, 14, "PER"),),
        )

    def test_joined_sighting_bridges_gap_into_one_envelope(self):
        queue = self.base_queue()
        # Trusted parts (10,12) and (13,14) leave token 12 outside both;
        # the joined edge sighting (10,14) overlaps both, so the envelope
        # over-masks the gap rather than blocking.
        self.mark(queue, 3, [(4, 5, "PER")])  # part (10,12) trusted in window (6,16)
        self.mark(queue, 4, [(5, 5, "PER")])  # part (13,14) trusted in window (8,18)
        self.mark(queue, 5, [(0, 3, "PER")])  # joined sighting in window (10,20)
        merger = self.make_merger(queue)
        self.assertEqual(
            merger.extract("x" * self.TOKEN_COUNT),
            (EntitySpan(10, 14, "PER"),),
        )

    def test_different_type_overlap_still_blocks(self):
        queue = self.base_queue()
        self.mark(queue, 3, [(4, 5, "PER")])  # PER (10,12) sighted in window (6,16)
        self.mark(queue, 5, [(1, 2, "ORG")])  # ORG (11,13) sighted in window (10,20)
        merger = self.make_merger(queue)
        with self.assertRaises(SafetyError) as ctx:
            merger.extract("x" * self.TOKEN_COUNT)
        assert_blocked(self, ctx, "contradictory_span_labels", "x")

    def test_edge_only_entity_emits_envelope(self):
        queue = self.base_queue()
        self.mark(queue, 5, [(0, 3, "PER")])  # sighted by one window only
        merger = self.make_merger(queue)
        self.assertEqual(
            merger.extract("x" * self.TOKEN_COUNT),
            (EntitySpan(10, 14, "PER"),),
        )


if __name__ == "__main__":
    unittest.main()
