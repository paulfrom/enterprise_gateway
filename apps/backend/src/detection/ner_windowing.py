"""Sliding-window NER extraction with exact source-offset recovery.

Inputs longer than one model window are processed with fixed-stride sliding
windows and merged deterministically into entity spans on original-text code
point coordinates (half-open ``[start, end)``).

Pipeline (deterministic: the same input always yields the same output):

1. Encode the full text once (no special tokens, no truncation). Token
   offsets must cover the whole text on legal code point boundaries
   (in-range, non-inverted, monotonic); any deviation blocks. A head or
   tail region the tokenizer legitimately drops is tolerated only when it
   consists solely of whitespace/control characters — such characters
   cannot carry an entity, and uncovered regions simply yield no spans.
2. Slice the token sequence into windows of ``window_length`` tokens
   (budget includes one ``[CLS]`` and one ``[SEP]``); consecutive windows
   advance by ``stride`` content tokens and the last window is realigned to
   the text end.
3. Run the ONNX session on fixed-size batches of windows and decode BIO
   labels into spans using the same lenient-continuation semantics as the
   single-window reference decoder (``I-X`` after ``O`` or a different type
   opens a new entity; empty-offset tokens act as boundaries).
4. Merge: every window sighting votes. Same-type spans that overlap —
   directly or through a chain of overlaps — union into one envelope and
   every envelope is emitted. Windows frequently disagree on entity
   boundaries (split/join variants, off-by-one edges, core-region misses);
   masking the union is the safe direction for a privacy gateway, and the
   union of actual model outputs stays deterministic. Two envelopes of
   different types that overlap block — the windows produced contradictory
   labels with no deterministic resolution.

Anything that breaks offset integrity blocks with
``SafetyCode.NER_OFFSET_UNRECOVERABLE``. Public messages carry only static
diagnostic slugs and never contain document text. Constructor arguments are
wiring-time configuration and fail with plain ``ValueError``.
"""

from __future__ import annotations

import re
import time
import unicodedata
from dataclasses import dataclass
from typing import Any, NoReturn

import numpy as np

from infra.errors import SafetyCode, SafetyError

DEFAULT_WINDOW_LENGTH = 384
DEFAULT_STRIDE = 318

_INFERENCE_BATCH_SIZE = 32

_CLS_TOKEN = "[CLS]"
_SEP_TOKEN = "[SEP]"

_ONNX_LOGITS = "logits"
_ONNX_INPUT_IDS = "input_ids"
_ONNX_ATTENTION_MASK = "attention_mask"

_LABEL_PATTERN = re.compile(r"^(O|[BI]-[A-Z0-9]+)$")


def _fail(detail: str) -> NoReturn:
    raise SafetyError(SafetyCode.NER_OFFSET_UNRECOVERABLE, detail)


def _droppable(region: str) -> bool:
    """Characters a tokenizer may legitimately drop: whitespace/control only."""
    return all(
        char.isspace() or unicodedata.category(char) in ("Cc", "Cf")
        for char in region
    )


def _checked_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    return value


def plan_windows(
    token_count: int, capacity: int, stride: int
) -> tuple[tuple[int, int], ...]:
    """Deterministic half-open ``[start, end)`` content-token windows.

    Windows have full ``capacity`` except that a text shorter than one
    window yields a single ``(0, token_count)`` window. Starts advance by
    ``stride`` and the last window is realigned to end at ``token_count``;
    adjacent windows therefore overlap by ``capacity - stride`` tokens.
    """
    token_count = _checked_int(token_count, "token_count")
    capacity = _checked_int(capacity, "capacity")
    stride = _checked_int(stride, "stride")
    if token_count < 0 or capacity < 1 or not 1 <= stride <= capacity:
        raise ValueError("invalid window plan parameters")
    if token_count == 0:
        return ()
    if token_count <= capacity:
        return ((0, token_count),)
    last_start = token_count - capacity
    starts = list(range(0, last_start + 1, stride))
    if starts[-1] != last_start:
        starts.append(last_start)
    return tuple((start, start + capacity) for start in starts)


def plan_sentence_windows(text, offsets, capacity, stride):
    """Cut at token boundaries near sentence/line ends, retaining overlap."""
    if len(offsets) <= capacity:
        return plan_windows(len(offsets), capacity, stride)
    overlap = capacity - stride
    windows = []
    start = 0
    while start < len(offsets):
        end = min(start + capacity, len(offsets))
        if end < len(offsets):
            minimum = max(start + capacity // 2, start + overlap + max(1, stride // 2))
            for breaks in ('\n\r', '。；;！!？?'):
                candidates = [index + 1 for index in range(minimum, end)
                              if offsets[index][1] > offsets[index][0]
                              and text[offsets[index][1] - 1] in breaks]
                if candidates:
                    end = candidates[-1]
                    break
        windows.append((start, end))
        if end == len(offsets):
            break
        start = max(start + 1, end - overlap)
    return tuple(windows)


@dataclass(frozen=True, slots=True)
class EntitySpan:
    """A recovered entity on original-text code point coordinates."""

    start: int
    end: int
    entity_type: str


@dataclass(frozen=True, slots=True)
class _WindowSpan:
    entity_type: str
    start: int
    end: int


def _decode_window_spans(
    offsets: list[tuple[int, int]],
    labels: list[str],
) -> list[_WindowSpan]:
    """BIO-decode one window.

    Mirrors the single-window reference decoder: ``I-X`` after ``O`` or a
    different type opens a new entity, and empty-offset tokens act as
    boundaries.
    """
    spans: list[_WindowSpan] = []
    open_type: str | None = None
    open_start = 0
    open_end = 0

    def close() -> None:
        nonlocal open_type
        if open_type is None:
            return
        spans.append(
            _WindowSpan(entity_type=open_type, start=open_start, end=open_end)
        )
        open_type = None

    for (start, end), label in zip(offsets, labels):
        if start == end or label == "O":
            close()
            continue
        prefix, _, entity_type = label.partition("-")
        if prefix == "B" or open_type != entity_type:
            close()
            open_type = entity_type
            open_start = start
        open_end = end
    close()
    return spans


class NerWindowMerger:
    """Fixed-window NER extractor with deterministic offset recovery.

    ``tokenizer``/``session``/``id2label`` are the components of a ``LoadedNerPackage`` (duck-typed here so tests can inject controlled
    fakes; production wiring passes ``load_model_package`` results).
    ``window_length`` counts the special tokens; ``stride`` is the content
    advance between consecutive windows.
    """

    def __init__(
        self,
        tokenizer: Any,
        session: Any,
        id2label: dict[int, str],
        *,
        window_length: int = DEFAULT_WINDOW_LENGTH,
        stride: int = DEFAULT_STRIDE,
        batch_tokens: int = 4096,
        sentence_boundaries: bool = False,
    ) -> None:
        window_length = _checked_int(window_length, "window_length")
        stride = _checked_int(stride, "stride")
        batch_tokens = _checked_int(batch_tokens, "batch_tokens")
        if batch_tokens < window_length or type(sentence_boundaries) is not bool:
            raise ValueError('invalid batch/window options')
        capacity = window_length - 2
        if capacity < 1:
            raise ValueError("window_length must leave room for content tokens")
        if not 1 <= stride <= capacity:
            raise ValueError("stride must be between 1 and the content capacity")
        labels = dict(id2label)
        if not labels or set(labels) != set(range(len(labels))):
            raise ValueError("id2label keys must be exactly 0..N-1")
        if not all(
            isinstance(value, str) and _LABEL_PATTERN.fullmatch(value)
            for value in labels.values()
        ):
            raise ValueError("id2label values must be BIO labels")
        encode = getattr(tokenizer, "encode", None)
        token_to_id = getattr(tokenizer, "token_to_id", None)
        if not callable(encode) or not callable(token_to_id):
            raise ValueError("tokenizer must provide encode and token_to_id")
        cls_id = token_to_id(_CLS_TOKEN)
        sep_id = token_to_id(_SEP_TOKEN)
        if (
            isinstance(cls_id, bool)
            or isinstance(sep_id, bool)
            or not isinstance(cls_id, int)
            or not isinstance(sep_id, int)
        ):
            raise ValueError("tokenizer must define [CLS] and [SEP]")
        run = getattr(session, "run", None)
        if not callable(run):
            raise ValueError("session must provide run")
        self._tokenizer = tokenizer
        self._session = session
        self._id2label = labels
        self._cls_id = cls_id
        self._sep_id = sep_id
        self._window_length = window_length
        self._capacity = capacity
        self._stride = stride
        self._num_labels = len(labels)
        self._batch_tokens = batch_tokens
        self._sentence_boundaries = sentence_boundaries

    def extract(self, text: str, *, metrics: dict[str, float] | None = None) -> tuple[EntitySpan, ...]:
        """Recover entity spans for ``text``; block on any ambiguity.

        Returns the deterministic tuple of spans sorted by
        ``(start, end, entity_type)``; ``text[start:end]`` is the exact
        original mention surface.
        """
        return self.extract_many((text,), metrics=metrics)[0]

    def extract_many(self, texts, *, metrics=None):
        """Encode once per fragment and batch windows across fragment boundaries.

        Length buckets reduce padding. Results are scattered back to the exact
        original fragment; no text/logits/offsets survive this call.
        """
        texts = tuple(texts)
        started = time.perf_counter() if metrics is not None else 0.0
        encoded = []
        rows = []
        token_count = 0
        for index, text in enumerate(texts):
            if not isinstance(text, str):
                raise ValueError('text must be a string')
            if text == '':
                encoded.append(([], []))
                continue
            encoding = self._tokenizer.encode(text, add_special_tokens=False)
            ids = list(encoding.ids)
            offsets = self._validated_offsets(encoding.offsets, len(ids), text)
            encoded.append((ids, offsets))
            token_count += len(ids)
            windows = (plan_sentence_windows(text, offsets, self._capacity, self._stride)
                       if self._sentence_boundaries else plan_windows(len(ids), self._capacity, self._stride))
            rows.extend((index, begin, end) for begin, end in windows)
        rows.sort(key=lambda row: (row[2] - row[1], row[0], row[1]))
        if metrics is not None:
            metrics["tokenize_window_ms"] = metrics.get("tokenize_window_ms", 0.0) + (time.perf_counter() - started) * 1000
            metrics["token_count"] = metrics.get("token_count", 0) + token_count
            metrics["window_count"] = metrics.get("window_count", 0) + len(rows)
            metrics['content_tokens_processed'] = metrics.get('content_tokens_processed', 0) + sum(end - begin for _, begin, end in rows)
        occurrences = [[] for _ in texts]
        cursor = 0
        while cursor < len(rows):
            stop = cursor
            width = 0
            bucket_width = rows[cursor][2] - rows[cursor][1] + 2
            while stop < len(rows) and stop - cursor < _INFERENCE_BATCH_SIZE:
                next_width = rows[stop][2] - rows[stop][1] + 2
                if stop > cursor and next_width > bucket_width * 1.25:
                    break
                width = max(width, next_width)
                if (stop - cursor + 1) * width > self._batch_tokens:
                    break
                stop += 1
            selected = rows[cursor:stop]
            batches = self._infer_rows([(encoded[index][0], encoded[index][1], begin, end)
                                       for index, begin, end in selected], metrics=metrics)
            for (index, _, _), sightings in zip(selected, batches, strict=True):
                occurrences[index].extend(sightings)
            cursor = stop
        started = time.perf_counter() if metrics is not None else 0.0
        results = []
        for text, sightings in zip(texts, occurrences, strict=True):
            spans = tuple(EntitySpan(start=start, end=end, entity_type=kind)
                          for kind, start, end in self._union_envelopes(sightings))
            for span in spans:
                if not 0 <= span.start < span.end <= len(text):
                    _fail('span_out_of_range')
            results.append(spans)
        if metrics is not None:
            metrics["decode_ms"] = metrics.get("decode_ms", 0.0) + (time.perf_counter() - started) * 1000
        return tuple(results)

    def _validated_offsets(
        self, raw_offsets: Any, token_count: int, text: str
    ) -> list[tuple[int, int]]:
        text_length = len(text)
        if raw_offsets is None:
            _fail("offsets_unavailable")
        if len(raw_offsets) != token_count or token_count == 0:
            _fail("offset_malformed")
        offsets: list[tuple[int, int]] = []
        for item in raw_offsets:
            if (
                not isinstance(item, (tuple, list))
                or len(item) != 2
                or any(isinstance(v, bool) or not isinstance(v, int) for v in item)
            ):
                _fail("offset_malformed")
            offsets.append((item[0], item[1]))
        if not offsets:
            _fail("offset_coverage_incomplete")
        previous: tuple[int, int] | None = None
        first_start: int | None = None
        for start, end in offsets:
            if start < 0 or end > text_length:
                _fail("offset_out_of_range")
            if start > end:
                _fail("offset_inverted")
            if start == end:
                continue
            if first_start is None:
                first_start = start
            if previous is not None and (start < previous[0] or end < previous[1]):
                _fail("offset_non_monotonic")
            previous = (start, end)
        head = text[:first_start] if first_start is not None else text
        tail = text[previous[1]:] if previous is not None else ""
        if not _droppable(head) or not _droppable(tail):
            _fail("offset_coverage_incomplete")
        return offsets

    def _infer_batch(
        self,
        ids: list[int],
        offsets: list[tuple[int, int]],
        windows: tuple[tuple[int, int], ...],
        *, metrics: dict[str, float] | None = None,
    ) -> list[_WindowSpan]:
        """Run one batched ONNX call for a chunk of windows.

        Rows are right-padded with ``[SEP]`` under a zero attention mask, so
        each window's real positions produce exactly the logits an isolated
        call would; only the decode loop consumes them, per window.
        """
        return [span for row in self._infer_rows([(ids, offsets, begin, end)
                for begin, end in windows], metrics=metrics) for span in row]

    def _infer_rows(self, rows, *, metrics=None):
        started = time.perf_counter() if metrics is not None else 0.0
        sequences = [
            [self._cls_id, *ids[win_start:win_end], self._sep_id]
            for ids, _, win_start, win_end in rows
        ]
        width = max(len(sequence) for sequence in sequences)
        batch = np.full((len(sequences), width), self._sep_id, dtype=np.int64)
        mask = np.zeros((len(sequences), width), dtype=np.int64)
        for row, sequence in enumerate(sequences):
            batch[row, : len(sequence)] = sequence
            mask[row, : len(sequence)] = 1
        feed = {_ONNX_INPUT_IDS: batch, _ONNX_ATTENTION_MASK: mask}
        if metrics is not None:
            metrics["batch_prepare_ms"] = metrics.get("batch_prepare_ms", 0.0) + (time.perf_counter() - started) * 1000
            started = time.perf_counter()
        logits = np.asarray(self._session.run([_ONNX_LOGITS], feed)[0])
        if metrics is not None:
            metrics["onnx_ms"] = metrics.get("onnx_ms", 0.0) + (time.perf_counter() - started) * 1000
            metrics["onnx_calls"] = metrics.get("onnx_calls", 0) + 1
            started = time.perf_counter()
        if logits.shape != (len(sequences), width, self._num_labels):
            _fail("logits_shape_mismatch")
        spans = []
        for row, (_, offsets, win_start, win_end) in enumerate(rows):
            win_len = win_end - win_start
            label_ids = np.argmax(logits[row], axis=-1)[1 : 1 + win_len]
            labels = [self._id2label[int(label_id)] for label_id in label_ids]
            spans.append(_decode_window_spans(offsets[win_start:win_end], labels))
        if metrics is not None:
            metrics["decode_ms"] = metrics.get("decode_ms", 0.0) + (time.perf_counter() - started) * 1000
        return spans

    @staticmethod
    def _union_envelopes(
        occurrences: list[_WindowSpan],
    ) -> list[tuple[str, int, int]]:
        """Union-envelope merge of same-type overlapping window sightings.

        Every window sighting votes: same-type spans that overlap, directly or
        through a chain of overlaps, union into one emitted envelope. Windows
        routinely disagree on entity boundaries, and masking the union is the
        safe direction for a privacy gateway. Two envelopes of different types
        that overlap are a contradiction with no deterministic resolution and
        block.
        """
        by_type: dict[str, list[tuple[int, int]]] = {}
        for span in occurrences:
            by_type.setdefault(span.entity_type, []).append((span.start, span.end))
        envelopes: list[tuple[str, int, int]] = []
        for entity_type, sightings in by_type.items():
            sightings.sort()
            env_start = env_end = -1
            for start, end in sightings:
                if env_start >= 0 and start < env_end:
                    env_end = max(env_end, end)
                    continue
                if env_start >= 0:
                    envelopes.append((entity_type, env_start, env_end))
                env_start, env_end = start, end
            if env_start >= 0:
                envelopes.append((entity_type, env_start, env_end))
        envelopes.sort(key=lambda item: (item[1], item[2], item[0]))
        for first, second in zip(envelopes, envelopes[1:]):
            if second[1] < first[2]:
                _fail("contradictory_span_labels")
        return envelopes
