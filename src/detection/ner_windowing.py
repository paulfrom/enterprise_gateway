"""D-09 sliding-window NER extraction with exact source-offset recovery.

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
import unicodedata
from dataclasses import dataclass
from typing import Any, NoReturn

import numpy as np

from infra.errors import SafetyCode, SafetyError

DEFAULT_WINDOW_LENGTH = 128
DEFAULT_STRIDE = 32

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

    ``tokenizer``/``session``/``id2label`` are the components of a D-08
    ``LoadedNerPackage`` (duck-typed here so tests can inject controlled
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
    ) -> None:
        window_length = _checked_int(window_length, "window_length")
        stride = _checked_int(stride, "stride")
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

    def extract(self, text: str) -> tuple[EntitySpan, ...]:
        """Recover entity spans for ``text``; block on any ambiguity.

        Returns the deterministic tuple of spans sorted by
        ``(start, end, entity_type)``; ``text[start:end]`` is the exact
        original mention surface.
        """
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        if text == "":
            return ()
        encoding = self._tokenizer.encode(text, add_special_tokens=False)
        ids = list(encoding.ids)
        offsets = self._validated_offsets(encoding.offsets, len(ids), text)
        token_count = len(offsets)
        windows = plan_windows(token_count, self._capacity, self._stride)
        occurrences: list[_WindowSpan] = []
        for start in range(0, len(windows), _INFERENCE_BATCH_SIZE):
            occurrences.extend(
                self._infer_batch(
                    ids, offsets, windows[start : start + _INFERENCE_BATCH_SIZE]
                )
            )
        envelopes = self._union_envelopes(occurrences)
        spans = tuple(
            EntitySpan(start=start, end=end, entity_type=entity_type)
            for entity_type, start, end in envelopes
        )
        for span in spans:
            if not 0 <= span.start < span.end <= len(text):
                _fail("span_out_of_range")
        return spans

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
    ) -> list[_WindowSpan]:
        """Run one batched ONNX call for a chunk of windows.

        Rows are right-padded with ``[SEP]`` under a zero attention mask, so
        each window's real positions produce exactly the logits an isolated
        call would; only the decode loop consumes them, per window.
        """
        sequences = [
            [self._cls_id, *ids[win_start:win_end], self._sep_id]
            for win_start, win_end in windows
        ]
        width = max(len(sequence) for sequence in sequences)
        batch = np.full((len(sequences), width), self._sep_id, dtype=np.int64)
        mask = np.zeros((len(sequences), width), dtype=np.int64)
        for row, sequence in enumerate(sequences):
            batch[row, : len(sequence)] = sequence
            mask[row, : len(sequence)] = 1
        feed = {_ONNX_INPUT_IDS: batch, _ONNX_ATTENTION_MASK: mask}
        logits = np.asarray(self._session.run([_ONNX_LOGITS], feed)[0])
        if logits.shape != (len(sequences), width, self._num_labels):
            _fail("logits_shape_mismatch")
        spans: list[_WindowSpan] = []
        for row, (win_start, win_end) in enumerate(windows):
            win_len = win_end - win_start
            label_ids = np.argmax(logits[row], axis=-1)[1 : 1 + win_len]
            labels = [self._id2label[int(label_id)] for label_id in label_ids]
            spans.extend(_decode_window_spans(offsets[win_start:win_end], labels))
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
