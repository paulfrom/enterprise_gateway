"""D-09 sliding-window NER extraction with exact source-offset recovery.

Inputs longer than one model window are processed with fixed-stride sliding
windows and merged deterministically into entity spans on original-text code
point coordinates (half-open ``[start, end)``).

Pipeline (deterministic: the same input always yields the same output):

1. Encode the full text once (no special tokens, no truncation). Token
   offsets must cover the whole text on legal code point boundaries
   (in-range, non-inverted, monotonic); any deviation blocks.
2. Slice the token sequence into windows of ``window_length`` tokens
   (budget includes one ``[CLS]`` and one ``[SEP]``); consecutive windows
   advance by ``stride`` content tokens and the last window is realigned to
   the text end.
3. Run the ONNX session per window and decode BIO labels into spans using
   the same lenient-continuation semantics as the single-window reference
   decoder (``I-X`` after ``O`` or a different type opens a new entity;
   empty-offset tokens act as boundaries).
4. Trust a window span only when it lies fully inside the window core
   region: the window minus the overlap band on each side, split evenly
   between the two windows sharing it (band = ``(capacity - stride) / 2``).
   The first window keeps its left side and the last window keeps its
   right side, so adjacent cores cover the whole token sequence without
   gaps (a realigned final window may overlap its predecessor's core).
5. Merge: identical ``(type, start, end)`` spans collapse to one. Two
   trusted spans that overlap without being identical block — the windows
   produced contradictory labels with no deterministic resolution. Every
   untrusted window span must be explained by a trusted span of the same
   type with identical coordinates or sharing one end (truncation cut);
   an entity that no core region ever recovers completely blocks instead
   of emitting a guessed span.

Anything that breaks offset integrity blocks with
``SafetyCode.NER_OFFSET_UNRECOVERABLE``. Public messages carry only static
diagnostic slugs and never contain document text. Constructor arguments are
wiring-time configuration and fail with plain ``ValueError``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, NoReturn

import numpy as np

from infra.errors import SafetyCode, SafetyError

DEFAULT_WINDOW_LENGTH = 128
DEFAULT_STRIDE = 32

_CLS_TOKEN = "[CLS]"
_SEP_TOKEN = "[SEP]"

_ONNX_LOGITS = "logits"
_ONNX_INPUT_IDS = "input_ids"
_ONNX_ATTENTION_MASK = "attention_mask"

_LABEL_PATTERN = re.compile(r"^(O|[BI]-[A-Z0-9]+)$")


def _fail(detail: str) -> NoReturn:
    raise SafetyError(SafetyCode.NER_OFFSET_UNRECOVERABLE, detail)


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
    first_token: int
    last_token: int
    trusted: bool


def _decode_window_spans(
    offsets: list[tuple[int, int]],
    labels: list[str],
    core_lo: int,
    core_hi: int,
) -> list[_WindowSpan]:
    """BIO-decode one window and flag core-region trust.

    Mirrors the single-window reference decoder: ``I-X`` after ``O`` or a
    different type opens a new entity, and empty-offset tokens act as
    boundaries. A span is trusted only when its whole token run lies inside
    the core region ``[core_lo, core_hi)``.
    """
    spans: list[_WindowSpan] = []
    open_type: str | None = None
    open_start = 0
    open_end = 0
    open_first = 0
    open_last = 0

    def close() -> None:
        nonlocal open_type
        if open_type is None:
            return
        spans.append(
            _WindowSpan(
                entity_type=open_type,
                start=open_start,
                end=open_end,
                first_token=open_first,
                last_token=open_last,
                trusted=open_first >= core_lo and open_last < core_hi,
            )
        )
        open_type = None

    for index, ((start, end), label) in enumerate(zip(offsets, labels)):
        if start == end or label == "O":
            close()
            continue
        prefix, _, entity_type = label.partition("-")
        if prefix == "B" or open_type != entity_type:
            close()
            open_type = entity_type
            open_start = start
            open_first = index
        open_end = end
        open_last = index
    close()
    return spans


class NerWindowMerger:
    """Fixed-window NER extractor with deterministic offset recovery.

    ``tokenizer``/``session``/``id2label`` are the components of a D-08
    ``LoadedNerPackage`` (duck-typed here so tests can inject controlled
    fakes; production wiring passes ``load_model_package`` results).
    ``window_length`` counts the special tokens; ``stride`` is the content
    advance between consecutive windows and must keep
    ``window_length - 2 - stride`` even so the overlap band splits evenly.
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
        if (capacity - stride) % 2 != 0:
            raise ValueError("capacity minus stride must be even")
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
        self._band = (capacity - stride) // 2
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
        offsets = self._validated_offsets(encoding.offsets, len(ids), len(text))
        token_count = len(offsets)
        windows = plan_windows(token_count, self._capacity, self._stride)
        trusted: dict[tuple[str, int, int], None] = {}
        occurrences: list[_WindowSpan] = []
        for win_start, win_end in windows:
            occurrences.extend(
                self._infer_window(ids, offsets, win_start, win_end, token_count, trusted)
            )
        self._check_contradictions(trusted)
        self._explain_untrusted(occurrences, trusted)
        spans = tuple(
            sorted(
                (
                    EntitySpan(start=start, end=end, entity_type=entity_type)
                    for (entity_type, start, end) in trusted
                ),
                key=lambda span: (span.start, span.end, span.entity_type),
            )
        )
        for span in spans:
            if not 0 <= span.start < span.end <= len(text):
                _fail("span_out_of_range")
        return spans

    def _validated_offsets(
        self, raw_offsets: Any, token_count: int, text_length: int
    ) -> list[tuple[int, int]]:
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
        if first_start != 0 or previous is None or previous[1] != text_length:
            _fail("offset_coverage_incomplete")
        return offsets

    def _infer_window(
        self,
        ids: list[int],
        offsets: list[tuple[int, int]],
        win_start: int,
        win_end: int,
        token_count: int,
        trusted: dict[tuple[str, int, int], None],
    ) -> list[_WindowSpan]:
        win_len = win_end - win_start
        input_ids = [self._cls_id, *ids[win_start:win_end], self._sep_id]
        feed = {
            _ONNX_INPUT_IDS: np.array([input_ids], dtype=np.int64),
            _ONNX_ATTENTION_MASK: np.ones((1, len(input_ids)), dtype=np.int64),
        }
        logits = np.asarray(self._session.run([_ONNX_LOGITS], feed)[0])
        if logits.shape != (1, win_len + 2, self._num_labels):
            _fail("logits_shape_mismatch")
        label_ids = np.argmax(logits[0], axis=-1)[1:-1]
        labels = [self._id2label[int(label_id)] for label_id in label_ids]
        core_lo = 0 if win_start == 0 else self._band
        core_hi = win_len if win_end == token_count else win_len - self._band
        spans = _decode_window_spans(offsets[win_start:win_end], labels, core_lo, core_hi)
        for span in spans:
            if span.trusted:
                trusted[(span.entity_type, span.start, span.end)] = None
        return spans

    @staticmethod
    def _check_contradictions(trusted: dict[tuple[str, int, int], None]) -> None:
        keys = sorted(trusted)
        for i in range(len(keys)):
            _, s1, e1 = keys[i]
            for j in range(i + 1, len(keys)):
                _, s2, e2 = keys[j]
                if s1 < e2 and s2 < e1:
                    _fail("contradictory_span_labels")

    @staticmethod
    def _explain_untrusted(
        occurrences: list[_WindowSpan], trusted: dict[tuple[str, int, int], None]
    ) -> None:
        for span in occurrences:
            if span.trusted:
                continue
            explained = False
            for entity_type, start, end in trusted:
                if entity_type != span.entity_type:
                    continue
                same_span = start == span.start and end == span.end
                prefix_cut = start == span.start and end > span.end
                suffix_cut = end == span.end and start < span.start
                if same_span or prefix_cut or suffix_cut:
                    explained = True
                    break
            if not explained:
                _fail("entity_not_recovered_in_core")
