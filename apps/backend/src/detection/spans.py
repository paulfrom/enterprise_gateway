"""Protected-span union and exact replacement; this module is not detection."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from infra.errors import SafetyCode, SafetyError
from masking.mapping import MappingContext, reject_reserved_literals
from detection.span_resolver import DetectionCandidate, resolve_spans

_LEGACY_SOURCE = "span"


@dataclass(frozen=True, slots=True)
class Span:
    """Half-open offsets in the original Python string's Unicode code points."""

    start: int
    end: int
    entity_type: str
    priority: int = 3


def merge_spans(spans: Iterable[Span], *, text_length: int) -> tuple[Span, ...]:
    """Union overlapping protected ranges; priority never removes covered text.

    Delegates conflict resolution to ``span_resolver.resolve_spans``; priority
    zero means a secret and blocks the whole request. Adjacent ranges remain
    separate. Mixed overlapping types are labelled MIXED deterministically.
    """
    if type(text_length) is not int or text_length < 0:
        raise SafetyError(SafetyCode.INVALID_TEXT_LENGTH)
    candidates = list(spans)
    for span in candidates:
        if not isinstance(span, Span):
            raise SafetyError(SafetyCode.INVALID_SPAN)
    resolved = resolve_spans(
        [
            DetectionCandidate(span.start, span.end, span.entity_type, span.priority, _LEGACY_SOURCE)
            for span in candidates
        ],
        text_length=text_length,
    )
    return tuple(Span(item.start, item.end, item.entity_type, item.priority) for item in resolved)


def redact_text(text: str, spans: Iterable[Span], context: MappingContext) -> str:
    """Replace precomputed spans. This is not detection or egress authorization."""
    context.require_active()
    reject_reserved_literals(text)
    merged = merge_spans(spans, text_length=len(text))
    parts: list[str] = []
    cursor = 0
    for span in merged:
        parts.extend((text[cursor:span.start], context.token_for(span.entity_type, text[span.start:span.end])))
        cursor = span.end
    parts.append(text[cursor:])
    return "".join(parts)
