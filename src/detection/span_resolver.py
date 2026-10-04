"""Deterministic conflict resolution of detector candidates into final spans.

This module is the single conflict-resolution authority for all detection
paths (rule recognizers, dictionary, NER windowing). It is not detection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from infra.errors import SafetyCode, SafetyError

_ENTITY_TYPE = re.compile(r"[A-Z][A-Z0-9_]{0,31}\Z")
_VALID_PRIORITIES = frozenset({0, 1, 2, 3})


@dataclass(frozen=True, slots=True)
class DetectionCandidate:
    """One span proposal from one detector path.

    ``source`` is the detector identifier (e.g. ``"rule:phone"``, ``"dict"``,
    ``"ner"``) so every final span can be traced back to the detectors that
    proposed it. Offsets are half-open code point intervals in the original
    text; ``priority`` 0 means a secret and blocks the whole request.
    """

    start: int
    end: int
    entity_type: str
    priority: int
    source: str


@dataclass(frozen=True, slots=True)
class ResolvedSpan:
    """A final non-overlapping span; ``sources`` is the sorted tuple of the
    detector identifiers that contributed to it."""

    start: int
    end: int
    entity_type: str
    priority: int
    sources: tuple[str, ...]


def candidate_from(obj: object, *, source: str, priority: int | None = None) -> DetectionCandidate:
    """Adapt a detection-path output (``Span``, ``EntitySpan``, or any object
    with ``start``/``end``/``entity_type``) into a ``DetectionCandidate``.

    ``priority`` overrides the object's own ``priority`` attribute; when it is
    ``None`` the object's attribute is used, falling back to the default 3.
    Field-shape violations raise ``SafetyError(INVALID_SPAN)``; text-bound
    checks happen in ``resolve_spans`` where the text length is known.
    """
    if isinstance(obj, DetectionCandidate) and priority is None:
        if source != obj.source:
            raise SafetyError(SafetyCode.INVALID_SPAN, "source")
        return obj
    if not isinstance(source, str) or not source:
        raise SafetyError(SafetyCode.INVALID_SPAN, "source")
    if obj is None or not hasattr(obj, "start") or not hasattr(obj, "end") or not hasattr(obj, "entity_type"):
        raise SafetyError(SafetyCode.INVALID_SPAN, "candidate")
    resolved_priority = priority if priority is not None else getattr(obj, "priority", 3)
    return DetectionCandidate(obj.start, obj.end, obj.entity_type, resolved_priority, source)


def _validate(candidate: object, text_length: int) -> None:
    if (
        not isinstance(candidate, DetectionCandidate)
        or type(candidate.start) is not int
        or type(candidate.end) is not int
        or not 0 <= candidate.start < candidate.end <= text_length
        or type(candidate.priority) is not int
        or candidate.priority not in _VALID_PRIORITIES
        or not isinstance(candidate.entity_type, str)
        or not _ENTITY_TYPE.fullmatch(candidate.entity_type)
        or not isinstance(candidate.source, str)
        or not candidate.source
    ):
        raise SafetyError(SafetyCode.INVALID_SPAN)


def resolve_spans(
    candidates: Iterable[DetectionCandidate], *, text_length: int
) -> tuple[ResolvedSpan, ...]:
    """Resolve all detector candidates into a deterministic, pairwise
    non-overlapping final span set. Resolution rules, in order:

    1. ``text_length`` must be an ``int`` >= 0, else ``INVALID_TEXT_LENGTH``.
    2. Every candidate must be a ``DetectionCandidate`` with integer offsets
       ``0 <= start < end <= text_length``, a priority in ``{0, 1, 2, 3}``, an
       uppercase ``entity_type`` matching the registry pattern, and a non-empty
       string ``source``; any violation raises ``INVALID_SPAN``.
    3. Any priority-0 (secret) candidate raises ``SECRET_DETECTED`` for the
       whole request, regardless of its position in the input.
    4. Candidates are ordered by the total key
       ``(start, end, entity_type, priority, source)``, so any permutation of
       the same candidate set yields the identical output.
    5. A sweep merges each candidate with the previous output span when they
       overlap or nest (``start < previous.end``); endpoint-adjacent spans
       (``start == previous.end``) are not merged. Merging takes the union
       range, keeps the entity type when both agree and labels it ``MIXED``
       otherwise, keeps the minimum priority, and unions the ``source`` sets.
       Because only unions are taken, final coverage always equals candidate
       coverage and never shrinks.
    """
    if type(text_length) is not int or text_length < 0:
        raise SafetyError(SafetyCode.INVALID_TEXT_LENGTH)
    items = list(candidates)
    for candidate in items:
        _validate(candidate, text_length)
    if any(candidate.priority == 0 for candidate in items):
        raise SafetyError(SafetyCode.SECRET_DETECTED)
    items.sort(key=lambda item: (item.start, item.end, item.entity_type, item.priority, item.source))
    merged: list[ResolvedSpan] = []
    for candidate in items:
        if not merged or candidate.start >= merged[-1].end:
            merged.append(
                ResolvedSpan(candidate.start, candidate.end, candidate.entity_type, candidate.priority, (candidate.source,))
            )
            continue
        previous = merged[-1]
        merged[-1] = ResolvedSpan(
            previous.start,
            max(previous.end, candidate.end),
            previous.entity_type if previous.entity_type == candidate.entity_type else "MIXED",
            min(previous.priority, candidate.priority),
            tuple(sorted({*previous.sources, candidate.source})),
        )
    return tuple(merged)
