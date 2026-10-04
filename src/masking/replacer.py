"""P-05 editable-field-only request replacer.

Applies per-fragment final detection spans (the D-12 product) to the business
text positions that the C-03 protocol contract classifies as editable, and
returns an egress-ready protocol request. Every other field is preserved
exactly; a detection result addressed to any other position fails closed with
``UNSAFE_REPLACEMENT`` — the whole request is blocked, never stripped,
passed through, or partially degraded.

Editable positions, derived from the actual protocols.py model contracts and
the P-04 fragment enumeration in ingress.py:

- DeepSeek Chat Completions: ``messages[i].content`` only.
- Claude Messages: ``system``, ``messages[i].content`` (string form), and
  ``messages[i].text`` positions of text blocks only.

Everything else is protocol structure and must never carry replacement:
``model``, sampling/number parameters (``temperature``, ``top_p``,
``top_k``, ``max_tokens``), ``stop``/``stop_sequences`` (protocol parameters
even though string-valued), ``response_format``, message ``role``, and block
``type``. Replacement itself is delegated to spans.redact_text through the
request-local MappingContext, so reserved token literals keep their P-03
fail-closed semantics and every token restores the exact original substring.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from infra.errors import SafetyCode, SafetyError
from gateway.ingress import BusinessTextFragment, ValidatedIngressRequest
from masking.mapping import MappingContext
from protocol.protocols import (
    CLAUDE_MESSAGES_PROTOCOL,
    DEEPSEEK_CHAT_PROTOCOL,
    ClaudeMessagesRequest,
    ClaudeTextBlock,
    DeepSeekChatRequest,
)
from detection.span_resolver import ResolvedSpan
from detection.spans import Span, redact_text

__all__ = ["replace_request"]

_DEEPSEEK_MESSAGE_CONTENT = re.compile(r"messages\[(\d+)\]\.content\Z")
_CLAUDE_SYSTEM = re.compile(r"system\Z")
_CLAUDE_MESSAGE_CONTENT = re.compile(r"messages\[(\d+)\]\.content\Z")
_CLAUDE_BLOCK_TEXT = re.compile(r"messages\[(\d+)\]\.content\[(\d+)\]\.text\Z")

_DEEPSEEK_CONTENT = "deepseek_content"
_CLAUDE_SYSTEM_KIND = "claude_system"
_CLAUDE_CONTENT = "claude_content"
_CLAUDE_BLOCK = "claude_block_text"


@dataclass(frozen=True, slots=True)
class _Location:
    """Where an editable text lives inside the parsed protocol request."""

    kind: str
    indices: tuple[int, ...]


def _resolve_location(
    protocol: str, parsed: DeepSeekChatRequest | ClaudeMessagesRequest, path: object
) -> _Location | None:
    """Map a fragment json_path to an editable position; ``None`` otherwise."""
    if not isinstance(path, str):
        return None
    if protocol == DEEPSEEK_CHAT_PROTOCOL:
        match = _DEEPSEEK_MESSAGE_CONTENT.fullmatch(path)
        if match is None:
            return None
        index = int(match.group(1))
        if index >= len(parsed.messages):
            return None
        return _Location(_DEEPSEEK_CONTENT, (index,))
    match = _CLAUDE_BLOCK_TEXT.fullmatch(path)
    if match is not None:
        i, j = int(match.group(1)), int(match.group(2))
        if i >= len(parsed.messages):
            return None
        content = parsed.messages[i].content
        if isinstance(content, list) and j < len(content) and isinstance(content[j], ClaudeTextBlock):
            return _Location(_CLAUDE_BLOCK, (i, j))
        return None
    if _CLAUDE_SYSTEM.fullmatch(path):
        if parsed.system is None:
            return None
        return _Location(_CLAUDE_SYSTEM_KIND, ())
    match = _CLAUDE_MESSAGE_CONTENT.fullmatch(path)
    if match is not None:
        i = int(match.group(1))
        if i < len(parsed.messages) and isinstance(parsed.messages[i].content, str):
            return _Location(_CLAUDE_CONTENT, (i,))
        return None
    return None


def _text_at(parsed: DeepSeekChatRequest | ClaudeMessagesRequest, location: _Location) -> str | None:
    kind = location.kind
    if kind == _DEEPSEEK_CONTENT:
        return parsed.messages[location.indices[0]].content
    if kind == _CLAUDE_SYSTEM_KIND:
        return parsed.system
    if kind == _CLAUDE_CONTENT:
        content = parsed.messages[location.indices[0]].content
        return content if isinstance(content, str) else None
    i, j = location.indices
    content = parsed.messages[i].content
    if isinstance(content, list) and isinstance(content[j], ClaudeTextBlock):
        return content[j].text
    return None


def _set_text(payload: dict, location: _Location, value: str) -> None:
    kind = location.kind
    if kind == _DEEPSEEK_CONTENT:
        payload["messages"][location.indices[0]]["content"] = value
    elif kind == _CLAUDE_SYSTEM_KIND:
        payload["system"] = value
    elif kind == _CLAUDE_CONTENT:
        payload["messages"][location.indices[0]]["content"] = value
    else:
        i, j = location.indices
        payload["messages"][i]["content"][j]["text"] = value


def _to_span(item: object) -> Span:
    if isinstance(item, Span):
        return item
    if isinstance(item, ResolvedSpan):
        return Span(item.start, item.end, item.entity_type, item.priority)
    raise SafetyError(SafetyCode.INVALID_SPAN)


def replace_request(
    validated: ValidatedIngressRequest,
    fragment_spans: Mapping[str, Iterable[Span | ResolvedSpan]],
    context: MappingContext,
) -> DeepSeekChatRequest | ClaudeMessagesRequest:
    """Replace detected spans in editable text positions of a validated request.

    ``fragment_spans`` keys must be fragment json_paths of ``validated`` whose
    text positions are editable under the protocol contract. Any key that
    resolves to protocol structure (or nowhere) raises ``UNSAFE_REPLACEMENT``
    for the whole request. Every fragment that requires detection must have an
    entry; a missing entry raises ``DETECTION_INCOMPLETE``. Exempt fragments
    must carry an empty span set; a non-empty one raises ``UNSAFE_REPLACEMENT``.
    Span/text shape errors propagate from spans.redact_text unchanged
    (``INVALID_SPAN``, ``SECRET_DETECTED``, ``RESERVED_TOKEN_LITERAL``).
    """
    if not isinstance(validated, ValidatedIngressRequest):
        raise TypeError("validated must be a ValidatedIngressRequest")
    if not isinstance(context, MappingContext):
        raise TypeError("context must be a MappingContext")
    if not isinstance(fragment_spans, Mapping):
        raise SafetyError(SafetyCode.INVALID_DETECTOR_RESULTS)

    protocol = validated.protocol
    parsed = validated.parsed_request
    if protocol == DEEPSEEK_CHAT_PROTOCOL:
        model_cls: type[DeepSeekChatRequest] | type[ClaudeMessagesRequest] = DeepSeekChatRequest
        if not isinstance(parsed, DeepSeekChatRequest):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "protocol")
    elif protocol == CLAUDE_MESSAGES_PROTOCOL:
        model_cls = ClaudeMessagesRequest
        if not isinstance(parsed, ClaudeMessagesRequest):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "protocol")
    else:
        raise SafetyError(SafetyCode.UNSAFE_REPLACEMENT, "protocol")

    fragments_by_path: dict[str, BusinessTextFragment] = {}
    for fragment in validated.fragments:
        if fragment.json_path in fragments_by_path:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "fragment")
        fragments_by_path[fragment.json_path] = fragment

    locations: dict[str, _Location] = {}
    span_sets: dict[str, tuple[Span, ...]] = {}
    for path in sorted(fragment_spans, key=str):
        items = fragment_spans[path]
        if isinstance(items, (str, bytes)):
            raise SafetyError(SafetyCode.INVALID_DETECTOR_RESULTS)
        not_iterable = False
        try:
            raw_items = tuple(items)
        except TypeError:
            not_iterable = True
        if not_iterable:
            raise SafetyError(SafetyCode.INVALID_DETECTOR_RESULTS)
        location = _resolve_location(protocol, parsed, path)
        if location is None:
            # A span set addressed at protocol structure (model, numeric
            # parameters, roles, stop sequences, unknown paths, ...) must
            # never be applied; block the whole request instead.
            raise SafetyError(SafetyCode.UNSAFE_REPLACEMENT, "path")
        fragment = fragments_by_path.get(path)
        if fragment is None:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "fragment")
        spans = tuple(_to_span(item) for item in raw_items)
        if not fragment.requires_detection and spans:
            raise SafetyError(SafetyCode.UNSAFE_REPLACEMENT, "exempt_fragment")
        locations[path] = location
        span_sets[path] = spans

    for fragment in validated.fragments:
        if fragment.requires_detection and fragment.json_path not in span_sets:
            raise SafetyError(SafetyCode.DETECTION_INCOMPLETE, "fragment")

    replacements: dict[str, str] = {}
    for path in sorted(span_sets):
        spans = span_sets[path]
        if not spans:
            continue
        fragment = fragments_by_path[path]
        if _text_at(parsed, locations[path]) != fragment.content:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "fragment")
        replacements[path] = redact_text(fragment.content, spans, context)

    payload = parsed.model_dump()
    for path in sorted(replacements):
        _set_text(payload, locations[path], replacements[path])
    return model_cls.model_validate(payload)
