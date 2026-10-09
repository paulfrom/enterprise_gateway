"""Replace only ingress-classified editable leaves; detected structure blocks."""
from __future__ import annotations
import re
import json
from collections.abc import Iterable, Mapping
from infra.errors import SafetyCode, SafetyError
from gateway.ingress import BusinessTextFragment, ValidatedIngressRequest
from masking.mapping import MappingContext
from protocol.protocols import CLAUDE_MESSAGES_PROTOCOL, DEEPSEEK_CHAT_PROTOCOL, ClaudeMessagesRequest, DeepSeekChatRequest
from detection.span_resolver import ResolvedSpan
from detection.spans import Span, redact_text

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

    # The ingress contract classifies user text and tool results as editable
    # leaves; any other span path resolves to structure or nowhere and blocks.
    payload = parsed.model_dump(exclude_unset=True)
    def set_path(path: str, value: str) -> None:
        parts = re.findall(r'([^\.\[\]]+)|\[(\d+)\]', path)
        keys = [name if name else int(index) for name, index in parts]
        current = payload
        for key in keys[:-1]: current = current[key]
        current[keys[-1]] = value
    for path in fragment_spans:
        if path not in fragments_by_path:
            raise SafetyError(SafetyCode.UNSAFE_REPLACEMENT, 'path')
    for path, fragment in fragments_by_path.items():
        if fragment.requires_detection and path not in fragment_spans:
            raise SafetyError(SafetyCode.DETECTION_INCOMPLETE, 'fragment')
        raw_spans = fragment_spans.get(path, ())
        if isinstance(raw_spans,(str,bytes)) or raw_spans is None:
            raise SafetyError(SafetyCode.INVALID_DETECTOR_RESULTS)
        try: raw_spans = tuple(raw_spans)
        except TypeError: raise SafetyError(SafetyCode.INVALID_DETECTOR_RESULTS) from None
        spans = tuple(_to_span(s) for s in raw_spans)
        if not fragment.editable:
            if spans:
                raise SafetyError(SafetyCode.UNSAFE_REPLACEMENT, 'structure')
            # Reserved tokens in structure must also fail, even when detectors
            # report no entity span.
            if '<<ENT' in fragment.content:
                raise SafetyError(SafetyCode.RESERVED_TOKEN_LITERAL)
            continue
        if not fragment.requires_detection and spans:
            raise SafetyError(SafetyCode.UNSAFE_REPLACEMENT, 'exempt_fragment')
        set_path(path, redact_text(fragment.content, spans, context))
    from protocol.passthrough import PassthroughPayload, parse_passthrough_request
    if isinstance(parsed, PassthroughPayload):
        return parse_passthrough_request(json.dumps(payload), protocol, frozenset({parsed.model}))
    return model_cls.model_validate(payload)

