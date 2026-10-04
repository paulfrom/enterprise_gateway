"""P-06 non-streaming response restorer.

Restores mapped exact-value tokens in editable text positions of upstream
non-streaming responses, preserving all protocol structure, metadata, and
billing fields (such as usage) with exact equality.

Editable positions:
- DeepSeek Chat Completions: ``choices[i].message.content`` only.
- Claude Messages: ``content[j].text`` for text blocks only.

Tokens in uneditable positions (such as model, id, role, or usage) fail closed
with ``CONTRACT_VIOLATION``. Unknown or malformed tokens fail closed with
``UNKNOWN_TOKEN`` and ``MALFORMED_TOKEN``, respectively.
"""

from __future__ import annotations

from typing import Annotated, Callable, ClassVar, Literal, NoReturn, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from infra.errors import SafetyCode, SafetyError
from masking.mapping import MappingContext
from protocol.protocols import DeepSeekToolCall, ClaudeToolUseBlock, ClaudeThinkingBlock
from protocol.tool_buffer import BoundedToolCallBuffer
import json
from protocol.protocols import (
    CLAUDE_MESSAGES_PROTOCOL,
    DEEPSEEK_CHAT_PROTOCOL,
)
from infra.strict_json import JsonRejectKind, parse_strict_json

__all__ = [
    "ClaudeMessagesResponse",
    "ClaudeTextBlockResponse",
    "ClaudeUsage",
    "DeepSeekChatResponse",
    "DeepSeekChoice",
    "DeepSeekResponseMessage",
    "DeepSeekUsage",
    "restore_response",
]

_RESERVED_PREFIX = "<<ENT"
_RESERVED_PREFIXES = (_RESERVED_PREFIX, "<<E", "<<EN")


def _reject_json(protocol: str) -> Callable[[JsonRejectKind], NoReturn]:
    def reject(kind: JsonRejectKind) -> NoReturn:
        if kind is JsonRejectKind.DUPLICATE_KEY:
            raise SafetyError(SafetyCode.DUPLICATE_JSON_KEY, protocol)
        if kind is JsonRejectKind.INVALID_UTF8:
            raise SafetyError(SafetyCode.INVALID_UTF8, protocol)
        raise SafetyError(SafetyCode.MALFORMED_JSON, protocol)

    return reject


def _has_reserved_token(text: str) -> bool:
    """Return True if text contains or ends with reserved token indicators."""
    return _RESERVED_PREFIX in text or text.endswith(("<<E", "<<EN"))


class DeepSeekUsage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    prompt_tokens: Annotated[int, Field(ge=0)]
    completion_tokens: Annotated[int, Field(ge=0)]
    total_tokens: Annotated[int, Field(ge=0)]
    prompt_cache_hit_tokens: int | None = None
    prompt_cache_miss_tokens: int | None = None


class DeepSeekResponseMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    role: Literal["assistant"]
    content: str | None = None
    tool_calls: list[DeepSeekToolCall] | None = None


class DeepSeekChoice(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    index: int
    message: DeepSeekResponseMessage
    finish_reason: Literal["stop", "length", "content_filter", 'tool_calls'] | None = None


class DeepSeekChatResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    protocol: ClassVar[str] = DEEPSEEK_CHAT_PROTOCOL

    id: str
    object: Literal["chat.completion"] = "chat.completion"
    created: int
    model: str
    choices: Annotated[list[DeepSeekChoice], Field(min_length=1)]
    usage: DeepSeekUsage | None = None

    @field_validator("model")
    @classmethod
    def _model_non_empty(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("model must be a non-empty string")
        return value


class ClaudeUsage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    input_tokens: Annotated[int, Field(ge=0)]
    output_tokens: Annotated[int, Field(ge=0)]


class ClaudeTextBlockResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    type: Literal["text"] = "text"
    text: str


class ClaudeMessagesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    protocol: ClassVar[str] = CLAUDE_MESSAGES_PROTOCOL

    id: str
    type: Literal["message"] = "message"
    role: Literal["assistant"] = "assistant"
    model: str
    content: Annotated[list[ClaudeTextBlockResponse | ClaudeToolUseBlock | ClaudeThinkingBlock], Field(min_length=1)]
    stop_reason: Literal["end_turn", "max_tokens", "stop_sequence", 'tool_use'] | None = None
    stop_sequence: str | None = None
    usage: ClaudeUsage | None = None

    @field_validator("model")
    @classmethod
    def _model_non_empty(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("model must be a non-empty string")
        return value


class ClaudeUpstreamThinkingBlock(BaseModel):
    """Supplier wire state has a supplier signature and no gateway receipt."""
    model_config = ConfigDict(extra='forbid',frozen=True,strict=True)
    type: Literal['thinking']
    thinking: str
    signature: str = Field(min_length=1)


class ClaudeUpstreamMessagesResponse(ClaudeMessagesResponse):
    content: Annotated[list[ClaudeTextBlockResponse | ClaudeToolUseBlock | ClaudeUpstreamThinkingBlock],Field(min_length=1)]


_ResponseModelT = TypeVar("_ResponseModelT", bound=BaseModel)


def _assert_no_tokens_in_uneditable(protocol: str, parsed: DeepSeekChatResponse | ClaudeMessagesResponse) -> None:
    """Fail closed if token literals appear anywhere outside editable text fields."""
    if isinstance(parsed, DeepSeekChatResponse):
        uneditable_strings: list[str | None] = [
            parsed.id,
            parsed.object,
            parsed.model,
        ]
        for c in parsed.choices:
            uneditable_strings.append(c.message.role)
            uneditable_strings.append(c.finish_reason)
    elif isinstance(parsed, ClaudeMessagesResponse):
        uneditable_strings = [
            parsed.id,
            parsed.type,
            parsed.role,
            parsed.model,
            parsed.stop_reason,
            parsed.stop_sequence,
        ]
        for block in parsed.content:
            uneditable_strings.append(block.type)
            if isinstance(block,ClaudeUpstreamThinkingBlock):
                uneditable_strings.extend((block.thinking,block.signature))
    else:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, protocol)

    for item in uneditable_strings:
        if isinstance(item, str) and _has_reserved_token(item):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "token in uneditable field")


def restore_response(
    protocol: str,
    raw_response: str | bytes | dict | DeepSeekChatResponse | ClaudeMessagesResponse,
    context: MappingContext,
    allowed_models: frozenset[str] | None = None,
    allowed_tools=None,
    state_validator=None,
) -> DeepSeekChatResponse | ClaudeMessagesResponse:
    """Restore mapped tokens in editable positions of an upstream non-streaming response.

    Only editable positions are modified:
    - DeepSeek: ``choices[i].message.content``
    - Claude: ``content[j].text``

    All other fields, especially ``usage``, are checked for exact value equality.
    Unknown or malformed tokens, tokens in uneditable fields, or inactive mapping
    contexts fail closed.
    """
    if not isinstance(context, MappingContext):
        raise TypeError("context must be a MappingContext")

    context.require_active()

    if protocol == DEEPSEEK_CHAT_PROTOCOL:
        model_cls: type[DeepSeekChatResponse] | type[ClaudeMessagesResponse] = DeepSeekChatResponse
    elif protocol == CLAUDE_MESSAGES_PROTOCOL:
        model_cls = ClaudeUpstreamMessagesResponse
    else:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "unsupported protocol")

    # 1. Parse or adapt input payload
    if isinstance(raw_response, (str, bytes)):
        payload = parse_strict_json(raw_response, reject=_reject_json(protocol))
        if not isinstance(payload, dict):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, protocol)
    elif isinstance(raw_response, dict):
        payload = raw_response
    elif isinstance(raw_response, model_cls):
        payload = raw_response.model_dump()
    else:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, protocol)

    # 2. Validate input against protocol contract
    validation_failed = False
    try:
        parsed_input = model_cls.model_validate(payload)
    except ValidationError:
        validation_failed = True

    if validation_failed:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, protocol)

    if not allowed_models or parsed_input.model not in allowed_models:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "model not allowed")

    # 3. Guard: fail closed if any token appears in uneditable fields
    _assert_no_tokens_in_uneditable(protocol, parsed_input)

    # 4. Perform in-memory exact restoration on editable positions
    restored_payload = parsed_input.model_dump(exclude_unset=True)

    if isinstance(parsed_input, DeepSeekChatResponse):
        for idx, choice in enumerate(parsed_input.choices):
            if choice.message.content is not None:
                restored_payload["choices"][idx]["message"]["content"] = context.restore(choice.message.content)
            buffer = BoundedToolCallBuffer()
            for j, call in enumerate(choice.message.tool_calls or []):
                if _has_reserved_token(call.id) or _has_reserved_token(call.function.name):
                    raise SafetyError(SafetyCode.CONTRACT_VIOLATION,'tool structure')
                buffer.register_tool(call.id,call.function.name)
                buffer.feed_argument_delta(call.id,call.function.arguments)
            for j, call in enumerate(choice.message.tool_calls or []):
                args = buffer.finalize_and_verify(call.id,context,allowed_tools=allowed_tools or {})
                restored_payload['choices'][idx]['message']['tool_calls'][j]['function']['arguments'] = json.dumps(args,ensure_ascii=False,separators=(',',':'))
    elif isinstance(parsed_input, ClaudeMessagesResponse):
        buffer = BoundedToolCallBuffer()
        for idx, block in enumerate(parsed_input.content):
            if isinstance(block, ClaudeTextBlockResponse):
                restored_payload["content"][idx]["text"] = context.restore(block.text)
            elif isinstance(block, ClaudeToolUseBlock):
                if _has_reserved_token(block.id) or _has_reserved_token(block.name):
                    raise SafetyError(SafetyCode.CONTRACT_VIOLATION,'tool structure')
                buffer.register_tool(block.id,block.name)
                buffer.feed_argument_delta(block.id,json.dumps(block.input,ensure_ascii=False))
                restored_payload['content'][idx]['input'] = buffer.finalize_and_verify(block.id,context,allowed_tools=allowed_tools or {})
            else:
                if state_validator is None: raise SafetyError(SafetyCode.CONTRACT_VIOLATION,'unverified reasoning state')
                from protocol.history_state import ReasoningBlock
                verified = state_validator.admit_upstream_block(ReasoningBlock('thinking',block.thinking,block.signature,{}))
                restored_payload['content'][idx]['metadata'] = dict(verified.metadata)

    # 5. Validate restored result against protocol contract
    try:
        output_cls=ClaudeMessagesResponse if protocol==CLAUDE_MESSAGES_PROTOCOL else DeepSeekChatResponse
        restored_result = output_cls.model_validate(restored_payload)
    except ValidationError:
        validation_failed = True

    if validation_failed:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, protocol)

    # 6. Strict diff assurance: non-editable fields and usage MUST be identical
    if parsed_input.usage is not None or restored_result.usage is not None:
        if parsed_input.usage != restored_result.usage:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "usage mutated")

    if isinstance(parsed_input, DeepSeekChatResponse) and isinstance(restored_result, DeepSeekChatResponse):
        if (
            parsed_input.id != restored_result.id
            or parsed_input.object != restored_result.object
            or parsed_input.created != restored_result.created
            or parsed_input.model != restored_result.model
            or len(parsed_input.choices) != len(restored_result.choices)
        ):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "metadata mutated")
        for orig_c, rest_c in zip(parsed_input.choices, restored_result.choices, strict=True):
            if (
                orig_c.index != rest_c.index
                or orig_c.finish_reason != rest_c.finish_reason
                or orig_c.message.role != rest_c.message.role
            ):
                raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "choice metadata mutated")
    elif isinstance(parsed_input, ClaudeMessagesResponse) and isinstance(restored_result, ClaudeMessagesResponse):
        if (
            parsed_input.id != restored_result.id
            or parsed_input.type != restored_result.type
            or parsed_input.role != restored_result.role
            or parsed_input.model != restored_result.model
            or parsed_input.stop_reason != restored_result.stop_reason
            or parsed_input.stop_sequence != restored_result.stop_sequence
            or len(parsed_input.content) != len(restored_result.content)
        ):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "metadata mutated")
        for orig_b, rest_b in zip(parsed_input.content, restored_result.content, strict=True):
            if orig_b.type != rest_b.type:
                raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "block type mutated")

    return restored_result
