"""Strict candidate request contracts for DeepSeek Chat Completions and Claude Messages.

Only the explicitly selected plain-text chat subset is admissible; everything
else fails closed with a ContractError whose message never contains submitted
business text. Contract snapshot fixed from official sources read 2026-10-03.
"""

import json
from enum import StrEnum
from typing import Annotated, ClassVar, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

DEEPSEEK_CHAT_PROTOCOL = "deepseek-chat-completions"
CLAUDE_MESSAGES_PROTOCOL = "claude-messages"

DEEPSEEK_MODEL_WHITELIST: frozenset[str] = frozenset({"deepseek-flash", "deepseek-v4-pro"})
CLAUDE_MODEL_WHITELIST: frozenset[str] = frozenset(
    {"claude-sonnet-5-5", "claude-fable-5-1", "claude-opus-5-5"}
)


class RejectReason(StrEnum):
    MALFORMED_JSON = "malformed_json"
    INVALID_UTF8 = "invalid_utf8"
    DUPLICATE_JSON_KEY = "duplicate_json_key"
    CONTRACT_VIOLATION = "contract_violation"


class ContractError(ValueError):
    """Controlled protocol-contract failure; the message carries no submitted text."""

    def __init__(self, protocol: str, reason: RejectReason) -> None:
        self.protocol = protocol
        self.reason = reason
        super().__init__(f"{protocol} request rejected: {reason.value}")


def _check_whitelist(protocol: str, allowed: frozenset[str], value: str) -> str:
    if value not in allowed:
        raise ValueError(f"model not in {protocol} contract whitelist")
    return value


class DeepSeekResponseFormat(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    type: Literal["text", "json_object"] = "text"


class DeepSeekMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    role: Literal["system", "user", "assistant"]
    content: str


class DeepSeekChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    protocol: ClassVar[str] = DEEPSEEK_CHAT_PROTOCOL

    model: str
    messages: Annotated[list[DeepSeekMessage], Field(min_length=1)]
    temperature: Annotated[float, Field(ge=0, le=2)] | None = None
    top_p: Annotated[float, Field(gt=0, le=1)] | None = None
    stop: str | Annotated[list[str], Field(max_length=16)] | None = None
    response_format: DeepSeekResponseFormat | None = None

    @field_validator("model")
    @classmethod
    def _model_whitelisted(cls, value: str) -> str:
        return _check_whitelist(DEEPSEEK_CHAT_PROTOCOL, DEEPSEEK_MODEL_WHITELIST, value)


class ClaudeTextBlock(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    type: Literal["text"]
    text: str


class ClaudeMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    role: Literal["user", "assistant"]
    content: str | Annotated[list[ClaudeTextBlock], Field(min_length=1)]


class ClaudeMessagesRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    protocol: ClassVar[str] = CLAUDE_MESSAGES_PROTOCOL

    model: str
    max_tokens: Annotated[int, Field(ge=1)]
    messages: Annotated[list[ClaudeMessage], Field(min_length=1)]
    system: str | None = None
    stop_sequences: list[str] | None = None
    temperature: Annotated[float, Field(ge=0, le=1)] | None = None
    top_p: Annotated[float, Field(gt=0, le=1)] | None = None
    top_k: int | None = None

    @field_validator("model")
    @classmethod
    def _model_whitelisted(cls, value: str) -> str:
        return _check_whitelist(CLAUDE_MESSAGES_PROTOCOL, CLAUDE_MODEL_WHITELIST, value)


def _load_unique_json(protocol: str, text: str) -> object:
    def unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ContractError(protocol, RejectReason.DUPLICATE_JSON_KEY)
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ContractError(protocol, RejectReason.MALFORMED_JSON)

    try:
        return json.loads(text, object_pairs_hook=unique_pairs, parse_constant=reject_constant)
    except (json.JSONDecodeError, RecursionError):
        pass
    raise ContractError(protocol, RejectReason.MALFORMED_JSON)


def _decode_text(protocol: str, raw: str | bytes) -> str:
    if isinstance(raw, str):
        return raw
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    raise ContractError(protocol, RejectReason.INVALID_UTF8)


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _parse(protocol: str, model_cls: type[_ModelT], raw: str | bytes) -> _ModelT:
    payload = _load_unique_json(protocol, _decode_text(protocol, raw))
    try:
        return model_cls.model_validate(payload)
    except ValidationError:
        pass
    raise ContractError(protocol, RejectReason.CONTRACT_VIOLATION)


def parse_deepseek_chat_completion(raw: str | bytes) -> DeepSeekChatRequest:
    return _parse(DEEPSEEK_CHAT_PROTOCOL, DeepSeekChatRequest, raw)


def parse_claude_messages(raw: str | bytes) -> ClaudeMessagesRequest:
    return _parse(CLAUDE_MESSAGES_PROTOCOL, ClaudeMessagesRequest, raw)
