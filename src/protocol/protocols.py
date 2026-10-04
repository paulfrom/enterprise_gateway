"""Strict candidate request contracts for DeepSeek Chat Completions and Claude Messages.

Only the explicitly selected plain-text chat subset is admissible; everything
else fails closed with a SafetyError whose message never contains submitted
business text. Contract snapshot fixed from official sources read 2026-10-03.
"""

from typing import Annotated, Callable, ClassVar, Literal, NoReturn, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from infra.errors import SafetyCode, SafetyError
from infra.strict_json import JsonRejectKind, parse_strict_json

DEEPSEEK_CHAT_PROTOCOL = "deepseek-chat-completions"
CLAUDE_MESSAGES_PROTOCOL = "claude-messages"

DEEPSEEK_MODEL_WHITELIST: frozenset[str] = frozenset({"deepseek-flash", "deepseek-v4-pro"})
CLAUDE_MODEL_WHITELIST: frozenset[str] = frozenset(
    {"claude-sonnet-5-5", "claude-fable-5-1", "claude-opus-5-5"}
)


def _reject_json(protocol: str) -> Callable[[JsonRejectKind], NoReturn]:
    def reject(kind: JsonRejectKind) -> NoReturn:
        if kind is JsonRejectKind.DUPLICATE_KEY:
            raise SafetyError(SafetyCode.DUPLICATE_JSON_KEY, protocol)
        if kind is JsonRejectKind.INVALID_UTF8:
            raise SafetyError(SafetyCode.INVALID_UTF8, protocol)
        raise SafetyError(SafetyCode.MALFORMED_JSON, protocol)

    return reject


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


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _parse(protocol: str, model_cls: type[_ModelT], raw: str | bytes) -> _ModelT:
    if not isinstance(raw, (str, bytes)):
        raise SafetyError(SafetyCode.MALFORMED_JSON, protocol)
    payload = parse_strict_json(raw, reject=_reject_json(protocol))
    validation_failed = False
    try:
        parsed = model_cls.model_validate(payload)
    except ValidationError:
        validation_failed = True
    if validation_failed:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, protocol)
    return parsed


def parse_deepseek_chat_completion(raw: str | bytes) -> DeepSeekChatRequest:
    return _parse(DEEPSEEK_CHAT_PROTOCOL, DeepSeekChatRequest, raw)


def parse_claude_messages(raw: str | bytes) -> ClaudeMessagesRequest:
    return _parse(CLAUDE_MESSAGES_PROTOCOL, ClaudeMessagesRequest, raw)
