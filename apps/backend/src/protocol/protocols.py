"""Strict candidate request contracts for DeepSeek Chat Completions and Claude Messages.

Only the explicitly selected plain-text chat subset is admissible; everything
else fails closed with a SafetyError whose message never contains submitted
business text. Contract snapshot fixed from official sources read 2026-10-03.
"""

from typing import Annotated, Any, Callable, ClassVar, Literal, NoReturn, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from infra.errors import SafetyCode, SafetyError
from infra.strict_json import JsonRejectKind, parse_strict_json

DEEPSEEK_CHAT_PROTOCOL = "deepseek-chat-completions"
CLAUDE_MESSAGES_PROTOCOL = "claude-messages"



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


class DeepSeekTextBlock(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    type: Literal["text"]
    text: str


class DeepSeekMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    role: Literal["system", "user", "assistant", "tool"]
    content: str | Annotated[list[DeepSeekTextBlock], Field(min_length=1)] | None = None
    tool_calls: list['DeepSeekToolCall'] | None = None
    tool_call_id: str | None = None
    reasoning_content: str | None = None

    @model_validator(mode='after')
    def _valid_role_content(self):
        if self.reasoning_content is not None and self.role != 'assistant':
            raise ValueError('reasoning role')
        if self.role == 'tool':
            if not self.tool_call_id or self.content is None or self.tool_calls:
                raise ValueError('tool result shape')
        elif self.tool_call_id is not None or (self.tool_calls is not None and self.role != 'assistant') or (self.content is None and not self.tool_calls):
            raise ValueError('message shape')
        return self


class ToolFunction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    name: Annotated[str, Field(min_length=1)]
    arguments: str


class DeepSeekToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    id: Annotated[str, Field(min_length=1)]
    type: Literal['function']
    function: ToolFunction


class ToolDefinitionFunction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    name: Annotated[str, Field(min_length=1)]
    description: str | None = None
    parameters: dict[str, Any]
    strict: bool | None = None


class DeepSeekToolDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    type: Literal['function']
    function: ToolDefinitionFunction


class DeepSeekNamedTool(BaseModel):
    model_config = ConfigDict(extra='forbid',frozen=True,strict=True)
    type: Literal['function']
    function: dict[Literal['name'],str]


class DeepSeekStreamOptions(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    include_usage: bool = False


class DeepSeekThinking(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    type: Literal['enabled', 'disabled']


class DeepSeekChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    protocol: ClassVar[str] = DEEPSEEK_CHAT_PROTOCOL

    model: str
    messages: Annotated[list[DeepSeekMessage], Field(min_length=1)]
    temperature: Annotated[float, Field(ge=0, le=2)] | None = None
    top_p: Annotated[float, Field(gt=0, le=1)] | None = None
    stop: str | Annotated[list[str], Field(max_length=16)] | None = None
    response_format: DeepSeekResponseFormat | None = None
    stream: bool = False
    stream_options: DeepSeekStreamOptions | None = None
    thinking: DeepSeekThinking | None = None
    reasoning_effort: Literal['none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max'] | None = None
    tools: list[DeepSeekToolDefinition] | None = None
    tool_choice: Literal['auto','none','required'] | DeepSeekNamedTool | None = None

    @field_validator("model")
    @classmethod
    def _model_non_empty(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("model must be a non-empty string")
        return value


class ClaudeTextBlock(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    type: Literal["text"]
    text: str


class ClaudeToolUseBlock(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True, strict=True)
    type: Literal['tool_use']
    id: Annotated[str, Field(min_length=1)]
    name: Annotated[str, Field(min_length=1)]
    input: dict[str, Any]


class ClaudeToolResultBlock(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True, strict=True)
    type: Literal['tool_result']
    tool_use_id: Annotated[str, Field(min_length=1)]
    content: str
    is_error: bool | None = None


class ClaudeThinkingBlock(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True, strict=True)
    type: Literal['thinking']
    thinking: str
    signature: str
    metadata: dict[str, str]


class ClaudeToolDefinition(BaseModel):
    model_config = ConfigDict(extra='forbid', frozen=True, strict=True)
    name: Annotated[str, Field(min_length=1)]
    description: str | None = None
    input_schema: dict[str, Any]


class ClaudeToolChoice(BaseModel):
    model_config = ConfigDict(extra='forbid',frozen=True,strict=True)
    type: Literal['auto','any','tool','none']
    name: str | None = None
    disable_parallel_tool_use: bool | None = None

    @model_validator(mode='after')
    def _name_required(self):
        if (self.type=='tool') != (self.name is not None): raise ValueError('tool choice name')
        return self


class ClaudeMessage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    role: Literal["user", "assistant"]
    content: str | Annotated[list[ClaudeTextBlock | ClaudeToolUseBlock | ClaudeToolResultBlock | ClaudeThinkingBlock], Field(min_length=1)]


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
    stream: bool = False
    tools: list[ClaudeToolDefinition] | None = None
    tool_choice: ClaudeToolChoice | None = None

    @field_validator("model")
    @classmethod
    def _model_non_empty(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("model must be a non-empty string")
        return value


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _parse(
    protocol: str,
    model_cls: type[_ModelT],
    raw: str | bytes,
    allowed_models: frozenset[str] | None = None,
) -> _ModelT:
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
    if not allowed_models or parsed.model not in allowed_models:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, f"model not in allowed models for {protocol}")
    return parsed


def parse_deepseek_chat_completion(
    raw: str | bytes,
    allowed_models: frozenset[str] | None = None,
) -> DeepSeekChatRequest:
    return _parse(DEEPSEEK_CHAT_PROTOCOL, DeepSeekChatRequest, raw, allowed_models=allowed_models)


def parse_claude_messages(
    raw: str | bytes,
    allowed_models: frozenset[str] | None = None,
) -> ClaudeMessagesRequest:
    return _parse(CLAUDE_MESSAGES_PROTOCOL, ClaudeMessagesRequest, raw, allowed_models=allowed_models)
