"""Unified ingress validator combining policy (C-01), protocol (C-03), and static exemption (C-04).

Selects supported text for protection while preserving opaque provider fields.
An explicit strict parser remains available for offline contract checks.
Detection and masking apply to user-role and assistant-role message text and
to tool/MCP results; system prompts, tool definitions and tool arguments pass
through undetected by design. Results of skill-loading tools are exempt so
that skill instructions reach the model verbatim.
"""

from __future__ import annotations

from dataclasses import dataclass
from protocol.history_state import HistoricalStateAdapter

from infra.errors import SafetyCode, SafetyError
from policy.policy import ClassificationPolicy, resolve_egress_policy
from protocol.protocols import (
    CLAUDE_MESSAGES_PROTOCOL,
    DEEPSEEK_CHAT_PROTOCOL,
    ClaudeMessagesRequest,
    ClaudeTextBlock,
    ClaudeToolResultBlock,
    ClaudeToolUseBlock,
    DeepSeekChatRequest,
    parse_claude_messages,
    parse_deepseek_chat_completion,
)
from protocol.static_exemption import (
    ExemptionDecision,
    ExemptionStatus,
    StaticExemptionRegistry,
    inspect_static_exemption,
)

# Tool names whose results carry skill instructions rather than business data;
# their results bypass detection so masking cannot corrupt instructions.
SKILL_RESULT_EXEMPT_TOOLS = frozenset({"Skill"})


@dataclass(frozen=True, slots=True)
class BusinessTextFragment:
    """A single logical business text unit targeted for detection or exemption."""

    json_path: str
    content: str
    requires_detection: bool
    matched_template_id: str | None
    editable: bool = True
    source_kind: str = 'user-input'


@dataclass(frozen=True, slots=True)
class ValidatedIngressRequest:
    """A routed request with supported text paths selected for protection."""

    protocol: str
    model: str
    category: str
    domain: str
    parsed_request: DeepSeekChatRequest | ClaudeMessagesRequest
    fragments: tuple[BusinessTextFragment, ...]


class IngressValidator:
    """Combines policy, protocol, and exemption into a single immutable gateway barrier."""

    @staticmethod
    def validate_request(
        raw_body: str | bytes,
        protocol: str,
        domain: str,
        category: str,
        policy: ClassificationPolicy,
        exemption_registry: StaticExemptionRegistry | None = None,
        allowed_models: frozenset[str] | None = None,
        history_adapter: HistoricalStateAdapter | None = None,
        local_collection_only: bool = False,
        allow_unsupported: bool = True,
    ) -> ValidatedIngressRequest:
        # 1. Enforce egress classification policy (C-01)
        try:
            if not local_collection_only:
                resolve_egress_policy(policy, category)
        except SafetyError as exc:
            raise SafetyError(SafetyCode.POLICY_REJECTED, exc.code.value) from None

        # 2. Strict candidate protocol parse (C-03)
        if allow_unsupported:
            from protocol.passthrough import parse_passthrough_request, text_fragments
            parsed = parse_passthrough_request(raw_body, protocol, allowed_models)
            model_name = parsed.model
            raw_fragments = list(text_fragments(parsed.model_dump(), protocol, SKILL_RESULT_EXEMPT_TOOLS))
        elif protocol == DEEPSEEK_CHAT_PROTOCOL:
            try:
                parsed = parse_deepseek_chat_completion(raw_body, allowed_models=allowed_models)
            except SafetyError as exc:
                raise SafetyError(SafetyCode.PROTOCOL_VIOLATION, exc.code.value) from None
            model_name = parsed.model
            tool_names = {call.id: call.function.name for msg in parsed.messages
                          for call in msg.tool_calls or ()}
            raw_fragments = []
            for i, msg in enumerate(parsed.messages):
                if msg.role == 'assistant' and msg.reasoning_content is not None:
                    raw_fragments.append((f"messages[{i}].reasoning_content", msg.reasoning_content))
                if msg.role == 'tool':
                    # Tool/MCP results may carry sensitive file contents and are
                    # detected, except results of skill-loading tools.
                    if tool_names.get(msg.tool_call_id) in SKILL_RESULT_EXEMPT_TOOLS:
                        continue
                    if isinstance(msg.content, str):
                        raw_fragments.append((f"messages[{i}].content", msg.content))
                    elif isinstance(msg.content, list):
                        for j, block in enumerate(msg.content):
                            raw_fragments.append((f"messages[{i}].content[{j}].text", block.text))
                elif msg.role in ('user', 'assistant'):
                    if isinstance(msg.content, str):
                        raw_fragments.append((f"messages[{i}].content", msg.content))
                    elif isinstance(msg.content, list):
                        for j, block in enumerate(msg.content):
                            raw_fragments.append((f"messages[{i}].content[{j}].text", block.text))

        elif protocol == CLAUDE_MESSAGES_PROTOCOL:
            try:
                parsed = parse_claude_messages(raw_body, allowed_models=allowed_models)
            except SafetyError as exc:
                raise SafetyError(SafetyCode.PROTOCOL_VIOLATION, exc.code.value) from None
            model_name = parsed.model
            tool_names = {block.id: block.name for msg in parsed.messages
                          if isinstance(msg.content, list) for block in msg.content
                          if isinstance(block, ClaudeToolUseBlock)}
            raw_fragments = []
            for i, msg in enumerate(parsed.messages):
                if isinstance(msg.content, str):
                    raw_fragments.append((f"messages[{i}].content", msg.content))
                else:
                    for j, block in enumerate(msg.content):
                        if isinstance(block, ClaudeTextBlock):
                            raw_fragments.append((f"messages[{i}].content[{j}].text", block.text))
                        elif isinstance(block, ClaudeToolResultBlock):
                            if tool_names.get(block.tool_use_id) in SKILL_RESULT_EXEMPT_TOOLS:
                                continue
                            raw_fragments.append((f"messages[{i}].content[{j}].content", block.content))
        else:
            raise SafetyError(
                SafetyCode.UNSUPPORTED_PROTOCOL, f"protocol '{protocol}' is not supported"
            )

        payload = parsed.model_dump(exclude_none=True)
        if not allow_unsupported and history_adapter is not None:
            history_adapter.validate_message_history(payload['messages'])
        elif not allow_unsupported and any(isinstance(m.get('content'), list) and any(b.get('type') == 'thinking' for b in m['content']) for m in payload['messages']):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, 'unverified history')
        # Detection scope is user/assistant message text and tool results;
        # tools and other structure are validated for shape, never scanned.
        tools = [] if allow_unsupported else (payload.get('tools') or [])
        names = [t['function']['name'] if protocol == DEEPSEEK_CHAT_PROTOCOL else t['name'] for t in tools]
        if len(names) != len(set(names)):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, 'duplicate tools')
        from jsonschema import validators, exceptions
        schemas = {}
        def check_schema_fields(schema):
            if not isinstance(schema,(dict,bool)): raise SafetyError(SafetyCode.CONTRACT_VIOLATION,'schema shape')
            if isinstance(schema,bool): return
            allowed=set(validators.Draft202012Validator.VALIDATORS)|{'$schema','$id','$defs','title','description','default','examples','deprecated','readOnly','writeOnly'}
            if set(schema)-allowed: raise SafetyError(SafetyCode.CONTRACT_VIOLATION,'unknown schema keyword')
            if '$id' in schema: raise SafetyError(SafetyCode.CONTRACT_VIOLATION,'unadmitted schema resource')
            if '$ref' in schema and (not isinstance(schema['$ref'],str) or not schema['$ref'].startswith('#/')): raise SafetyError(SafetyCode.CONTRACT_VIOLATION,'external schema reference')
            if '$schema' in schema and schema['$schema'] not in {'https://json-schema.org/draft/2020-12/schema','http://json-schema.org/draft-07/schema#'}: raise SafetyError(SafetyCode.CONTRACT_VIOLATION,'unadmitted schema dialect')
            for key in ('properties','patternProperties','$defs','dependentSchemas'):
                for child in schema.get(key,{}).values(): check_schema_fields(child)
            for key in ('items','additionalProperties','contains','not','if','then','else','unevaluatedProperties','unevaluatedItems','propertyNames'):
                if key in schema: check_schema_fields(schema[key])
            for key in ('allOf','anyOf','oneOf','prefixItems'):
                for child in schema.get(key,[]): check_schema_fields(child)
        for tool in tools:
            schema = tool['function']['parameters'] if protocol == DEEPSEEK_CHAT_PROTOCOL else tool['input_schema']
            check_schema_fields(schema)
            try: validators.validator_for(schema).check_schema(schema)
            except exceptions.SchemaError: raise SafetyError(SafetyCode.CONTRACT_VIOLATION, 'invalid tool schema') from None
            name = tool['function']['name'] if protocol == DEEPSEEK_CHAT_PROTOCOL else tool['name']
            schemas[name] = schema
        choice=None if allow_unsupported else payload.get('tool_choice')
        if choice is not None:
            name=(choice.get('function',{}).get('name') if protocol==DEEPSEEK_CHAT_PROTOCOL else choice.get('name')) if isinstance(choice,dict) else None
            if name is not None and name not in schemas:
                raise SafetyError(SafetyCode.CONTRACT_VIOLATION,'unknown selected tool')
        from infra.strict_json import parse_strict_json
        for message in [] if allow_unsupported else payload['messages']:
            calls = message.get('tool_calls',[]) if protocol == DEEPSEEK_CHAT_PROTOCOL else [b for b in message['content'] if b['type']=='tool_use'] if isinstance(message['content'],list) else []
            for call in calls:
                name = call['function']['name'] if protocol == DEEPSEEK_CHAT_PROTOCOL else call['name']
                arguments = parse_strict_json(call['function']['arguments'],reject=lambda _: (_ for _ in ()).throw(SafetyError(SafetyCode.MALFORMED_JSON))) if protocol == DEEPSEEK_CHAT_PROTOCOL else call['input']
                if name not in schemas:
                    raise SafetyError(SafetyCode.CONTRACT_VIOLATION,'unknown historical tool')
                if list(validators.validator_for(schemas[name])(schemas[name]).iter_errors(arguments)):
                    raise SafetyError(SafetyCode.CONTRACT_VIOLATION,'historical tool schema')

        # 3. Precise static content exemption evaluation (C-04)
        processed_fragments: list[BusinessTextFragment] = []
        for path, text in raw_fragments:
            if exemption_registry is not None:
                decision = inspect_static_exemption(text, domain, exemption_registry)
                if decision.status is ExemptionStatus.EXEMPT:
                    processed_fragments.append(
                        BusinessTextFragment(
                            json_path=path,
                            content=text,
                            requires_detection=False,
                            matched_template_id=decision.matched_template_id,
                        )
                    )
                    continue

            # Default: requires full detection pipeline
            processed_fragments.append(
                BusinessTextFragment(
                    json_path=path,
                    content=text,
                    requires_detection=True,
                    matched_template_id=None,
                    source_kind='model-output' if path.startswith('messages[') and payload['messages'][int(path.split('[')[1].split(']')[0])].get('role') == 'assistant' else 'user-input',
                )
            )

        return ValidatedIngressRequest(
            protocol=protocol,
            model=model_name,
            category=category,
            domain=domain,
            parsed_request=parsed,
            fragments=tuple(processed_fragments),
        )
