"""Unified ingress validator combining policy (C-01), protocol (C-03), and static exemption (C-04).

Enforces fail-closed input admission: unapproved categories, unsupported protocols,
extra/unknown fields, non-text inputs (images/files), streaming, and tool calls
are rejected at the gate. No fields are stripped or quietly bypassed.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any
from protocol.history_state import HistoricalStateAdapter

from infra.errors import SafetyCode, SafetyError
from policy.policy import ClassificationPolicy, resolve_egress_policy
from protocol.protocols import (
    CLAUDE_MESSAGES_PROTOCOL,
    DEEPSEEK_CHAT_PROTOCOL,
    ClaudeMessagesRequest,
    ClaudeTextBlock,
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
    """A strictly validated request candidate ready for downstream detection & spooling."""

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
    ) -> ValidatedIngressRequest:
        # 1. Enforce egress classification policy (C-01)
        try:
            if not local_collection_only:
                resolve_egress_policy(policy, category)
        except SafetyError as exc:
            raise SafetyError(SafetyCode.POLICY_REJECTED, exc.code.value) from None

        # 2. Strict candidate protocol parse (C-03)
        if protocol == DEEPSEEK_CHAT_PROTOCOL:
            try:
                parsed = parse_deepseek_chat_completion(raw_body, allowed_models=allowed_models)
            except SafetyError as exc:
                raise SafetyError(SafetyCode.PROTOCOL_VIOLATION, exc.code.value) from None
            model_name = parsed.model
            raw_fragments = [(f"messages[{i}].content", msg.content) for i, msg in enumerate(parsed.messages) if msg.content is not None]
            if parsed.stop is not None:
                if isinstance(parsed.stop, str):
                    raw_fragments.append(("stop", parsed.stop))
                elif isinstance(parsed.stop, list):
                    for k, s in enumerate(parsed.stop):
                        raw_fragments.append((f"stop[{k}]", s))

        elif protocol == CLAUDE_MESSAGES_PROTOCOL:
            try:
                parsed = parse_claude_messages(raw_body, allowed_models=allowed_models)
            except SafetyError as exc:
                raise SafetyError(SafetyCode.PROTOCOL_VIOLATION, exc.code.value) from None
            model_name = parsed.model
            raw_fragments = []
            if parsed.system is not None:
                raw_fragments.append(("system", parsed.system))
            for i, msg in enumerate(parsed.messages):
                if isinstance(msg.content, str):
                    raw_fragments.append((f"messages[{i}].content", msg.content))
                else:
                    for j, block in enumerate(msg.content):
                        if isinstance(block, ClaudeTextBlock):
                            raw_fragments.append((f"messages[{i}].content[{j}].text", block.text))
            if parsed.stop_sequences is not None:
                for k, s in enumerate(parsed.stop_sequences):
                    raw_fragments.append((f"stop_sequences[{k}]", s))
        else:
            raise SafetyError(
                SafetyCode.UNSUPPORTED_PROTOCOL, f"protocol '{protocol}' is not supported"
            )

        payload = parsed.model_dump(exclude_none=True)
        if history_adapter is not None:
            history_adapter.validate_message_history(payload['messages'])
        elif any(isinstance(m.get('content'), list) and any(b.get('type') == 'thinking' for b in m['content']) for m in payload['messages']):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, 'unverified history')
        # Enumerate all string values and object keys. Structure is detected too,
        # but must be rejected rather than rewritten when it contains entities.
        editable_paths = {p for p, _ in raw_fragments if not p.startswith(('stop', 'stop_sequences'))}
        def walk(value: Any, path: str):
            if isinstance(value, str):
                if path != 'model' and not path.endswith(('.role','.type')):
                    raw_fragments.append((path, value))
            elif isinstance(value, list):
                for i, child in enumerate(value): walk(child, f'{path}[{i}]')
            elif isinstance(value, dict):
                for key, child in value.items():
                    # Field/property names are immutable protocol structure.
                    if '.properties' in path:
                        raw_fragments.append((f'{path}.__key__[{key}]', key))
                    child_path = f'{path}.{key}' if path else key
                    if key in ('description','arguments') or (key == 'content' and isinstance(child, str) and 'messages[' in child_path) or ('.input.' in child_path and isinstance(child, str)):
                        editable_paths.add(child_path)
                    walk(child, child_path)
        # Existing plain text positions are already present; avoid duplicates.
        walk(payload, '')
        raw_fragments = list(dict(raw_fragments).items())
        tools = (payload.get('tools') or [])
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
        choice=payload.get('tool_choice')
        if choice is not None:
            name=(choice.get('function',{}).get('name') if protocol==DEEPSEEK_CHAT_PROTOCOL else choice.get('name')) if isinstance(choice,dict) else None
            if name is not None and name not in schemas:
                raise SafetyError(SafetyCode.CONTRACT_VIOLATION,'unknown selected tool')
        from infra.strict_json import parse_strict_json
        for message in payload['messages']:
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
                    editable=path in editable_paths,
                    source_kind='model-output' if path.startswith('messages[') and parsed.messages[int(path.split('[')[1].split(']')[0])].role == 'assistant' else 'user-input',
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
