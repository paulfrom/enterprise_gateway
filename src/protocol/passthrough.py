"""Keep provider payloads intact and expose only fields the gateway uses."""
from copy import deepcopy
import json
from types import SimpleNamespace

from pydantic import BaseModel, PrivateAttr

from infra.errors import SafetyCode, SafetyError
from infra.strict_json import parse_strict_json
from protocol.protocols import (
    CLAUDE_MESSAGES_PROTOCOL, DEEPSEEK_CHAT_PROTOCOL,
    ClaudeMessagesRequest, ClaudeMessage, ClaudeTextBlock, ClaudeToolUseBlock,
    ClaudeToolResultBlock, ClaudeToolDefinition, DeepSeekChatRequest, DeepSeekMessage,
    DeepSeekTextBlock, DeepSeekToolDefinition, ToolDefinitionFunction,
)


class PassthroughPayload(BaseModel):
    _raw_payload: dict = PrivateAttr(default_factory=dict)

    def model_dump(self, **kwargs):
        payload = deepcopy(self._raw_payload)
        if 'model' in payload:
            payload['model'] = self.model
        return payload


class PassthroughChatRequest(PassthroughPayload, DeepSeekChatRequest):
    pass


class PassthroughMessagesRequest(PassthroughPayload, ClaudeMessagesRequest):
    pass


def parse_passthrough_request(raw, protocol, allowed_models):
    if protocol not in (DEEPSEEK_CHAT_PROTOCOL, CLAUDE_MESSAGES_PROTOCOL):
        raise SafetyError(SafetyCode.UNSUPPORTED_PROTOCOL)
    def reject(_kind):
        raise SafetyError(SafetyCode.MALFORMED_JSON)
    payload = parse_strict_json(raw, reject=reject)
    if not isinstance(payload, dict) or not isinstance(payload.get('model'), str):
        raise SafetyError(SafetyCode.MALFORMED_JSON)
    if not allowed_models or payload['model'] not in allowed_models:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, 'unbound model')
    tools = []
    for tool in payload.get('tools', []) if isinstance(payload.get('tools'), list) else []:
        if not isinstance(tool, dict):
            continue
        if protocol == DEEPSEEK_CHAT_PROTOCOL:
            function = tool.get('function')
            if tool.get('type') == 'function' and isinstance(function, dict) and isinstance(function.get('name'), str):
                tools.append(DeepSeekToolDefinition.model_construct(type='function',
                    function=ToolDefinitionFunction.model_construct(name=function['name'], parameters={})))
        elif isinstance(tool.get('name'), str):
            tools.append(ClaudeToolDefinition.model_construct(name=tool['name'], input_schema={}))
    messages = []
    for message in payload.get('messages', []) if isinstance(payload.get('messages'), list) else []:
        if not isinstance(message, dict):
            continue
        content = message.get('content')
        if isinstance(content, list):
            blocks = []
            for block in content:
                cls = None
                if isinstance(block, dict):
                    if block.get('type') == 'text':
                        cls = DeepSeekTextBlock if protocol == DEEPSEEK_CHAT_PROTOCOL else ClaudeTextBlock
                    elif protocol == CLAUDE_MESSAGES_PROTOCOL and isinstance(block.get('type'), str):
                        cls = {'tool_use': ClaudeToolUseBlock, 'tool_result': ClaudeToolResultBlock}.get(block.get('type'))
                blocks.append(cls.model_construct(**block) if cls else block)
            content = blocks
        cls = DeepSeekMessage if protocol == DEEPSEEK_CHAT_PROTOCOL else ClaudeMessage
        messages.append(cls.model_construct(**{**message, 'content': content}))
    if protocol == DEEPSEEK_CHAT_PROTOCOL:
        request = PassthroughChatRequest.model_construct(**{**payload, 'messages': messages,
            'tools': tools, 'stream': payload.get('stream') is True})
    elif protocol == CLAUDE_MESSAGES_PROTOCOL:
        request = PassthroughMessagesRequest.model_construct(**{**payload, 'messages': messages,
            'tools': tools, 'stream': payload.get('stream') is True})
    else:
        raise SafetyError(SafetyCode.UNSUPPORTED_PROTOCOL)
    request._raw_payload = payload
    return request


def text_fragments(payload, protocol, exempt_tools):
    """Yield supported text paths without inspecting opaque provider content."""
    messages = payload.get('messages')
    if not isinstance(messages, list):
        return
    tool_names = {}
    for message in messages:
        if not isinstance(message, dict):
            continue
        if protocol == DEEPSEEK_CHAT_PROTOCOL:
            calls = message.get('tool_calls')
            for call in calls if isinstance(calls, list) else []:
                if (isinstance(call, dict) and isinstance(call.get('id'), str)
                        and isinstance(call.get('function'), dict)
                        and isinstance(call['function'].get('name'), str)):
                    tool_names[call['id']] = call['function'].get('name')
        else:
            content = message.get('content')
            for block in content if isinstance(content, list) else []:
                if (isinstance(block, dict) and block.get('type') == 'tool_use'
                        and isinstance(block.get('id'), str) and isinstance(block.get('name'), str)):
                    tool_names[block['id']] = block.get('name')

    def content_text(content, path):
        if isinstance(content, str):
            yield path, content
        elif isinstance(content, list):
            for index, block in enumerate(content):
                if isinstance(block, dict) and block.get('type') == 'text' and isinstance(block.get('text'), str):
                    yield f'{path}[{index}].text', block['text']

    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            continue
        role = message.get('role')
        path = f'messages[{index}]'
        if role not in ('user', 'assistant', 'tool'):
            continue
        if role == 'tool' and isinstance(message.get('tool_call_id'), str) and tool_names.get(message['tool_call_id']) in exempt_tools:
            continue
        content = message.get('content')
        if protocol == CLAUDE_MESSAGES_PROTOCOL and isinstance(content, list):
            for block_index, block in enumerate(content):
                if not isinstance(block, dict):
                    continue
                if block.get('type') == 'text' and isinstance(block.get('text'), str):
                    yield f'{path}.content[{block_index}].text', block['text']
                elif (block.get('type') == 'tool_result' and isinstance(block.get('tool_use_id'), str)
                      and tool_names.get(block['tool_use_id']) not in exempt_tools):
                    yield from content_text(block.get('content'), f'{path}.content[{block_index}].content')
        else:
            yield from content_text(content, path + '.content')
        if role == 'assistant':
            for field in ('reasoning', 'reasoning_content'):
                if isinstance(message.get(field), str):
                    yield path + '.' + field, message[field]


class PassthroughResponse(PassthroughPayload):
    model: str | None = None

    def __getattr__(self, name):
        try:
            return super().__getattr__(name)
        except AttributeError:
            payload = self._raw_payload
            if not isinstance(payload, dict) or name not in payload:
                raise
            def view(value):
                if isinstance(value, dict): return SimpleNamespace(**{k: view(v) for k, v in value.items()})
                if isinstance(value, list): return [view(v) for v in value]
                return value
            return view(payload[name])


def restore_passthrough_response(payload, protocol, context):
    result = deepcopy(payload)
    def restore_values(value):
        if isinstance(value, str): return context.restore(value)
        if isinstance(value, list): return [restore_values(v) for v in value]
        if isinstance(value, dict): return {k: restore_values(v) for k, v in value.items()}
        return value
    def restore_content(message):
        if not isinstance(message, dict): return
        for field in ('content', 'reasoning_content', 'reasoning'):
            if isinstance(message.get(field), str):
                message[field] = context.restore(message[field])
        content = message.get('content')
        for block in content if isinstance(content, list) else []:
            if isinstance(block, dict) and block.get('type') == 'text' and isinstance(block.get('text'), str):
                block['text'] = context.restore(block['text'])
            elif (isinstance(block, dict) and block.get('type') == 'thinking'
                  and not block.get('signature') and isinstance(block.get('thinking'), str)):
                block['thinking'] = context.restore(block['thinking'])
        details = message.get('reasoning_details')
        for detail in details if isinstance(details, list) else []:
            if isinstance(detail, dict) and isinstance(detail.get('text'), str):
                detail['text'] = context.restore(detail['text'])
        calls = message.get('tool_calls')
        for call in calls if isinstance(calls, list) else []:
            function = call.get('function') if isinstance(call, dict) else None
            if not isinstance(function, dict) or not isinstance(function.get('arguments'), str): continue
            try: arguments = json.loads(function['arguments'])
            except ValueError: continue
            restored = restore_values(arguments)
            if restored != arguments:
                function['arguments'] = json.dumps(restored, ensure_ascii=False)
    if isinstance(result, dict):
        if protocol == DEEPSEEK_CHAT_PROTOCOL:
            choices = result.get('choices')
            for choice in choices if isinstance(choices, list) else []:
                if isinstance(choice, dict): restore_content(choice.get('message'))
        else:
            restore_content(result)
            content = result.get('content')
            for block in content if isinstance(content, list) else []:
                if isinstance(block, dict) and block.get('type') == 'tool_use' and isinstance(block.get('input'), dict):
                    block['input'] = restore_values(block['input'])
    response = PassthroughResponse.model_construct(model=result.get('model') if isinstance(result, dict) else None)
    response._raw_payload = result
    return response
