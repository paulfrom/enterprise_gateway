"""Opaque provider data survives while supported text is masked and restored."""
import json
import unittest
from copy import deepcopy

from detection.spans import Span
from gateway.ingress import IngressValidator
from gateway.streaming import PassthroughStream
from masking.mapping import MappingContext
from masking.replacer import replace_request
from masking.restorer import restore_response
from policy.policy import load_policy
from protocol.protocols import DEEPSEEK_CHAT_PROTOCOL, CLAUDE_MESSAGES_PROTOCOL


class PassthroughTests(unittest.TestCase):
    def test_opaque_request_fields_and_content_survive_at_original_paths(self):
        for protocol in (DEEPSEEK_CHAT_PROTOCOL, CLAUDE_MESSAGES_PROTOCOL):
            body = {'model': 'synthetic', 'messages': [{'role': 'user', 'content': [
                {'type': 'image', 'source': {'opaque': ['untouched']}},
                {'type': 'text', 'text': '合成公司', 'annotations': [{'unknown': True}]},
                {'type': 'future', 'text': 'opaque text'}, {'type': {'vendor_type': True}}], 'vendor_metadata': [1, 2]}],
                'vendor_control': {'unknown': True}, 'temperature': 'provider-decides',
                'tool_choice': {'vendor_type': 'unknown'}}
            if protocol == CLAUDE_MESSAGES_PROTOCOL: body['max_tokens'] = 32
            original = deepcopy(body)
            policy = load_policy({'version': 'test', 'rules': [
                {'category': 'APPROVED', 'label': 'approved_external', 'scope': 'test'}]})
            validated = IngressValidator.validate_request(json.dumps(body), protocol, 'test', 'APPROVED',
                policy, allowed_models=frozenset({'synthetic'}))
            self.assertEqual([f.json_path for f in validated.fragments], ['messages[0].content[1].text'])
            with MappingContext('test', 'v1', b'h' * 32) as context:
                masked = replace_request(validated, {'messages[0].content[1].text': [Span(0, 4, 'ORG', 1)]}, context)
                output = masked.model_dump(exclude_none=True)
                token = output['messages'][0]['content'][1]['text']
                self.assertNotEqual(token, '合成公司')
                self.assertEqual(context.restore(token), '合成公司')
                output['messages'][0]['content'][1]['text'] = '合成公司'
                self.assertEqual(output, original)
                self.assertEqual(masked.model_copy(update={'model': 'mapped'}).model_dump()['model'], 'mapped')
            self.assertEqual(body, original)

    def test_unknown_response_fields_are_preserved_while_text_is_restored(self):
        with MappingContext('test', 'v1', b'h' * 32) as context:
            token = context.token_for('ORG', '合成公司')
            body = {'model': 'provider-future-model', 'vendor_unknown': {'opaque': True},
                    'choices': [{'message': {'role': 'assistant', 'content': token,
                        'vendor_metadata': {'unknown': True}}, 'future_choice': [1]}]}
            result = restore_response(DEEPSEEK_CHAT_PROTOCOL, body, context, allow_unsupported=True)
            expected = deepcopy(body)
            expected['choices'][0]['message']['content'] = '合成公司'
            self.assertEqual(result.model_dump(), expected)
            self.assertEqual(body['choices'][0]['message']['content'], token)

    def test_stream_preserves_unknown_usage_and_delta_fields(self):
        with MappingContext('test', 'v1', b'h' * 32) as context:
            token = context.token_for('ORG', '合成公司')
            stream = PassthroughStream(DEEPSEEK_CHAT_PROTOCOL, 'synthetic', context)
            event = {'id': 'synthetic-stream', 'object': 'chat.completion.chunk', 'created': 1,
                'model': 'synthetic', 'vendor_top': {'opaque': True},
                'choices': [{'index': 0, 'delta': {'role': 'assistant', 'content': token,
                    'vendor_delta': {'opaque': True}}, 'finish_reason': 'stop',
                    'logprobs': {'opaque': True}}], 'usage': {'vendor_usage': [1, 2]}}
            wire = b'data: ' + json.dumps(event).encode() + b'\n\ndata: [DONE]\n\n'
            stream.feed(wire)
            output = b''.join(stream.finalize()).decode()
            restored = json.loads(next(line[6:] for line in output.splitlines() if line.startswith('data: {')))
            event['choices'][0]['delta']['content'] = '合成公司'
            self.assertEqual(restored, event)
            self.assertIn('data: [DONE]', output)

    def test_stream_relays_opaque_events_and_custom_tool_calls(self):
        with MappingContext('test', 'v1', b'h' * 32) as context:
            stream = PassthroughStream(DEEPSEEK_CHAT_PROTOCOL, 'synthetic', context)
            calls = [
                {'index': 0, 'id': 'synthetic-call', 'type': 'custom',
                 'custom': {'name': 'opaque', 'input': 'vendor input'}},
                {'index': 0, 'custom': {'input': 'continued input'}}]
            frames = []
            for index, call in enumerate(calls):
                frames.append({'id': 'synthetic-stream', 'object': 'chat.completion.chunk',
                    'created': 1, 'model': 'synthetic', 'choices': [{'index': 0,
                        'delta': {'tool_calls': [call]}, 'finish_reason': 'tool_calls' if index else None}]})
            wire = b'event: vendor_progress\ndata: opaque progress\n\n'
            wire += b''.join(b'data: ' + json.dumps(frame).encode() + b'\n\n' for frame in frames)
            wire += b'data: [DONE]\n\n'
            stream.feed(wire)
            output = b''.join(stream.finalize()).decode()
            self.assertIn('event: vendor_progress\ndata: opaque progress', output)
            data = [json.loads(line[6:]) for line in output.splitlines() if line.startswith('data: {')]
            self.assertEqual(data, frames)

    def test_claude_opaque_content_block_is_relayed(self):
        with MappingContext('test', 'v1', b'h' * 32) as context:
            stream = PassthroughStream(CLAUDE_MESSAGES_PROTOCOL, 'synthetic', context)
            events = [
                {'type': 'message_start', 'message': {'id': 'synthetic-message', 'type': 'message',
                    'role': 'assistant', 'model': 'synthetic', 'content': [], 'stop_reason': None,
                    'stop_sequence': None, 'usage': {'input_tokens': 1, 'output_tokens': 0}}},
                {'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'vendor_document', 'opaque': True}},
                {'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'vendor_delta', 'opaque': [1]}},
                {'type': 'content_block_stop', 'index': 0},
                {'type': 'message_delta', 'delta': {'stop_reason': 'end_turn', 'stop_sequence': None},
                    'usage': {'output_tokens': 1}},
                {'type': 'message_stop'}]
            wire = b''.join(('event: ' + event['type'] + '\ndata: ' + json.dumps(event) + '\n\n').encode() for event in events)
            stream.feed(wire)
            output = b''.join(stream.finalize()).decode()
            data = [json.loads(line[6:]) for line in output.splitlines() if line.startswith('data: {')]
            self.assertEqual(data[1:4], events[1:4])
