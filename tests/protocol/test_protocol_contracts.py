"""Admitted protocol subset: explicit model bindings, strict text/tools/streams."""
import json
import unittest
from infra.errors import SafetyError
from protocol.protocols import parse_deepseek_chat_completion, parse_claude_messages

class ProtocolContracts(unittest.TestCase):
    def bodies(self):
        yield parse_deepseek_chat_completion, {"model":"synthetic-model","messages":[{"role":"user","content":"hello"}]}
        yield parse_claude_messages, {"model":"synthetic-model","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}

    def parse(self, parser, body):
        return parser(json.dumps(body), allowed_models=frozenset({"synthetic-model"}))

    def test_explicit_brand_independent_model_and_stream(self):
        for parser,body in self.bodies():
            body['stream']=True
            self.assertTrue(self.parse(parser,body).stream)

    def test_missing_empty_or_unbound_model_set_is_rejected(self):
        for parser,body in self.bodies():
            for models in (None,frozenset(),frozenset({'other'})):
                with self.assertRaises(SafetyError): parser(json.dumps(body),allowed_models=models)

    def test_unknown_fields_wrong_types_nontext_and_duplicate_json(self):
        for parser,body in self.bodies():
            for extra in ({'unknown':'secret'},{'stream':'true'},{'model':32},{'temperature':3.0}):
                with self.subTest(parser=parser.__name__,extra=extra),self.assertRaises(SafetyError): self.parse(parser,{**body,**extra})
            for messages in ([{'role':'user','content':{'image':'secret'}}],[{'role':'user','content':'hi','unknown':'secret'}]):
                with self.assertRaises(SafetyError): self.parse(parser,{**body,'messages':messages})
            with self.assertRaises(SafetyError): parser('{"model":"x","model":"y"}',allowed_models=frozenset({'x'}))
            with self.assertRaises(SafetyError): parser(b'{"model":"\xff"}',allowed_models=frozenset({'x'}))

    def test_tools_supported_and_unknown_nested_fields_rejected(self):
        schema={'type':'object','properties':{'org':{'type':'string'}},'required':['org'],'additionalProperties':False}
        for parser,body in self.bodies():
            if parser is parse_deepseek_chat_completion:
                tool={'type':'function','function':{'name':'lookup','description':'Search','parameters':schema}}
            else: tool={'name':'lookup','description':'Search','input_schema':schema}
            parsed=self.parse(parser,{**body,'tools':[tool]})
            self.assertEqual(len(parsed.tools),1)
            tool['unknown']='secret'
            with self.assertRaises(SafetyError): self.parse(parser,{**body,'tools':[tool]})

    def test_deepseek_tool_result_requires_linked_id(self):
        body={'model':'synthetic-model','messages':[{'role':'tool','content':'result'}]}
        with self.assertRaises(SafetyError): self.parse(parse_deepseek_chat_completion,body)
        body['messages'][0]['tool_call_id']='call-1'
        self.assertEqual(self.parse(parse_deepseek_chat_completion,body).messages[0].role,'tool')

    def test_text_blocks_and_typed_controls_are_preserved(self):
        body = {'model': 'synthetic-model', 'messages': [{'role': 'user', 'content': [
            {'type': 'text', 'text': 'synthetic text'}]}], 'stream': True,
            'stream_options': {'include_usage': True}, 'thinking': {'type': 'enabled'}}
        self.assertEqual(self.parse(parse_deepseek_chat_completion, body).model_dump(exclude_unset=True), body)

    def test_unsupported_blocks_and_control_types_fail_closed(self):
        base = {'model': 'synthetic-model', 'messages': [{'role': 'user', 'content': 'hello'}]}
        for change in ({'thinking': {'type': 'unknown'}}, {'thinking': {'type': 'enabled', 'unknown': 'secret'}},
                       {'stream_options': {'include_usage': 'true'}}, {'stream_options': {'unknown': True}},
                       {'messages': [{'role': 'user', 'content': [{'type': 'image_url', 'image_url': {}}]}]},
                       {'messages': [{'role': 'user', 'content': [{'type': 'text', 'text': 'hello', 'unknown': 'secret'}]}]},
                       {'messages': [{'role': 'user', 'content': []}]}):
            with self.subTest(change=change), self.assertRaises(SafetyError):
                self.parse(parse_deepseek_chat_completion, {**base, **change})

    def test_reasoning_effort_accepts_documented_values_and_preserves_controls(self):
        base = {'model': 'synthetic-model', 'messages': [{'role': 'user', 'content': 'hello'}],
                'thinking': {'type': 'enabled'}}
        for effort in ('none', 'minimal', 'low', 'medium', 'high', 'xhigh', 'max'):
            with self.subTest(effort=effort):
                body = {**base, 'reasoning_effort': effort}
                self.assertEqual(self.parse(parse_deepseek_chat_completion, body).model_dump(exclude_unset=True), body)
        for effort in ('unknown', '', True, 1, {'level': 'high'}, ['high']):
            with self.subTest(effort=effort), self.assertRaises(SafetyError):
                self.parse(parse_deepseek_chat_completion, {**base, 'reasoning_effort': effort})

    def test_assistant_reasoning_history_is_typed_and_role_bound(self):
        body = {'model': 'synthetic-model', 'messages': [
            {'role': 'assistant', 'content': 'answer', 'reasoning_content': 'synthetic thought'}]}
        self.assertEqual(self.parse(parse_deepseek_chat_completion, body).model_dump(exclude_unset=True), body)
        for role, reasoning in (('user', 'thought'), ('tool', 'thought'), ('assistant', True),
                                ('assistant', {'text': 'thought'})):
            message = {'role': role, 'content': 'answer', 'reasoning_content': reasoning}
            if role == 'tool': message['tool_call_id'] = 'synthetic-call'
            with self.subTest(role=role, reasoning=reasoning), self.assertRaises(SafetyError):
                self.parse(parse_deepseek_chat_completion, {**body, 'messages': [message]})
