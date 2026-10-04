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
