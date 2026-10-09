"""Unit and contract tests for ingress validation barrier."""

import json
from pathlib import Path
import unittest

from infra.errors import SafetyCode, SafetyError
from gateway.ingress import IngressValidator
from policy.policy import load_policy
from protocol.protocols import CLAUDE_MESSAGES_PROTOCOL, DEEPSEEK_CHAT_PROTOCOL
from protocol.static_exemption import load_exemption_registry

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "ingress"


class IngressValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        policy_data = {
            "version": "1.0",
            "rules": [
                {"category": "cat-approved", "label": "approved_external", "scope": "scope-ext"},
                {"category": "cat-secret", "label": "secret", "scope": "scope-loc"},
                {"category": "cat-local", "label": "local_only", "scope": "scope-loc"},
            ],
        }
        self.policy = load_policy(policy_data)

        exemption_data = {
            "version": "1.0.0",
            "templates": [
                {
                    "template_id": "tpl-sys-v1",
                    "domain": "test-domain",
                    "version": "1.0",
                    "text": "You are a helpful assistant.",
                    "sha256": "75357d685f238b6afd7738be9786fdafde641eb6ca9a3be7471939715a68a4de",
                }
            ],
        }
        self.exemption_registry = load_exemption_registry(exemption_data)

    def test_deepseek_valid_request_admission(self) -> None:
        with open(FIXTURES_DIR / "deepseek_valid_request.json", "r", encoding="utf-8") as f:
            raw_body = f.read()

        validated = IngressValidator.validate_request(
            raw_body=raw_body,
            protocol=DEEPSEEK_CHAT_PROTOCOL,
            domain="test-domain",
            category="cat-approved",
            policy=self.policy,
            exemption_registry=self.exemption_registry,
        allowed_models=frozenset({"deepseek-flash","deepseek-v4-pro","claude-sonnet-5-5","claude-fable-5-1","claude-opus-5-5"}))

        self.assertEqual(validated.protocol, DEEPSEEK_CHAT_PROTOCOL)
        self.assertEqual(validated.model, "deepseek-flash")
        self.assertEqual(len(validated.fragments), 1)

        # Only the user-role message is a detection fragment; the system prompt
        # is out of detection scope even when it matches a registered template.
        self.assertEqual(validated.fragments[0].json_path, "messages[1].content")
        self.assertEqual(validated.fragments[0].content, "Hello DeepSeek!")
        self.assertTrue(validated.fragments[0].requires_detection)
        self.assertIsNone(validated.fragments[0].matched_template_id)

    def test_system_and_structure_never_produce_fragments(self) -> None:
        raw = json.dumps({
            "model": "deepseek-flash",
            "stop": ["合成停止词"],
            "messages": [
                {"role": "system", "content": "系统指令提到张三"},
                {"role": "assistant", "content": "历史回复含 13900001111"},
                {"role": "user", "content": "这句也进入检测"},
            ],
        }, ensure_ascii=False)
        validated = IngressValidator.validate_request(
            raw_body=raw,
            protocol=DEEPSEEK_CHAT_PROTOCOL,
            domain="test-domain",
            category="cat-approved",
            policy=self.policy,
            exemption_registry=self.exemption_registry,
        allowed_models=frozenset({"deepseek-flash"}))
        self.assertEqual([f.json_path for f in validated.fragments],
                         ["messages[1].content", "messages[2].content"])
        self.assertEqual([f.content for f in validated.fragments],
                         ["历史回复含 13900001111", "这句也进入检测"])
        self.assertEqual([f.source_kind for f in validated.fragments],
                         ["model-output", "user-input"])

    def test_tool_results_detected_and_skill_results_exempt(self) -> None:
        schema = {"type": "object", "properties": {}, "additionalProperties": False}
        raw = json.dumps({
            "model": "deepseek-flash",
            "tools": [
                {"type": "function", "function": {"name": "Read", "parameters": schema}},
                {"type": "function", "function": {"name": "Skill", "parameters": schema}},
            ],
            "messages": [
                {"role": "user", "content": "读取配置文件"},
                {"role": "assistant", "content": None, "tool_calls": [
                    {"id": "call-1", "type": "function", "function": {"name": "Read", "arguments": "{}"}},
                    {"id": "call-2", "type": "function", "function": {"name": "Skill", "arguments": "{}"}},
                ]},
                {"role": "tool", "tool_call_id": "call-1", "content": "secret = 13800001111"},
                {"role": "tool", "tool_call_id": "call-2", "content": "SKILL.md 正文提到张三"},
            ],
        }, ensure_ascii=False)
        validated = IngressValidator.validate_request(
            raw_body=raw,
            protocol=DEEPSEEK_CHAT_PROTOCOL,
            domain="test-domain",
            category="cat-approved",
            policy=self.policy,
        allowed_models=frozenset({"deepseek-flash"}))
        self.assertEqual(
            [f.json_path for f in validated.fragments],
            ["messages[0].content", "messages[2].content"])
        self.assertEqual(validated.fragments[1].content, "secret = 13800001111")

    def test_claude_tool_result_detected_and_skill_result_exempt(self) -> None:
        raw = json.dumps({
            "model": "claude-sonnet-5-5",
            "max_tokens": 64,
            "tools": [
                {"name": "Read", "input_schema": {"type": "object", "properties": {}, "additionalProperties": False}},
                {"name": "Skill", "input_schema": {"type": "object", "properties": {}, "additionalProperties": False}},
            ],
            "messages": [
                {"role": "user", "content": "读取配置文件"},
                {"role": "assistant", "content": [
                    {"type": "tool_use", "id": "tu-1", "name": "Read", "input": {}},
                    {"type": "tool_use", "id": "tu-2", "name": "Skill", "input": {}},
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "tu-1", "content": "token = 13900002222"},
                    {"type": "tool_result", "tool_use_id": "tu-2", "content": "SKILL.md 正文提到李四"},
                    {"type": "text", "text": "继续"},
                ]},
            ],
        }, ensure_ascii=False)
        validated = IngressValidator.validate_request(
            raw_body=raw,
            protocol=CLAUDE_MESSAGES_PROTOCOL,
            domain="test-domain",
            category="cat-approved",
            policy=self.policy,
        allowed_models=frozenset({"claude-sonnet-5-5"}))
        self.assertEqual(
            [f.json_path for f in validated.fragments],
            ["messages[0].content", "messages[2].content[0].content", "messages[2].content[2].text"])
        self.assertEqual(validated.fragments[1].content, "token = 13900002222")

    def test_claude_valid_request_admission(self) -> None:
        with open(FIXTURES_DIR / "claude_valid_request.json", "r", encoding="utf-8") as f:
            raw_body = f.read()

        validated = IngressValidator.validate_request(
            raw_body=raw_body,
            protocol=CLAUDE_MESSAGES_PROTOCOL,
            domain="test-domain",
            category="cat-approved",
            policy=self.policy,
        allowed_models=frozenset({"deepseek-flash","deepseek-v4-pro","claude-sonnet-5-5","claude-fable-5-1","claude-opus-5-5"}))
        self.assertEqual(validated.protocol, CLAUDE_MESSAGES_PROTOCOL)
        self.assertEqual(validated.model, "claude-sonnet-5-5")
        self.assertEqual(len(validated.fragments), 1)
        self.assertTrue(validated.fragments[0].requires_detection)

    def test_unapproved_category_fails_closed(self) -> None:
        with open(FIXTURES_DIR / "deepseek_valid_request.json", "r", encoding="utf-8") as f:
            raw_body = f.read()

        # Category 'cat-secret' is rejected before protocol parse
        with self.assertRaises(SafetyError) as ctx:
            IngressValidator.validate_request(
                raw_body=raw_body,
                protocol=DEEPSEEK_CHAT_PROTOCOL,
                domain="test-domain",
                category="cat-secret",
                policy=self.policy,
            allowed_models=frozenset({"deepseek-flash","deepseek-v4-pro","claude-sonnet-5-5","claude-fable-5-1","claude-opus-5-5"}))
        self.assertEqual(ctx.exception.code, SafetyCode.POLICY_REJECTED)

    def test_admitted_stream_parses_at_ingress(self):
        raw=(FIXTURES_DIR/'deepseek_stream_rejected.json').read_text(encoding='utf-8')
        result=IngressValidator.validate_request(raw,DEEPSEEK_CHAT_PROTOCOL,'test-domain','cat-approved',self.policy,allowed_models=frozenset({'deepseek-flash'}))
        self.assertTrue(result.parsed_request.stream)

    def test_tools_rejected_only_in_explicit_strict_parser(self) -> None:
        with open(FIXTURES_DIR / "claude_tools_rejected.json", "r", encoding="utf-8") as f:
            raw_body = f.read()

        with self.assertRaises(SafetyError) as ctx:
            IngressValidator.validate_request(
                raw_body=raw_body,
                protocol=CLAUDE_MESSAGES_PROTOCOL,
                domain="test-domain",
                category="cat-approved",
                policy=self.policy,
                allow_unsupported=False,
            allowed_models=frozenset({"deepseek-flash","deepseek-v4-pro","claude-sonnet-5-5","claude-fable-5-1","claude-opus-5-5"}))
        self.assertEqual(ctx.exception.code, SafetyCode.PROTOCOL_VIOLATION)

    def test_unsupported_protocol_rejected(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            IngressValidator.validate_request(
                raw_body="{}",
                protocol="unsupported-protocol-v9",
                domain="test-domain",
                category="cat-approved",
                policy=self.policy,
            allowed_models=frozenset({"deepseek-flash","deepseek-v4-pro","claude-sonnet-5-5","claude-fable-5-1","claude-opus-5-5"}))
        self.assertEqual(ctx.exception.code, SafetyCode.UNSUPPORTED_PROTOCOL)


if __name__ == "__main__":
    unittest.main()
