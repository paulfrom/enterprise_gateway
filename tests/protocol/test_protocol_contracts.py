"""Executable candidate-contract tests for the two protocol subsets; not channel evidence."""

import json
import traceback
import unittest
from pathlib import Path

from infra.errors import SafetyCode, SafetyError
from protocol.protocols import (
    CLAUDE_MESSAGES_PROTOCOL,
    CLAUDE_MODEL_WHITELIST,
    DEEPSEEK_CHAT_PROTOCOL,
    DEEPSEEK_MODEL_WHITELIST,
    parse_claude_messages,
    parse_deepseek_chat_completion,
)

FIXTURES = Path(__file__).parent / "fixtures" / "requests"


def load_fixture(protocol_dir: str, kind: str, name: str) -> str:
    return (FIXTURES / protocol_dir / kind / name).read_text(encoding="utf-8")


class RejectedFixtureMixin:
    parser = None
    protocol_dir = ""

    def assert_fixture_rejected(self, name: str) -> SafetyError:
        with self.assertRaises(SafetyError) as raised:
            self.parser(load_fixture(self.protocol_dir, "rejected", name))
        return raised.exception


class DeepSeekChatCompletionTests(RejectedFixtureMixin, unittest.TestCase):
    parser = staticmethod(parse_deepseek_chat_completion)
    protocol_dir = "deepseek"

    def test_minimal_text_conversation_parses(self):
        parsed = parse_deepseek_chat_completion(load_fixture("deepseek", "valid", "minimal.json"))
        self.assertEqual(parsed.protocol, DEEPSEEK_CHAT_PROTOCOL)
        self.assertEqual(parsed.model, "deepseek-flash")
        self.assertEqual([m.role for m in parsed.messages], ["system", "user", "assistant", "user"])
        self.assertEqual(parsed.messages[2].content, "这是上一轮的历史回复，涉及供应商甲公司。")
        self.assertEqual(parsed.response_format, None)

    def test_sampling_stop_and_response_format_options_parse(self):
        parsed = parse_deepseek_chat_completion(load_fixture("deepseek", "valid", "options.json"))
        self.assertEqual(parsed.model, "deepseek-v4-pro")
        self.assertEqual(parsed.temperature, 0.5)
        self.assertEqual(parsed.top_p, 0.9)
        self.assertEqual(parsed.stop, ["\n\n结论", "END"])
        self.assertEqual(parsed.response_format.type, "json_object")

    def test_bytes_body_parses(self):
        body = load_fixture("deepseek", "valid", "minimal.json").encode("utf-8")
        self.assertEqual(parse_deepseek_chat_completion(body).model, "deepseek-flash")

    def test_whitelisted_models_parse_and_unlisted_model_rejected(self):
        for model in DEEPSEEK_MODEL_WHITELIST:
            body = json.dumps({"model": model, "messages": [{"role": "user", "content": "x"}]})
            self.assertEqual(parse_deepseek_chat_completion(body).model, model)
        self.assert_fixture_rejected("model_not_in_whitelist.json")

    def test_all_message_content_is_business_text_regardless_of_role(self):
        parsed = parse_deepseek_chat_completion(load_fixture("deepseek", "valid", "minimal.json"))
        for message in parsed.messages:
            self.assertIsInstance(message.content, str)
        self.assertIn("system", [m.role for m in parsed.messages])
        self.assertIn("assistant", [m.role for m in parsed.messages])

    def test_unknown_top_level_field_rejected(self):
        self.assert_fixture_rejected("unknown_top_level.json")

    def test_unknown_message_field_rejected(self):
        self.assert_fixture_rejected("unknown_message_field.json")

    def test_non_string_model_rejected(self):
        self.assert_fixture_rejected("model_wrong_type.json")

    def test_tool_role_rejected(self):
        self.assert_fixture_rejected("role_tool.json")

    def test_block_content_form_rejected(self):
        self.assert_fixture_rejected("content_array.json")

    def test_tools_and_tool_choice_rejected(self):
        self.assert_fixture_rejected("tools.json")

    def test_stream_and_stream_options_rejected(self):
        self.assert_fixture_rejected("stream.json")

    def test_thinking_and_reasoning_fields_rejected(self):
        self.assert_fixture_rejected("thinking.json")

    def test_logprobs_rejected(self):
        self.assert_fixture_rejected("logprobs.json")

    def test_user_id_rejected(self):
        self.assert_fixture_rejected("user_id.json")

    def test_max_tokens_rejected_as_claude_specific_field(self):
        self.assert_fixture_rejected("max_tokens.json")

    def test_deprecated_penalty_rejected(self):
        self.assert_fixture_rejected("frequency_penalty.json")

    def test_response_format_unknown_type_rejected(self):
        self.assert_fixture_rejected("response_format_bad_type.json")

    def test_response_format_unknown_nested_key_rejected(self):
        self.assert_fixture_rejected("response_format_extra_key.json")

    def test_temperature_above_official_cap_rejected(self):
        self.assert_fixture_rejected("temperature_out_of_range.json")

    def test_non_object_top_level_rejected(self):
        self.assert_fixture_rejected("top_level_array.json")

    def test_empty_messages_rejected(self):
        self.assert_fixture_rejected("empty_messages.json")

    def test_missing_model_rejected(self):
        self.assert_fixture_rejected("missing_model.json")

    def test_stop_sequence_limit_rejected(self):
        self.assert_fixture_rejected("stop_too_many.json")

    def test_temperature_integer_form_accepted(self):
        body = json.dumps({"model": "deepseek-flash", "messages": [{"role": "user", "content": "x"}],
                           "temperature": 1})
        self.assertEqual(parse_deepseek_chat_completion(body).temperature, 1.0)

    def test_nonstandard_json_constant_rejected(self):
        error = self.assert_fixture_rejected("nonstandard_constant.json")
        self.assertEqual(error.code, SafetyCode.MALFORMED_JSON)

    def test_deeply_nested_json_rejected_as_controlled_error(self):
        body = '{"model": "deepseek-flash", "messages": ' + "[" * 2000 + "]" * 2000 + "}"
        with self.assertRaises(SafetyError) as raised:
            parse_deepseek_chat_completion(body)
        self.assertEqual(raised.exception.code, SafetyCode.MALFORMED_JSON)
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_duplicate_top_level_key_rejected(self):
        error = self.assert_fixture_rejected("duplicate_key.json")
        self.assertEqual(error.code, SafetyCode.DUPLICATE_JSON_KEY)

    def test_duplicate_nested_key_rejected(self):
        body = '{"model": "deepseek-flash", "messages": [{"role": "user", "role": "user", "content": "x"}]}'
        with self.assertRaises(SafetyError) as raised:
            parse_deepseek_chat_completion(body)
        self.assertEqual(raised.exception.code, SafetyCode.DUPLICATE_JSON_KEY)

    def test_malformed_json_rejected(self):
        error = self.assert_fixture_rejected("malformed.json")
        self.assertEqual(error.code, SafetyCode.MALFORMED_JSON)

    def test_invalid_utf8_rejected(self):
        with self.assertRaises(SafetyError) as raised:
            parse_deepseek_chat_completion(b'{"model": "deepseek-flash", "messages": [{"role": "\xff"}]}')
        self.assertEqual(raised.exception.code, SafetyCode.INVALID_UTF8)

    def test_non_string_bytes_input_rejected_as_controlled_error(self):
        for raw in (123, None, {"model": "deepseek-flash"}):
            with self.subTest(raw=raw):
                with self.assertRaises(SafetyError) as raised:
                    parse_deepseek_chat_completion(raw)
                self.assertEqual(raised.exception.code, SafetyCode.MALFORMED_JSON)
                self.assertIn(DEEPSEEK_CHAT_PROTOCOL, str(raised.exception))

    def test_claude_messages_payload_rejected(self):
        claude_body = json.dumps(
            {
                "model": "claude-sonnet-5-5",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": "你好"}],
            }
        )
        with self.assertRaises(SafetyError):
            parse_deepseek_chat_completion(claude_body)

    def test_error_message_does_not_echo_business_text(self):
        canary = "CNRY-协议契约合成秘密-789"
        body = json.dumps(
            {
                "model": "deepseek-flash",
                "messages": [{"role": "user", "content": canary}],
                "undeclared": canary,
            }
        )
        with self.assertRaises(SafetyError) as raised:
            parse_deepseek_chat_completion(body)
        self.assertNotIn(canary, str(raised.exception))
        self.assertNotIn(canary, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn(canary, traceback.format_exc())


class ClaudeMessagesTests(RejectedFixtureMixin, unittest.TestCase):
    parser = staticmethod(parse_claude_messages)
    protocol_dir = "claude"

    def test_minimal_text_conversation_parses(self):
        parsed = parse_claude_messages(load_fixture("claude", "valid", "minimal.json"))
        self.assertEqual(parsed.protocol, CLAUDE_MESSAGES_PROTOCOL)
        self.assertEqual(parsed.model, "claude-sonnet-5-5")
        self.assertEqual(parsed.max_tokens, 1024)
        self.assertEqual([m.role for m in parsed.messages], ["user", "assistant", "user"])
        self.assertEqual(parsed.messages[1].content, "上一轮审查意见涉及乙公司交付义务。")

    def test_text_block_array_and_sampling_options_parse(self):
        parsed = parse_claude_messages(load_fixture("claude", "valid", "full_options.json"))
        self.assertEqual(parsed.model, "claude-opus-5-5")
        self.assertEqual(parsed.system, "你是企业内部的合规审查助手。")
        self.assertEqual(parsed.stop_sequences, ["\n\n审查结束"])
        self.assertEqual(parsed.temperature, 0.3)
        self.assertEqual(parsed.top_p, 0.9)
        self.assertEqual(parsed.top_k, 40)
        blocks = parsed.messages[0].content
        self.assertEqual([b.type for b in blocks], ["text", "text"])
        self.assertEqual(blocks[1].text, "第二部分：需要审查的问题清单。")

    def test_whitelisted_models_parse_and_unlisted_model_rejected(self):
        for model in CLAUDE_MODEL_WHITELIST:
            body = json.dumps(
                {"model": model, "max_tokens": 1, "messages": [{"role": "user", "content": "x"}]}
            )
            self.assertEqual(parse_claude_messages(body).model, model)
        self.assert_fixture_rejected("model_not_in_whitelist.json")

    def test_all_message_content_is_business_text_regardless_of_role(self):
        parsed = parse_claude_messages(load_fixture("claude", "valid", "minimal.json"))
        for message in parsed.messages:
            self.assertIsInstance(message.content, str)
        self.assertIn("assistant", [m.role for m in parsed.messages])

    def test_metadata_rejected(self):
        self.assert_fixture_rejected("metadata.json")

    def test_stream_rejected(self):
        self.assert_fixture_rejected("stream.json")

    def test_tools_and_tool_choice_rejected(self):
        self.assert_fixture_rejected("tools.json")

    def test_thinking_config_rejected(self):
        self.assert_fixture_rejected("thinking.json")

    def test_image_block_rejected(self):
        self.assert_fixture_rejected("image_block.json")

    def test_document_block_rejected(self):
        self.assert_fixture_rejected("document_block.json")

    def test_tool_use_and_tool_result_blocks_rejected(self):
        self.assert_fixture_rejected("tool_blocks.json")

    def test_system_as_block_array_rejected(self):
        self.assert_fixture_rejected("system_array.json")

    def test_text_block_extra_field_rejected(self):
        self.assert_fixture_rejected("block_extra_field.json")

    def test_response_format_rejected_as_deepseek_specific_field(self):
        self.assert_fixture_rejected("response_format.json")

    def test_missing_max_tokens_rejected(self):
        self.assert_fixture_rejected("missing_max_tokens.json")

    def test_zero_max_tokens_rejected(self):
        self.assert_fixture_rejected("max_tokens_zero.json")

    def test_system_role_rejected(self):
        self.assert_fixture_rejected("system_role.json")

    def test_empty_messages_rejected(self):
        self.assert_fixture_rejected("empty_messages.json")

    def test_missing_model_rejected(self):
        self.assert_fixture_rejected("missing_model.json")

    def test_empty_content_block_array_rejected(self):
        self.assert_fixture_rejected("empty_content_blocks.json")

    def test_nonstandard_json_constant_rejected(self):
        error = self.assert_fixture_rejected("nonstandard_constant.json")
        self.assertEqual(error.code, SafetyCode.MALFORMED_JSON)

    def test_duplicate_top_level_key_rejected(self):
        error = self.assert_fixture_rejected("duplicate_key.json")
        self.assertEqual(error.code, SafetyCode.DUPLICATE_JSON_KEY)

    def test_duplicate_nested_key_rejected(self):
        body = (
            '{"model": "claude-sonnet-5-5", "max_tokens": 1, "messages": '
            '[{"role": "user", "content": "a", "content": "b"}]}'
        )
        with self.assertRaises(SafetyError) as raised:
            parse_claude_messages(body)
        self.assertEqual(raised.exception.code, SafetyCode.DUPLICATE_JSON_KEY)

    def test_malformed_json_rejected(self):
        error = self.assert_fixture_rejected("malformed.json")
        self.assertEqual(error.code, SafetyCode.MALFORMED_JSON)

    def test_deepseek_chat_payload_rejected(self):
        deepseek_body = json.dumps(
            {
                "model": "deepseek-flash",
                "messages": [{"role": "system", "content": "系统提示"}, {"role": "user", "content": "你好"}],
                "response_format": {"type": "text"},
            }
        )
        with self.assertRaises(SafetyError):
            parse_claude_messages(deepseek_body)

    def test_non_string_bytes_input_rejected_as_controlled_error(self):
        for raw in (456, None, ["claude-sonnet-5-5"]):
            with self.subTest(raw=raw):
                with self.assertRaises(SafetyError) as raised:
                    parse_claude_messages(raw)
                self.assertEqual(raised.exception.code, SafetyCode.MALFORMED_JSON)
                self.assertIn(CLAUDE_MESSAGES_PROTOCOL, str(raised.exception))

    def test_error_message_does_not_echo_business_text(self):
        canary = "CNRY-协议契约合成秘密-790"
        body = json.dumps(
            {
                "model": "claude-sonnet-5-5",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": canary}],
                "metadata": {"user_id": canary},
            }
        )
        with self.assertRaises(SafetyError) as raised:
            parse_claude_messages(body)
        self.assertNotIn(canary, str(raised.exception))
        self.assertNotIn(canary, repr(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn(canary, traceback.format_exc())


if __name__ == "__main__":
    unittest.main()
