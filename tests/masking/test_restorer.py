"""Tests for response token restorer (restorer.py)."""

import json
from pathlib import Path
import unittest

from infra.errors import SafetyCode, SafetyError
from masking.mapping import MappingContext
from protocol.protocols import (
    CLAUDE_MESSAGES_PROTOCOL,
    DEEPSEEK_CHAT_PROTOCOL,
)
from masking.restorer import (
    ClaudeMessagesResponse,
    DeepSeekChatResponse,
    restore_response,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "restorer"
TEST_HMAC_KEY = b"0123456789abcdef0123456789abcdef"


class ResponseRestorerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = MappingContext(
            scope="test-scope",
            key_version="v1",
            key=TEST_HMAC_KEY,
        )

    def test_deepseek_single_choice_restoration_positive(self) -> None:
        with self.context as ctx:
            tok1 = ctx.token_for("ORGANIZATION", "阿尔法科技")
            tok2 = ctx.token_for("PERSON", "张三")

            with open(FIXTURES_DIR / "deepseek_response.json", "r", encoding="utf-8") as f:
                template = f.read()

            raw = template.replace("<<ENT_v1_REPLACE_TOKEN_1>>", tok1).replace("<<ENT_v1_REPLACE_TOKEN_2>>", tok2)
            restored = restore_response(DEEPSEEK_CHAT_PROTOCOL, raw, ctx)

            self.assertIsInstance(restored, DeepSeekChatResponse)
            self.assertEqual("deepseek-flash", restored.model)
            self.assertIn("阿尔法科技", restored.choices[0].message.content)
            self.assertIn("张三", restored.choices[0].message.content)
            self.assertNotIn("<<ENT", restored.choices[0].message.content)

            # Metadata and usage equality
            self.assertIsNotNone(restored.usage)
            self.assertEqual(42, restored.usage.prompt_tokens)
            self.assertEqual(28, restored.usage.completion_tokens)
            self.assertEqual(70, restored.usage.total_tokens)
            self.assertEqual(10, restored.usage.prompt_cache_hit_tokens)
            self.assertEqual(32, restored.usage.prompt_cache_miss_tokens)
            self.assertEqual("chatcmpl-9abcdef012345", restored.id)

    def test_deepseek_multi_choice_restoration_positive(self) -> None:
        with self.context as ctx:
            tok1 = ctx.token_for("LOCATION", "北京总部")
            tok2 = ctx.token_for("PERSON", "李四")

            with open(FIXTURES_DIR / "deepseek_multi_choice_response.json", "r", encoding="utf-8") as f:
                template = f.read()

            raw = template.replace("<<ENT_v1_REPLACE_TOKEN_1>>", tok1).replace("<<ENT_v1_REPLACE_TOKEN_2>>", tok2)
            restored = restore_response(DEEPSEEK_CHAT_PROTOCOL, raw, ctx)

            self.assertEqual(2, len(restored.choices))
            self.assertIn("北京总部", restored.choices[0].message.content)
            self.assertIn("李四", restored.choices[1].message.content)
            self.assertEqual("deepseek-v4-pro", restored.model)
            self.assertEqual(90, restored.usage.total_tokens)

    def test_claude_single_block_restoration_positive(self) -> None:
        with self.context as ctx:
            tok1 = ctx.token_for("PERSON", "王五")
            tok2 = ctx.token_for("ORGANIZATION", "贝塔银行")

            with open(FIXTURES_DIR / "claude_response.json", "r", encoding="utf-8") as f:
                template = f.read()

            raw = template.replace("<<ENT_v1_REPLACE_TOKEN_1>>", tok1).replace("<<ENT_v1_REPLACE_TOKEN_2>>", tok2)
            restored = restore_response(CLAUDE_MESSAGES_PROTOCOL, raw, ctx)

            self.assertIsInstance(restored, ClaudeMessagesResponse)
            self.assertEqual("claude-sonnet-5-5", restored.model)
            self.assertEqual(1, len(restored.content))
            self.assertIn("王五", restored.content[0].text)
            self.assertIn("贝塔银行", restored.content[0].text)
            self.assertNotIn("<<ENT", restored.content[0].text)

            self.assertIsNotNone(restored.usage)
            self.assertEqual(55, restored.usage.input_tokens)
            self.assertEqual(30, restored.usage.output_tokens)
            self.assertEqual("end_turn", restored.stop_reason)

    def test_claude_multi_block_restoration_positive(self) -> None:
        with self.context as ctx:
            tok1 = ctx.token_for("PERSON", "赵六")
            tok2 = ctx.token_for("ORGANIZATION", "伽马资产")

            with open(FIXTURES_DIR / "claude_multi_block_response.json", "r", encoding="utf-8") as f:
                template = f.read()

            raw = template.replace("<<ENT_v1_REPLACE_TOKEN_1>>", tok1).replace("<<ENT_v1_REPLACE_TOKEN_2>>", tok2)
            restored = restore_response(CLAUDE_MESSAGES_PROTOCOL, raw, ctx)

            self.assertEqual(2, len(restored.content))
            self.assertIn("赵六", restored.content[0].text)
            self.assertIn("伽马资产", restored.content[1].text)
            self.assertEqual("claude-opus-5-5", restored.model)

    def test_no_tokens_content_preserved_as_is(self) -> None:
        with self.context as ctx:
            with open(FIXTURES_DIR / "token_in_uneditable_field.json", "r", encoding="utf-8") as f:
                raw = f.read()
            restored = restore_response(DEEPSEEK_CHAT_PROTOCOL, raw, ctx)
            self.assertEqual("正常回复", restored.choices[0].message.content)

    def test_accepts_parsed_model_or_dict(self) -> None:
        with self.context as ctx:
            tok = ctx.token_for("PERSON", "张三")
            payload = {
                "id": "chatcmpl-test01",
                "object": "chat.completion",
                "created": 1727950000,
                "model": "deepseek-flash",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": f"你好 {tok}"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            }
            # As dict
            res_dict = restore_response(DEEPSEEK_CHAT_PROTOCOL, payload, ctx)
            self.assertIn("张三", res_dict.choices[0].message.content)

            # As model instance
            parsed_model = DeepSeekChatResponse.model_validate(payload)
            res_model = restore_response(DEEPSEEK_CHAT_PROTOCOL, parsed_model, ctx)
            self.assertIn("张三", res_model.choices[0].message.content)

    def test_unknown_token_rejected(self) -> None:
        with self.context as ctx:
            with open(FIXTURES_DIR / "unknown_token_response.json", "r", encoding="utf-8") as f:
                raw = f.read()
            with self.assertRaises(SafetyError) as exc_info:
                restore_response(DEEPSEEK_CHAT_PROTOCOL, raw, ctx)
            self.assertEqual(SafetyCode.UNKNOWN_TOKEN, exc_info.exception.code)
            self.assertIsNone(exc_info.exception.__cause__)
            self.assertIsNone(exc_info.exception.__context__)

    def test_malformed_token_rejected(self) -> None:
        with self.context as ctx:
            with open(FIXTURES_DIR / "malformed_token_response.json", "r", encoding="utf-8") as f:
                raw = f.read()
            with self.assertRaises(SafetyError) as exc_info:
                restore_response(DEEPSEEK_CHAT_PROTOCOL, raw, ctx)
            self.assertEqual(SafetyCode.MALFORMED_TOKEN, exc_info.exception.code)

    def test_mapping_not_active_rejected(self) -> None:
        # Context not entered
        raw = '{"id":"chatcmpl-01","object":"chat.completion","created":100,"model":"deepseek-flash","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}'
        with self.assertRaises(SafetyError) as exc_info:
            restore_response(DEEPSEEK_CHAT_PROTOCOL, raw, self.context)
        self.assertEqual(SafetyCode.MAPPING_NOT_ACTIVE, exc_info.exception.code)

    def test_token_in_uneditable_model_rejected(self) -> None:
        with self.context as ctx:
            tok = ctx.token_for("PERSON", "张三")
            raw = {
                "id": "chatcmpl-test01",
                "object": "chat.completion",
                "created": 1727950000,
                "model": tok,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "你好"},
                        "finish_reason": "stop",
                    }
                ],
            }
            with self.assertRaises(SafetyError) as exc_info:
                restore_response(DEEPSEEK_CHAT_PROTOCOL, raw, ctx)
            self.assertEqual(SafetyCode.CONTRACT_VIOLATION, exc_info.exception.code)

    def test_token_in_uneditable_id_rejected(self) -> None:
        with self.context as ctx:
            tok = ctx.token_for("PERSON", "张三")
            raw = {
                "id": f"chatcmpl-{tok}",
                "object": "chat.completion",
                "created": 1727950000,
                "model": "deepseek-flash",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "你好"},
                        "finish_reason": "stop",
                    }
                ],
            }
            with self.assertRaises(SafetyError) as exc_info:
                restore_response(DEEPSEEK_CHAT_PROTOCOL, raw, ctx)
            self.assertEqual(SafetyCode.CONTRACT_VIOLATION, exc_info.exception.code)

    def test_token_in_uneditable_role_rejected(self) -> None:
        with self.context as ctx:
            tok = ctx.token_for("PERSON", "张三")
            raw = {
                "id": "chatcmpl-01",
                "object": "chat.completion",
                "created": 1727950000,
                "model": "deepseek-flash",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": tok, "content": "你好"},
                        "finish_reason": "stop",
                    }
                ],
            }
            with self.assertRaises(SafetyError) as exc_info:
                restore_response(DEEPSEEK_CHAT_PROTOCOL, raw, ctx)
            self.assertEqual(SafetyCode.CONTRACT_VIOLATION, exc_info.exception.code)

    def test_unwhitelisted_model_rejected(self) -> None:
        with self.context as ctx:
            raw = {
                "id": "chatcmpl-01",
                "object": "chat.completion",
                "created": 1727950000,
                "model": "unsupported-model-v1",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "你好"},
                        "finish_reason": "stop",
                    }
                ],
            }
            with self.assertRaises(SafetyError) as exc_info:
                restore_response(DEEPSEEK_CHAT_PROTOCOL, raw, ctx)
            self.assertEqual(SafetyCode.CONTRACT_VIOLATION, exc_info.exception.code)

    def test_duplicate_json_keys_rejected(self) -> None:
        with self.context as ctx:
            raw = '{"id":"chatcmpl-01","id":"chatcmpl-02","object":"chat.completion","created":100,"model":"deepseek-flash","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}'
            with self.assertRaises(SafetyError) as exc_info:
                restore_response(DEEPSEEK_CHAT_PROTOCOL, raw, ctx)
            self.assertEqual(SafetyCode.DUPLICATE_JSON_KEY, exc_info.exception.code)

    def test_malformed_json_rejected(self) -> None:
        with self.context as ctx:
            raw = '{"id": "chatcmpl-01", "unclosed...'
            with self.assertRaises(SafetyError) as exc_info:
                restore_response(DEEPSEEK_CHAT_PROTOCOL, raw, ctx)
            self.assertEqual(SafetyCode.MALFORMED_JSON, exc_info.exception.code)

    def test_invalid_utf8_rejected(self) -> None:
        with self.context as ctx:
            raw_bytes = b'{"id":"chatcmpl-01", "test": \xff\xfe}'
            with self.assertRaises(SafetyError) as exc_info:
                restore_response(DEEPSEEK_CHAT_PROTOCOL, raw_bytes, ctx)
            self.assertEqual(SafetyCode.INVALID_UTF8, exc_info.exception.code)

    def test_unsupported_protocol_rejected(self) -> None:
        with self.context as ctx:
            with self.assertRaises(SafetyError) as exc_info:
                restore_response("unsupported-protocol", "{}", ctx)
            self.assertEqual(SafetyCode.CONTRACT_VIOLATION, exc_info.exception.code)

    def test_type_error_for_invalid_context(self) -> None:
        with self.assertRaises(TypeError):
            restore_response(DEEPSEEK_CHAT_PROTOCOL, "{}", None)  # type: ignore

    def test_token_in_uneditable_block_type_rejected(self) -> None:
        with self.context as ctx:
            tok = ctx.token_for("PERSON", "张三")
            raw = {
                "id": "msg_01",
                "type": "message",
                "role": "assistant",
                "model": "claude-sonnet-5-5",
                "content": [{"type": tok, "text": "hello"}],
            }
            with self.assertRaises(SafetyError) as exc_info:
                restore_response(CLAUDE_MESSAGES_PROTOCOL, raw, ctx)
            self.assertEqual(SafetyCode.CONTRACT_VIOLATION, exc_info.exception.code)

    def test_usage_strictly_equal_even_when_restored_text_expands(self) -> None:
        with self.context as ctx:
            tok = ctx.token_for("ORGANIZATION", "中华人民共和国超长组织机构名称")
            raw = {
                "id": "chatcmpl-01",
                "object": "chat.completion",
                "created": 1727950000,
                "model": "deepseek-flash",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": f"关于 {tok}"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            }
            restored = restore_response(DEEPSEEK_CHAT_PROTOCOL, raw, ctx)
            self.assertEqual(10, restored.usage.prompt_tokens)
            self.assertEqual(5, restored.usage.completion_tokens)
            self.assertEqual(15, restored.usage.total_tokens)
            # Original usage object is preserved without touching tokens
            self.assertEqual(raw["usage"]["total_tokens"], restored.usage.total_tokens)

    def test_canary_no_business_text_leakage(self) -> None:
        canary = "CONFIDENTIAL_CANARY_VALUE_P06_XYZ"
        with self.context as ctx:
            tok = ctx.token_for("SECRET", canary)
            # Corrupt the token in the message
            corrupted = tok[:-5] + "XXXX>>"
            raw = {
                "id": "chatcmpl-canary",
                "object": "chat.completion",
                "created": 1727950000,
                "model": "deepseek-flash",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": f"Here is {corrupted}"},
                        "finish_reason": "stop",
                    }
                ],
            }
            with self.assertRaises(SafetyError) as exc_info:
                restore_response(DEEPSEEK_CHAT_PROTOCOL, raw, ctx)
            self.assertNotIn(canary, str(exc_info.exception))

    def test_custom_allowed_models_positive_and_rejected(self) -> None:
        custom_allowed = frozenset(["qwen-max", "deepseek-custom"])
        with self.context as ctx:
            raw = {
                "id": "chatcmpl-custom",
                "object": "chat.completion",
                "created": 1727950000,
                "model": "qwen-max",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "custom model reply"},
                        "finish_reason": "stop",
                    }
                ],
            }
            # Success with custom allowed
            res = restore_response(DEEPSEEK_CHAT_PROTOCOL, raw, ctx, allowed_models=custom_allowed)
            self.assertEqual(res.model, "qwen-max")

            # Rejected when model is not in custom allowed
            with self.assertRaises(SafetyError) as exc_info:
                restore_response(DEEPSEEK_CHAT_PROTOCOL, raw, ctx, allowed_models=frozenset(["other-model"]))
            self.assertEqual(SafetyCode.CONTRACT_VIOLATION, exc_info.exception.code)


if __name__ == "__main__":
    unittest.main()
