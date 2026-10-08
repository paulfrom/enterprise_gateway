"""Aggregator/vendor response metadata admitted by the extended contract.

The supplier aggregator returns vendor-specific metadata beside the official
DeepSeek shape. These fields are explicitly typed and optional, so the contract
stays fail-closed for genuinely unknown extensions while admitting the
documented vendor variants.
"""
from copy import deepcopy
import unittest

from infra.errors import SafetyError
from masking.mapping import MappingContext
from masking.restorer import restore_response
from protocol.protocols import DEEPSEEK_CHAT_PROTOCOL

KEY = b"vendor-metadata-fixture-key-32!!"


def vendor_response(text, reasoning, detail_text):
    return {
        "id": "agg-synthetic",
        "object": "chat.completion",
        "created": 1,
        "model": "MiniMax-M3",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": text,
                "reasoning_content": reasoning,
                "name": "MiniMax AI",
                "audio_content": "",
                "reasoning_details": [
                    {"type": "reasoning.text", "id": "reasoning-text-1",
                     "format": "MiniMax-response-v1", "index": 0, "text": detail_text}
                ],
            },
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15,
            "total_characters": 0,
            "prompt_tokens_details": {"cached_tokens": 0},
            "completion_tokens_details": {"reasoning_tokens": 4},
        },
        "base_resp": {"status_code": 0, "status_msg": ""},
        "input_sensitive": False,
        "output_sensitive": False,
        "input_sensitive_type": 0,
        "output_sensitive_type": 0,
        "output_sensitive_int": 0,
        "service_tier": "standard",
    }


class VendorMetadataContractTests(unittest.TestCase):
    def test_vendor_metadata_restores_editable_text_and_preserves_the_rest(self):
        with MappingContext("corp.synthetic", "v1", KEY) as context:
            token = context.token_for("ORG", "合成甲公司")
            original = vendor_response(token, "分析" + token, "细节" + token)
            restored = restore_response(DEEPSEEK_CHAT_PROTOCOL, original, context,
                                        allowed_models=frozenset({"MiniMax-M3"}))
            payload = restored.model_dump(exclude_unset=True)
            expected = deepcopy(original)
            message = expected["choices"][0]["message"]
            message["content"] = "合成甲公司"
            message["reasoning_content"] = "分析合成甲公司"
            message["reasoning_details"][0]["text"] = "细节合成甲公司"
            self.assertEqual(expected, payload)
            self.assertEqual(original["usage"], payload["usage"])
            self.assertEqual("standard", payload["service_tier"])
            self.assertEqual({"status_code": 0, "status_msg": ""}, payload["base_resp"])

    def test_aggregator_usage_variants_are_accepted_and_preserved(self):
        variants = [
            # glm-style: semantic/source plus Claude billing envelope
            {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2,
             "usage_semantic": "openai", "usage_source": "anthropic",
             "input_tokens": 16, "output_tokens": 0, "input_tokens_details": None,
             "prompt_tokens_details": {"text_tokens": 65, "audio_tokens": 0, "image_tokens": 0},
             "completion_tokens_details": {"text_tokens": 33, "reasoning_tokens": 30,
                                           "audio_tokens": 0, "image_tokens": 0},
             "billing_usage": {"source": "claude_messages", "semantic": "anthropic",
                               "claude_usage": {"cache_creation_input_tokens": 0,
                                                "cache_read_input_tokens": 0,
                                                "claude_cache_creation_1_h_tokens": 0,
                                                "claude_cache_creation_5_m_tokens": 0,
                                                "input_tokens": 16, "output_tokens": 0,
                                                "server_tool_use": {}}},
             "claude_cache_creation_1_h_tokens": 0, "claude_cache_creation_5_m_tokens": 0},
            # kimi-k3: cache_write_tokens present, cached_tokens absent
            {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2,
             "prompt_tokens_details": {"cache_write_tokens": 0},
             "completion_tokens_details": {"reasoning_tokens": 46}},
        ]
        for usage_variant in variants:
            with self.subTest(usage=usage_variant):
                with MappingContext("corp.synthetic", "v1", KEY) as context:
                    body = vendor_response("public", None, "public")
                    body["usage"] = usage_variant
                    restored = restore_response(DEEPSEEK_CHAT_PROTOCOL, body, context,
                                                allowed_models=frozenset({"MiniMax-M3"}))
                    self.assertEqual(usage_variant, restored.model_dump(exclude_unset=True)["usage"])

    def test_unknown_extensions_still_fail_closed(self):
        def payload(mutate):
            body = vendor_response("public", "reasoning", "detail")
            mutate(body)
            return body

        cases = [
            lambda b: b.update(supplier_extension={}),
            lambda b: b["choices"][0]["message"].update(opaque_reasoning={"state": "secret"}),
            lambda b: b["choices"][0]["message"]["reasoning_details"].append(
                {"type": "reasoning.text", "opaque": 1}),
            lambda b: b["usage"]["prompt_tokens_details"].update(future_tokens=0),
            lambda b: b["base_resp"].update(extra_status="x"),
            lambda b: b["usage"].update(future_usage=1),
        ]
        for mutate in cases:
            with self.subTest(mutate=mutate):
                with MappingContext("corp.synthetic", "v1", KEY) as context:
                    with self.assertRaises(SafetyError):
                        restore_response(DEEPSEEK_CHAT_PROTOCOL, payload(mutate), context,
                                         allowed_models=frozenset({"MiniMax-M3"}))

    def test_reserved_token_in_new_structural_field_fails_closed(self):
        with MappingContext("corp.synthetic", "v1", KEY) as context:
            token = context.token_for("ORG", "合成甲公司")
            for mutate in (
                lambda b: b.update(service_tier=token),
                lambda b: b["base_resp"].update(status_msg=token),
                lambda b: b["usage"].update(usage_source=token),
                lambda b: b["choices"][0]["message"]["reasoning_details"][0].update(format=token),
                lambda b: b["choices"][0]["message"].update(name=token),
            ):
                with self.subTest(mutate=mutate):
                    body = vendor_response("public", "reasoning", "detail")
                    mutate(body)
                    with self.assertRaises(SafetyError):
                        restore_response(DEEPSEEK_CHAT_PROTOCOL, body, context,
                                         allowed_models=frozenset({"MiniMax-M3"}))


if __name__ == "__main__":
    unittest.main()
