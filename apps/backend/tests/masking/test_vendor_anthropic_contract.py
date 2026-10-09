"""Aggregator Anthropic Messages metadata: extended usage and unsigned reasoning.

Some upstream aggregators speak Anthropic Messages but emit extended usage
metadata and reasoning blocks without a supplier signature. Signed (native)
reasoning keeps its proof-and-no-rewrite contract; unsigned reasoning is
admitted as editable text, mirroring the DeepSeek ``reasoning_content`` path.
"""
import unittest

from masking.mapping import MappingContext
from masking.restorer import restore_response
from protocol.protocols import CLAUDE_MESSAGES_PROTOCOL

KEY = b"vendor-anthropic-fixture-key-32!"


def extended_usage():
    return {
        "input_tokens": 0, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 10,
        "output_tokens": 64, "output_tokens_details": {"thinking_tokens": 63},
        "service_tier": "standard", "inference_geo": "not_available",
        "prompt_tokens": 10, "cached_tokens": 10, "completion_tokens": 64, "total_tokens": 74,
    }


class VendorAnthropicContractTests(unittest.TestCase):
    def test_unsigned_thinking_editable_and_extended_usage_preserved(self):
        with MappingContext("corp.synthetic", "v1", KEY) as ctx:
            token = ctx.token_for("ORG", "合成甲公司")
            original = {"id": "agg", "type": "message", "role": "assistant", "model": "kimi-k2.6",
                        "content": [{"type": "thinking", "thinking": token},
                                    {"type": "text", "text": token}],
                        "stop_reason": "end_turn", "stop_sequence": None, "usage": extended_usage()}
            restored = restore_response(CLAUDE_MESSAGES_PROTOCOL, original, ctx,
                                        allowed_models=frozenset({"kimi-k2.6"}))
            payload = restored.model_dump(exclude_unset=True)
            self.assertEqual("合成甲公司", payload["content"][0]["thinking"])
            self.assertEqual("", payload["content"][0]["signature"])
            self.assertEqual({}, payload["content"][0]["metadata"])
            self.assertEqual("合成甲公司", payload["content"][1]["text"])
            self.assertEqual(extended_usage(), payload["usage"])

    def test_base_resp_and_service_tier_preserved(self):
        with MappingContext("corp.synthetic", "v1", KEY) as ctx:
            usage = {"input_tokens": 25, "output_tokens": 2, "cache_creation_input_tokens": 0,
                     "cache_read_input_tokens": 142, "service_tier": "standard"}
            body = {"id": "agg2", "type": "message", "role": "assistant", "model": "MiniMax-M3",
                    "content": [{"type": "text", "text": "public"}],
                    "stop_reason": "end_turn", "stop_sequence": None, "usage": usage,
                    "base_resp": {"status_code": 0, "status_msg": ""}}
            restored = restore_response(CLAUDE_MESSAGES_PROTOCOL, body, ctx,
                                        allowed_models=frozenset({"MiniMax-M3"}))
            payload = restored.model_dump(exclude_unset=True)
            self.assertEqual({"status_code": 0, "status_msg": ""}, payload["base_resp"])
            self.assertEqual(usage, payload["usage"])

    def test_unknown_anthropic_metadata_still_fails_closed(self):
        with MappingContext("corp.synthetic", "v1", KEY) as ctx:
            body = {"id": "agg3", "type": "message", "role": "assistant", "model": "kimi-k2.6",
                    "content": [{"type": "text", "text": "public"}],
                    "stop_reason": "end_turn", "stop_sequence": None,
                    "usage": {**extended_usage(), "future_fee": 1}}
            with self.assertRaises(Exception):
                restore_response(CLAUDE_MESSAGES_PROTOCOL, body, ctx,
                                 allowed_models=frozenset({"kimi-k2.6"}))


if __name__ == "__main__":
    unittest.main()
