"""Finite official DeepSeek response extension with synthetic wire fixtures."""
from copy import deepcopy
from contextlib import redirect_stderr
import io
import unittest
import warnings

from infra.errors import SafetyError
from masking.mapping import MappingContext
from masking.restorer import DeepSeekChatResponse, DeepSeekUsage, restore_response
from protocol.protocols import DEEPSEEK_CHAT_PROTOCOL

KEY = b"deepseek-response-fixture-key-32!"


def usage():
    return {"prompt_tokens": 17, "completion_tokens": 9, "total_tokens": 26,
            "prompt_cache_hit_tokens": 0, "prompt_cache_miss_tokens": 17,
            "prompt_tokens_details": {"cached_tokens": 0},
            "completion_tokens_details": {"reasoning_tokens": 5}}


def response(text="synthetic text", reasoning="synthetic reasoning"):
    return {"id": "synthetic-chat", "object": "chat.completion", "created": 1,
            "model": "deepseek-flash", "system_fingerprint": "fp_synthetic",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text,
                          "reasoning_content": reasoning}, "finish_reason": "stop", "logprobs": None}],
            "usage": usage()}


class OfficialDeepSeekResponseTests(unittest.TestCase):
    def test_invalid_constructed_typed_usage_rejects_without_canary_diagnostics(self):
        canary = "CNRY-synthetic-private-typed-diagnostic"
        original = DeepSeekChatResponse.model_validate(response())
        invalid_usage = DeepSeekUsage.model_construct(
            prompt_tokens=canary, completion_tokens=9, total_tokens=26)
        invalid = original.model_copy(update={"usage": invalid_usage})
        diagnostic = io.StringIO()
        with MappingContext("corp.synthetic", "v1", KEY) as context:
            with warnings.catch_warnings(record=True) as captured:
                warnings.simplefilter("always")
                with redirect_stderr(diagnostic):
                    with self.assertRaises(SafetyError) as caught:
                        restore_response(DEEPSEEK_CHAT_PROTOCOL, invalid, context,
                                         allowed_models=frozenset({"deepseek-flash"}))
            canary_warnings = [w for w in captured if canary in str(w.message)]
            self.assertEqual([], canary_warnings)
            self.assertNotIn(canary, diagnostic.getvalue())
            self.assertNotIn(canary, str(caught.exception))

    def test_valid_typed_extended_response_still_restores_all_fields(self):
        with MappingContext("corp.synthetic", "v1", KEY) as context:
            token = context.token_for("ORG", "合成甲公司")
            original = response(token, token)
            typed = DeepSeekChatResponse.model_validate(original)
            restored = restore_response(DEEPSEEK_CHAT_PROTOCOL, typed, context,
                                        allowed_models=frozenset({"deepseek-flash"}))
            expected = deepcopy(original)
            expected["choices"][0]["message"].update(content="合成甲公司", reasoning_content="合成甲公司")
            self.assertEqual(expected, restored.model_dump(exclude_unset=True))

    def test_plain_reasoning_and_content_restore_preserving_all_usage_metadata(self):
        with MappingContext("corp.synthetic", "v1", KEY) as context:
            token = context.token_for("ORG", "合成甲公司")
            original = response(token, "分析" + token)
            restored = restore_response(DEEPSEEK_CHAT_PROTOCOL, original, context,
                                        allowed_models=frozenset({"deepseek-flash"}))
            payload = restored.model_dump(exclude_unset=True)
            expected = deepcopy(original)
            expected["choices"][0]["message"]["content"] = "合成甲公司"
            expected["choices"][0]["message"]["reasoning_content"] = "分析合成甲公司"
            self.assertEqual(expected, payload)
            self.assertEqual(original["usage"], payload["usage"])

    def test_nullable_reasoning_is_preserved_without_new_state_proof(self):
        with MappingContext("corp.synthetic", "v1", KEY) as context:
            original = response("public text", None)
            restored = restore_response(DEEPSEEK_CHAT_PROTOCOL, original, context,
                                        allowed_models=frozenset({"deepseek-flash"}))
            self.assertEqual(original, restored.model_dump(exclude_unset=True))

    def test_unknown_metadata_opaque_logprobs_or_invalid_usage_reject(self):
        payloads = []
        for target, key, value in (("top", "supplier_extension", {}),
                                   ("message", "opaque_reasoning", {"state": "secret"}),
                                   ("message", "reasoning_content", {"signed": "opaque"}),
                                   ("choice", "logprobs", {"content": [{"token": "secret", "bytes": [115]}]}),
                                   ("choice", "logprobs", "opaque-secret"),
                                   ("prompt_details", "future_tokens", 0),
                                   ("completion_details", "future_tokens", 0)):
            body = response()
            node = {"top": body, "message": body["choices"][0]["message"],
                    "choice": body["choices"][0], "prompt_details": body["usage"]["prompt_tokens_details"],
                    "completion_details": body["usage"]["completion_tokens_details"]}[target]
            node[key] = value
            payloads.append(body)
        for invalid in (-1, True, 1.2, "1"):
            body = response()
            body["usage"]["completion_tokens_details"]["reasoning_tokens"] = invalid
            payloads.append(body)
        with MappingContext("corp.synthetic", "v1", KEY) as context:
            for body in payloads:
                with self.assertRaises(SafetyError):
                    restore_response(DEEPSEEK_CHAT_PROTOCOL, body, context,
                                     allowed_models=frozenset({"deepseek-flash"}))

    def test_unknown_reasoning_token_and_structural_fingerprint_token_reject(self):
        with MappingContext("corp.synthetic", "v1", KEY) as context:
            token = context.token_for("ORG", "合成甲公司")
            for body in (response(reasoning="<<ENT_unknown>>"), {**response(), "system_fingerprint": token}):
                with self.assertRaises(SafetyError):
                    restore_response(DEEPSEEK_CHAT_PROTOCOL, body, context,
                                     allowed_models=frozenset({"deepseek-flash"}))


if __name__ == "__main__":
    unittest.main()
