"""Finite DeepSeek SSE fields; retain EOF gating and branch-safe restoration."""
from copy import deepcopy
import unittest

from gateway.streaming import ProtectedStream
from infra.errors import SafetyError
from masking.mapping import MappingContext
from protocol.protocols import DEEPSEEK_CHAT_PROTOCOL
from tests.masking.test_deepseek_response_contract import KEY, usage
from tests.protocol.test_stream_events import wire, decode_frames


def frame(delta, finish=None, counts=None):
    payload = {"id": "synthetic-chat", "object": "chat.completion.chunk", "created": 1,
               "model": "deepseek-flash", "system_fingerprint": "fp_synthetic",
               "choices": [{"index": 0, "delta": delta, "finish_reason": finish, "logprobs": None}]}
    if counts is not None:
        payload["usage"] = counts
    return payload


class OfficialDeepSeekStreamTests(unittest.TestCase):
    def test_byte_split_reasoning_nested_usage_and_null_terminal_role_restore_at_eof(self):
        with MappingContext("corp.synthetic", "v1", KEY) as context:
            token = context.token_for("ORG", "合成甲公司")
            stream = ProtectedStream(DEEPSEEK_CHAT_PROTOCOL, "deepseek-flash", context)
            source = [frame({"role": "assistant", "reasoning_content": token[:8]}),
                      frame({"reasoning_content": token[8:], "content": token}),
                      frame({"role": None, "content": ""}, "stop", usage())]
            for byte in b"".join(wire(chunk) for chunk in source) + b"data: [DONE]\n\n":
                self.assertEqual([], stream.feed(bytes([byte])))
            decoded = decode_frames(stream.finalize())
            self.assertEqual("合成甲公司", "".join(v["choices"][0]["delta"].get("reasoning_content", "") for v in decoded))
            self.assertEqual("合成甲公司", "".join(v["choices"][0]["delta"].get("content", "") for v in decoded))
            self.assertEqual(source[-1]["usage"], decoded[-1]["usage"])
            self.assertIsNone(decoded[-1]["choices"][0]["delta"]["role"])
            self.assertTrue(all(v["system_fingerprint"] == "fp_synthetic" for v in decoded))

    def test_bad_typed_usage_opaque_logprobs_or_role_reject_zero_business_release(self):
        base = frame({"content": "public text"}, "stop", usage())
        bad_frames = []
        for details, key, value in (("prompt_tokens_details", "future_tokens", 1),
                                    ("completion_tokens_details", "reasoning_tokens", -1),
                                    ("completion_tokens_details", "reasoning_tokens", True)):
            bad = deepcopy(base)
            bad["usage"][details][key] = value
            bad_frames.append(bad)
        for value in ({"token": "secret", "bytes": [115]}, "opaque-secret", []):
            bad = deepcopy(base)
            bad["choices"][0]["logprobs"] = value
            bad_frames.append(bad)
        for role in ("user", True, {}):
            bad = deepcopy(base)
            bad["choices"][0]["delta"]["role"] = role
            bad_frames.append(bad)
        for bad in bad_frames:
            with MappingContext("corp.synthetic", "v1", KEY) as context:
                stream = ProtectedStream(DEEPSEEK_CHAT_PROTOCOL, "deepseek-flash", context)
                self.assertEqual([], stream.feed(wire(frame({"content": "pending business"}))))
                with self.assertRaises(SafetyError):
                    stream.feed(wire(bad))
                self.assertEqual([], stream._pending_frames)

    def test_plain_reasoning_unknown_token_rejects_no_release(self):
        with MappingContext("corp.synthetic", "v1", KEY) as context:
            stream = ProtectedStream(DEEPSEEK_CHAT_PROTOCOL, "deepseek-flash", context)
            with self.assertRaises(SafetyError):
                stream.feed(wire(frame({"reasoning_content": "<<ENT_unknown>>"}, "stop")))
            self.assertEqual([], stream._pending_frames)


if __name__ == "__main__":
    unittest.main()
