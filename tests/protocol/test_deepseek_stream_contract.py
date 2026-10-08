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

    def test_terminal_choice_may_carry_nested_usage(self):
        with MappingContext("corp.synthetic", "v1", KEY) as context:
            stream = ProtectedStream(DEEPSEEK_CHAT_PROTOCOL, "deepseek-flash", context)
            first = frame({"role": "assistant", "content": "public"})
            terminal = frame({}, "stop")
            # Some aggregators nest the terminal usage inside the choice object.
            terminal["choices"][0]["usage"] = usage()
            for chunk in (first, terminal):
                self.assertEqual([], stream.feed(wire(chunk)))
            stream.feed(b"data: [DONE]\n\n")
            decoded = decode_frames(stream.finalize())
            self.assertEqual(usage(), decoded[-1]["choices"][0]["usage"])

    def test_terminal_usage_chunk_may_carry_a_refreshed_created_timestamp(self):
        with MappingContext("corp.synthetic", "v1", KEY) as context:
            stream = ProtectedStream(DEEPSEEK_CHAT_PROTOCOL, "deepseek-flash", context)
            first = frame({"role": "assistant", "content": "public"}, "stop")
            usage_chunk = frame({}, None, usage())
            # Aggregator refreshes `created` on the trailing usage-only chunk.
            usage_chunk["created"] = first["created"] + 5
            usage_chunk["choices"] = []
            for chunk in (first, usage_chunk):
                self.assertEqual([], stream.feed(wire(chunk)))
            stream.feed(b"data: [DONE]\n\n")
            decoded = decode_frames(stream.finalize())
            self.assertEqual(usage(), decoded[-1]["usage"])

    def test_vendor_metadata_delta_and_usage_admitted_and_details_restored(self):
        def vendor(chunk):
            chunk.update({"base_resp": {"status_code": 0, "status_msg": ""},
                          "service_tier": "standard", "input_sensitive": False,
                          "output_sensitive": False, "input_sensitive_type": 0,
                          "output_sensitive_type": 0, "output_sensitive_int": 0})
            return chunk

        with MappingContext("corp.synthetic", "v1", KEY) as context:
            token = context.token_for("ORG", "合成甲公司")
            counts = {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2,
                      "total_characters": 0, "prompt_tokens_details": {"cached_tokens": 0},
                      "completion_tokens_details": {"reasoning_tokens": 1}}
            source = [
                vendor(frame({"role": "assistant", "name": "MiniMax AI", "audio_content": "",
                              "reasoning_content": token,
                              "reasoning_details": [{"type": "reasoning.text", "id": "r1",
                                                     "format": "MiniMax-response-v1", "index": 0,
                                                     "text": token}]})),
                vendor(frame({"content": token}, "stop", counts)),
            ]
            stream = ProtectedStream(DEEPSEEK_CHAT_PROTOCOL, "deepseek-flash", context)
            for byte in b"".join(wire(chunk) for chunk in source) + b"data: [DONE]\n\n":
                self.assertEqual([], stream.feed(bytes([byte])))
            decoded = decode_frames(stream.finalize())
            reasoning = "".join(v["choices"][0]["delta"].get("reasoning_content", "") for v in decoded)
            details = "".join(d.get("text", "") for v in decoded
                              for d in (v["choices"][0]["delta"].get("reasoning_details") or []))
            self.assertEqual("合成甲公司", reasoning)
            self.assertEqual("合成甲公司", details)
            self.assertEqual("合成甲公司", decoded[-1]["choices"][0]["delta"]["content"])
            self.assertEqual(counts, decoded[-1]["usage"])
            self.assertTrue(all(v["service_tier"] == "standard" for v in decoded))


if __name__ == "__main__":
    unittest.main()
