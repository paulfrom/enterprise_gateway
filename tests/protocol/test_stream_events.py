"""Real typed SSE state machine tests with synthetic provider wire frames."""
import asyncio
import json
import hmac
import time
import unittest

from gateway.streaming import ProtectedStream, iter_protected_stream
from infra.errors import SafetyError
from masking.mapping import MappingContext
from protocol.protocols import DEEPSEEK_CHAT_PROTOCOL as CHAT, CLAUDE_MESSAGES_PROTOCOL as CLAUDE
from protocol.history_state import ReasoningBlock, ReasoningStateValidator, ProviderStateVerifier
from tests.protocol.provider_fixtures import verify_hmac_sha256

KEY = b"stream-fixture-key-32-bytes!!!!!!"
SCHEMA = {"type": "object", "properties": {"query": {"type": "string", "maxLength": 20}}, "required": ["query"], "additionalProperties": False}


def wire(data, event=None):
    return (("event: " + event + "\n" if event else "") + "data: " + json.dumps(data, ensure_ascii=False) + "\n\n").encode()


def chat(choices, usage=None, model="synthetic-model"):
    value = {"id": "chat-1", "object": "chat.completion.chunk", "created": 1, "model": model, "choices": choices}
    if usage is not None:
        value["usage"] = usage
    return wire(value)


def choice(index=0, delta=None, finish=None):
    return {"index": index, "delta": delta or {}, "finish_reason": finish}


def claude(kind, **fields):
    return wire({"type": kind, **fields}, kind)


def message_start():
    return claude("message_start", message={"id": "msg-1", "type": "message", "role": "assistant", "model": "synthetic-model", "content": [], "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 11, "output_tokens": 0}})


def decode_frames(frames):
    data = []
    for frame in frames:
        for line in frame.decode().splitlines():
            if line.startswith("data: ") and line != "data: [DONE]":
                data.append(json.loads(line[6:]))
    return data


class StreamEventsTests(unittest.TestCase):
    def test_client_model_alias_typed_fields_only(self):
        with MappingContext("corp.test", "v1", KEY) as ctx:
            stream = ProtectedStream(CHAT, "synthetic-model", ctx, client_model="client-alias")
            self.assertEqual([], stream.feed(chat([choice(delta={"content": "synthetic-model remains text"})])))
            frames = stream.feed(chat([choice(finish="stop")]) + b"data: [DONE]\n\n")
            self.assertEqual([], frames)
            frames += stream.finalize()
            decoded = decode_frames(frames)
            self.assertTrue(all(item["model"] == "client-alias" for item in decoded))
            self.assertEqual("synthetic-model remains text", decoded[0]["choices"][0]["delta"]["content"])
        with MappingContext("corp.test", "v1", KEY) as ctx:
            stream = ProtectedStream(CLAUDE, "synthetic-model", ctx, client_model="client-alias")
            payload = message_start() + claude("content_block_start", index=0, content_block={"type": "text", "text": ""}) + claude("content_block_stop", index=0) + claude("message_delta", delta={"stop_reason": "end_turn", "stop_sequence": None}, usage={"output_tokens": 0}) + claude("message_stop")
            self.assertEqual([], stream.feed(payload))
            decoded = decode_frames(stream.finalize())
            self.assertEqual("client-alias", decoded[0]["message"]["model"])

    def test_provider_verified_reasoning_payload_preserved_receipt_binding(self):
        provider_key = b"synthetic-provider-only-32bytes!!"
        content = "synthetic immutable reasoning"
        signature = hmac.digest(provider_key, content.encode(), "sha256").hex()
        validator = ReasoningStateValidator(KEY, scope="corp.test", version="full-package-v1", provider_verifier=ProviderStateVerifier(verify_hmac_sha256, provider_key))
        with MappingContext("corp.test", "v1", KEY) as ctx:
            stream = ProtectedStream(CLAUDE, "synthetic-model", ctx, state_validator=validator, state_version="full-package-v1")
            for frame in (message_start(), claude("content_block_start", index=0, content_block={"type": "thinking", "thinking": "", "signature": ""}), claude("content_block_delta", index=0, delta={"type": "thinking_delta", "thinking": content}), claude("content_block_delta", index=0, delta={"type": "signature_delta", "signature": signature}), claude("content_block_stop", index=0)):
                self.assertEqual([], stream.feed(frame))
            receipt = stream.state_receipts[0]
            validator.verify_reasoning_block(receipt)
            frames = stream.feed(claude("message_delta", delta={"stop_reason": "end_turn", "stop_sequence": None}, usage={"output_tokens": 1}) + claude("message_stop"))
            self.assertEqual([], frames)
            frames += stream.finalize()
            decoded = decode_frames(frames)
            self.assertEqual(content, decoded[2]["delta"]["thinking"])
            self.assertEqual(signature, decoded[3]["delta"]["signature"])
            self.assertEqual({}, stream.state_receipts)

    def test_terminal_standalone_cr_at_eof_commits_and_trailing_event_rejects(self):
        with MappingContext("corp.test", "v1", KEY) as ctx:
            stream = ProtectedStream(CHAT, "synthetic-model", ctx)
            self.assertEqual([], stream.feed(chat([choice(delta={"content": "business"})])))
            self.assertEqual([], stream.feed(chat([choice(finish="stop")]) + b"data: [DONE]\r\r"))
            self.assertIn("business", b"".join(stream.finalize()).decode())
        with MappingContext("corp.test", "v1", KEY) as ctx:
            stream = ProtectedStream(CHAT, "synthetic-model", ctx)
            stream.feed(chat([choice(delta={"content": "business"})]))
            with self.assertRaises(SafetyError):
                stream.feed(chat([choice(finish="stop")]) + b"data: [DONE]\n\ndata: after\r\r")
                stream.finalize()
            self.assertEqual([], stream._pending_frames)

    def test_chat_every_wire_byte_token_splits_branches_usage_and_terminal(self):
        with MappingContext("corp.test", "v1", KEY) as ctx:
            token = ctx.token_for("ORG", "公司甲")
            stream = ProtectedStream(CHAT, "synthetic-model", ctx)
            frames = []
            payloads = [chat([choice(0, {"content": piece}), choice(1, {"content": "b" if i == 0 else ""})]) for i, piece in enumerate(token)]
            payloads += [chat([choice(0, finish="stop"), choice(1, finish="stop")]), chat([], {"prompt_tokens": 11, "completion_tokens": 2, "total_tokens": 13}), b"data: [DONE]\n\n"]
            for byte in b"".join(payloads):
                frames.extend(stream.feed(bytes([byte])))
            frames.extend(stream.finalize())
            decoded = decode_frames(frames)
            output = "".join(c["delta"].get("content", "") for item in decoded for c in item["choices"] if c["index"] == 0)
            self.assertEqual("公司甲", output)
            self.assertEqual({"prompt_tokens": 11, "completion_tokens": 2, "total_tokens": 13}, decoded[-1]["usage"])
            self.assertEqual({}, stream.restorer._buffers)

    def test_chat_parallel_tools_zero_partial_release_and_full_restore(self):
        with MappingContext("corp.test", "v1", KEY) as ctx:
            token = ctx.token_for("ORG", "公司甲")
            stream = ProtectedStream(CHAT, "synthetic-model", ctx, {"search": SCHEMA})
            frames = stream.feed(chat([choice(delta={"tool_calls": [{"index": i, "id": f"call-{i}", "type": "function", "function": {"name": "search", "arguments": '{"query":"'}} for i in range(2)]})]))
            self.assertFalse(any(c["delta"].get("tool_calls") for item in decode_frames(frames) for c in item["choices"]))
            frames += stream.feed(chat([choice(delta={"tool_calls": [{"index": i, "function": {"arguments": token + '"}'}} for i in range(2)]})]))
            self.assertNotIn("公司甲", b"".join(frames).decode())
            frames += stream.feed(chat([choice(finish="tool_calls")]))
            self.assertEqual([], frames)
            frames += stream.feed(b"data: [DONE]\n\n")
            self.assertEqual([], frames)
            frames += stream.finalize()
            calls = decode_frames(frames)[-1]["choices"][0]["delta"]["tool_calls"]
            self.assertEqual([{"query": "公司甲"}] * 2, [json.loads(c["function"]["arguments"]) for c in calls])

    def test_chat_invalid_schema_unknown_field_model_and_terminal_fail_closed(self):
        for frame in (chat([choice(delta={"unknown": "x"})]), chat([choice()], model="wrong"), b"data: [DONE]\n\n", b"data: {\"id\":1,\"id\":2}\n\n"):
            with MappingContext("corp.test", "v1", KEY) as ctx:
                stream = ProtectedStream(CHAT, "synthetic-model", ctx)
                with self.assertRaises(SafetyError):
                    stream.feed(frame)
                self.assertTrue(stream._closed)
        with MappingContext("corp.test", "v1", KEY) as ctx:
            stream = ProtectedStream(CHAT, "synthetic-model", ctx, {"search": SCHEMA})
            frame = chat([choice(delta={"tool_calls": [{"index": 0, "id": "call", "type": "function", "function": {"name": "search", "arguments": '{"query":7}'}}]})])
            self.assertNotIn("arguments", b"".join(stream.feed(frame)).decode())
            with self.assertRaises(SafetyError):
                stream.feed(chat([choice(finish="tool_calls")]))
            self.assertEqual({}, stream.tools._buffers)

    def test_claude_text_and_tool_wire_bytes_and_usage(self):
        with MappingContext("corp.test", "v1", KEY) as ctx:
            token = ctx.token_for("ORG", "公司甲")
            stream = ProtectedStream(CLAUDE, "synthetic-model", ctx, {"search": SCHEMA})
            payload = message_start() + claude("content_block_start", index=0, content_block={"type": "text", "text": ""})
            payload += b"".join(claude("content_block_delta", index=0, delta={"type": "text_delta", "text": c}) for c in token)
            payload += claude("content_block_stop", index=0)
            payload += claude("content_block_start", index=1, content_block={"type": "tool_use", "id": "call", "name": "search", "input": {}})
            payload += claude("content_block_delta", index=1, delta={"type": "input_json_delta", "partial_json": json.dumps({"query": token})})
            payload += claude("content_block_stop", index=1)
            payload += claude("message_delta", delta={"stop_reason": "tool_use", "stop_sequence": None}, usage={"output_tokens": 7})
            payload += claude("message_stop")
            frames = []
            for byte in payload:
                frames.extend(stream.feed(bytes([byte])))
            frames.extend(stream.finalize())
            decoded = decode_frames(frames)
            text = "".join(item["delta"]["text"] for item in decoded if item.get("delta", {}).get("type") == "text_delta")
            self.assertEqual("公司甲", text)
            args = [item["delta"]["partial_json"] for item in decoded if item.get("delta", {}).get("type") == "input_json_delta"]
            self.assertEqual([{"query": "公司甲"}], [json.loads(value) for value in args])
            self.assertEqual({"output_tokens": 7}, decoded[-2]["usage"])

    def test_claude_state_without_provider_proof_and_invalid_sequence(self):
        for frame in (claude("message_stop"), claude("content_block_start", index=0, content_block={"type": "thinking", "thinking": "", "signature": "made-up"}), claude("content_block_delta", index=0, delta={"type": "text_delta", "text": "x"})):
            with MappingContext("corp.test", "v1", KEY) as ctx:
                stream = ProtectedStream(CLAUDE, "synthetic-model", ctx)
                stream.feed(message_start())
                with self.assertRaises(SafetyError):
                    stream.feed(frame)

    def test_truncated_token_missing_done_and_event_after_done(self):
        with MappingContext("corp.test", "v1", KEY) as ctx:
            stream = ProtectedStream(CHAT, "synthetic-model", ctx)
            stream.feed(chat([choice(delta={"content": "<<ENT_v1_"})]))
            with self.assertRaises(SafetyError):
                stream.feed(chat([choice(finish="stop")]))
        with MappingContext("corp.test", "v1", KEY) as ctx:
            stream = ProtectedStream(CHAT, "synthetic-model", ctx)
            stream.feed(chat([choice(finish="stop")]))
            with self.assertRaises(SafetyError):
                stream.finalize()
        with MappingContext("corp.test", "v1", KEY) as ctx:
            stream = ProtectedStream(CHAT, "synthetic-model", ctx)
            stream.feed(chat([choice(finish="stop")]))
            stream.feed(b"data: [DONE]\n\n")
            with self.assertRaises(SafetyError):
                stream.feed(chat([choice()]))

    def test_late_unknown_token_and_truncated_terminal_zero_business_release(self):
        for late in (chat([choice(delta={"content": "<<ENT_v1_" + "0" * 32 + ">>"})]), chat([choice(finish="stop")]) + b"data: [DONE]\n\ndata: trailing"):
            with MappingContext("corp.test", "v1", KEY) as ctx:
                stream = ProtectedStream(CHAT, "synthetic-model", ctx)
                self.assertEqual([], stream.feed(chat([choice(delta={"content": "valid business prefix"})])))
                with self.assertRaises(SafetyError):
                    stream.feed(late)
                    stream.finalize()
                self.assertEqual([], stream._pending_frames)

    def test_restored_output_budget_zero_release(self):
        with MappingContext("corp.test", "v1", KEY) as ctx:
            token = ctx.token_for("ORG", "a" * 2000)
            stream = ProtectedStream(CHAT, "synthetic-model", ctx, max_stream_bytes=1000)
            with self.assertRaises(SafetyError):
                stream.feed(chat([choice(delta={"content": token})]))
            self.assertEqual([], stream._pending_frames)

    def test_claude_business_frames_wait_for_valid_terminal(self):
        with MappingContext("corp.test", "v1", KEY) as ctx:
            stream = ProtectedStream(CLAUDE, "synthetic-model", ctx)
            for frame in (message_start(), claude("content_block_start", index=0, content_block={"type": "text", "text": "business"}), claude("content_block_stop", index=0), claude("message_delta", delta={"stop_reason": "end_turn", "stop_sequence": None}, usage={"output_tokens": 1})):
                self.assertEqual([], stream.feed(frame))
            frames = stream.feed(claude("message_stop"))
            self.assertEqual([], frames)
            frames += stream.finalize()
            self.assertIn("business", b"".join(frames).decode())

    def test_trailing_bad_frame_every_transport_split_has_zero_release(self):
        valid = chat([choice(delta={"content": "BUSINESS"})]) + chat([choice(finish="stop")]) + b"data: [DONE]\n\n"
        payload = valid + b"data: invalid-after-terminal\n\n"
        for cut in range(len(payload) + 1):
            with self.subTest(cut=cut), MappingContext("corp.test", "v1", KEY) as ctx:
                stream = ProtectedStream(CHAT, "synthetic-model", ctx)
                frames = []
                with self.assertRaises(SafetyError):
                    frames.extend(stream.feed(payload[:cut]))
                    frames.extend(stream.feed(payload[cut:]))
                    frames.extend(stream.finalize())
                self.assertEqual([], frames)

    def test_valid_large_wire_chunk_and_small_chunks_identical(self):
        payload = chat([choice(delta={"content": "x" * 1000})]) * 950 + chat([choice(finish="stop")]) + b"data: [DONE]\n\n"
        self.assertGreater(len(payload), 1024 * 1024)
        results = []
        for size in (4096, len(payload)):
            with MappingContext("corp.test", "v1", KEY) as ctx:
                stream = ProtectedStream(CHAT, "synthetic-model", ctx)
                for offset in range(0, len(payload), size):
                    self.assertEqual([], stream.feed(payload[offset:offset + size]))
                results.append(stream.finalize())
        self.assertEqual(results[0], results[1])


class AsyncStreamTests(unittest.IsolatedAsyncioTestCase):
    async def test_success_closes_source_and_no_post_terminal_keepalive(self):
        closed = []
        async def source():
            try:
                yield chat([choice(delta={"content": "success"})])
                yield chat([choice(finish="stop")]) + b"data: [DONE]\n\n"
                await asyncio.sleep(0.025)
            finally:
                closed.append(True)
        with MappingContext("corp.test", "v1", KEY) as ctx:
            stream = ProtectedStream(CHAT, "synthetic-model", ctx)
            frames = [frame async for frame in iter_protected_stream(source(), stream, keepalive_seconds=0.01)]
            self.assertIn("success", b"".join(frames).decode())
            self.assertEqual(b"data: [DONE]\n\n", frames[-1])
            self.assertEqual([True], closed)

    async def test_terminal_waits_for_eof_late_error_zero_release(self):
        async def source():
            yield chat([choice(delta={"content": "BUSINESS"})])
            yield chat([choice(finish="stop")]) + b"data: [DONE]\n\n"
            yield b"data: invalid-after-terminal\n\n"
        with MappingContext("corp.test", "v1", KEY) as ctx:
            stream = ProtectedStream(CHAT, "synthetic-model", ctx)
            frames = []
            with self.assertRaises(SafetyError):
                async for frame in iter_protected_stream(source(), stream):
                    frames.append(frame)
            self.assertEqual([], frames)

    async def test_missing_eof_after_terminal_deadline_no_business_or_keepalive(self):
        closed = []
        async def source():
            try:
                yield chat([choice(delta={"content": "BUSINESS"})])
                yield chat([choice(finish="stop")]) + b"data: [DONE]\n\n"
                await asyncio.sleep(5)
            finally:
                closed.append(True)
        with MappingContext("corp.test", "v1", KEY) as ctx:
            stream = ProtectedStream(CHAT, "synthetic-model", ctx, deadline_at=time.monotonic() + 0.07)
            frames = []
            with self.assertRaises(SafetyError):
                async for frame in iter_protected_stream(source(), stream, keepalive_seconds=0.01):
                    frames.append(frame)
            self.assertEqual([], frames)
            self.assertEqual([True], closed)

    async def test_task_cancellation_clears_uncommitted_frames(self):
        started = asyncio.Event()
        closed = []
        async def source():
            try:
                yield chat([choice(delta={"content": "uncommitted business"})])
                started.set()
                await asyncio.sleep(5)
            finally:
                closed.append(True)
        with MappingContext("corp.test", "v1", KEY) as ctx:
            stream = ProtectedStream(CHAT, "synthetic-model", ctx)
            async def consume():
                return [frame async for frame in iter_protected_stream(source(), stream)]
            task = asyncio.create_task(consume())
            await started.wait()
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual([], stream._pending_frames)
            self.assertEqual([True], closed)

    async def test_deadline_keepalive_does_not_extend_and_source_closed(self):
        closed = []
        async def source():
            try:
                await asyncio.sleep(5)
                yield b""
            finally:
                closed.append(True)
        with MappingContext("corp.test", "v1", KEY) as ctx:
            stream = ProtectedStream(CHAT, "synthetic-model", ctx, deadline_at=time.monotonic() + 0.08)
            frames = []
            started = time.monotonic()
            with self.assertRaises(SafetyError):
                async for frame in iter_protected_stream(source(), stream, keepalive_seconds=0.01):
                    frames.append(frame)
            self.assertLess(time.monotonic() - started, 0.3)
            self.assertTrue(frames)
            self.assertTrue(all(frame == b": keep-alive\n\n" for frame in frames))
            self.assertEqual([True], closed)
            self.assertTrue(stream._closed)

    async def test_disconnect_cancels_pending_read_and_clears_resources(self):
        closed = []
        async def source():
            try:
                await asyncio.sleep(5)
                yield b""
            finally:
                closed.append(True)
        disconnect_at = time.monotonic() + 0.03
        with MappingContext("corp.test", "v1", KEY) as ctx:
            stream = ProtectedStream(CHAT, "synthetic-model", ctx)
            frames = [frame async for frame in iter_protected_stream(source(), stream, disconnected=lambda: time.monotonic() >= disconnect_at, keepalive_seconds=0.01)]
            self.assertEqual([True], closed)
            self.assertTrue(stream._closed)
            self.assertEqual({}, stream.tools._buffers)
