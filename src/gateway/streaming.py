"""Strict, request-local stream protection for Chat Completions and Messages.

Transport/authentication/version binding remain the pipeline's responsibility.
Only typed text fields are restored. All business events are buffered until a
complete valid terminal event and real transport EOF commit the response. During validation only
fixed comments or typed protocol pings may reach the client. Encoded input and
restored output each have a cumulative byte budget; cancellation discards the
uncommitted response. This is the sole release mode.
"""
from __future__ import annotations

import asyncio
import anyio
from copy import deepcopy
import inspect
import json
import math
import time
from typing import Any, AsyncIterable, AsyncIterator, Callable, Mapping

from infra.errors import SafetyCode, SafetyError
from infra.strict_json import JsonRejectKind, parse_strict_json
from masking.mapping import MappingContext
from masking.stream_restorer import BranchStreamingRestorer
from protocol.history_state import ReasoningBlock, ReasoningStateValidator
from protocol.protocols import CLAUDE_MESSAGES_PROTOCOL, DEEPSEEK_CHAT_PROTOCOL
from protocol.sse import ServerSentEvent, SseIncrementalParser
from protocol.tool_buffer import BoundedToolCallBuffer


def _reject(detail: str = "invalid stream contract") -> None:
    raise SafetyError(SafetyCode.CONTRACT_VIOLATION, detail)


def _json_reject(kind: JsonRejectKind) -> None:
    code = {JsonRejectKind.DUPLICATE_KEY: SafetyCode.DUPLICATE_JSON_KEY,
            JsonRejectKind.INVALID_UTF8: SafetyCode.INVALID_UTF8}.get(kind, SafetyCode.MALFORMED_JSON)
    raise SafetyError(code, "invalid stream JSON")


def _object(value: Any, fields: set[str], required: set[str] = frozenset()) -> dict:
    if not isinstance(value, dict) or set(value) - fields or required - set(value):
        _reject()
    return value


def _int(value: Any) -> None:
    if type(value) is not int or value < 0:
        _reject()


def _string(value: Any) -> None:
    if not isinstance(value, str):
        _reject()


def _structural(value: Any) -> None:
    if isinstance(value, str) and ("<<ENT" in value or value.endswith(("<<E", "<<EN"))):
        _reject("token in structural stream field")
    if isinstance(value, dict):
        for key, item in value.items():
            _structural(key)
            _structural(item)
    elif isinstance(value, list):
        for item in value:
            _structural(item)


def _usage(value: Any, claude: bool = False) -> None:
    fields = {"input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"} if claude else {
        "prompt_tokens", "completion_tokens", "total_tokens", "prompt_cache_hit_tokens", "prompt_cache_miss_tokens"}
    _object(value, fields)
    for count in value.values():
        _int(count)


def _frame(payload: dict, event: str | None = None) -> bytes:
    prefix = f"event: {event}\n" if event else ""
    return (prefix + "data: " + json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n\n").encode("utf-8")


class ProtectedStream:
    def __init__(self, protocol: str, expected_model: str, context: MappingContext,
                 allowed_tools: Mapping[str, dict | type] | None = None, deadline_at: float | None = None,
                 state_validator: ReasoningStateValidator | None = None, state_version: str | None = None,
                 max_stream_bytes: int = 8 * 1024 * 1024, client_model: str | None = None) -> None:
        if protocol not in (DEEPSEEK_CHAT_PROTOCOL, CLAUDE_MESSAGES_PROTOCOL) or not isinstance(expected_model, str) or not expected_model or type(max_stream_bytes) is not int or max_stream_bytes <= 0:
            _reject()
        if client_model is not None and (not isinstance(client_model, str) or not client_model):
            _reject()
        _structural([expected_model, client_model])
        if deadline_at is not None and (not isinstance(deadline_at, (float, int)) or not math.isfinite(deadline_at)):
            _reject("invalid stream deadline")
        context.require_active()
        if state_validator is not None and (not state_version or state_validator.scope != context.scope or state_validator.version != state_version):
            _reject("state validator binding mismatch")
        self.protocol = protocol
        self.expected_model = expected_model
        self.client_model = client_model or expected_model
        self.context = context
        self.allowed_tools = dict(allowed_tools or {})
        self.deadline_at = deadline_at if deadline_at is not None else time.monotonic() + 120
        self.state_validator = state_validator
        self.parser = SseIncrementalParser()
        self.restorer = BranchStreamingRestorer(context)
        self.tools = BoundedToolCallBuffer()
        self.max_stream_bytes = max_stream_bytes
        self._received = 0
        self._pending_frames: list[bytes] = []
        self._pending_bytes = 0
        self._closed = False
        self._done = False
        self._identity: tuple | None = None
        self._choices: dict[int, bool] = {}
        self._tool_calls: dict[tuple[int, int], dict] = {}
        self._message_started = False
        self._message_delta = False
        self._blocks: dict[int, dict] = {}
        self._closed_blocks: set[int] = set()
        self._had_tools = False
        self.state_receipts: dict[int, ReasoningBlock] = {}

    def _check(self) -> None:
        if self._closed:
            _reject("stream is closed")
        try:
            self.context.require_active()
        except SafetyError:
            self.cancel()
            raise
        if time.monotonic() >= self.deadline_at:
            self.cancel()
            _reject("stream absolute deadline exceeded")

    def feed(self, chunk: bytes) -> list[bytes]:
        self._check()
        if not isinstance(chunk, bytes):
            self.cancel()
            _reject()
        self._received += len(chunk)
        if self._received > self.max_stream_bytes:
            self.cancel()
            raise SafetyError(SafetyCode.ADMISSION_LIMIT_EXCEEDED, "stream size exceeded")
        try:
            result = []
            for event in self.parser.feed(chunk):
                self._queue(event, result)
            self._check()
            return result
        except SafetyError:
            self.cancel()
            raise
        except Exception:
            self.cancel()
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "invalid stream event") from None

    def _queue(self, event: ServerSentEvent, result: list[bytes]) -> None:
        frames = self._event(event)
        heartbeat = event.is_comment or self.protocol == CLAUDE_MESSAGES_PROTOCOL and event.event == "ping"
        if heartbeat:
            result.extend(frames)
            return
        for frame in frames:
            self._pending_bytes += len(frame)
            if self._pending_bytes > self.max_stream_bytes:
                raise SafetyError(SafetyCode.ADMISSION_LIMIT_EXCEEDED, "restored stream size exceeded")
            self._pending_frames.append(frame)

    def _event(self, event: ServerSentEvent) -> list[bytes]:
        if self._done:
            _reject("event after stream termination")
        if event.is_comment:
            # Upstream comments may contain arbitrary text; relay only a fixed heartbeat.
            return [b": keep-alive\n\n"]
        if event.id is not None or event.retry is not None:
            _reject("unsupported SSE control field")
        if self.protocol == DEEPSEEK_CHAT_PROTOCOL and event.data == "[DONE]":
            if event.event != "message" or not self._choices or not all(self._choices.values()):
                _reject("premature stream termination")
            self._done = True
            return [b"data: [DONE]\n\n"]
        payload = parse_strict_json(event.data, reject=_json_reject)
        if self.protocol == DEEPSEEK_CHAT_PROTOCOL:
            if event.event != "message":
                _reject()
            return self._chat(payload)
        return self._claude(payload, event.event)

    def _chat(self, value: Any) -> list[bytes]:
        data = deepcopy(_object(value, {"id", "object", "created", "model", "choices", "usage", "system_fingerprint"},
                                {"id", "object", "created", "model", "choices"}))
        if data["object"] != "chat.completion.chunk" or data["model"] != self.expected_model:
            _reject("unexpected stream model or object")
        _string(data["id"])
        _int(data["created"])
        identity = (data["id"], data["created"], data["model"])
        if self._identity is not None and identity != self._identity:
            _reject("stream identity changed")
        self._identity = identity
        data["model"] = self.client_model
        if "system_fingerprint" in data and data["system_fingerprint"] is not None:
            _string(data["system_fingerprint"])
        if data.get("usage") is not None:
            _usage(data["usage"])
        _structural({k: v for k, v in data.items() if k != "choices"})
        if not isinstance(data["choices"], list) or len(data["choices"]) > 128:
            _reject()
        if not data["choices"] and (data.get("usage") is None or not self._choices or not all(self._choices.values())):
            _reject("premature usage chunk")
        seen = set()
        for choice in data["choices"]:
            _object(choice, {"index", "delta", "finish_reason", "logprobs"}, {"index", "delta", "finish_reason"})
            index = choice["index"]
            _int(index)
            if index > 127 or index in seen or self._choices.get(index) is True:
                _reject("invalid or completed choice")
            seen.add(index)
            self._choices.setdefault(index, False)
            if choice.get("logprobs") is not None:
                _reject("unsupported logprobs")
            delta = _object(choice["delta"], {"role", "content", "reasoning_content", "tool_calls"})
            if "role" in delta and delta["role"] != "assistant":
                _reject()
            for field in ("content", "reasoning_content"):
                if field in delta and delta[field] is not None:
                    _string(delta[field])
                    delta[field] = self.restorer.feed(f"chat:{index}:{field}", delta[field])
            calls = delta.pop("tool_calls", [])
            if not isinstance(calls, list) or len(calls) > 128:
                _reject()
            call_indices = set()
            for call in calls:
                _object(call, {"index", "id", "type", "function"}, {"index", "function"})
                tool_index = call["index"]
                _int(tool_index)
                if tool_index > 127 or tool_index in call_indices:
                    _reject()
                call_indices.add(tool_index)
                function = _object(call["function"], {"name", "arguments"})
                key = (index, tool_index)
                if key not in self._tool_calls:
                    if call.get("type") != "function" or not isinstance(call.get("id"), str) or not call["id"] or not isinstance(function.get("name"), str):
                        _reject("incomplete initial tool metadata")
                    _structural({"id": call["id"], "name": function["name"]})
                    if function["name"] not in self.allowed_tools or any(v["id"] == call["id"] for v in self._tool_calls.values()):
                        _reject("unknown or duplicate tool")
                    self._tool_calls[key] = {"index": tool_index, "id": call["id"], "type": "function", "function": {"name": function["name"]}}
                    self.tools.register_tool(call["id"], function["name"])
                else:
                    stored = self._tool_calls[key]
                    if ("id" in call and call["id"] != stored["id"]) or ("type" in call and call["type"] != "function") or ("name" in function and function["name"] != stored["function"]["name"]):
                        _reject("tool identity changed")
                if "arguments" in function:
                    _string(function["arguments"])
                    self.tools.feed_argument_delta(self._tool_calls[key]["id"], function["arguments"])
            finish = choice["finish_reason"]
            if finish is not None:
                if finish not in ("stop", "length", "content_filter", "tool_calls"):
                    _reject()
                for field in ("content", "reasoning_content"):
                    tail = self.restorer.finalize(f"chat:{index}:{field}")
                    if tail:
                        delta[field] = (delta.get(field) or "") + tail
                branch_tools = [tool for (branch, _), tool in self._tool_calls.items() if branch == index]
                if branch_tools and finish != "tool_calls" or finish == "tool_calls" and not branch_tools:
                    _reject("tool terminal mismatch")
                # Verify the complete set before releasing any executable arguments.
                verified = []
                for tool in branch_tools:
                    restored = self.tools.finalize_and_verify(tool["id"], self.context, self.allowed_tools)
                    out = deepcopy(tool)
                    out["function"]["arguments"] = json.dumps(restored, ensure_ascii=False, separators=(",", ":"))
                    verified.append(out)
                if verified:
                    delta["tool_calls"] = verified
                self._choices[index] = True
            _structural({k: v for k, v in choice.items() if k != "delta"})
        return [_frame(data)]

    def _claude(self, value: Any, event: str) -> list[bytes]:
        data = deepcopy(_object(value, {"type", "message", "index", "content_block", "delta", "usage"}, {"type"}))
        kind = data["type"]
        if event != kind:
            _reject("SSE event and payload mismatch")
        if kind == "ping":
            _object(data, {"type"}, {"type"})
            return [_frame(data, kind)]
        if kind == "message_start":
            _object(data, {"type", "message"}, {"type", "message"})
            if self._message_started:
                _reject()
            message = _object(data["message"], {"id", "type", "role", "model", "content", "stop_reason", "stop_sequence", "usage"},
                              {"id", "type", "role", "model", "content", "stop_reason", "stop_sequence", "usage"})
            _string(message["id"])
            if message["type"] != "message" or message["role"] != "assistant" or message["model"] != self.expected_model or message["content"] != [] or message["stop_reason"] is not None or message["stop_sequence"] is not None:
                _reject("invalid message start")
            _usage(message["usage"], True)
            _structural(message)
            message["model"] = self.client_model
            self._message_started = True
            return [_frame(data, kind)]
        if not self._message_started:
            _reject("event before message start")
        if kind == "content_block_start":
            _object(data, {"type", "index", "content_block"}, {"type", "index", "content_block"})
            index = data["index"]
            _int(index)
            if index > 127 or index in self._blocks or index in self._closed_blocks or self._message_delta:
                _reject()
            block = _object(data["content_block"], {"type", "text", "id", "name", "input", "thinking", "signature"}, {"type"})
            block_kind = block["type"]
            if block_kind == "text":
                _object(block, {"type", "text"}, {"type", "text"})
                _string(block["text"])
                block["text"] = self.restorer.feed(f"claude:{index}", block["text"])
            elif block_kind == "tool_use":
                _object(block, {"type", "id", "name", "input"}, {"type", "id", "name", "input"})
                if not isinstance(block["id"], str) or not block["id"] or not isinstance(block["name"], str) or block["name"] not in self.allowed_tools or block["input"] != {}:
                    _reject("invalid tool block")
                _structural(block)
                self.tools.register_tool(block["id"], block["name"])
                self._had_tools = True
            elif block_kind == "thinking":
                _object(block, {"type", "thinking", "signature"}, {"type", "thinking"})
                if self.state_validator is None:
                    _reject("provider state verifier unavailable")
                _string(block["thinking"])
                if block.get("signature") is not None:
                    _string(block["signature"])
            else:
                _reject("unsupported content block")
            self._blocks[index] = {"block": block, "start": data, "thinking": block.get("thinking", ""), "signature": block.get("signature", ""), "events": []}
            return [_frame(data, kind)] if block_kind == "text" else []
        if kind == "content_block_delta":
            _object(data, {"type", "index", "delta"}, {"type", "index", "delta"})
            index = data["index"]
            _int(index)
            if index not in self._blocks or self._message_delta:
                _reject("delta without open block")
            state = self._blocks[index]
            delta = _object(data["delta"], {"type", "text", "partial_json", "thinking", "signature"}, {"type"})
            block_kind = state["block"]["type"]
            if block_kind == "text" and delta["type"] == "text_delta":
                _object(delta, {"type", "text"}, {"type", "text"})
                _string(delta["text"])
                delta["text"] = self.restorer.feed(f"claude:{index}", delta["text"])
                return [_frame(data, kind)]
            if block_kind == "tool_use" and delta["type"] == "input_json_delta":
                _object(delta, {"type", "partial_json"}, {"type", "partial_json"})
                _string(delta["partial_json"])
                self.tools.feed_argument_delta(state["block"]["id"], delta["partial_json"])
                return []
            if block_kind == "thinking" and delta["type"] in ("thinking_delta", "signature_delta"):
                field = "thinking" if delta["type"] == "thinking_delta" else "signature"
                _object(delta, {"type", field}, {"type", field})
                _string(delta[field])
                state[field] += delta[field]
                state["events"].append(data)
                return []
            _reject("delta type mismatch")
        if kind == "content_block_stop":
            _object(data, {"type", "index"}, {"type", "index"})
            index = data["index"]
            _int(index)
            if index not in self._blocks:
                _reject("stop without open block")
            state = self._blocks[index]
            block = state["block"]
            output = []
            if block["type"] == "text":
                tail = self.restorer.finalize(f"claude:{index}")
                if tail:
                    output.append(_frame({"type": "content_block_delta", "index": index, "delta": {"type": "text_delta", "text": tail}}, "content_block_delta"))
            elif block["type"] == "tool_use":
                restored = self.tools.finalize_and_verify(block["id"], self.context, self.allowed_tools)
                output.append(_frame(state["start"], "content_block_start"))
                output.append(_frame({"type": "content_block_delta", "index": index, "delta": {"type": "input_json_delta", "partial_json": json.dumps(restored, ensure_ascii=False, separators=(",", ":"))}}, "content_block_delta"))
            else:
                _structural(state["thinking"])
                receipt = self.state_validator.admit_upstream_block(ReasoningBlock("thinking", state["thinking"], state["signature"], {}))
                self.state_receipts[index] = receipt
                state['start']['content_block']['metadata']=dict(receipt.metadata)
                output.append(_frame(state["start"], "content_block_start"))
                output.extend(_frame(item, "content_block_delta") for item in state["events"])
            del self._blocks[index]
            self._closed_blocks.add(index)
            output.append(_frame(data, kind))
            return output
        if kind == "message_delta":
            _object(data, {"type", "delta", "usage"}, {"type", "delta", "usage"})
            delta = _object(data["delta"], {"stop_reason", "stop_sequence"}, {"stop_reason", "stop_sequence"})
            if self._blocks or self._message_delta or not self._closed_blocks or delta["stop_reason"] not in ("end_turn", "max_tokens", "stop_sequence", "tool_use"):
                _reject("invalid message termination")
            if self._had_tools != (delta["stop_reason"] == "tool_use"):
                _reject("tool terminal mismatch")
            if delta["stop_sequence"] is not None:
                _string(delta["stop_sequence"])
            _usage(data["usage"], True)
            _structural(data)
            self._message_delta = True
            return [_frame(data, kind)]
        if kind == "message_stop":
            _object(data, {"type"}, {"type"})
            if self._blocks or not self._message_delta:
                _reject("premature message stop")
            self._done = True
            return [_frame(data, kind)]
        _reject("unsupported upstream event")

    def finalize(self) -> list[bytes]:
        """Commit only after the caller has observed the real upstream body EOF.

        A protocol terminal event is insufficient: all subsequent transport
        bytes must first pass feed(), including any delayed trailing frame.
        """
        self._check()
        try:
            result = []
            for event in self.parser.flush():
                self._queue(event, result)
            self._check()
            if not self._done:
                _reject("missing terminal stream event")
            result.extend(self._pending_frames)
            return result
        finally:
            self.cancel()

    def cancel(self) -> None:
        self._closed = True
        self.parser.cancel()
        self.restorer.cancel_all()
        self.tools.cancel_all()
        self._blocks.clear()
        self._tool_calls.clear()
        self.state_receipts.clear()
        self._pending_frames.clear()
        self._pending_bytes = 0


async def iter_protected_stream(source: AsyncIterable[bytes], stream: ProtectedStream, *,
                                disconnected: Callable | None = None, close: Callable | None = None,
                                keepalive_seconds: float = 15.0) -> AsyncIterator[bytes]:
    """Single in-flight upstream read; deadlines/keepalives never restart it.

    The caller owns the MappingContext and keeps it active for this iterator.
    Explicit close runs on success, corruption, deadline and client cancellation.
    """
    if not isinstance(keepalive_seconds, (float, int)) or not math.isfinite(keepalive_seconds) or keepalive_seconds <= 0:
        _reject()
    iterator = source.__aiter__()
    pending = None
    last_activity = time.monotonic()
    try:
        while True:
            stream._check()
            if disconnected is not None:
                value = disconnected()
                if inspect.isawaitable(value):
                    value = await value
                if value:
                    return
            if pending is None:
                pending = asyncio.create_task(anext(iterator))
            now = time.monotonic()
            timeout = min(stream.deadline_at - now, 0.1)
            if not stream._done:
                timeout = min(timeout, keepalive_seconds - (now - last_activity))
            ready, _ = await asyncio.wait({pending}, timeout=max(0, timeout))
            stream._check()
            if not ready:
                if not stream._done and time.monotonic() - last_activity >= keepalive_seconds:
                    last_activity = time.monotonic()
                    yield b": keep-alive\n\n"
                continue
            task, pending = pending, None
            try:
                chunk = task.result()
            except StopAsyncIteration:
                for frame in stream.finalize():
                    yield frame
                return
            for frame in stream.feed(chunk):
                stream._check()
                yield frame
            last_activity = time.monotonic()
    finally:
        # Starlette disconnects cancel an AnyIO task group. Cleanup must survive
        # that enclosing cancel scope; plain asyncio.shield does not protect
        # subsequent awaits from level cancellation.
        stream.cancel()
        if pending is not None:
            pending.cancel()
        target = close if close is not None else getattr(iterator, "aclose", None)
        async def cleanup():
            # Close transport before joining the read task, so a blocked
            # synchronous read can be interrupted by the actual socket close.
            try:
                if target is not None:
                    value = target()
                    if inspect.isawaitable(value):
                        await value
            finally:
                if pending is not None:
                    await asyncio.gather(pending, return_exceptions=True)
        with anyio.CancelScope(shield=True):
            cleanup_task = asyncio.create_task(cleanup())
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError:
                await cleanup_task
                raise
