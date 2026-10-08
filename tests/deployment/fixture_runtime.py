"""Finite synthetic classifier and loopback supplier for deployment verification.

The classifier permits only the exact approved fixture content. Neither client
classification headers nor arbitrary category fields grant permission. The
supplier validates masking and BYOK in its own process and exposes only counts.
"""
from __future__ import annotations

import json
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

APPROVED_TEXT = "甲公司向乙公司采购设备。张三联系电话13800138000。"
LOCAL_TEXT = "内部资料：甲公司向乙公司采购设备。"
UNKNOWN_TEXT = "未分类资料：甲公司向乙公司采购设备。"
TRUTHS = ("甲公司", "乙公司", "张三", "13800138000")


def classify(raw: bytes) -> str:
    try:
        data = json.loads(raw)
        content = data["messages"][-1]["content"]
        if isinstance(content, list):
            if len(content) != 1 or content[0].get("type") != "text":
                return "UNKNOWN"
            content = content[0]["text"]
        return {APPROVED_TEXT: "STANDARD", LOCAL_TEXT: "LOCAL_ONLY"}.get(content, "UNKNOWN")
    except (ValueError, KeyError, TypeError, IndexError):
        return "UNKNOWN"


app = FastAPI()
_stats = {"calls": 0, "masked_calls": 0, "keys_seen": [], "stream_calls": 0,
          "protocols": [], "violations": 0}


@app.get("/status")
def status():
    return _stats


@app.post("/v1/chat/completions")
@app.post("/v1/messages")
async def supplier(request: Request):
    raw = await request.body()
    payload = json.loads(raw)
    _stats["calls"] += 1
    content = payload["messages"][-1]["content"]
    text = content[0]["text"] if isinstance(content, list) else content
    keys = json.loads(os.environ["DEPLOYMENT_SYNTHETIC_KEYS"])
    claude = request.url.path.endswith("/messages")
    key = request.headers.get("x-api-key") if claude else request.headers.get("authorization", "").removeprefix("Bearer ")
    masked = not any(truth in raw.decode() for truth in TRUTHS) and "<<ENT_" in text
    if not masked or key not in keys:
        _stats["violations"] += 1
        return JSONResponse({"error": "fixture supplier validation failed"}, status_code=400)
    _stats["masked_calls"] += 1
    index = keys.index(key) + 1
    if index not in _stats["keys_seen"]:
        _stats["keys_seen"].append(index)
    protocol = "claude" if claude else "chat"
    if protocol not in _stats["protocols"]:
        _stats["protocols"].append(protocol)
    if payload.get("stream"):
        _stats["stream_calls"] += 1
        frames = [
            {"id": "chat-local", "object": "chat.completion.chunk", "created": 1,
             "model": payload["model"], "choices": [{"index": 0,
             "delta": {"role": "assistant", "content": text}, "finish_reason": None}]},
            {"id": "chat-local", "object": "chat.completion.chunk", "created": 1,
             "model": payload["model"], "choices": [{"index": 0,
             "delta": {}, "finish_reason": "stop"}]},
        ]
        wire = "".join("data: " + json.dumps(frame) + "\n\n" for frame in frames) + "data: [DONE]\n\n"
        return StreamingResponse(iter([wire.encode()]), media_type="text/event-stream")
    if claude:
        return {"id": "msg-local", "type": "message", "role": "assistant",
                "model": payload["model"], "content": [{"type": "text", "text": text}],
                "stop_reason": "end_turn", "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1}}
    return {"id": "chat-local", "object": "chat.completion", "created": 1,
            "model": payload["model"], "choices": [{"index": 0,
            "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
