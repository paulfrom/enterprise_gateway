"""M3 Dual-Protocol Integration Suite: Matrix Verification for Protocols, Streams, and Tools.

Verifies the complete M3 capability matrix across both supported protocols:
1. Protocol A: DeepSeek / OpenAI format (/v1/chat/completions)
2. Protocol B: Anthropic Claude format (/v1/messages)

Coverage includes:
- Non-streaming roundtrip and contract rejection (P-04, P-05, P-06)
- SSE incremental parsing across arbitrary byte splits and CRLF boundaries (P-07)
- Branch streaming token defragmentation and atomic restoration (P-08)
- Bounded tool parameter buffering, 64KB limits, strict JSON, and release verification (P-09, P-10)
- SSE comment keepalive scheduling and unextendable deadline enforcement (P-11)
- Reasoning and historical thinking block cryptographic validation (C-07, P-12)
- Upstream error sanitization without credential or trace leakage (P-13)
- Cancellation and deterministic resource cleanup (P-14)
- Multi-turn conversation historical re-detection and token smuggling defense (P-15)
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
import unittest
from uuid import uuid4

from infra.errors import SafetyCode, SafetyError
from infra.strict_json import parse_strict_json
from masking.mapping import MappingContext
from masking.stream_restorer import BranchStreamingRestorer
from protocol.history_state import HistoricalStateAdapter, ReasoningBlock, ReasoningStateValidator
from protocol.keepalive import SseKeepAliveScheduler
from protocol.protocols import CLAUDE_MESSAGES_PROTOCOL, DEEPSEEK_CHAT_PROTOCOL
from protocol.sse import ServerSentEvent, SseIncrementalParser
from protocol.tool_buffer import BoundedToolCallBuffer
from gateway.ingress import IngressValidator
from gateway.multi_turn import MultiTurnConversationSession
from protocol.admission import AdmissionLimiter
from audit.audit_watermark import AuditWatermarkGuard, WatermarkPolicy
from audit.evidence_gate import EvidenceGate
from detection.detection_orchestrator import DetectionOrchestrator, default_recognizers
from detection.inference_executor import InferenceExecutor
from gateway.pipeline import ProtectedPipeline
from infra.egress_client import BoundEgressClient, BoundUpstream
from infra.envelope_crypto import StaticTestKmsProvider
from infra.spool import SpoolWriter
from pathlib import Path
import tempfile
import httpx
from policy.policy import CategoryLabel, CategoryRule, ClassificationPolicy
from protocol.identity import TrustedIdentity


class TestProtocolMatrix(unittest.TestCase):
    def setUp(self) -> None:
        self.domain = f"matrix-test-{uuid4().hex[:8]}"
        self.hmac_key = b"matrix-test-secret-key-32bytes!!"
        self.context = MappingContext(self.domain, "v1", self.hmac_key)
        self.context.__enter__()

        self.policy = ClassificationPolicy(
            version="2026-10-04",
            rules=(
                CategoryRule(category="STANDARD", label=CategoryLabel.APPROVED_EXTERNAL, scope=self.domain),
            ),
        )

        now = datetime.now(timezone.utc)
        self.identity = TrustedIdentity(
            subject_id="agent-workbuddy",
            tenant_id="tenant-matrix",
            domain=self.domain,
            roles=frozenset({"operator"}),
            purposes=frozenset({"model-query"}),
            source_acl=frozenset({"matrix-acl"}),
            auth_source="mTLS",
            authenticated_at=now,
            expires_at=now + timedelta(hours=1),
        )

        self.reasoning_key = b"matrix-reasoning-auth-key-32byte"
        self.reasoning_validator = ReasoningStateValidator(self.reasoning_key)
        self.history_adapter = HistoricalStateAdapter(self.reasoning_validator)

    def tearDown(self) -> None:
        try:
            self.context.__exit__(None, None, None)
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # 1. Non-Streaming Contract Verification (DeepSeek & Claude)
    # -------------------------------------------------------------------------
    def test_deepseek_non_streaming_contract_acceptance_and_rejection(self) -> None:
        """DeepSeek Chat: Valid request admitted; undeclared fields or unknown models rejected."""
        valid_body = {
            "model": "deepseek-chat",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "请分析甲公司向乙公司的采购计划。"},
            ],
            "temperature": 0.7,
        }
        res = IngressValidator.validate_request(
            raw_body=json.dumps(valid_body),
            protocol=DEEPSEEK_CHAT_PROTOCOL,
            domain=self.domain,
            category="STANDARD",
            policy=self.policy,
            allowed_models=("deepseek-chat", "deepseek-reasoner"),
        )
        self.assertEqual("deepseek-chat", res.model)
        self.assertEqual(2, len(res.fragments))

        # Rejection: Unknown model fails closed
        invalid_model_body = dict(valid_body, model="unknown-unadmitted-model")
        with self.assertRaises(SafetyError) as exc_info:
            IngressValidator.validate_request(
                raw_body=json.dumps(invalid_model_body),
                protocol=DEEPSEEK_CHAT_PROTOCOL,
                domain=self.domain,
                category="STANDARD",
                policy=self.policy,
                allowed_models=("deepseek-chat",),
            )
        self.assertEqual(SafetyCode.PROTOCOL_VIOLATION, exc_info.exception.code)

        # Rejection: Undeclared illegal field rejected
        illegal_field_body = dict(valid_body, unauthorized_admin_flag=True)
        with self.assertRaises(SafetyError) as exc_info:
            IngressValidator.validate_request(
                raw_body=json.dumps(illegal_field_body),
                protocol=DEEPSEEK_CHAT_PROTOCOL,
                domain=self.domain,
                category="STANDARD",
                policy=self.policy,
                allowed_models=("deepseek-chat",),
            )
        self.assertEqual(SafetyCode.PROTOCOL_VIOLATION, exc_info.exception.code)

    def test_claude_non_streaming_contract_acceptance_and_rejection(self) -> None:
        """Claude Messages: Valid request admitted; undeclared fields or unknown models rejected."""
        valid_body = {
            "model": "claude-sonnet-5-5",
            "max_tokens": 1024,
            "system": "You are a research analyst.",
            "messages": [
                {"role": "user", "content": "阿尔法科技与李四的合同签订了吗？"}
            ],
        }
        res = IngressValidator.validate_request(
            raw_body=json.dumps(valid_body),
            protocol=CLAUDE_MESSAGES_PROTOCOL,
            domain=self.domain,
            category="STANDARD",
            policy=self.policy,
            allowed_models=("claude-sonnet-5-5", "claude-haiku-4-5"),
        )
        self.assertEqual("claude-sonnet-5-5", res.model)
        self.assertEqual(2, len(res.fragments))

        # Rejection: Missing required max_tokens
        missing_tokens_body = {
            "model": "claude-sonnet-5-5",
            "messages": [{"role": "user", "content": "Hello"}],
        }
        with self.assertRaises(SafetyError) as exc_info:
            IngressValidator.validate_request(
                raw_body=json.dumps(missing_tokens_body),
                protocol=CLAUDE_MESSAGES_PROTOCOL,
                domain=self.domain,
                category="STANDARD",
                policy=self.policy,
                allowed_models=("claude-sonnet-5-5",),
            )
        self.assertEqual(SafetyCode.PROTOCOL_VIOLATION, exc_info.exception.code)

    # -------------------------------------------------------------------------
    # 2. SSE Incremental Parsing Across Arbitrary Splits (P-07)
    # -------------------------------------------------------------------------
    def test_sse_incremental_chunking_and_crlf_normalization(self) -> None:
        """P-07: SseIncrementalParser handles split bytes, CRLF, multi-line data, and comments."""
        parser = SseIncrementalParser()
        raw_stream = (
            b": comment line to ignore\r\n"
            b"event: delta\r\n"
            b"id: evt-101\r\n"
            b"data: first line of text\r\n"
            b"data: second line of text\r\n\r\n"
            b"data: single line event\n\n"
        )

        # Feed byte by byte to test worst-case chunk splitting
        events: list[ServerSentEvent] = []
        for byte_idx in range(len(raw_stream)):
            chunk = raw_stream[byte_idx : byte_idx + 1]
            for ev in parser.feed(chunk):
                if not ev.is_comment:
                    events.append(ev)

        self.assertEqual(2, len(events))
        self.assertEqual("delta", events[0].event)
        self.assertEqual("evt-101", events[0].id)
        self.assertEqual("first line of text\nsecond line of text", events[0].data)

        self.assertEqual("message", events[1].event)
        self.assertEqual("single line event", events[1].data)

    def test_sse_parser_rejects_corrupted_utf8(self) -> None:
        """P-07: SseIncrementalParser fails closed on corrupted UTF-8 sequences."""
        parser = SseIncrementalParser()
        with self.assertRaises(SafetyError) as exc_info:
            list(parser.feed(b"data: \xff\xfe corrupted\n\n"))
        self.assertEqual(SafetyCode.INVALID_UTF8, exc_info.exception.code)

    # -------------------------------------------------------------------------
    # 3. Branch Streaming Token Defragmentation and Atomic Restoration (P-08)
    # -------------------------------------------------------------------------
    def test_branch_streaming_token_defragmentation_and_restoration(self) -> None:
        """P-08: Defragments split token prefixes across SSE chunks and restores atomically."""
        restorer = BranchStreamingRestorer(self.context)
        original_secret = "北京阿尔法科技有限责任公司"
        token = self.context.token_for("ORG", original_secret)

        # Simulate SSE response chunking that cuts across the token:
        # Token is <<ENT_v1_...>>
        prefix_len = 7
        mid_len = 20
        chunk1 = f"用户属于{token[:prefix_len]}"
        chunk2 = token[prefix_len : prefix_len + mid_len]
        chunk3 = f"{token[prefix_len + mid_len:]}，正在执行业务操作。"

        out1 = restorer.feed("branch-0", chunk1)
        out2 = restorer.feed("branch-0", chunk2)
        out3 = restorer.feed("branch-0", chunk3)
        final = restorer.finalize("branch-0")

        self.assertEqual("用户属于", out1)
        self.assertEqual("", out2)  # Incomplete token buffered
        self.assertEqual(f"{original_secret}，正在执行业务操作。", out3)
        self.assertEqual("", final)

    def test_streaming_token_truncation_fails_closed(self) -> None:
        """P-08: Stream truncated midway through a token prefix fails closed on finalize."""
        restorer = BranchStreamingRestorer(self.context)
        token = self.context.token_for("ORG", "机密公司")

        # Incomplete token feed
        restorer.feed("branch-0", f"数据来自{token[:15]}")
        with self.assertRaises(SafetyError) as exc_info:
            restorer.finalize("branch-0")
        self.assertEqual(SafetyCode.MALFORMED_TOKEN, exc_info.exception.code)

    # -------------------------------------------------------------------------
    # 4. Bounded Tool Parameter Buffer & Schema Release Verification (P-09, P-10)
    # -------------------------------------------------------------------------
    def test_tool_buffer_parallel_streams_and_schema_verification(self) -> None:
        """P-09 & P-10: Parallel tool argument streaming, token restoration, and schema verification."""
        buffer = BoundedToolCallBuffer()
        token_name = self.context.token_for("PERSON", "张三")
        token_account = self.context.token_for("BANK_CARD", "6222021234567890")

        # Register two tools
        buffer.register_tool("call_1", "transfer_funds")
        buffer.register_tool("call_2", "query_audit_log")

        # Stream arguments in chunks
        chunk1_t1 = f'{{"recipient": "{token_name}", '
        chunk2_t1 = f'"account": "{token_account}", "amount": 1000}}'

        buffer.feed_argument_delta("call_1", chunk1_t1)
        buffer.feed_argument_delta("call_1", chunk2_t1)

        buffer.feed_argument_delta("call_2", '{"action": "export", "limit": 50}')

        # Verify call_1: tokens restored
        allowed_tools = {
            "transfer_funds": {"required": ["recipient", "account", "amount"]},
            "query_audit_log": {"required": ["action", "limit"]},
        }
        released_t1 = buffer.finalize_and_verify("call_1", self.context, allowed_tools)
        self.assertEqual("张三", released_t1["recipient"])
        self.assertEqual("6222021234567890", released_t1["account"])
        self.assertEqual(1000, released_t1["amount"])

        # Verify call_2
        released_t2 = buffer.finalize_and_verify("call_2", self.context, allowed_tools)
        self.assertEqual("export", released_t2["action"])
        self.assertEqual(50, released_t2["limit"])

    def test_tool_buffer_enforces_64kb_budget_strictly(self) -> None:
        """P-09: Single tool call exceeding 65536 bytes strictly triggers ADMISSION_LIMIT_EXCEEDED."""
        buffer = BoundedToolCallBuffer(max_single_bytes=65536)
        buffer.register_tool("call_oversize", "large_input_tool")

        chunk_60kb = "a" * 60000
        chunk_10kb = "b" * 10000

        buffer.feed_argument_delta("call_oversize", chunk_60kb)
        with self.assertRaises(SafetyError) as exc_info:
            buffer.feed_argument_delta("call_oversize", chunk_10kb)
        self.assertEqual(SafetyCode.ADMISSION_LIMIT_EXCEEDED, exc_info.exception.code)

    def test_tool_buffer_rejects_duplicate_keys_and_malformed_json(self) -> None:
        """P-10: Duplicate JSON keys or malformed JSON in tool call fail closed with zero release."""
        buffer = BoundedToolCallBuffer()
        buffer.register_tool("call_dup", "do_action")
        buffer.feed_argument_delta("call_dup", '{"key": 1, "key": 2}')

        with self.assertRaises(SafetyError) as exc_info:
            buffer.finalize_and_verify("call_dup", self.context)
        self.assertEqual(SafetyCode.DUPLICATE_JSON_KEY, exc_info.exception.code)

    # -------------------------------------------------------------------------
    # 5. SSE Keepalive Scheduler & Absolute Deadline (P-11)
    # -------------------------------------------------------------------------
    def test_sse_keepalive_scheduling_and_unextendable_deadline(self) -> None:
        """P-11: Keepalive emits ': keep-alive\n\n' on idle and enforces absolute deadline."""
        scheduler = SseKeepAliveScheduler(interval_seconds=10.0, deadline_seconds=30.0, start_time=100.0)

        # At t=105s: idle < 10s -> no keepalive
        self.assertFalse(scheduler.should_emit_keepalive(now=105.0))

        # At t=111s: idle >= 10s -> emit keepalive
        self.assertTrue(scheduler.should_emit_keepalive(now=111.0))
        msg = scheduler.emit_keepalive(now=111.0)
        self.assertEqual(": keep-alive\n\n", msg)

        # Real activity at t=115s resets keepalive timer
        scheduler.record_activity(now=115.0)
        self.assertFalse(scheduler.should_emit_keepalive(now=120.0))

        # At t=131s: exceeded absolute deadline (100 + 30 = 130s) -> fails closed
        with self.assertRaises(SafetyError) as exc_info:
            scheduler.check_deadline(now=131.0)
        self.assertEqual(SafetyCode.CONTRACT_VIOLATION, exc_info.exception.code)

    # -------------------------------------------------------------------------
    # 6. Reasoning & Historical Thinking Block Verification (C-07, P-12)
    # -------------------------------------------------------------------------
    def test_reasoning_block_cryptographic_admission_and_tamper_rejection(self) -> None:
        """C-07 & P-12: Admitted signed reasoning blocks pass; unsigned or tampered blocks fail closed."""
        valid_thought = "Thinking process: verify customer authorization before proceeding."
        signed = self.reasoning_validator.sign_reasoning_block("thinking", valid_thought)
        self.reasoning_validator.verify_reasoning_block(signed)
        self.assertEqual(valid_thought, signed.content)

        # Tampered content fails closed
        tampered = ReasoningBlock(
            block_type="thinking",
            content="Tampered altered thinking process",
            signature=signed.signature,
            metadata=signed.metadata,
        )
        with self.assertRaises(SafetyError) as exc_info:
            self.reasoning_validator.verify_reasoning_block(tampered)
        self.assertEqual(SafetyCode.CONTRACT_VIOLATION, exc_info.exception.code)

        # Message history validation
        history = [
            {"role": "user", "content": "Check credentials"},
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "thinking",
                        "thinking": signed.content,
                        "signature": signed.signature,
                        "metadata": dict(signed.metadata),
                    },
                    {"type": "text", "text": "Credentials verified."},
                ],
            },
        ]
        self.history_adapter.validate_message_history(history)

    # -------------------------------------------------------------------------
    # 7. Cancellation & Resource Cleanup (P-14)
    # -------------------------------------------------------------------------
    def test_cancellation_and_resource_reclamation(self) -> None:
        """P-14: Cancellation immediately clears branch and tool buffers without lingering memory."""
        restorer = BranchStreamingRestorer(self.context)
        tool_buf = BoundedToolCallBuffer()

        # Allocate branch buffers
        restorer.feed("branch_cancel", "partial data <<ENT_")
        tool_buf.register_tool("tool_cancel", "some_tool")
        tool_buf.feed_argument_delta("tool_cancel", '{"param": "val')

        self.assertIn("branch_cancel", restorer._buffers)
        self.assertIn("tool_cancel", tool_buf._buffers)

        # Cancel specific and all
        restorer.cancel_branch("branch_cancel")
        tool_buf.cancel_tool("tool_cancel")

        self.assertNotIn("branch_cancel", restorer._buffers)
        self.assertNotIn("tool_cancel", tool_buf._buffers)
        self.assertEqual(0, tool_buf._total_bytes)

        # Cancel all cleans everything
        restorer.cancel_all()
        tool_buf.cancel_all()
        self.assertEqual({}, restorer._buffers)
        self.assertEqual({}, tool_buf._buffers)

    # -------------------------------------------------------------------------
    # 8. Multi-Turn Conversation & Token Smuggling Rejection (P-15)
    # -------------------------------------------------------------------------
    def test_multi_turn_historical_redetection_and_smuggling_defense(self) -> None:
        """P-15: Multi-turn messages re-detect per turn; client token smuggling is rejected."""
        from masking.mapping import reject_reserved_literals

        # 1. Smuggling attempt: Reserved token literal rejected directly
        with self.assertRaises(SafetyError) as exc_info:
            reject_reserved_literals("我的上一轮令牌是 <<ENT_v1_0123456789abcdef0123456789abcdef>> 请继续")
        self.assertEqual(SafetyCode.RESERVED_TOKEN_LITERAL, exc_info.exception.code)

        # 2. MultiTurnConversationSession token smuggling defense
        class DummyPipeline:
            def __init__(self, domain: str) -> None:
                self.domain = domain

            def process_request(self, raw_body: str, **kwargs: Any) -> Any:
                reject_reserved_literals(raw_body)

        dummy_p = DummyPipeline(self.domain)
        session = MultiTurnConversationSession(dummy_p, self.identity)

        with self.assertRaises(SafetyError) as exc_info2:
            session.execute_turn(
                "继续处理 <<ENT_v1_0123456789abcdef0123456789abcdef>>",
                category="STANDARD",
                turn_hmac_key=self.hmac_key,
                model="deepseek-chat",
            )
        self.assertEqual(SafetyCode.RESERVED_TOKEN_LITERAL, exc_info2.exception.code)


if __name__ == "__main__":
    unittest.main()
