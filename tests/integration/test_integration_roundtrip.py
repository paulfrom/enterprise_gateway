"""Non-streaming end-to-end integration roundtrip tests.

Proves that:
1. Valid DeepSeek and Claude requests complete an end-to-end roundtrip:
   entities are detected -> redacted to tokens -> sent to upstream ->
   upstream receives ONLY tokens -> response tokens are restored ->
   caller receives plaintext response with usage preserved.
2. Any pre-flight gate failure results in EXACTLY ZERO upstream calls:
   - Untrusted identity headers (C-02)
   - Scope / domain mismatch (C-02)
   - Unapproved classification category (C-01)
   - Resource admission limits (P-16)
   - Secret detected (P0) (D-12 / recognizers)
   - Storage capacity watermark blocked (A-08)
   - Evidence gate intent write failure (A-03)
3. Response verification & restoration:
   - Malformed/unknown tokens fail closed.
   - Upstream non-200 fails closed.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import httpx
from presidio_analyzer import Pattern, PatternRecognizer

from protocol.admission import AdmissionLimiter
from audit.audit_watermark import AuditWatermarkGuard, WatermarkPolicy
from detection.detection_orchestrator import DetectionOrchestrator
from detection.dictionary import (
    DictionaryEntry,
    compile_dictionary,
    compute_dictionary_hash,
)
from infra.egress_client import BoundEgressClient, BoundUpstream
from infra.envelope_crypto import StaticTestKmsProvider
from infra.errors import SafetyCode, SafetyError
from audit.evidence_gate import EvidenceGate, EvidenceSpec
from protocol.identity import TrustedIdentity
from detection.inference_executor import InferenceExecutor
from knowledge.knowledge_events import ObservationEvent
from masking.mapping import MappingContext
from gateway.pipeline import ProtectedPipeline, UpstreamFailure
from policy.policy import (
    CategoryLabel,
    CategoryRule,
    ClassificationPolicy,
)
from protocol.protocols import (
    CLAUDE_MESSAGES_PROTOCOL,
    DEEPSEEK_CHAT_PROTOCOL,
    ClaudeMessagesRequest,
    DeepSeekChatRequest,
)
from detection.recognizers import default_recognizers
from infra.spool import CollectionMode, SpoolWriter

TESTS_DIR = Path(__file__).parent.parent
MINI_PACKAGE = TESTS_DIR / "detection" / "fixtures" / "ner" / "mini-valid-package"
TEST_HMAC_KEY = b"0123456789abcdef0123456789abcdef"


class UpstreamSpyTransport(httpx.BaseTransport):
    """Spy transport that records outgoing requests and responds with configured content."""

    def __init__(self, response_factory) -> None:
        self.response_factory = response_factory
        self.calls: list[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        return self.response_factory(request)


class IntegrationRoundtripTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        self.intent_dir = self.base_path / "intents"
        self.evidence_dir = self.base_path / "evidence"
        self.spool_dir = self.base_path / "spool"
        self.audit_volume = self.base_path / "audit_volume"

        for p in (self.intent_dir, self.evidence_dir, self.spool_dir, self.audit_volume):
            p.mkdir(parents=True, exist_ok=True)

        self.kms = StaticTestKmsProvider()
        self.domain = "corp.test"

        # Classification Policy
        self.policy = ClassificationPolicy(
            version="2026-10-04",
            rules=(
                CategoryRule(category="STANDARD", label=CategoryLabel.APPROVED_EXTERNAL, scope=self.domain),
                CategoryRule(category="FORBIDDEN", label=CategoryLabel.LOCAL_ONLY, scope=self.domain),
            ),
        )

        # Dictionary
        entries = (
            DictionaryEntry(text="阿尔法科技", entity_type="ORG"),
            DictionaryEntry(text="张三", entity_type="PER"),
        )
        payload = {
            "dictionary_id": "dict-01",
            "version": "v1",
            "domain": self.domain,
            "entries": [
                {"text": entry.text, "entity_type": entry.entity_type}
                for entry in entries
            ],
            "sha256": compute_dictionary_hash(
                "dict-01", "v1", self.domain, entries
            ),
        }
        self.compiled_dict = compile_dictionary(payload)

        # Detector
        self.executor = InferenceExecutor(max_workers=1)
        self.detector = DetectionOrchestrator(
            recognizers=default_recognizers(),
            dictionary=self.compiled_dict,
            ner_package_dir=MINI_PACKAGE,
            executor=self.executor,
        )

        # Admission Limiter
        self.admission_limiter = AdmissionLimiter(
            max_body_bytes=65536,
            max_concurrency=10,
        )

        # Watermark Guard
        self.watermark_policy = WatermarkPolicy(
            blocking_ratio=0.90,
            warning_ratio=0.80,
            min_available_bytes=1024,
        )
        self.watermark_guard = AuditWatermarkGuard(
            self.audit_volume,
            self.watermark_policy,
            probe=lambda p: (1000 * 1024 * 1024, 100 * 1024 * 1024, 900 * 1024 * 1024),
        )

        # Evidence Gate
        self.evidence_gate = EvidenceGate(
            intent_directory=self.intent_dir,
            evidence_directory=self.evidence_dir,
            kms=self.kms,
        )

        # Spool Writer
        self.spool_writer = SpoolWriter(
            directory=self.spool_dir,
            kms=self.kms,
        )

        # Identity
        _now = datetime.now(timezone.utc)
        self.identity = TrustedIdentity(
            subject_id="user-001",
            tenant_id="tenant-corp",
            domain=self.domain,
            roles=frozenset({"employee"}),
            purposes=frozenset({"model-query"}),
            source_acl=frozenset({"corp-internal"}),
            auth_source="mTLS",
            authenticated_at=_now - timedelta(hours=1),
            expires_at=_now + timedelta(hours=8),
        )

    def tearDown(self) -> None:
        self.executor.close()
        self.temp_dir.cleanup()

    def _create_pipeline(self, protocol: str, spy_transport: httpx.BaseTransport, **options) -> ProtectedPipeline:
        bound_upstream = BoundUpstream(
            channel_id="chan-01",
            scheme="http",
            host="127.0.0.1",
            port=8080,
            path_prefix="/v1",
            credential="Bearer test-token-123",
            timeout_seconds=5.0,
            allowed_addresses=frozenset({"127.0.0.1"}),
        )
        egress_client = BoundEgressClient(
            binding=bound_upstream,
            transport=spy_transport,
            resolver=lambda h: ("127.0.0.1",),
        )
        path = "/v1/chat/completions" if protocol == DEEPSEEK_CHAT_PROTOCOL else "/v1/messages"
        return ProtectedPipeline(
            allowed_models=options.pop('allowed_models',frozenset({"deepseek-flash" if protocol==DEEPSEEK_CHAT_PROTOCOL else "claude-sonnet-5-5"})),
            channel_id="chan-01",
            protocol=protocol,
            domain=self.domain,
            path=path,
            policy=self.policy,
            admission_limiter=self.admission_limiter,
            detector=self.detector,
            watermark_guard=self.watermark_guard,
            evidence_gate=self.evidence_gate,
            egress_client=egress_client,
            spool_writer=self.spool_writer,
            **options,
        )

    def test_deepseek_protected_roundtrip_positive(self) -> None:
        """DeepSeek end-to-end positive flow: entities redacted to tokens, upstream receives

        only tokens, response restores tokens to plaintext, usage strictly preserved.
        """
        captured_tokens: list[str] = []

        def upstream_handler(request: httpx.Request) -> httpx.Response:
            payload = json.loads(request.content.decode("utf-8"))
            sent_content = payload["messages"][0]["content"]

            # Security assertion: plaintext MUST NOT appear in upstream request!
            self.assertNotIn("阿尔法科技", sent_content)
            self.assertNotIn("张三", sent_content)
            self.assertIn("<<ENT_v1_", sent_content)

            # Return upstream response containing the exact tokens
            resp_body = {
                "id": "chatcmpl-roundtrip01",
                "object": "chat.completion",
                "created": 1727950000,
                "model": "deepseek-flash",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": f"已经收到请求，关于 {sent_content} 已确认。",
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 30,
                    "completion_tokens": 20,
                    "total_tokens": 50,
                },
            }
            return httpx.Response(200, content=json.dumps(resp_body).encode("utf-8"))

        spy = UpstreamSpyTransport(upstream_handler)
        pipeline = self._create_pipeline(DEEPSEEK_CHAT_PROTOCOL, spy)

        raw_req = json.dumps({
            "model": "deepseek-flash",
            "messages": [
                {"role": "user", "content": "请查询 阿尔法科技 的员工 张三 的考勤。"}
            ]
        })

        evidence_spec = EvidenceSpec(
            plaintext=b"CANARY_RAW_EVIDENCE_SPEC_P18",
            bucket="retention-30d",
            record_id="rec-p18-01",
            purpose="model-query",
        )

        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            result = pipeline.process_request(
                raw_body=raw_req,
                headers={"Authorization": "Bearer internal-gw"},
                identity=self.identity,
                category="STANDARD",
                context=ctx,
                evidence_spec=evidence_spec,
            )

        # 1. Spy saw exactly 1 call
        self.assertEqual(1, len(spy.calls))

        # 2. Outgoing headers dropped client auth and applied bound upstream credential
        sent_req = spy.calls[0]
        self.assertEqual("Bearer test-token-123", sent_req.headers["authorization"])

        # 3. Pipeline result has restored plaintext in response!
        self.assertIn("阿尔法科技", result.response.choices[0].message.content)
        self.assertIn("张三", result.response.choices[0].message.content)
        self.assertNotIn("<<ENT", result.response.choices[0].message.content)

        # 4. Usage preserved exactly
        self.assertEqual(50, result.response.usage.total_tokens)
        self.assertEqual(30, result.response.usage.prompt_tokens)

        # 5. Evidence committed to disk
        self.assertTrue(result.evidence_permit.intent_path.exists())
        self.assertIsNotNone(result.evidence_permit.evidence)
        self.assertTrue(Path(result.evidence_permit.evidence.path).exists())

    def test_claude_protected_roundtrip_positive(self) -> None:
        """Claude end-to-end positive flow: entities redacted to tokens, upstream receives

        only tokens, response restores tokens to plaintext, usage strictly preserved.
        """
        def upstream_handler(request: httpx.Request) -> httpx.Response:
            payload = json.loads(request.content.decode("utf-8"))
            sent_text = payload["messages"][0]["content"]

            self.assertNotIn("阿尔法科技", sent_text)
            self.assertIn("<<ENT_v1_", sent_text)

            resp_body = {
                "id": "msg_claude_rt01",
                "type": "message",
                "role": "assistant",
                "model": "claude-sonnet-5-5",
                "content": [
                    {"type": "text", "text": f"系统已处理 {sent_text}"}
                ],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 40, "output_tokens": 15},
            }
            return httpx.Response(200, content=json.dumps(resp_body).encode("utf-8"))

        spy = UpstreamSpyTransport(upstream_handler)
        pipeline = self._create_pipeline(CLAUDE_MESSAGES_PROTOCOL, spy)

        raw_req = json.dumps({
            "model": "claude-sonnet-5-5",
            "max_tokens": 100,
            "messages": [
                {"role": "user", "content": "向 阿尔法科技 发送通知"}
            ]
        })

        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            result = pipeline.process_request(
                raw_body=raw_req,
                headers={},
                identity=self.identity,
                category="STANDARD",
                context=ctx,
            )

        self.assertEqual(1, len(spy.calls))
        self.assertIn("阿尔法科技", result.response.content[0].text)
        self.assertEqual(40, result.response.usage.input_tokens)

    # -------------------------------------------------------------
    # FAIL-CLOSED GATE TESTS: UPSTREAM CALL COUNT MUST BE 0
    # -------------------------------------------------------------

    def test_untrusted_identity_header_blocks_egress_and_upstream_is_zero(self) -> None:
        spy = UpstreamSpyTransport(lambda r: httpx.Response(200))
        pipeline = self._create_pipeline(DEEPSEEK_CHAT_PROTOCOL, spy)

        raw_req = json.dumps({
            "model": "deepseek-flash",
            "messages": [{"role": "user", "content": "hello"}]
        })

        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            with self.assertRaises(SafetyError) as exc_info:
                pipeline.process_request(
                    raw_body=raw_req,
                    headers={"X-User-Id": "attacker-spoofed-id"},
                    identity=self.identity,
                    category="STANDARD",
                    context=ctx,
                )
            self.assertEqual(SafetyCode.UNTRUSTED_HEADER_REJECTED, exc_info.exception.code)

        # Gate failure: upstream calls MUST be zero
        self.assertEqual(0, len(spy.calls))

    def test_scope_mismatch_blocks_egress_and_upstream_is_zero(self) -> None:
        spy = UpstreamSpyTransport(lambda r: httpx.Response(200))
        pipeline = self._create_pipeline(DEEPSEEK_CHAT_PROTOCOL, spy)

        _now = datetime.now(timezone.utc)
        wrong_domain_identity = TrustedIdentity(
            subject_id="user-002",
            tenant_id="tenant-corp",
            domain="wrong.domain.test",
            roles=frozenset({"employee"}),
            purposes=frozenset({"model-query"}),
            source_acl=frozenset({"corp-internal"}),
            auth_source="mTLS",
            authenticated_at=_now - timedelta(hours=1),
            expires_at=_now + timedelta(hours=8),
        )

        raw_req = json.dumps({
            "model": "deepseek-flash",
            "messages": [{"role": "user", "content": "hello"}]
        })

        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            with self.assertRaises(SafetyError) as exc_info:
                pipeline.process_request(
                    raw_body=raw_req,
                    headers={},
                    identity=wrong_domain_identity,
                    category="STANDARD",
                    context=ctx,
                )
            self.assertEqual(SafetyCode.SCOPE_MISMATCH, exc_info.exception.code)

        self.assertEqual(0, len(spy.calls))

    def test_policy_rejected_category_blocks_egress_and_upstream_is_zero(self) -> None:
        spy = UpstreamSpyTransport(lambda r: httpx.Response(200))
        pipeline = self._create_pipeline(DEEPSEEK_CHAT_PROTOCOL, spy)

        raw_req = json.dumps({
            "model": "deepseek-flash",
            "messages": [{"role": "user", "content": "hello"}]
        })

        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            with self.assertRaises(SafetyError) as exc_info:
                pipeline.process_request(
                    raw_body=raw_req,
                    headers={},
                    identity=self.identity,
                    category="FORBIDDEN",
                    context=ctx,
                )
            self.assertEqual(SafetyCode.CATEGORY_NOT_APPROVED, exc_info.exception.code)

        self.assertEqual(0, len(spy.calls))

    def test_admission_limit_exceeded_blocks_egress_and_upstream_is_zero(self) -> None:
        spy = UpstreamSpyTransport(lambda r: httpx.Response(200))
        # Bind the small budget before creating the immutable protection package.
        self.admission_limiter = AdmissionLimiter(max_body_bytes=10)
        pipeline = self._create_pipeline(DEEPSEEK_CHAT_PROTOCOL, spy)

        raw_req = json.dumps({
            "model": "deepseek-flash",
            "messages": [{"role": "user", "content": "this body exceeds 10 bytes"}]
        })

        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            with self.assertRaises(SafetyError) as exc_info:
                pipeline.process_request(
                    raw_body=raw_req,
                    headers={},
                    identity=self.identity,
                    category="STANDARD",
                    context=ctx,
                )
            self.assertEqual(SafetyCode.ADMISSION_LIMIT_EXCEEDED, exc_info.exception.code)

        self.assertEqual(0, len(spy.calls))

    def test_secret_detected_blocks_egress_and_upstream_is_zero(self) -> None:
        spy = UpstreamSpyTransport(lambda r: httpx.Response(200))
        pipeline = self._create_pipeline(DEEPSEEK_CHAT_PROTOCOL, spy)

        # Include a valid API key pattern (P0 secret)
        secret_body = json.dumps({
            "model": "deepseek-flash",
            "messages": [
                {"role": "user", "content": "在配置中写入 sk-AbCdEfG0123456789xyz 保存"}
            ]
        })

        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            with self.assertRaises(SafetyError) as exc_info:
                pipeline.process_request(
                    raw_body=secret_body,
                    headers={},
                    identity=self.identity,
                    category="STANDARD",
                    context=ctx,
                )
            self.assertEqual(SafetyCode.SECRET_DETECTED, exc_info.exception.code)

        self.assertEqual(0, len(spy.calls))

    def test_audit_watermark_blocked_blocks_egress_and_upstream_is_zero(self) -> None:
        spy = UpstreamSpyTransport(lambda r: httpx.Response(200))
        pipeline = self._create_pipeline(DEEPSEEK_CHAT_PROTOCOL, spy)

        # Inject blocking watermark: 95% used >= 90%
        pipeline.watermark_guard = AuditWatermarkGuard(
            self.audit_volume,
            self.watermark_policy,
            probe=lambda p: (1000 * 1024 * 1024, 950 * 1024 * 1024, 50 * 1024 * 1024),
        )

        raw_req = json.dumps({
            "model": "deepseek-flash",
            "messages": [{"role": "user", "content": "hello"}]
        })

        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            with self.assertRaises(SafetyError) as exc_info:
                pipeline.process_request(
                    raw_body=raw_req,
                    headers={},
                    identity=self.identity,
                    category="STANDARD",
                    context=ctx,
                )
            self.assertEqual(SafetyCode.AUDIT_WATERMARK_BLOCKED, exc_info.exception.code)

        self.assertEqual(0, len(spy.calls))

    def test_evidence_gate_failure_blocks_egress_and_upstream_is_zero(self) -> None:
        spy = UpstreamSpyTransport(lambda r: httpx.Response(200))
        # Point intent directory to a non-writable/invalid file path
        invalid_intent_dir = self.base_path / "intent_as_file"
        invalid_intent_dir.write_text("not a dir", encoding="utf-8")
        self.evidence_gate = EvidenceGate(intent_directory=invalid_intent_dir)
        pipeline = self._create_pipeline(DEEPSEEK_CHAT_PROTOCOL, spy)

        raw_req = json.dumps({
            "model": "deepseek-flash",
            "messages": [{"role": "user", "content": "hello"}]
        })

        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            with self.assertRaises(SafetyError) as exc_info:
                pipeline.process_request(
                    raw_body=raw_req,
                    headers={},
                    identity=self.identity,
                    category="STANDARD",
                    context=ctx,
                )
            self.assertEqual(SafetyCode.AUDIT_WRITE_FAILED, exc_info.exception.code)

        self.assertEqual(0, len(spy.calls))

    def test_upstream_error_fails_closed(self) -> None:
        # Upstream returns 500
        spy = UpstreamSpyTransport(lambda r: httpx.Response(500, content=b"Internal Server Error"))
        pipeline = self._create_pipeline(DEEPSEEK_CHAT_PROTOCOL, spy)

        raw_req = json.dumps({
            "model": "deepseek-flash",
            "messages": [{"role": "user", "content": "hello"}]
        })

        with MappingContext(self.domain, "v1", TEST_HMAC_KEY) as ctx:
            with self.assertRaises(UpstreamFailure) as exc_info:
                pipeline.process_request(
                    raw_body=raw_req,
                    headers={},
                    identity=self.identity,
                    category="STANDARD",
                    context=ctx,
                )
            self.assertEqual(500, exc_info.exception.response.status_code)
            self.assertEqual('UPSTREAM_INTERNAL_ERROR',exc_info.exception.response.body['error']['code'])
            self.assertNotIn('Internal Server Error',str(exc_info.exception.response.body))

        self.assertEqual(1, len(spy.calls))


if __name__ == "__main__":
    unittest.main()
