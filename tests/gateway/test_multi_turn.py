"""Tests for P-15 multi-turn conversation processing and historical re-detection."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest

import httpx

from audit.audit_watermark import AuditWatermarkGuard, WatermarkPolicy
from audit.evidence_gate import EvidenceGate
from detection.detection_orchestrator import DetectionOrchestrator, default_recognizers
from detection.dictionary import DictionaryEntry, compile_dictionary, compute_dictionary_hash
from gateway.multi_turn import MultiTurnConversationSession
from gateway.pipeline import ProtectedPipeline
from infra.egress_client import BoundEgressClient, BoundUpstream
from infra.envelope_crypto import StaticTestKmsProvider
from infra.errors import SafetyCode, SafetyError
from detection.inference_executor import InferenceExecutor
from infra.spool import SpoolWriter
from policy.policy import CategoryLabel, CategoryRule, ClassificationPolicy
from protocol.admission import AdmissionLimiter
from protocol.identity import TrustedIdentity
from protocol.protocols import DEEPSEEK_CHAT_PROTOCOL

MINI_PACKAGE = Path(__file__).resolve().parent.parent / "detection" / "fixtures" / "ner" / "mini-valid-package"


class TestMultiTurnConversation(unittest.TestCase):
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
            ),
        )

        # Dictionary with known entities
        entries = (
            DictionaryEntry(text="阿尔法科技", entity_type="ORG"),
            DictionaryEntry(text="张三", entity_type="PER"),
            DictionaryEntry(text="李四", entity_type="PER"),
        )
        payload = {
            "dictionary_id": "dict-multiturn",
            "version": "v1",
            "domain": self.domain,
            "entries": [{"text": e.text, "entity_type": e.entity_type} for e in entries],
            "sha256": compute_dictionary_hash("dict-multiturn", "v1", self.domain, entries),
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

        self.watermark_guard = AuditWatermarkGuard(
            self.audit_volume,
            WatermarkPolicy(0.90, 0.80, 1024),
            probe=lambda p: (1000 * 1024 * 1024, 100 * 1024 * 1024, 900 * 1024 * 1024),
        )
        self.evidence_gate = EvidenceGate(
            intent_directory=self.intent_dir,
            evidence_directory=self.evidence_dir,
            kms=self.kms,
        )
        self.spool_writer = SpoolWriter(directory=self.spool_dir, kms=self.kms)

        now = datetime.now(timezone.utc)
        self.identity = TrustedIdentity(
            subject_id="agent-001",
            tenant_id="tenant-corp",
            domain=self.domain,
            roles=frozenset({"employee"}),
            purposes=frozenset({"model-query"}),
            source_acl=frozenset({"corp-internal"}),
            auth_source="mTLS",
            authenticated_at=now - timedelta(hours=1),
            expires_at=now + timedelta(hours=8),
        )

    def tearDown(self) -> None:
        self.executor.close()
        self.temp_dir.cleanup()

    def test_p15_five_turn_conversation_redaction_and_restoration(self) -> None:
        """P-15: 5-turn conversation verifies complete redaction and zero upstream leaks across all turns."""
        upstream_requests: list[dict] = []

        def spy_handler(req: httpx.Request) -> httpx.Response:
            payload = json.loads(req.content.decode("utf-8"))
            upstream_requests.append(payload)
            last_msg = payload["messages"][-1]["content"]

            # Security assertion: Plaintext must never reach upstream in ANY turn!
            self.assertNotIn("阿尔法科技", req.content.decode("utf-8"))
            self.assertNotIn("张三", req.content.decode("utf-8"))
            self.assertNotIn("李四", req.content.decode("utf-8"))

            resp_body = {
                "id": f"chatcmpl-turn-{len(upstream_requests)}",
                "object": "chat.completion",
                "created": 1727950000,
                "model": "deepseek-flash",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": f"收到，关于 {last_msg} 的处理已完成。",
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70},
            }
            return httpx.Response(200, content=json.dumps(resp_body).encode("utf-8"))

        transport = httpx.MockTransport(spy_handler)
        bound = BoundUpstream(
            channel_id="chan-turn",
            scheme="http",
            host="127.0.0.1",
            port=8080,
            path_prefix="/v1",

            timeout_seconds=5.0,
            allowed_addresses=frozenset({"127.0.0.1"}),
        )
        client = BoundEgressClient(binding=bound, transport=transport, resolver=lambda h: ("127.0.0.1",))

        pipeline = ProtectedPipeline(
            allowed_models=frozenset({"deepseek-flash"}),
            channel_id="chan-turn",
            domain=self.domain,
            protocol=DEEPSEEK_CHAT_PROTOCOL,
            package_version="pkg-v1.0",
            path="/v1/chat/completions",
            policy=self.policy,
            detector=self.detector,
            admission_limiter=AdmissionLimiter(max_body_bytes=65536),
            watermark_guard=self.watermark_guard,
            evidence_gate=self.evidence_gate,
            egress_client=client,
            spool_writer=self.spool_writer,
            evidence_bucket="synthetic-retention",
        )

        session = MultiTurnConversationSession(pipeline, self.identity)

        # Turn 1
        key1 = b"turn-1-hmac-key-32bytes-secret!!"
        rep1 = session.execute_turn("请查询 阿尔法科技 的员工 张三 的基本信息。", "STANDARD", key1,model="deepseek-flash", headers={"Authorization": "Bearer synthetic-turn-key"})
        self.assertIn("阿尔法科技", rep1)
        self.assertIn("张三", rep1)

        # Turn 2
        key2 = b"turn-2-hmac-key-32bytes-secret!!"
        rep2 = session.execute_turn("再查询他的同事 李四 的信息。", "STANDARD", key2,model="deepseek-flash", headers={"Authorization": "Bearer synthetic-turn-key"})
        self.assertIn("李四", rep2)

        # Turn 3
        key3 = b"turn-3-hmac-key-32bytes-secret!!"
        rep3 = session.execute_turn("对比 张三 和 李四 的考勤记录。", "STANDARD", key3,model="deepseek-flash", headers={"Authorization": "Bearer synthetic-turn-key"})
        self.assertIn("张三", rep3)
        self.assertIn("李四", rep3)

        # Turn 4
        key4 = b"turn-4-hmac-key-32bytes-secret!!"
        rep4 = session.execute_turn("总结 阿尔法科技 这两位员工的表现。", "STANDARD", key4,model="deepseek-flash", headers={"Authorization": "Bearer synthetic-turn-key"})
        self.assertIn("阿尔法科技", rep4)

        # Turn 5
        key5 = b"turn-5-hmac-key-32bytes-secret!!"
        rep5 = session.execute_turn("将报告发送给 张三 确认。", "STANDARD", key5,model="deepseek-flash", headers={"Authorization": "Bearer synthetic-turn-key"})
        self.assertIn("张三", rep5)

        # Verify 5 turns executed
        self.assertEqual(5, len(upstream_requests))
        # Turn 5 history contains 5 user turns and 4 assistant turns = 9 messages
        self.assertEqual(9, len(upstream_requests[4]["messages"]))

    def test_p15_client_smuggled_token_fails_closed(self) -> None:
        """P-15: Client attempting to inject reserved token literal in history is blocked (P-03)."""
        transport = httpx.MockTransport(lambda r: httpx.Response(200))
        bound = BoundUpstream(
            channel_id="chan-turn",
            scheme="http",
            host="127.0.0.1",
            port=8080,
            path_prefix="/v1",

            timeout_seconds=5.0,
            allowed_addresses=frozenset({"127.0.0.1"}),
        )
        client = BoundEgressClient(binding=bound, transport=transport, resolver=lambda h: ("127.0.0.1",))
        pipeline = ProtectedPipeline(
            allowed_models=frozenset({"deepseek-flash"}),
            channel_id="chan-turn",
            domain=self.domain,
            protocol=DEEPSEEK_CHAT_PROTOCOL,
            package_version="pkg-v1.0",
            path="/v1/chat/completions",
            policy=self.policy,
            detector=self.detector,
            admission_limiter=AdmissionLimiter(max_body_bytes=65536),
            watermark_guard=self.watermark_guard,
            evidence_gate=self.evidence_gate,
            egress_client=client,
            spool_writer=self.spool_writer,
            evidence_bucket="synthetic-retention",
        )

        session = MultiTurnConversationSession(pipeline, self.identity)
        key = b"turn-bad-hmac-key-32bytes-secret"

        # Inject reserved token prefix directly in user input
        with self.assertRaises(SafetyError) as exc_info:
            session.execute_turn("这是上次的令牌 <<ENT_v1_fake>> 请继续", "STANDARD", key,model="deepseek-flash", headers={"Authorization": "Bearer synthetic-turn-key"})
        self.assertEqual(SafetyCode.RESERVED_TOKEN_LITERAL, exc_info.exception.code)


if __name__ == "__main__":
    unittest.main()
