"""WorkBuddy Synthetic Dialogue & Automatic Knowledge Sedimentation Verification Suite.

Validates the full front-gateway architecture:
WorkBuddy/Agent -> Enterprise Authenticated Gateway -> Upstream Provider (New API / Direct Provider)
with:
1. Agent only configured with Gateway address & enterprise credentials;
   Upstream credentials injected server-side; caller credentials stripped.
2. Dual-protocol support (/v1/chat/completions for DeepSeek, /v1/messages for Claude).
3. Zero upstream leaks of sensitive entities (names, phone numbers, companies).
4. Plaintext preserved and restored for the Agent upon response.
5. Automatic knowledge observation event generation and encrypted spooling.
6. Offline extraction and relational sedimentation into live PostgreSQL database.
7. Governance review, transactional outbox publishing, and dictionary compilation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

import httpx
from starlette.testclient import TestClient

from audit.audit_watermark import AuditWatermarkGuard, WatermarkPolicy
from audit.evidence_gate import EvidenceGate
from detection.detection_orchestrator import DetectionOrchestrator, default_recognizers
from detection.dictionary import DictionaryEntry, analyze_dictionary, compile_dictionary, compute_dictionary_hash
from detection.inference_executor import InferenceExecutor
from gateway.app import create_app
from gateway.pipeline import ProtectedPipeline
from infra.egress_client import BoundEgressClient, BoundUpstream
from infra.envelope_crypto import StaticTestKmsProvider
from infra.spool import CollectionMode, SpoolWriter
from knowledge.extractor import RelationExtractor
from knowledge.governance import KnowledgeGovernanceService
from knowledge.knowledge import (
    CandidateState,
    Entity,
    Modality,
    Polarity,
    Predicate,
    Publication,
    Role,
    Source,
    SourceKind,
    TrustedActor,
)
from knowledge.storage import PostgresKnowledgeStorage
from policy.policy import CategoryLabel, CategoryRule, ClassificationPolicy
from protocol.admission import AdmissionLimiter
from protocol.identity import TrustedIdentity
from protocol.protocols import CLAUDE_MESSAGES_PROTOCOL, DEEPSEEK_CHAT_PROTOCOL

MINI_PACKAGE = Path(__file__).resolve().parent.parent / "detection" / "fixtures" / "ner" / "mini-valid-package"
LIVE_PG_URI = "postgresql://paul:lslin%4032@42.193.11.211:5432/enter_gateway"


class TestWorkBuddySyntheticRoundtrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.storage = PostgresKnowledgeStorage(LIVE_PG_URI)
        cls.storage.init_database(enable_rls=True)

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
        self.domain = f"wb-test-{uuid4().hex[:8]}"

        self.policy = ClassificationPolicy(
            version="2026-10-04",
            rules=(
                CategoryRule(category="STANDARD", label=CategoryLabel.APPROVED_EXTERNAL, scope=self.domain),
            ),
        )

        entries = (
            DictionaryEntry(text="甲公司", entity_type="ORG"),
            DictionaryEntry(text="乙公司", entity_type="ORG"),
            DictionaryEntry(text="阿尔法科技", entity_type="ORG"),
            DictionaryEntry(text="张三", entity_type="PER"),
            DictionaryEntry(text="李四", entity_type="PER"),
        )
        dict_payload = {
            "dictionary_id": "dict-workbuddy",
            "version": "v1",
            "domain": self.domain,
            "entries": [{"text": e.text, "entity_type": e.entity_type} for e in entries],
            "sha256": compute_dictionary_hash("dict-workbuddy", "v1", self.domain, entries),
        }
        self.compiled_dict = compile_dictionary(dict_payload)

        self.executor = InferenceExecutor(max_workers=2)
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
        self.agent_identity = TrustedIdentity(
            subject_id="workbuddy-agent-001",
            tenant_id="tenant-corp",
            domain=self.domain,
            roles=frozenset({"employee", "ai-assistant"}),
            purposes=frozenset({"model-query"}),
            source_acl=frozenset({f"{self.domain}:general-staff"}),
            auth_source="enterprise-iam",
            authenticated_at=now - timedelta(hours=1),
            expires_at=now + timedelta(hours=8),
        )

    def tearDown(self) -> None:
        self.executor.close()
        self.temp_dir.cleanup()

    def test_workbuddy_full_dialogue_redaction_and_knowledge_sedimentation(self) -> None:
        """Full end-to-end WorkBuddy dialogue verification and automatic knowledge sedimentation."""
        intercepted_deepseek_reqs: list[httpx.Request] = []
        intercepted_claude_reqs: list[httpx.Request] = []

        # ---------------------------------------------------------------------
        # 1. Setup Egress Mocks for DeepSeek and Claude Providers
        # ---------------------------------------------------------------------
        def deepseek_upstream(req: httpx.Request) -> httpx.Response:
            intercepted_deepseek_reqs.append(req)
            body_str = req.content.decode("utf-8")
            payload = json.loads(body_str)
            user_msg = payload["messages"][0]["content"]

            # Security assertion: upstream NEVER sees plaintext sensitive values!
            self.assertNotIn("甲公司", body_str)
            self.assertNotIn("乙公司", body_str)
            self.assertNotIn("张三", body_str)
            self.assertNotIn("13800138000", body_str)

            # Security assertion: caller authorization stripped, upstream credential injected
            self.assertNotIn("agent-corp-token", req.headers.get("authorization", ""))
            self.assertEqual("Bearer sk-deepseek-upstream-secret", req.headers.get("authorization"))

            resp_body = {
                "id": "chatcmpl-wb-001",
                "object": "chat.completion",
                "created": 1727950000,
                "model": "deepseek-flash",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": f"已经为您核实：{user_msg}，合同处于正常履行状态，质检设备已如期发货。",
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 45, "completion_tokens": 30, "total_tokens": 75},
            }
            return httpx.Response(200, content=json.dumps(resp_body).encode("utf-8"))

        def claude_upstream(req: httpx.Request) -> httpx.Response:
            intercepted_claude_reqs.append(req)
            body_str = req.content.decode("utf-8")
            payload = json.loads(body_str)
            user_msg = payload["messages"][0]["content"]

            # Security assertion: upstream NEVER sees plaintext sensitive values!
            self.assertNotIn("阿尔法科技", body_str)
            self.assertNotIn("李四", body_str)

            # Security assertion: caller auth stripped, Claude upstream header injected
            self.assertNotIn("agent-corp-token", req.headers.get("authorization", ""))
            self.assertEqual("sk-ant-claude-upstream-secret", req.headers.get("x-api-key"))
            self.assertEqual("2023-06-01", req.headers.get("anthropic-version"))

            resp_body = {
                "id": "msg_wb_002",
                "type": "message",
                "role": "assistant",
                "model": "claude-sonnet-5-5",
                "content": [{"type": "text", "text": f"好的，发票确认函已生成，已向 {user_msg} 发送完毕。"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 35, "output_tokens": 25},
            }
            return httpx.Response(200, content=json.dumps(resp_body).encode("utf-8"))

        ds_client = BoundEgressClient(
            binding=BoundUpstream(
                channel_id="chan-deepseek-main",
                scheme="http",
                host="127.0.0.1",
                port=8080,
                path_prefix="/v1",
                credential="Bearer sk-deepseek-upstream-secret",
                timeout_seconds=5.0,
                allowed_addresses=frozenset({"127.0.0.1"}),
            ),
            transport=httpx.MockTransport(deepseek_upstream),
            resolver=lambda h: ("127.0.0.1",),
        )

        claude_client = BoundEgressClient(
            binding=BoundUpstream(
                channel_id="chan-claude-main",
                scheme="http",
                host="127.0.0.1",
                port=8080,
                path_prefix="/v1",
                credential="sk-ant-claude-upstream-secret",
                timeout_seconds=5.0,
                allowed_addresses=frozenset({"127.0.0.1"}),
            ),
            transport=httpx.MockTransport(claude_upstream),
            resolver=lambda h: ("127.0.0.1",),
        )

        deepseek_pipeline = ProtectedPipeline(
            channel_id="chan-deepseek-main",
            domain=self.domain,
            protocol=DEEPSEEK_CHAT_PROTOCOL,
            package_version="pkg-wb-1.0",
            path="/v1/chat/completions",
            policy=self.policy,
            detector=self.detector,
            admission_limiter=AdmissionLimiter(max_body_bytes=65536),
            watermark_guard=self.watermark_guard,
            evidence_gate=self.evidence_gate,
            egress_client=ds_client,
            spool_writer=self.spool_writer,
        )

        claude_pipeline = ProtectedPipeline(
            channel_id="chan-claude-main",
            domain=self.domain,
            protocol=CLAUDE_MESSAGES_PROTOCOL,
            package_version="pkg-wb-1.0",
            path="/v1/messages",
            policy=self.policy,
            detector=self.detector,
            admission_limiter=AdmissionLimiter(max_body_bytes=65536),
            watermark_guard=self.watermark_guard,
            evidence_gate=self.evidence_gate,
            egress_client=claude_client,
            spool_writer=self.spool_writer,
        )

        # ---------------------------------------------------------------------
        # 2. Mount Gateway Application and Test Client
        # ---------------------------------------------------------------------
        hmac_key = b"workbuddy-test-hmac-key-32bytes!"
        app = create_app(
            deepseek_pipeline=deepseek_pipeline,
            claude_pipeline=claude_pipeline,
            trusted_identity=self.agent_identity,
            hmac_key=hmac_key,
        )
        client = TestClient(app)

        # ---------------------------------------------------------------------
        # 3. WorkBuddy Round 1: DeepSeek Chat Completion Call
        # ---------------------------------------------------------------------
        prompt_1 = "请查询甲公司向乙公司采购五台智能质检设备的履约进度，并核对联系人张三的电话 13800138000。"
        resp1 = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer agent-corp-token"},
            json={
                "model": "deepseek-flash",
                "messages": [{"role": "user", "content": prompt_1}],
            },
        )
        self.assertEqual(200, resp1.status_code)
        resp1_data = resp1.json()
        reply1_text = resp1_data["choices"][0]["message"]["content"]

        # Plaintext is faithfully restored to WorkBuddy!
        self.assertIn("甲公司", reply1_text)
        self.assertIn("乙公司", reply1_text)
        self.assertIn("张三", reply1_text)
        self.assertIn("13800138000", reply1_text)
        self.assertIn("质检设备已如期发货", reply1_text)

        # Upstream received 1 call
        self.assertEqual(1, len(intercepted_deepseek_reqs))

        # ---------------------------------------------------------------------
        # 4. WorkBuddy Round 2: Claude Messages Call
        # ---------------------------------------------------------------------
        prompt_2 = "向阿尔法科技的李四发送发票确认函。"
        resp2 = client.post(
            "/v1/messages",
            headers={"Authorization": "Bearer agent-corp-token"},
            json={
                "model": "claude-sonnet-5-5",
                "max_tokens": 200,
                "messages": [{"role": "user", "content": prompt_2}],
            },
        )
        self.assertEqual(200, resp2.status_code)
        resp2_data = resp2.json()
        reply2_text = resp2_data["content"][0]["text"]

        # Plaintext is faithfully restored to WorkBuddy!
        self.assertIn("阿尔法科技", reply2_text)
        self.assertIn("李四", reply2_text)
        self.assertIn("发票确认函已生成", reply2_text)

        # Upstream received 1 call
        self.assertEqual(1, len(intercepted_claude_reqs))

        # ---------------------------------------------------------------------
        # 5. Automatic Knowledge Observation Verification (Spool Queue)
        # ---------------------------------------------------------------------
        spool_files = list(self.spool_dir.glob("*.env.json"))
        # Both requests automatically generated and persisted encrypted observations
        self.assertEqual(2, len(spool_files))

        # ---------------------------------------------------------------------
        # 6. Offline Worker Knowledge Sedimentation to PostgreSQL (M2B)
        # ---------------------------------------------------------------------
        governance = KnowledgeGovernanceService(self.domain)
        extractor = RelationExtractor(self.domain)

        # Worker connects to real PostgreSQL
        import psycopg
        with psycopg.connect(LIVE_PG_URI) as db_conn:
            self.storage.set_session_domain(db_conn, self.domain)

            # Ingest Round 1 input
            now = datetime.now(timezone.utc)
            source_wb = Source(
                tenant_id="tenant-corp",
                domain=self.domain,
                source_id="workbuddy-session-001",
                version="v1",
                source_kind=SourceKind.USER_ASSERTION,
                acl=self.agent_identity.source_acl,
                purpose="enterprise-knowledge",
                observed_at=now,
                retention_until=now + timedelta(days=90),
            )
            self.storage.save_source(db_conn, source_wb)

            ent_jia = Entity(uuid4(), "tenant-corp", self.domain, "ORG", "甲公司")
            ent_yi = Entity(uuid4(), "tenant-corp", self.domain, "ORG", "乙公司")
            self.storage.save_entity(db_conn, ent_jia)
            self.storage.save_entity(db_conn, ent_yi)

            # Extract business relation: '甲公司向乙公司采购五台智能质检设备'
            candidates = extractor.extract_from_text(
                prompt_1, source_wb, [ent_jia, ent_yi], sha256(prompt_1.encode()).hexdigest()
            )
            self.assertEqual(1, len(candidates))
            cand = candidates[0]
            self.assertEqual("乙公司", cand.claim.subject.name)
            self.assertEqual(Predicate.SUPPLIES, cand.claim.predicate)
            self.assertEqual("甲公司", cand.claim.object.name)
            self.assertEqual(Polarity.POSITIVE, cand.claim.polarity)
            self.assertEqual(Modality.ASSERTED, cand.claim.modality)

            eid = self.storage.save_evidence(db_conn, cand.evidence[0])
            claim_id = self.storage.save_candidate(db_conn, cand, [eid])
            db_conn.commit()

            # Two-party review
            sec_rev = TrustedActor("sec-wb-01", "tenant-corp", self.domain, frozenset({Role.SECURITY_REVIEWER}), frozenset({"gov"}))
            biz_rev = TrustedActor("biz-wb-01", "tenant-corp", self.domain, frozenset({Role.BUSINESS_REVIEWER}), frozenset({"gov"}))
            publisher = TrustedActor("pub-wb-01", "tenant-corp", self.domain, frozenset({Role.PUBLISHER}), frozenset({"pub"}))

            c_sec = governance.approve_candidate(cand, sec_rev, Role.SECURITY_REVIEWER, "audit-sec", now)
            self.storage.save_approval(db_conn, cand.candidate_id, c_sec.approvals[0])

            c_biz = governance.approve_candidate(c_sec, biz_rev, Role.BUSINESS_REVIEWER, "audit-biz", now)
            self.storage.save_approval(db_conn, cand.candidate_id, c_biz.approvals[1])

            # Atomic publication & outbox
            pub, _ = governance.publish_candidate(c_biz, publisher, now + timedelta(days=180), now)
            self.storage.publish_transactional(db_conn, pub, claim_id)
            db_conn.commit()

            # Verify Outbox event
            pending = self.storage.fetch_pending_outbox(db_conn)
            self.assertTrue(any(p["aggregate_id"] == pub.publication_id for p in pending))

            # Compile into dictionary package for next version
            new_dict_payload = governance.compile_approved_dictionary_payload(
                "dict-wb-sedimented", "v2.0", [pub]
            )
            new_compiled_dict = compile_dictionary(new_dict_payload)
            self.assertEqual("dict-wb-sedimented", new_compiled_dict.dictionary_id)
            det = analyze_dictionary("核对甲公司与乙公司合同", new_compiled_dict)
            self.assertEqual(2, len(det.spans))


if __name__ == "__main__":
    unittest.main()
