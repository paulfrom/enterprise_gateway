"""Synthetic BYOK HTTP and real PostgreSQL restricted sedimentation.

This fixture proves protection, encrypted observations, idempotent candidates and
restart reads. Source ownership remains unassigned; publication and unauthorized
reads are rejected. It does not verify WorkBuddy desktop or real suppliers.
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
from gateway.provider_router import ProviderRouter
from infra.egress_client import BoundEgressClient, BoundUpstream
from infra.envelope_crypto import StaticTestKmsProvider
from infra.spool import CollectionMode, SpoolWriter
from infra.envelope_crypto import parse_record, decrypt_record
from infra.spool_relay import compute_dedup_key
from knowledge.knowledge_events import ObservationEvent
from knowledge.worker import KnowledgeWorker, PostgresKnowledgeSink, GovernedConsumer
from tests.pg_support import get_test_dsn, prepare_test_database
from knowledge.governance import AdminActionContext, GovernanceError, KnowledgeGovernanceService
from knowledge.knowledge import (
    CandidateState,
    KnowledgeError,
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
from protocol.identity import ByokAuthenticator
from protocol.protocols import CLAUDE_MESSAGES_PROTOCOL, DEEPSEEK_CHAT_PROTOCOL

NER_PACKAGE = Path(__file__).resolve().parents[2] / "models" / "bert4ner-base-chinese-onnx"


class TestWorkBuddySyntheticRoundtrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        prepare_test_database()
        cls.storage = PostgresKnowledgeStorage(get_test_dsn())

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
            ner_package_dir=NER_PACKAGE,
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


    def tearDown(self) -> None:
        self.executor.close()
        self.temp_dir.cleanup()

    def test_workbuddy_full_dialogue_redaction_and_knowledge_sedimentation(self) -> None:
        """Controlled dialogue becomes persistent restricted candidates without inferred ownership."""
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

            # Security assertion: only this request's caller BYOK reaches the bound supplier
            self.assertEqual("Bearer synthetic-ds-client-key", req.headers.get("authorization"))
            self.assertNotIn("x-api-key", req.headers)

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

            # Security assertion: native Claude BYOK is sent without duplicate authorization
            self.assertNotIn("authorization", req.headers)
            self.assertEqual("synthetic-claude-client-key", req.headers.get("x-api-key"))
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

                credential_header="x-api-key",
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
            allowed_models=frozenset({'deepseek-flash'}),
            path="/v1/chat/completions",
            policy=self.policy,
            detector=self.detector,
            admission_limiter=AdmissionLimiter(max_body_bytes=65536),
            watermark_guard=self.watermark_guard,
            evidence_gate=self.evidence_gate,
            egress_client=ds_client,
            spool_writer=self.spool_writer,
            evidence_bucket="synthetic-retention",
        )

        claude_pipeline = ProtectedPipeline(
            channel_id="chan-claude-main",
            domain=self.domain,
            protocol=CLAUDE_MESSAGES_PROTOCOL,
            package_version="pkg-wb-1.0",
            allowed_models=frozenset({'claude-sonnet-5-5'}),
            path="/v1/messages",
            policy=self.policy,
            detector=self.detector,
            admission_limiter=AdmissionLimiter(max_body_bytes=65536),
            watermark_guard=self.watermark_guard,
            evidence_gate=self.evidence_gate,
            egress_client=claude_client,
            spool_writer=self.spool_writer,
            evidence_bucket="synthetic-retention",
        )

        # ---------------------------------------------------------------------
        # 2. Mount Gateway Application and Test Client
        # ---------------------------------------------------------------------
        hmac_key = b"workbuddy-test-hmac-key-32bytes-synthetic!"
        app = create_app(
            router=ProviderRouter({"deepseek-flash": deepseek_pipeline, "claude-sonnet-5-5": claude_pipeline}),
            authenticator=ByokAuthenticator(domain=self.domain, tenant_id="restricted-ingress", correlation_key=hmac_key),
            classifier=lambda raw: "STANDARD",
            hmac_key=hmac_key,
        )
        client = TestClient(app)

        # ---------------------------------------------------------------------
        # 3. WorkBuddy Round 1: DeepSeek Chat Completion Call
        # ---------------------------------------------------------------------
        prompt_1 = "采购记录显示：甲公司向乙公司采购五台智能质检设备。请核对联系人张三的电话 13800138000。"
        resp1 = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer synthetic-ds-client-key"},
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
            headers={"x-api-key": "synthetic-claude-client-key"},
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

        # 6. Real worker input is the encrypted spool generated by HTTP.
        import psycopg
        events = [ObservationEvent.model_validate_json(decrypt_record(self.kms,parse_record(p.read_bytes())))
                  for p in spool_files]
        event = next(e for e in events if e.evidence_text == prompt_1)
        self.assertEqual("unverified", event.source_provenance)
        self.assertEqual("unassigned", event.ownership_status)
        self.assertEqual(frozenset({f"{self.domain}:restricted-candidate"}), event.acl)
        self.assertFalse(event.source_independence_verified)
        self.assertGreater(event.retention_until, event.observed_at)
        purpose = frozenset({event.purpose})
        def actor(name,*roles):
            return TrustedActor(name,event.tenant,self.domain,frozenset(roles),purpose)
        processing_actor = actor('synthetic-processing-service', Role.KNOWLEDGE_PROCESSOR)
        processing_acl = (f'{self.domain}:restricted-candidate',)
        worker = KnowledgeWorker(self.spool_dir,self.kms,PostgresKnowledgeSink(self.storage,processing_actor,self.kms,processing_acl=processing_acl))
        self.assertEqual(2,worker.run_once().submitted)
        self.assertEqual([],list(self.spool_dir.glob('*.env.json')))
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,processing_actor,processing_acl=processing_acl)
            ids = conn.execute('SELECT candidate_ids FROM knowledge_observations WHERE dedup_key=%s',
                               (compute_dedup_key(event),)).fetchone()[0]
            candidates = [self.storage.load_candidate(conn,cid) for cid in ids]
        cand = next(c for c in candidates if c.claim.predicate == Predicate.SUPPLIES)
        self.assertEqual('乙公司',cand.claim.subject.name)
        self.assertEqual('甲公司',cand.claim.object.name)
        self.assertEqual(0,cand.independent_source_count)
        self.assertEqual(CandidateState.PROPOSED, cand.state)
        self.assertEqual(frozenset({f'{self.domain}:restricted-candidate'}), cand.acl)
        self.assertEqual(0, worker.run_once().submitted)
        # A new storage instance reads the same persisted restricted candidate.
        restarted_storage = PostgresKnowledgeStorage(get_test_dsn())
        with psycopg.connect(get_test_dsn()) as conn:
            restarted_storage.set_session_identity(conn, processing_actor, processing_acl=processing_acl)
            restored = restarted_storage.load_candidate(conn, cand.candidate_id)
            self.assertEqual(cand, restored)
        now = datetime.now(timezone.utc)
        governance = KnowledgeGovernanceService(tenant_id=event.tenant, domain=self.domain,
                                                storage=restarted_storage)
        # Governance actions without a configured admin connection refuse with the
        # fixed capability code instead of falling back to memory or old two-person flow.
        with self.assertRaises(GovernanceError) as rejected:
            governance.reject_candidate(str(cand.candidate_id), basis='synthetic/rejection',
                                        context=AdminActionContext(
                                            actor_id='admin', session_digest=sha256(b'session').hexdigest(),
                                            tenant_id=event.tenant, domain=self.domain))
        self.assertEqual('KNOWLEDGE_ADMIN_UNAVAILABLE', rejected.exception.code)
        with self.assertRaises(GovernanceError) as rejected:
            governance.publish_candidate(str(cand.candidate_id), expected_version=1, use='knowledge',
                                         audiences=('reader',), valid_until=now + timedelta(days=1),
                                         idempotency_key=None, basis='synthetic/publish',
                                         context=AdminActionContext(
                                             actor_id='admin', session_digest=sha256(b'session').hexdigest(),
                                             tenant_id=event.tenant, domain=self.domain))
        self.assertEqual('KNOWLEDGE_ADMIN_UNAVAILABLE', rejected.exception.code)
        with psycopg.connect(get_test_dsn()) as conn:
            restarted_storage.set_session_identity(conn, actor('reader'))
            with self.assertRaises(KnowledgeError):
                restarted_storage.load_candidate(conn, cand.candidate_id)
        client.close()
        ds_client.close()
        claude_client.close()


if __name__ == "__main__":
    unittest.main()
