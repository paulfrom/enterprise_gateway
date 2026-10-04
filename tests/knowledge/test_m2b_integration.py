"""K-10 End-to-end synthetic knowledge vertical slice integration suite.

Verifies the entire lifecycle against the live PostgreSQL database:
1. Gateway Observation event generated from input
2. Spool writing and encrypted persistence
3. Worker extraction of business relations (K-11)
4. Candidate persistence to PostgreSQL with FK integrity (K-04)
5. Two-party governance review & state machine (K-06)
6. Transactional outbox publication (K-12)
7. Versioned JSONL export with ACL access control (K-08)
8. Dictionary package compilation (K-09) and runtime dictionary usage
9. Revocation, tombstoning, and consumer receipt confirmation (K-13)
10. Row Level Security cross-domain isolation (K-14)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from uuid import UUID, uuid4

import psycopg

from detection.dictionary import analyze_dictionary, compile_dictionary
from infra.envelope_crypto import StaticTestKmsProvider
from infra.spool import CollectionMode, SpoolWriter
from knowledge.extractor import RelationExtractor
from knowledge.governance import KnowledgeGovernanceService
from knowledge.knowledge import (
    Approval,
    Candidate,
    CandidateState,
    Claim,
    Entity,
    Evidence,
    Modality,
    Polarity,
    Predicate,
    Publication,
    Role,
    Source,
    SourceKind,
    Tombstone,
    TrustedActor,
)
from knowledge.knowledge_events import build_gateway_observation
from knowledge.storage import PostgresKnowledgeStorage

LIVE_PG_URI = "postgresql://paul:lslin%4032@42.193.11.211:5432/enter_gateway"


class TestM2BKnowledgeIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.storage = PostgresKnowledgeStorage(LIVE_PG_URI)
        cls.storage.init_database(enable_rls=True)

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.spool_dir = Path(self.temp_dir.name) / "spool"
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        self.kms = StaticTestKmsProvider()

        self.test_domain = f"m2b-test-{uuid4().hex[:8]}"
        self.governance = KnowledgeGovernanceService(self.test_domain)
        self.extractor = RelationExtractor(self.test_domain)

        self.conn = psycopg.connect(LIVE_PG_URI)
        self.storage.set_session_domain(self.conn, self.test_domain)

        self.now = datetime.now(timezone.utc)

    def tearDown(self) -> None:
        self.conn.rollback()
        self.conn.close()
        self.temp_dir.cleanup()

    def test_k10_full_knowledge_lifecycle(self) -> None:
        """K-10: Complete end-to-end knowledge lifecycle with real PostgreSQL."""
        # ---------------------------------------------------------------------
        # Stage 1: Gateway Observation Event Generation & Spooling (K-01, K-02)
        # ---------------------------------------------------------------------
        request_id = f"req-{uuid4().hex[:12]}"
        prompt_text = "甲公司向乙公司采购设备五台，合同编号HT-2026-001。"
        prompt_digest = sha256(prompt_text.encode("utf-8")).hexdigest()

        obs_event = build_gateway_observation(
            tenant="tenant-corp",
            domain=self.test_domain,
            request_id=request_id,
            evidence_digest=prompt_digest,
            source_acl=[f"{self.test_domain}:procurement-team"],
            observed_at=self.now,
        )
        self.assertEqual(f"req:{request_id}", obs_event.source_id)
        self.assertEqual(prompt_digest, obs_event.evidence_ref.digest)

        # Write to encrypted spool
        spool_writer = SpoolWriter(directory=self.spool_dir, kms=self.kms)
        permit = spool_writer.collect(obs_event, mode=CollectionMode.REQUIRED)
        self.assertIsNotNone(permit)
        spool_files = list(self.spool_dir.glob("*.env.json"))
        self.assertEqual(1, len(spool_files))

        # ---------------------------------------------------------------------
        # Stage 2: Worker Extraction & Persistence to PostgreSQL (K-04, K-11)
        # ---------------------------------------------------------------------
        source = Source(
            tenant_id=obs_event.tenant,
            domain=obs_event.domain,
            source_id=obs_event.source_id,
            version=obs_event.source_version,
            source_kind=obs_event.source_kind,
            acl=obs_event.acl,
            purpose=obs_event.purpose,
            observed_at=obs_event.observed_at,
            retention_until=self.now + timedelta(days=90),
        )
        self.storage.save_source(self.conn, source)

        ent_jia = Entity(uuid4(), "tenant-corp", self.test_domain, "ORG", "甲公司")
        ent_yi = Entity(uuid4(), "tenant-corp", self.test_domain, "ORG", "乙公司")
        self.storage.save_entity(self.conn, ent_jia)
        self.storage.save_entity(self.conn, ent_yi)

        # Extract business relation candidates
        candidates = self.extractor.extract_from_text(
            prompt_text, source, [ent_jia, ent_yi], prompt_digest
        )
        self.assertEqual(1, len(candidates))
        candidate = candidates[0]
        self.assertEqual("乙公司", candidate.claim.subject.name)
        self.assertEqual(Predicate.SUPPLIES, candidate.claim.predicate)
        self.assertEqual("甲公司", candidate.claim.object.name)
        self.assertEqual(Polarity.POSITIVE, candidate.claim.polarity)
        self.assertEqual(Modality.ASSERTED, candidate.claim.modality)

        # Persist candidate and evidence to real PostgreSQL
        eid = self.storage.save_evidence(self.conn, candidate.evidence[0])
        claim_id = self.storage.save_candidate(self.conn, candidate, [eid])
        self.conn.commit()

        # ---------------------------------------------------------------------
        # Stage 3: Two-Reviewer Governance Workflow (K-06)
        # ---------------------------------------------------------------------
        sec_reviewer = TrustedActor(
            subject_id="sec-officer-01",
            tenant_id="tenant-corp",
            domain=self.test_domain,
            roles=frozenset({Role.SECURITY_REVIEWER}),
            purposes=frozenset({"knowledge-governance"}),
        )
        biz_reviewer = TrustedActor(
            subject_id="biz-officer-01",
            tenant_id="tenant-corp",
            domain=self.test_domain,
            roles=frozenset({Role.BUSINESS_REVIEWER}),
            purposes=frozenset({"knowledge-governance"}),
        )
        publisher = TrustedActor(
            subject_id="pub-officer-01",
            tenant_id="tenant-corp",
            domain=self.test_domain,
            roles=frozenset({Role.PUBLISHER}),
            purposes=frozenset({"knowledge-publishing"}),
        )

        c_sec = self.governance.approve_candidate(
            candidate, sec_reviewer, Role.SECURITY_REVIEWER, "audit/sec/001", self.now
        )
        self.storage.save_approval(self.conn, candidate.candidate_id, c_sec.approvals[0])
        self.assertEqual(CandidateState.PROPOSED, c_sec.state)

        c_biz = self.governance.approve_candidate(
            c_sec, biz_reviewer, Role.BUSINESS_REVIEWER, "audit/biz/001", self.now
        )
        self.storage.save_approval(self.conn, candidate.candidate_id, c_biz.approvals[1])
        self.assertEqual(CandidateState.APPROVED, c_biz.state)

        # ---------------------------------------------------------------------
        # Stage 4: Transactional Outbox Publishing (K-12)
        # ---------------------------------------------------------------------
        pub, _ = self.governance.publish_candidate(
            c_biz, publisher, self.now + timedelta(days=180), self.now
        )
        self.storage.publish_transactional(self.conn, pub, claim_id)
        self.conn.commit()

        # Verify outbox event on real database
        with psycopg.connect(LIVE_PG_URI) as verify_conn:
            self.storage.set_session_domain(verify_conn, self.test_domain)
            pending_outbox = self.storage.fetch_pending_outbox(verify_conn)
            self.assertEqual(1, len(pending_outbox))
            event = pending_outbox[0]
            self.assertEqual("KNOWLEDGE_PUBLISHED", event["event_type"])
            self.assertEqual(pub.publication_id, event["aggregate_id"])

            # Mark processed
            self.storage.mark_outbox_processed(verify_conn, [event["outbox_id"]])
            verify_conn.commit()

        # ---------------------------------------------------------------------
        # Stage 5: Authorized Versioned JSONL Export (K-08)
        # ---------------------------------------------------------------------
        consumer = TrustedActor(
            subject_id="procurement-agent-01",
            tenant_id="tenant-corp",
            domain=self.test_domain,
            roles=frozenset({Role.SECURITY_REVIEWER}),
            purposes=frozenset({"knowledge-read"}),
        )
        # Authorize consumer via ACL token
        pub_with_consumer = Publication(
            publication_id=pub.publication_id,
            candidate_id=pub.candidate_id,
            claim=pub.claim,
            evidence=pub.evidence,
            acl=frozenset({consumer.subject_id}),
            purpose=pub.purpose,
            published_at=pub.published_at,
            valid_until=pub.valid_until,
        )
        jsonl = self.governance.export_versioned_jsonl([pub_with_consumer], consumer, "v1.0.0")
        self.assertTrue(len(jsonl) > 0)
        parsed_record = json.loads(jsonl.splitlines()[0])
        self.assertEqual("乙公司", parsed_record["subject"]["name"])
        self.assertEqual("甲公司", parsed_record["object"]["name"])

        # ---------------------------------------------------------------------
        # Stage 6: Dictionary Package Compilation & Runtime Use (K-09)
        # ---------------------------------------------------------------------
        dict_payload = self.governance.compile_approved_dictionary_payload(
            "dict-procurement-v1", "v1.0.0", [pub]
        )
        compiled_dict = compile_dictionary(dict_payload)
        self.assertEqual("dict-procurement-v1", compiled_dict.dictionary_id)
        # Both entities are recognized by the compiled dictionary
        text_test = "这是甲公司的办公地点"
        detection = analyze_dictionary(text_test, compiled_dict)
        self.assertEqual(1, len(detection.spans))
        span = detection.spans[0]
        self.assertEqual("ORG", span.entity_type)
        self.assertEqual("甲公司", text_test[span.start:span.end])

        # ---------------------------------------------------------------------
        # Stage 7: Invalidation, Tombstoning & Consumer Receipt (K-13)
        # ---------------------------------------------------------------------
        steward = TrustedActor(
            subject_id="steward-01",
            tenant_id="tenant-corp",
            domain=self.test_domain,
            roles=frozenset({Role.DATA_STEWARD}),
            purposes=frozenset({"knowledge-lifecycle"}),
        )
        tombstone = self.governance.revoke_publication(
            pub, steward, "Customer procurement contract terminated"
        )
        self.storage.revoke_transactional(self.conn, tombstone)
        self.conn.commit()

        # Consumer confirms invalidation with receipt
        self.storage.record_consumer_receipt(
            self.conn,
            consumer_id=consumer.subject_id,
            event_id=pub.publication_id,
            domain=self.test_domain,
            action="tombstone_applied",
        )
        self.conn.commit()

        # Verify receipt in DB
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM consumer_receipts WHERE consumer_id = %s",
                (consumer.subject_id,),
            )
            receipt_status = cur.fetchone()[0]
            self.assertEqual("confirmed", receipt_status)

        # ---------------------------------------------------------------------
        # Stage 8: Row Level Security Cross-Domain Isolation (K-14)
        # ---------------------------------------------------------------------
        with psycopg.connect(LIVE_PG_URI) as cross_conn:
            self.storage.set_session_domain(cross_conn, "unrelated-other-domain")
            with cross_conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*) FROM knowledge_entities WHERE entity_id IN (%s, %s)",
                    (ent_jia.entity_id, ent_yi.entity_id),
                )
                count = cur.fetchone()[0]
                self.assertEqual(0, count)  # Completely hidden by RLS!


if __name__ == "__main__":
    unittest.main()
