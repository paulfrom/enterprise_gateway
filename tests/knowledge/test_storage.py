"""Tests for PostgreSQL knowledge storage adapter (K-04, K-12, K-14).

Verifies relational constraints, foreign keys, transactional outbox atomicity,
and PostgreSQL Row Level Security (RLS) isolation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest
from uuid import uuid4

import psycopg
from psycopg.errors import CheckViolation, ForeignKeyViolation

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
)
from knowledge.storage import PostgresKnowledgeStorage

LIVE_PG_URI = "postgresql://paul:lslin%4032@42.193.11.211:5432/enter_gateway"


class TestPostgresKnowledgeStorage(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.storage = PostgresKnowledgeStorage(LIVE_PG_URI)
        cls.storage.init_database(enable_rls=True)

    def setUp(self) -> None:
        self.conn = psycopg.connect(LIVE_PG_URI)
        self.test_domain = f"test-domain-{uuid4().hex[:8]}"
        self.other_domain = f"other-domain-{uuid4().hex[:8]}"
        self.storage.set_session_domain(self.conn, self.test_domain)

    def tearDown(self) -> None:
        self.conn.rollback()
        self.conn.close()

    def _sample_source(self, domain: str, source_id: str = "src-01") -> Source:
        now = datetime.now(timezone.utc)
        return Source(
            tenant_id="tenant-corp",
            domain=domain,
            source_id=source_id,
            version="v1",
            source_kind=SourceKind.USER_ASSERTION,
            acl=frozenset({f"{domain}:team-a"}),
            purpose="knowledge-accumulation",
            observed_at=now,
            retention_until=now + timedelta(days=90),
        )

    def test_k04_foreign_key_and_constraint_enforcement(self) -> None:
        """K-04: FK violations fail closed."""
        source = self._sample_source(self.test_domain)
        # Attempt to insert evidence referencing a non-existent source
        with self.assertRaises(ForeignKeyViolation):
            with self.conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO knowledge_evidence (
                        tenant_id, domain, source_id, version,
                        content_sha256, char_start, char_end
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        source.tenant_id,
                        self.test_domain,
                        "non-existent-source",
                        "v1",
                        "a" * 64,
                        0,
                        10,
                    ),
                )
        self.conn.rollback()
        self.storage.set_session_domain(self.conn, self.test_domain)

        # Attempt to insert evidence with invalid span (end <= start)
        self.storage.save_source(self.conn, source)
        with self.assertRaises(CheckViolation):
            with self.conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO knowledge_evidence (
                        tenant_id, domain, source_id, version,
                        content_sha256, char_start, char_end
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        source.tenant_id,
                        self.test_domain,
                        source.source_id,
                        source.version,
                        "a" * 64,
                        10,
                        5,
                    ),
                )
        self.conn.rollback()
        self.storage.set_session_domain(self.conn, self.test_domain)

    def test_k12_transactional_outbox_publishing(self) -> None:
        """K-12: Publication status and outbox entry are committed atomically."""
        source = self._sample_source(self.test_domain)
        evidence = Evidence(source, "b" * 64, 0, 15)
        ent1 = Entity(uuid4(), "tenant-corp", self.test_domain, "ORG", "甲公司")
        ent2 = Entity(uuid4(), "tenant-corp", self.test_domain, "ORG", "乙公司")
        claim = Claim(ent1, Predicate.SUPPLIES, ent2)
        candidate = Candidate(
            candidate_id=uuid4(),
            claim=claim,
            evidence=(evidence,),
            acl=frozenset({f"{self.test_domain}:team-a"}),
            purpose="business-graph",
        )

        # 1. Save candidate and evidence
        eid = self.storage.save_evidence(self.conn, evidence)
        claim_id = self.storage.save_candidate(self.conn, candidate, [eid])

        # 2. Add two approvals
        now = datetime.now(timezone.utc)
        self.storage.save_approval(
            self.conn,
            candidate.candidate_id,
            Approval("rev-sec", Role.SECURITY_REVIEWER, "audit-sec-01", now),
        )
        self.storage.save_approval(
            self.conn,
            candidate.candidate_id,
            Approval("rev-biz", Role.BUSINESS_REVIEWER, "audit-biz-01", now),
        )

        # 3. Publish candidate transactionally
        pub_id = uuid4()
        publication = Publication(
            publication_id=pub_id,
            candidate_id=candidate.candidate_id,
            claim=claim,
            evidence=(evidence,),
            acl=candidate.acl,
            purpose=candidate.purpose,
            published_at=now,
            valid_until=now + timedelta(days=180),
        )
        self.storage.publish_transactional(self.conn, publication, claim_id)
        self.conn.commit()

        # Reconnect to verify committed data
        with psycopg.connect(LIVE_PG_URI) as conn2:
            self.storage.set_session_domain(conn2, self.test_domain)
            with conn2.cursor() as cur:
                # Candidate is published
                cur.execute(
                    "SELECT state FROM knowledge_candidates WHERE candidate_id = %s",
                    (candidate.candidate_id,),
                )
                state = cur.fetchone()[0]
                self.assertEqual(CandidateState.PUBLISHED.value, state)

                # Outbox contains KNOWLEDGE_PUBLISHED event
                cur.execute(
                    "SELECT event_type, aggregate_id, status FROM knowledge_outbox WHERE aggregate_id = %s",
                    (pub_id,),
                )
                row = cur.fetchone()
                self.assertIsNotNone(row)
                self.assertEqual("KNOWLEDGE_PUBLISHED", row[0])
                self.assertEqual(pub_id, row[1])
                self.assertEqual("pending", row[2])

    def test_k14_rls_domain_isolation(self) -> None:
        """K-14: Database RLS rejects or hides cross-domain rows."""
        # 1. Insert entity in test_domain
        ent1 = Entity(uuid4(), "tenant-corp", self.test_domain, "ORG", "本域实体")
        self.storage.save_entity(self.conn, ent1)
        self.conn.commit()

        # 2. In session with test_domain, entity is visible
        with psycopg.connect(LIVE_PG_URI) as conn_test:
            self.storage.set_session_domain(conn_test, self.test_domain)
            with conn_test.cursor() as cur:
                cur.execute(
                    "SELECT name FROM knowledge_entities WHERE entity_id = %s",
                    (ent1.entity_id,),
                )
                row = cur.fetchone()
                self.assertIsNotNone(row)
                self.assertEqual("本域实体", row[0])

        # 3. In session with other_domain, entity is completely HIDDEN by RLS
        with psycopg.connect(LIVE_PG_URI) as conn_other:
            self.storage.set_session_domain(conn_other, self.other_domain)
            with conn_other.cursor() as cur:
                cur.execute(
                    "SELECT name FROM knowledge_entities WHERE entity_id = %s",
                    (ent1.entity_id,),
                )
                row = cur.fetchone()
                self.assertIsNone(row)  # Hidden by RLS!

        # 4. In session without domain setting, entity is completely HIDDEN
        with psycopg.connect(LIVE_PG_URI) as conn_none:
            with conn_none.cursor() as cur:
                cur.execute(
                    "SELECT name FROM knowledge_entities WHERE entity_id = %s",
                    (ent1.entity_id,),
                )
                row = cur.fetchone()
                self.assertIsNone(row)  # Hidden by RLS!


if __name__ == "__main__":
    unittest.main()
