"""PostgreSQL storage adapter for enterprise knowledge domain (K-04, K-12, K-14).

Provides relational persistence for knowledge sources, entities, claims,
evidence, review workflows, transactional outbox events, and consumer receipts.
Enforces foreign key integrity, cross-domain isolation, and PostgreSQL Row-Level
Security (RLS).
"""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

import psycopg
from psycopg.rows import dict_row

from infra.errors import SafetyCode, SafetyError
from knowledge.knowledge import (
    Approval,
    Candidate,
    CandidateState,
    Claim,
    Entity,
    Evidence,
    KnowledgeError,
    Modality,
    Polarity,
    Predicate,
    Publication,
    Role,
    Source,
    SourceKind,
    Tombstone,
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS knowledge_sources (
    tenant_id VARCHAR(128) NOT NULL,
    domain VARCHAR(128) NOT NULL,
    source_id VARCHAR(256) NOT NULL,
    version VARCHAR(64) NOT NULL,
    source_kind VARCHAR(64) NOT NULL,
    acl TEXT[] NOT NULL,
    purpose VARCHAR(128) NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    retention_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (tenant_id, domain, source_id, version)
);

CREATE TABLE IF NOT EXISTS knowledge_entities (
    entity_id UUID PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    domain VARCHAR(128) NOT NULL,
    entity_type VARCHAR(64) NOT NULL,
    name VARCHAR(256) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_entity_scope_name UNIQUE (tenant_id, domain, entity_type, name)
);

CREATE TABLE IF NOT EXISTS knowledge_evidence (
    evidence_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(128) NOT NULL,
    domain VARCHAR(128) NOT NULL,
    source_id VARCHAR(256) NOT NULL,
    version VARCHAR(64) NOT NULL,
    content_sha256 CHAR(64) NOT NULL,
    char_start INT NOT NULL,
    char_end INT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id, domain, source_id, version)
        REFERENCES knowledge_sources(tenant_id, domain, source_id, version)
        ON DELETE CASCADE,
    CONSTRAINT chk_char_span CHECK (char_start >= 0 AND char_end > char_start)
);

CREATE TABLE IF NOT EXISTS knowledge_claims (
    claim_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(128) NOT NULL,
    domain VARCHAR(128) NOT NULL,
    subject_id UUID NOT NULL REFERENCES knowledge_entities(entity_id) ON DELETE CASCADE,
    predicate VARCHAR(64) NOT NULL,
    object_id UUID NOT NULL REFERENCES knowledge_entities(entity_id) ON DELETE CASCADE,
    polarity VARCHAR(32) NOT NULL DEFAULT 'positive',
    modality VARCHAR(32) NOT NULL DEFAULT 'asserted',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_claim UNIQUE (tenant_id, domain, subject_id, predicate, object_id, polarity, modality)
);

CREATE TABLE IF NOT EXISTS knowledge_candidates (
    candidate_id UUID PRIMARY KEY,
    claim_id UUID NOT NULL REFERENCES knowledge_claims(claim_id) ON DELETE CASCADE,
    tenant_id VARCHAR(128) NOT NULL,
    domain VARCHAR(128) NOT NULL,
    acl TEXT[] NOT NULL,
    purpose VARCHAR(128) NOT NULL,
    state VARCHAR(32) NOT NULL DEFAULT 'proposed',
    rejection_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS candidate_evidence_links (
    candidate_id UUID NOT NULL REFERENCES knowledge_candidates(candidate_id) ON DELETE CASCADE,
    evidence_id UUID NOT NULL REFERENCES knowledge_evidence(evidence_id) ON DELETE CASCADE,
    PRIMARY KEY (candidate_id, evidence_id)
);

CREATE TABLE IF NOT EXISTS knowledge_approvals (
    approval_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    candidate_id UUID NOT NULL REFERENCES knowledge_candidates(candidate_id) ON DELETE CASCADE,
    reviewer_id VARCHAR(128) NOT NULL,
    role VARCHAR(64) NOT NULL,
    verification_ref VARCHAR(256) NOT NULL,
    approved_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS knowledge_publications (
    publication_id UUID PRIMARY KEY,
    candidate_id UUID NOT NULL REFERENCES knowledge_candidates(candidate_id) ON DELETE CASCADE,
    claim_id UUID NOT NULL REFERENCES knowledge_claims(claim_id) ON DELETE CASCADE,
    tenant_id VARCHAR(128) NOT NULL,
    domain VARCHAR(128) NOT NULL,
    acl TEXT[] NOT NULL,
    purpose VARCHAR(128) NOT NULL,
    published_at TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS knowledge_tombstones (
    tombstone_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    publication_id UUID NOT NULL,
    candidate_id UUID NOT NULL,
    tenant_id VARCHAR(128) NOT NULL,
    domain VARCHAR(128) NOT NULL,
    reason TEXT NOT NULL,
    effective_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS knowledge_outbox (
    outbox_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(64) NOT NULL,
    aggregate_type VARCHAR(64) NOT NULL,
    aggregate_id UUID NOT NULL,
    tenant_id VARCHAR(128) NOT NULL,
    domain VARCHAR(128) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS consumer_receipts (
    receipt_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    consumer_id VARCHAR(128) NOT NULL,
    event_id UUID NOT NULL,
    domain VARCHAR(128) NOT NULL,
    action VARCHAR(64) NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(32) NOT NULL DEFAULT 'confirmed'
);
"""

RLS_SETUP_SQL = """
ALTER TABLE knowledge_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge_entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge_publications ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge_outbox ENABLE ROW LEVEL SECURITY;

ALTER TABLE knowledge_sources FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge_entities FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge_claims FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge_candidates FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge_publications FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge_outbox FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'rls_sources_domain') THEN
        CREATE POLICY rls_sources_domain ON knowledge_sources
            USING (domain = nullif(current_setting('app.current_domain', true), ''));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'rls_entities_domain') THEN
        CREATE POLICY rls_entities_domain ON knowledge_entities
            USING (domain = nullif(current_setting('app.current_domain', true), ''));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'rls_evidence_domain') THEN
        CREATE POLICY rls_evidence_domain ON knowledge_evidence
            USING (domain = nullif(current_setting('app.current_domain', true), ''));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'rls_claims_domain') THEN
        CREATE POLICY rls_claims_domain ON knowledge_claims
            USING (domain = nullif(current_setting('app.current_domain', true), ''));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'rls_candidates_domain') THEN
        CREATE POLICY rls_candidates_domain ON knowledge_candidates
            USING (domain = nullif(current_setting('app.current_domain', true), ''));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'rls_publications_domain') THEN
        CREATE POLICY rls_publications_domain ON knowledge_publications
            USING (domain = nullif(current_setting('app.current_domain', true), ''));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'rls_outbox_domain') THEN
        CREATE POLICY rls_outbox_domain ON knowledge_outbox
            USING (domain = nullif(current_setting('app.current_domain', true), ''));
    END IF;
END $$;
"""


class PostgresKnowledgeStorage:
    """Relational knowledge repository implementing K-04, K-12, K-14."""

    def __init__(self, connection_uri: str) -> None:
        self.connection_uri = connection_uri

    def init_database(self, enable_rls: bool = True) -> None:
        """Create tables and optionally set up Row Level Security."""
        with psycopg.connect(self.connection_uri, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)
                if enable_rls:
                    cur.execute(RLS_SETUP_SQL)

    def set_session_domain(self, conn: psycopg.Connection, domain: str) -> None:
        """Set session variable for RLS domain isolation."""
        with conn.cursor() as cur:
            cur.execute("SELECT set_config('app.current_domain', %s, false)", (domain,))

    def save_source(self, conn: psycopg.Connection, source: Source) -> None:
        """Persist a trusted source. Fails if invalid."""
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO knowledge_sources (
                    tenant_id, domain, source_id, version, source_kind,
                    acl, purpose, observed_at, retention_until
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, domain, source_id, version) DO UPDATE SET
                    acl = EXCLUDED.acl,
                    retention_until = EXCLUDED.retention_until
                """,
                (
                    source.tenant_id,
                    source.domain,
                    source.source_id,
                    source.version,
                    source.source_kind.value,
                    list(source.acl),
                    source.purpose,
                    source.observed_at,
                    source.retention_until,
                ),
            )

    def save_entity(self, conn: psycopg.Connection, entity: Entity) -> None:
        """Persist an entity definition."""
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO knowledge_entities (
                    entity_id, tenant_id, domain, entity_type, name
                ) VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, domain, entity_type, name) DO NOTHING
                """,
                (
                    entity.entity_id,
                    entity.tenant_id,
                    entity.domain,
                    entity.entity_type,
                    entity.name,
                ),
            )

    def save_evidence(self, conn: psycopg.Connection, evidence: Evidence) -> UUID:
        """Persist an evidence span linked to a source."""
        # Ensure parent source exists
        self.save_source(conn, evidence.source)
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO knowledge_evidence (
                    tenant_id, domain, source_id, version,
                    content_sha256, char_start, char_end
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING evidence_id
                """,
                (
                    evidence.source.tenant_id,
                    evidence.source.domain,
                    evidence.source.source_id,
                    evidence.source.version,
                    evidence.content_sha256,
                    evidence.start,
                    evidence.end,
                ),
            )
            row = cur.fetchone()
            if not row:
                raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "failed to insert evidence")
            return row[0]

    def save_claim(self, conn: psycopg.Connection, claim: Claim) -> UUID:
        """Persist a semantic relation claim between two entities."""
        self.save_entity(conn, claim.subject)
        self.save_entity(conn, claim.object)
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO knowledge_claims (
                    tenant_id, domain, subject_id, predicate, object_id, polarity, modality
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, domain, subject_id, predicate, object_id, polarity, modality)
                DO UPDATE SET created_at = CURRENT_TIMESTAMP
                RETURNING claim_id
                """,
                (
                    claim.subject.tenant_id,
                    claim.subject.domain,
                    claim.subject.entity_id,
                    claim.predicate.value,
                    claim.object.entity_id,
                    claim.polarity.value,
                    claim.modality.value,
                ),
            )
            row = cur.fetchone()
            if not row:
                raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "failed to insert claim")
            return row[0]

    def save_candidate(
        self,
        conn: psycopg.Connection,
        candidate: Candidate,
        evidence_ids: list[UUID] | None = None,
    ) -> UUID:
        """Persist a candidate with its claim and evidence links."""
        claim_id = self.save_claim(conn, candidate.claim)
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO knowledge_candidates (
                    candidate_id, claim_id, tenant_id, domain,
                    acl, purpose, state, rejection_reason
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (candidate_id) DO UPDATE SET
                    state = EXCLUDED.state,
                    rejection_reason = EXCLUDED.rejection_reason,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    candidate.candidate_id,
                    claim_id,
                    candidate.claim.subject.tenant_id,
                    candidate.claim.subject.domain,
                    list(candidate.acl),
                    candidate.purpose,
                    candidate.state.value,
                    candidate.rejection_reason,
                ),
            )
            if evidence_ids:
                for eid in evidence_ids:
                    cur.execute(
                        """
                        INSERT INTO candidate_evidence_links (candidate_id, evidence_id)
                        VALUES (%s, %s)
                        ON CONFLICT DO NOTHING
                        """,
                        (candidate.candidate_id, eid),
                    )
        return claim_id

    def save_approval(
        self,
        conn: psycopg.Connection,
        candidate_id: UUID,
        approval: Approval,
    ) -> None:
        """Record an approval signature."""
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO knowledge_approvals (
                    candidate_id, reviewer_id, role, verification_ref, approved_at
                ) VALUES (%s, %s, %s, %s, %s)
                """,
                (
                    candidate_id,
                    approval.reviewer_id,
                    approval.role.value,
                    approval.verification_ref,
                    approval.approved_at,
                ),
            )

    def publish_transactional(
        self,
        conn: psycopg.Connection,
        publication: Publication,
        claim_id: UUID,
    ) -> None:
        """Publish a candidate and insert an outbox event in ONE atomic transaction (K-12)."""
        with conn.cursor() as cur:
            # 1. Update candidate state to published
            cur.execute(
                """
                UPDATE knowledge_candidates
                SET state = %s, updated_at = CURRENT_TIMESTAMP
                WHERE candidate_id = %s
                """,
                (CandidateState.PUBLISHED.value, publication.candidate_id),
            )
            # 2. Insert publication
            cur.execute(
                """
                INSERT INTO knowledge_publications (
                    publication_id, candidate_id, claim_id, tenant_id,
                    domain, acl, purpose, published_at, valid_until
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    publication.publication_id,
                    publication.candidate_id,
                    claim_id,
                    publication.claim.subject.tenant_id,
                    publication.claim.subject.domain,
                    list(publication.acl),
                    publication.purpose,
                    publication.published_at,
                    publication.valid_until,
                ),
            )
            # 3. Insert transactional outbox record (K-12)
            outbox_payload = {
                "publication_id": str(publication.publication_id),
                "candidate_id": str(publication.candidate_id),
                "subject": publication.claim.subject.name,
                "predicate": publication.claim.predicate.value,
                "object": publication.claim.object.name,
                "published_at": publication.published_at.isoformat(),
                "valid_until": publication.valid_until.isoformat(),
                "acl": list(publication.acl),
            }
            cur.execute(
                """
                INSERT INTO knowledge_outbox (
                    event_type, aggregate_type, aggregate_id, tenant_id,
                    domain, payload, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    "KNOWLEDGE_PUBLISHED",
                    "Publication",
                    publication.publication_id,
                    publication.claim.subject.tenant_id,
                    publication.claim.subject.domain,
                    json.dumps(outbox_payload),
                    "pending",
                ),
            )

    def revoke_transactional(
        self,
        conn: psycopg.Connection,
        tombstone: Tombstone,
    ) -> None:
        """Revoke a publication and write outbox tombstone in ONE transaction (K-12, K-13)."""
        with conn.cursor() as cur:
            # 1. Update candidate state to withdrawn
            cur.execute(
                """
                UPDATE knowledge_candidates
                SET state = %s, updated_at = CURRENT_TIMESTAMP
                WHERE candidate_id = %s
                """,
                (CandidateState.WITHDRAWN.value, tombstone.candidate_id),
            )
            # 2. Insert tombstone
            cur.execute(
                """
                INSERT INTO knowledge_tombstones (
                    publication_id, candidate_id, tenant_id, domain, reason, effective_at
                ) VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    tombstone.publication_id,
                    tombstone.candidate_id,
                    tombstone.tenant_id,
                    tombstone.domain,
                    tombstone.reason,
                    tombstone.effective_at,
                ),
            )
            # 3. Insert outbox record for downstream consumers
            outbox_payload = {
                "publication_id": str(tombstone.publication_id),
                "candidate_id": str(tombstone.candidate_id),
                "reason": tombstone.reason,
                "effective_at": tombstone.effective_at.isoformat(),
            }
            cur.execute(
                """
                INSERT INTO knowledge_outbox (
                    event_type, aggregate_type, aggregate_id, tenant_id,
                    domain, payload, status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    "KNOWLEDGE_REVOKED",
                    "Publication",
                    tombstone.publication_id,
                    tombstone.tenant_id,
                    tombstone.domain,
                    json.dumps(outbox_payload),
                    "pending",
                ),
            )

    def record_consumer_receipt(
        self,
        conn: psycopg.Connection,
        consumer_id: str,
        event_id: UUID,
        domain: str,
        action: str,
    ) -> None:
        """Store receipt from consumer proving consumption/invalidation (K-13)."""
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO consumer_receipts (
                    consumer_id, event_id, domain, action, status
                ) VALUES (%s, %s, %s, %s, %s)
                """,
                (consumer_id, event_id, domain, action, "confirmed"),
            )

    def fetch_pending_outbox(
        self,
        conn: psycopg.Connection,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Fetch unhandled outbox events."""
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """
                SELECT outbox_id, event_type, aggregate_type, aggregate_id,
                       tenant_id, domain, payload, status, created_at
                FROM knowledge_outbox
                WHERE status = 'pending'
                ORDER BY created_at ASC
                LIMIT %s
                """,
                (limit,),
            )
            return cur.fetchall()

    def mark_outbox_processed(
        self,
        conn: psycopg.Connection,
        outbox_ids: list[UUID],
    ) -> None:
        """Mark outbox items as processed."""
        if not outbox_ids:
            return
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE knowledge_outbox
                SET status = 'processed', processed_at = CURRENT_TIMESTAMP
                WHERE outbox_id = ANY(%s)
                """,
                (outbox_ids,),
            )
