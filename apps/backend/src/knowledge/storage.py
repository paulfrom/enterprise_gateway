"""PostgreSQL storage adapter for enterprise knowledge domain (K-04, K-12, K-14).

Provides relational persistence for knowledge sources, entities, claims,
evidence, transactional outbox events, and consumer receipts.
Enforces foreign key integrity, cross-domain isolation, and PostgreSQL Row-Level
Security (RLS). Schema v2 binds every governance mutation to a recorded
single-admin action and pins the deployed structure with a normalized fingerprint.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from typing import Any, Iterator
from uuid import UUID, uuid4

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from infra.errors import SafetyCode, SafetyError
from knowledge.knowledge import (
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
    TrustedActor,
)

SCHEMA_VERSION = 2
# Locked to the measured metadata fingerprint of SCHEMA_SQL v2 (see
# tests.knowledge.test_storage.TestSchemaFingerprint); any structural drift
# must update this constant in the same change.
SCHEMA_FINGERPRINT_V2 = '808ff8d8afb5cbf8a5d9b019f57a38721d5bb5f302b630f8b34985e1e24d8ed0'


class KnowledgeSchemaError(RuntimeError):
    """The deployed knowledge schema does not match the supported v2 contract."""

    code = 'KNOWLEDGE_SCHEMA_INCOMPATIBLE'

    def __init__(self, detail: str = 'knowledge schema metadata does not match the supported v2 contract'):
        super().__init__(f'{self.code}: {detail}')


def compute_schema_fingerprint(conn: psycopg.Connection, *, admin_role: str) -> str:
    """Normalized sha256 over the schema's table/column/constraint/index/trigger/function/policy metadata.

    OIDs, the schema name and deployment-specific role-name literals are stripped
    so independently deployed v2 namespaces fingerprint identically.
    """
    schema = conn.execute('SELECT current_schema()').fetchone()[0]

    def norm(value: Any) -> Any:
        if isinstance(value, str):
            if admin_role:
                value = value.replace(admin_role, '<ADMIN_ROLE>')
            return value.replace(schema, '<SCHEMA>')
        if isinstance(value, (list, tuple)):
            return [norm(item) for item in value]
        return value

    tables = conn.execute(
        "SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c "
        "JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname=current_schema() AND c.relkind='r' ORDER BY c.relname").fetchall()
    columns = conn.execute(
        "SELECT table_name,column_name,ordinal_position,data_type,is_nullable,column_default "
        "FROM information_schema.columns WHERE table_schema=current_schema() "
        "ORDER BY table_name,ordinal_position").fetchall()
    constraints = conn.execute(
        "SELECT conrelid::regclass::text,conname,contype,condeferrable,condeferred,"
        "pg_get_constraintdef(c.oid) FROM pg_constraint c "
        "WHERE c.connamespace=current_schema()::regnamespace ORDER BY conname").fetchall()
    indexes = conn.execute(
        "SELECT tablename,indexname,indexdef FROM pg_indexes WHERE schemaname=current_schema() "
        "ORDER BY indexname").fetchall()
    triggers = conn.execute(
        "SELECT tgrelid::regclass::text,tgname,pg_get_triggerdef(t.oid) FROM pg_trigger t "
        "WHERE NOT t.tgisinternal AND t.tgrelid IN (SELECT c.oid FROM pg_class c "
        "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema()) "
        "ORDER BY tgname").fetchall()
    functions = conn.execute(
        "SELECT p.proname,pg_get_function_identity_arguments(p.oid),p.prosecdef,p.proconfig,p.prosrc "
        "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
        "WHERE n.nspname=current_schema() ORDER BY p.proname").fetchall()
    policies = conn.execute(
        "SELECT tablename,policyname,cmd,roles,qual,with_check FROM pg_policies "
        "WHERE schemaname=current_schema() ORDER BY policyname,tablename").fetchall()
    canonical = {
        'tables': norm(tables),
        'columns': norm(columns),
        'constraints': norm(constraints),
        'indexes': norm(indexes),
        'triggers': norm(triggers),
        'functions': norm(functions),
        'policies': norm(policies),
    }
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True, default=str).encode('utf-8')).hexdigest()


SCHEMA_SQL = """
CREATE TABLE knowledge_sources (
 tenant_id TEXT NOT NULL, domain TEXT NOT NULL, source_id TEXT NOT NULL, version TEXT NOT NULL,
 source_kind TEXT NOT NULL, acl TEXT[] NOT NULL CHECK(cardinality(acl)>0), purpose TEXT NOT NULL,
 observed_at TIMESTAMPTZ NOT NULL, retention_until TIMESTAMPTZ NOT NULL CHECK(retention_until>observed_at),
 independence_verified BOOLEAN NOT NULL DEFAULT FALSE, withdrawn BOOLEAN NOT NULL DEFAULT FALSE,
 PRIMARY KEY(tenant_id,domain,source_id,version));
CREATE TABLE knowledge_entities (
 entity_id UUID PRIMARY KEY, tenant_id TEXT NOT NULL, domain TEXT NOT NULL,
 entity_type TEXT NOT NULL, name TEXT NOT NULL, acl TEXT[] NOT NULL, purpose TEXT NOT NULL,
 UNIQUE(tenant_id,domain,entity_id), UNIQUE(tenant_id,domain,entity_type,name));
CREATE TABLE knowledge_evidence (
 evidence_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id TEXT NOT NULL, domain TEXT NOT NULL,
 source_id TEXT NOT NULL, version TEXT NOT NULL, content_sha256 CHAR(64) NOT NULL,
 char_start INT NOT NULL, char_end INT NOT NULL, acl TEXT[] NOT NULL, purpose TEXT NOT NULL,
 FOREIGN KEY(tenant_id,domain,source_id,version) REFERENCES knowledge_sources(tenant_id,domain,source_id,version),
 UNIQUE(tenant_id,domain,evidence_id), UNIQUE(tenant_id,domain,source_id,version,content_sha256,char_start,char_end),
 CHECK(char_start>=0 AND char_end>char_start));
CREATE TABLE knowledge_claims (
 claim_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),tenant_id TEXT NOT NULL,domain TEXT NOT NULL,
 subject_id UUID NOT NULL,predicate TEXT NOT NULL,object_id UUID NOT NULL,
 polarity TEXT NOT NULL,modality TEXT NOT NULL,acl TEXT[] NOT NULL,purpose TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(tenant_id,domain,subject_id) REFERENCES knowledge_entities(tenant_id,domain,entity_id),
 FOREIGN KEY(tenant_id,domain,object_id) REFERENCES knowledge_entities(tenant_id,domain,entity_id),
 UNIQUE(tenant_id,domain,claim_id),UNIQUE(tenant_id,domain,subject_id,predicate,object_id,polarity,modality));
CREATE TABLE knowledge_candidates (
 candidate_id UUID PRIMARY KEY,claim_id UUID NOT NULL,tenant_id TEXT NOT NULL,domain TEXT NOT NULL,
 acl TEXT[] NOT NULL,purpose TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'proposed',rejection_reason TEXT,
 candidate_version INTEGER NOT NULL DEFAULT 1,derived_from UUID,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(tenant_id,domain,claim_id) REFERENCES knowledge_claims(tenant_id,domain,claim_id),
 UNIQUE(tenant_id,domain,candidate_id));
CREATE TABLE candidate_evidence_links (
 candidate_id UUID NOT NULL,evidence_id UUID NOT NULL,tenant_id TEXT NOT NULL,domain TEXT NOT NULL,
 acl TEXT[] NOT NULL,purpose TEXT NOT NULL,PRIMARY KEY(candidate_id,evidence_id),
 FOREIGN KEY(tenant_id,domain,candidate_id) REFERENCES knowledge_candidates(tenant_id,domain,candidate_id),
 FOREIGN KEY(tenant_id,domain,evidence_id) REFERENCES knowledge_evidence(tenant_id,domain,evidence_id));
CREATE TABLE knowledge_admin_actions (
    admin_action_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    session_digest TEXT NOT NULL,
    action_type TEXT NOT NULL CHECK (action_type IN ('governance_confirm','publish','reject','revise','withdraw','revoke')),
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    object_version TEXT,
    rationale TEXT NOT NULL,
    intended_use TEXT,
    consumer_audiences TEXT[],
    result TEXT NOT NULL CHECK (result IN ('succeeded','failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE knowledge_governance_versions (
    governance_version_id UUID PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_version TEXT NOT NULL,
    admin_action_id UUID NOT NULL REFERENCES knowledge_admin_actions(admin_action_id),
    ownership_confirmed BOOLEAN NOT NULL,
    intended_use TEXT NOT NULL,
    consumer_audiences TEXT[] NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    valid_until TIMESTAMPTZ NOT NULL,
    rationale TEXT NOT NULL,
    supersedes_version_id UUID REFERENCES knowledge_governance_versions(governance_version_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, domain, source_id, source_version, governance_version_id)
);
CREATE TABLE knowledge_publications (
 publication_id UUID PRIMARY KEY,candidate_id UUID NOT NULL,claim_id UUID NOT NULL,
 tenant_id TEXT NOT NULL,domain TEXT NOT NULL,acl TEXT[] NOT NULL,purpose TEXT NOT NULL,
 candidate_version INTEGER NOT NULL,
 intended_use TEXT NOT NULL,consumer_audiences TEXT[] NOT NULL CHECK(cardinality(consumer_audiences)>0),
 published_at TIMESTAMPTZ NOT NULL,valid_until TIMESTAMPTZ NOT NULL,
 admin_action_id UUID NOT NULL,idempotency_key TEXT,
 FOREIGN KEY(tenant_id,domain,candidate_id) REFERENCES knowledge_candidates(tenant_id,domain,candidate_id),
 FOREIGN KEY(tenant_id,domain,claim_id) REFERENCES knowledge_claims(tenant_id,domain,claim_id),
 UNIQUE(tenant_id,domain,candidate_id,candidate_version),
 UNIQUE(tenant_id,domain,publication_id));
CREATE UNIQUE INDEX knowledge_publications_idempotency
    ON knowledge_publications(candidate_id, candidate_version, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE TABLE knowledge_publication_sources (
    publication_id UUID NOT NULL REFERENCES knowledge_publications(publication_id) DEFERRABLE INITIALLY DEFERRED,
    tenant_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_version TEXT NOT NULL,
    governance_version_id UUID NOT NULL,
    PRIMARY KEY (publication_id, source_id, source_version),
    FOREIGN KEY (tenant_id, domain, source_id, source_version, governance_version_id)
      REFERENCES knowledge_governance_versions(tenant_id, domain, source_id, source_version, governance_version_id)
);
CREATE TABLE knowledge_tombstones (
 tombstone_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),publication_id UUID NOT NULL,candidate_id UUID NOT NULL,
 tenant_id TEXT NOT NULL,domain TEXT NOT NULL,acl TEXT[] NOT NULL,purpose TEXT NOT NULL,reason TEXT NOT NULL,
 effective_at TIMESTAMPTZ NOT NULL,UNIQUE(publication_id),
 FOREIGN KEY(tenant_id,domain,publication_id) REFERENCES knowledge_publications(tenant_id,domain,publication_id));
CREATE TABLE knowledge_outbox (
 outbox_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),event_type TEXT NOT NULL,aggregate_type TEXT NOT NULL,
 aggregate_id UUID NOT NULL,tenant_id TEXT NOT NULL,domain TEXT NOT NULL,acl TEXT[] NOT NULL,purpose TEXT NOT NULL,
 payload JSONB NOT NULL,status TEXT NOT NULL DEFAULT 'pending',
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,processed_at TIMESTAMPTZ,
 UNIQUE(tenant_id,domain,outbox_id),UNIQUE(aggregate_id,event_type));
CREATE TABLE consumer_receipts (
 receipt_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),consumer_id TEXT NOT NULL,event_id UUID NOT NULL,
 tenant_id TEXT NOT NULL,domain TEXT NOT NULL,acl TEXT[] NOT NULL,purpose TEXT NOT NULL,
 action TEXT NOT NULL,received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,status TEXT NOT NULL,
 delivery_result TEXT,last_error_code TEXT,
 FOREIGN KEY(tenant_id,domain,event_id) REFERENCES knowledge_outbox(tenant_id,domain,outbox_id),
 UNIQUE(consumer_id,event_id,action));
CREATE TABLE knowledge_consumer_assets (
 consumer_id TEXT NOT NULL,publication_id UUID NOT NULL,tenant_id TEXT NOT NULL,domain TEXT NOT NULL,
 acl TEXT[] NOT NULL,purpose TEXT NOT NULL,active BOOLEAN NOT NULL,
 asset_version INTEGER NOT NULL DEFAULT 1,asset_kind TEXT NOT NULL,intended_use TEXT NOT NULL,
 lineage JSONB NOT NULL DEFAULT '{}',
 PRIMARY KEY(consumer_id,publication_id),
 FOREIGN KEY(tenant_id,domain,publication_id) REFERENCES knowledge_publications(tenant_id,domain,publication_id));
CREATE TABLE knowledge_observations (
 dedup_key TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,domain TEXT NOT NULL,acl TEXT[] NOT NULL,purpose TEXT NOT NULL,
 source_id TEXT NOT NULL,source_version TEXT NOT NULL,candidate_ids UUID[] NOT NULL,
 encrypted_observation BYTEA NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(tenant_id,domain,source_id,source_version) REFERENCES knowledge_sources(tenant_id,domain,source_id,version));

CREATE FUNCTION enforce_publication_admission() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    v_src RECORD;
    v_s_withdrawn BOOLEAN;
    v_s_retention TIMESTAMPTZ;
    v_g_use TEXT;
    v_g_audiences TEXT[];
    v_g_until TIMESTAMPTZ;
    v_first BOOLEAN := true;
    v_audience_intersection TEXT[];
    v_bound_until TIMESTAMPTZ := NULL;
BEGIN
    IF current_user <> __ADMIN_ROLE__ THEN
        RAISE EXCEPTION 'KNOWLEDGE_PUBLISHER_REQUIRED';
    END IF;
    IF nullif(current_setting('app.admin_context',true),'') IS DISTINCT FROM 'true' THEN
        RAISE EXCEPTION 'KNOWLEDGE_ADMIN_CONTEXT_REQUIRED';
    END IF;
    IF NEW.valid_until <= clock_timestamp() THEN
        RAISE EXCEPTION 'KNOWLEDGE_VALIDITY_EXCEEDS_SOURCE';
    END IF;
    IF NEW.consumer_audiences IS NULL OR cardinality(NEW.consumer_audiences) = 0 THEN
        RAISE EXCEPTION 'KNOWLEDGE_PUBLICATION_AUDIENCE_DENIED';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM knowledge_admin_actions a
        WHERE a.admin_action_id = NEW.admin_action_id
          AND a.action_type='publish' AND a.result='succeeded'
          AND a.object_type='candidate' AND a.object_id = NEW.candidate_id::text
          AND (a.object_version IS NULL OR a.object_version = NEW.candidate_version::text)
          AND a.tenant_id = NEW.tenant_id AND a.domain = NEW.domain) THEN
        RAISE EXCEPTION 'KNOWLEDGE_ADMIN_ACTION_REQUIRED';
    END IF;
    PERFORM 1 FROM knowledge_candidates
     WHERE candidate_id=NEW.candidate_id AND candidate_version=NEW.candidate_version FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'KNOWLEDGE_CANDIDATE_VERSION_NOT_FOUND'; END IF;
    -- Every contributing source of the candidate (candidate_evidence_links ->
    -- knowledge_evidence source references) must be bound in this publication.
    IF EXISTS (
        SELECT 1 FROM (
            SELECT DISTINCT e.source_id, e.version AS source_version
            FROM candidate_evidence_links l JOIN knowledge_evidence e USING(evidence_id)
            WHERE l.candidate_id=NEW.candidate_id AND (e.tenant_id,e.domain)=(NEW.tenant_id,NEW.domain)
        ) csl WHERE NOT EXISTS (
        SELECT 1 FROM knowledge_publication_sources ps
         WHERE ps.publication_id=NEW.publication_id
           AND ps.source_id=csl.source_id AND ps.source_version=csl.source_version)) THEN
        RAISE EXCEPTION 'KNOWLEDGE_PUBLICATION_SOURCE_MISSING';
    END IF;
    -- Fixed lock order: sources ordered by (source_id, source_version), then governance versions.
    FOR v_src IN SELECT source_id, source_version, governance_version_id
        FROM knowledge_publication_sources
       WHERE publication_id=NEW.publication_id
       ORDER BY source_id, source_version FOR UPDATE LOOP
        SELECT s.withdrawn, s.retention_until INTO v_s_withdrawn, v_s_retention
          FROM knowledge_sources s
         WHERE s.tenant_id=NEW.tenant_id AND s.domain=NEW.domain
           AND s.source_id=v_src.source_id AND s.version=v_src.source_version
           FOR SHARE;
        IF NOT FOUND OR v_s_withdrawn THEN
            RAISE EXCEPTION 'KNOWLEDGE_SOURCE_WITHDRAWN';
        END IF;
        IF v_s_retention <= clock_timestamp() THEN
            RAISE EXCEPTION 'KNOWLEDGE_SOURCE_EXPIRED';
        END IF;

        SELECT g.intended_use, g.consumer_audiences, g.valid_until
          INTO v_g_use, v_g_audiences, v_g_until
          FROM knowledge_governance_versions g
         WHERE g.tenant_id=NEW.tenant_id AND g.domain=NEW.domain
           AND g.source_id=v_src.source_id AND g.source_version=v_src.source_version
           AND g.governance_version_id=v_src.governance_version_id
           AND g.valid_from <= clock_timestamp() AND g.valid_until > clock_timestamp()
           AND NOT EXISTS (SELECT 1 FROM knowledge_governance_versions n
                            WHERE n.supersedes_version_id=g.governance_version_id)
           FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'KNOWLEDGE_GOVERNANCE_VERSION_INVALID';
        END IF;

        IF v_g_use IS DISTINCT FROM NEW.intended_use THEN
            RAISE EXCEPTION 'KNOWLEDGE_PUBLICATION_PURPOSE_DENIED';
        END IF;

        IF NOT (NEW.consumer_audiences <@ v_g_audiences) THEN
            RAISE EXCEPTION 'KNOWLEDGE_PUBLICATION_AUDIENCE_DENIED';
        END IF;

        IF v_first THEN
            v_audience_intersection := v_g_audiences;
            v_first := false;
        ELSE
            SELECT array_agg(x) INTO v_audience_intersection
              FROM (SELECT unnest(v_audience_intersection) INTERSECT SELECT unnest(v_g_audiences)) t(x);
        END IF;

        v_bound_until := LEAST(COALESCE(v_bound_until, v_g_until), v_g_until, v_s_retention);
    END LOOP;

    IF v_first THEN
        RAISE EXCEPTION 'KNOWLEDGE_PUBLICATION_SOURCE_MISSING';
    END IF;

    IF v_audience_intersection IS NULL OR cardinality(v_audience_intersection) = 0
       OR NOT (NEW.consumer_audiences <@ v_audience_intersection) THEN
        RAISE EXCEPTION 'KNOWLEDGE_PUBLICATION_AUDIENCE_DENIED';
    END IF;

    IF NEW.valid_until > v_bound_until THEN
        RAISE EXCEPTION 'KNOWLEDGE_VALIDITY_EXCEEDS_SOURCE';
    END IF;

    RETURN NEW;
END $$;
CREATE TRIGGER enforce_publication_admission BEFORE INSERT ON knowledge_publications
 FOR EACH ROW EXECUTE FUNCTION enforce_publication_admission();

CREATE FUNCTION invalidate_knowledge_source(p_source_id TEXT,p_version TEXT,p_reason TEXT,p_effective TIMESTAMPTZ)
RETURNS TABLE(out_publication_id UUID,out_candidate_id UUID) LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,__GOVERNANCE_SCHEMA__ AS $$
DECLARE source_row RECORD; pub_row RECORD; candidate_ids UUID[]; claim_ids UUID[]; entity_ids UUID[];
        caller_tenant TEXT:=current_setting('app.tenant',true); caller_domain TEXT:=current_setting('app.domain',true);
        caller_subject TEXT:=current_setting('app.subject',true);
BEGIN
 IF NOT ('data_steward'=ANY(COALESCE(nullif(current_setting('app.roles',true),'')::text[],ARRAY[]::text[])))
 OR length(trim(p_reason))=0 THEN
   RAISE EXCEPTION 'authorized source stewardship required' USING ERRCODE='42501';
 END IF;
 SELECT * INTO source_row FROM knowledge_sources s
 WHERE (s.tenant_id,s.domain,s.source_id,s.version)=(caller_tenant,caller_domain,p_source_id,p_version) FOR UPDATE;
 IF source_row IS NULL OR NOT COALESCE(caller_subject=ANY(source_row.acl),false)
 OR NOT (source_row.purpose=ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[],ARRAY[]::text[]))) THEN
   RAISE EXCEPTION 'source management access denied' USING ERRCODE='42501';
 END IF;
 IF source_row.withdrawn THEN RETURN; END IF;
 SELECT array_agg(DISTINCT l.candidate_id) INTO candidate_ids FROM candidate_evidence_links l
 JOIN knowledge_evidence e USING(evidence_id)
 WHERE (e.tenant_id,e.domain,e.source_id,e.version)=(caller_tenant,caller_domain,p_source_id,p_version);
 SELECT array_agg(DISTINCT c.claim_id) INTO claim_ids FROM knowledge_candidates c WHERE c.candidate_id=ANY(candidate_ids);
 SELECT array_agg(DISTINCT entity_id) INTO entity_ids FROM (
   SELECT k.subject_id AS entity_id FROM knowledge_claims k WHERE k.claim_id=ANY(claim_ids)
   UNION SELECT k.object_id FROM knowledge_claims k WHERE k.claim_id=ANY(claim_ids)) identities;
 FOR pub_row IN SELECT p.* FROM knowledge_publications p WHERE p.candidate_id=ANY(candidate_ids) LOOP
   INSERT INTO knowledge_tombstones(publication_id,candidate_id,tenant_id,domain,acl,purpose,reason,effective_at)
   VALUES(pub_row.publication_id,pub_row.candidate_id,caller_tenant,caller_domain,pub_row.acl,pub_row.purpose,p_reason,p_effective)
   ON CONFLICT(publication_id) DO NOTHING;
   INSERT INTO knowledge_outbox(event_type,aggregate_type,aggregate_id,tenant_id,domain,acl,purpose,payload)
   VALUES('KNOWLEDGE_REVOKED','Publication',pub_row.publication_id,caller_tenant,caller_domain,pub_row.acl,pub_row.purpose,
     jsonb_build_object('publication_id',pub_row.publication_id,'candidate_id',pub_row.candidate_id,
                        'reason',p_reason,'effective_at',p_effective)) ON CONFLICT(aggregate_id,event_type) DO NOTHING;
   UPDATE knowledge_outbox SET payload=jsonb_build_object('publication_id',pub_row.publication_id),acl=ARRAY[]::text[]
     WHERE aggregate_id=pub_row.publication_id AND event_type='KNOWLEDGE_PUBLISHED';
   UPDATE knowledge_consumer_assets SET active=false WHERE publication_id=pub_row.publication_id;
   out_publication_id:=pub_row.publication_id;out_candidate_id:=pub_row.candidate_id; RETURN NEXT;
 END LOOP;
 UPDATE knowledge_candidates SET state='withdrawn' WHERE candidate_id=ANY(candidate_ids);
 UPDATE knowledge_sources SET withdrawn=true WHERE (tenant_id,domain,source_id,version)=(caller_tenant,caller_domain,p_source_id,p_version);
END $$;
REVOKE ALL ON FUNCTION invalidate_knowledge_source(TEXT,TEXT,TEXT,TIMESTAMPTZ) FROM PUBLIC;

CREATE FUNCTION read_authorized_knowledge_candidate(p_candidate_id UUID) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,__GOVERNANCE_SCHEMA__ AS $$
DECLARE candidate_row RECORD; pub_row RECORD; claim_row RECORD; subject_row RECORD; object_row RECORD;
        linked_count INT; admitted_count INT; bound_count INT; valid_count INT; evidence_payload JSONB;
        caller_tenant TEXT:=current_setting('app.tenant',true); caller_domain TEXT:=current_setting('app.domain',true);
        caller_subjects TEXT[]:=COALESCE(nullif(current_setting('app.subjects',true),'')::text[],ARRAY[]::text[]);
        caller_purposes TEXT[]:=COALESCE(nullif(current_setting('app.purposes',true),'')::text[],ARRAY[]::text[]);
        caller_subject TEXT:=current_setting('app.subject',true);
        caller_roles TEXT[]:=COALESCE(nullif(current_setting('app.roles',true),'')::text[],ARRAY[]::text[]);
BEGIN
 IF NOT COALESCE(caller_subject=ANY(caller_subjects),false) OR EXISTS(
   SELECT 1 FROM unnest(caller_subjects) token WHERE token IS DISTINCT FROM caller_subject
   AND (token IS DISTINCT FROM caller_domain||':restricted-candidate' OR NOT ('knowledge_processor'=ANY(caller_roles)))) THEN
   RAISE EXCEPTION 'authenticated subject or processing scope invalid' USING ERRCODE='42501';
 END IF;

 -- Lock every actual source before reading candidate state or checking ACLs.
 -- FOR SHARE conflicts with withdrawal's FOR UPDATE and stays held until the
 -- caller transaction ends, including after this function returns. Stable
 -- identity order avoids opposite source acquisition order across candidates.
 PERFORM s.source_id FROM knowledge_sources s
 WHERE (s.tenant_id,s.domain)=(caller_tenant,caller_domain) AND EXISTS(
   SELECT 1 FROM candidate_evidence_links l JOIN knowledge_evidence e USING(evidence_id)
   WHERE l.candidate_id=p_candidate_id
   AND (e.tenant_id,e.domain,e.source_id,e.version)=(s.tenant_id,s.domain,s.source_id,s.version))
 ORDER BY s.tenant_id,s.domain,s.source_id,s.version FOR SHARE OF s;

 SELECT * INTO candidate_row FROM knowledge_candidates c WHERE c.candidate_id=p_candidate_id
 AND (c.tenant_id,c.domain)=(caller_tenant,caller_domain);
 IF candidate_row IS NULL THEN
   RAISE EXCEPTION 'candidate context access denied' USING ERRCODE='42501';
 END IF;

 IF candidate_row.acl && caller_subjects AND candidate_row.purpose=ANY(caller_purposes) THEN
   SELECT count(*) INTO linked_count FROM candidate_evidence_links l WHERE l.candidate_id=p_candidate_id;
   SELECT count(*) INTO admitted_count FROM candidate_evidence_links l JOIN knowledge_evidence e USING(evidence_id)
   JOIN knowledge_sources s ON (s.tenant_id,s.domain,s.source_id,s.version)=(e.tenant_id,e.domain,e.source_id,e.version)
   WHERE l.candidate_id=p_candidate_id AND (s.tenant_id,s.domain)=(caller_tenant,caller_domain)
   AND s.purpose=candidate_row.purpose AND e.purpose=candidate_row.purpose AND l.purpose=candidate_row.purpose
   AND s.acl && caller_subjects AND e.acl && caller_subjects AND l.acl && caller_subjects
   AND candidate_row.acl<@s.acl AND candidate_row.acl<@e.acl AND candidate_row.acl<@l.acl
   AND NOT s.withdrawn AND s.observed_at<=CURRENT_TIMESTAMP AND s.retention_until>CURRENT_TIMESTAMP;
   IF linked_count=0 OR linked_count<>admitted_count THEN
     RAISE EXCEPTION 'candidate source access denied or source inactive' USING ERRCODE='42501';
   END IF;
 ELSE
   SELECT * INTO pub_row FROM knowledge_publications p
   WHERE (p.tenant_id,p.domain,p.candidate_id)=(caller_tenant,caller_domain,p_candidate_id)
     AND p.candidate_version=candidate_row.candidate_version
   ORDER BY p.published_at DESC, p.publication_id DESC LIMIT 1;

   IF pub_row IS NULL
   OR EXISTS(SELECT 1 FROM knowledge_tombstones t WHERE (t.tenant_id,t.domain,t.publication_id)=(caller_tenant,caller_domain,pub_row.publication_id))
   OR pub_row.valid_until<=CURRENT_TIMESTAMP
   OR NOT (caller_subject=ANY(pub_row.consumer_audiences))
   OR NOT (pub_row.intended_use=ANY(caller_purposes)) THEN
     RAISE EXCEPTION 'candidate context access denied' USING ERRCODE='42501';
   END IF;

   SELECT count(*) INTO bound_count FROM knowledge_publication_sources ps WHERE ps.publication_id=pub_row.publication_id;
   SELECT count(*) INTO valid_count FROM knowledge_publication_sources ps
   JOIN knowledge_sources s ON (s.tenant_id,s.domain,s.source_id,s.version)=(ps.tenant_id,ps.domain,ps.source_id,ps.source_version)
   JOIN knowledge_governance_versions g ON (g.tenant_id,g.domain,g.source_id,g.source_version,g.governance_version_id)=
                                          (ps.tenant_id,ps.domain,ps.source_id,ps.source_version,ps.governance_version_id)
   WHERE ps.publication_id=pub_row.publication_id
     AND (s.tenant_id,s.domain)=(caller_tenant,caller_domain)
     AND NOT s.withdrawn AND s.observed_at<=CURRENT_TIMESTAMP AND s.retention_until>CURRENT_TIMESTAMP
     AND g.valid_from<=CURRENT_TIMESTAMP AND g.valid_until>CURRENT_TIMESTAMP
     AND NOT EXISTS (SELECT 1 FROM knowledge_governance_versions n WHERE n.supersedes_version_id=g.governance_version_id);

   IF bound_count=0 OR bound_count<>valid_count THEN
     RAISE EXCEPTION 'candidate source access denied or source inactive' USING ERRCODE='42501';
   END IF;
 END IF;

 SELECT * INTO claim_row FROM knowledge_claims k WHERE k.claim_id=candidate_row.claim_id
 AND (k.tenant_id,k.domain)=(caller_tenant,caller_domain);
 SELECT * INTO subject_row FROM knowledge_entities e WHERE e.entity_id=claim_row.subject_id
 AND (e.tenant_id,e.domain)=(caller_tenant,caller_domain);
 SELECT * INTO object_row FROM knowledge_entities e WHERE e.entity_id=claim_row.object_id
 AND (e.tenant_id,e.domain)=(caller_tenant,caller_domain);
 IF claim_row IS NULL OR subject_row IS NULL OR object_row IS NULL THEN
   RAISE EXCEPTION 'candidate descriptor missing' USING ERRCODE='23514';
 END IF;
 SELECT jsonb_agg(jsonb_build_object('source',jsonb_build_object(
   'tenant_id',s.tenant_id,'domain',s.domain,'source_id',s.source_id,'version',s.version,
   'source_kind',s.source_kind,'acl',s.acl,'purpose',s.purpose,'observed_at',s.observed_at,
   'retention_until',s.retention_until,'independence_verified',s.independence_verified),
   'content_sha256',e.content_sha256,'start',e.char_start,'end',e.char_end)
   ORDER BY s.source_id,e.char_start) INTO evidence_payload
 FROM candidate_evidence_links l JOIN knowledge_evidence e USING(evidence_id) JOIN knowledge_sources s
 ON (s.tenant_id,s.domain,s.source_id,s.version)=(e.tenant_id,e.domain,e.source_id,e.version)
 WHERE l.candidate_id=p_candidate_id;
 RETURN jsonb_build_object('candidate_id',candidate_row.candidate_id,'state',candidate_row.state,
   'acl',candidate_row.acl,'purpose',candidate_row.purpose,'rejection_reason',candidate_row.rejection_reason,
   'claim',jsonb_build_object('predicate',claim_row.predicate,'polarity',claim_row.polarity,'modality',claim_row.modality,
     'subject',jsonb_build_object('entity_id',subject_row.entity_id,'tenant_id',subject_row.tenant_id,'domain',subject_row.domain,
       'entity_type',subject_row.entity_type,'name',subject_row.name),
     'object',jsonb_build_object('entity_id',object_row.entity_id,'tenant_id',object_row.tenant_id,'domain',object_row.domain,
       'entity_type',object_row.entity_type,'name',object_row.name)),
   'evidence',evidence_payload);
END $$;
REVOKE ALL ON FUNCTION read_authorized_knowledge_candidate(UUID) FROM PUBLIC;
"""

_ASSET_TABLES = ('knowledge_sources','knowledge_entities','knowledge_evidence','knowledge_claims',
 'knowledge_candidates','candidate_evidence_links','knowledge_publications',
 'knowledge_tombstones','knowledge_outbox','consumer_receipts','knowledge_observations',
 'knowledge_consumer_assets')
_ADMIN_TABLES = ('knowledge_admin_actions','knowledge_governance_versions','knowledge_publication_sources')
_SCOPE_POLICY = """tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[]))"""
_ADMIN_POLICY = ("current_user = __ADMIN_ROLE__ "
 "AND nullif(current_setting('app.admin_context',true),'') = 'true' "
 "AND tenant_id = nullif(current_setting('app.tenant',true),'') "
 "AND domain = nullif(current_setting('app.domain',true),'')")
RLS_SETUP_SQL = '\n'.join(
 [f'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; ALTER TABLE {table} FORCE ROW LEVEL SECURITY; '
  f'CREATE POLICY governed_access ON {table} USING ({_SCOPE_POLICY}) WITH CHECK ({_SCOPE_POLICY}); '
  f'CREATE POLICY admin_access ON {table} USING ({_ADMIN_POLICY}) WITH CHECK ({_ADMIN_POLICY});'
  for table in _ASSET_TABLES]
 + [f'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; ALTER TABLE {table} FORCE ROW LEVEL SECURITY; '
    f'CREATE POLICY admin_access ON {table} USING ({_ADMIN_POLICY}) WITH CHECK ({_ADMIN_POLICY});'
    for table in _ADMIN_TABLES])


class PostgresKnowledgeStorage:
    """Relational knowledge repository implementing K-04, K-12, K-14."""

    def __init__(self, connection_uri: str, *, tenant_id: str | None = None, domain: str | None = None,
                 admin_dsn: str | None = None, admin_role: str | None = None) -> None:
        self.connection_uri = connection_uri
        self.tenant_id = tenant_id
        self.domain = domain
        self.admin_dsn = admin_dsn
        self.admin_role = admin_role

    def init_database(self, *, enable_rls: bool = True, application_role: str | None = None,
                      admin_role: str | None = None) -> str:
        """Create the v2 schema objects and optionally set up Row Level Security.

        Returns the measured schema fingerprint of the freshly deployed namespace.
        Grants for the schema-bound application and dedicated admin roles are
        applied when the corresponding role names are supplied.
        """
        admin_role = admin_role or self.admin_role
        with psycopg.connect(self.connection_uri, autocommit=True) as conn:
            with conn.cursor() as cur:
                owner=cur.execute('SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user').fetchone()
                if not owner or not owner[0]:
                    raise KnowledgeError('fixed governed functions require a controlled RLS-bypassing owner; application roles must not bypass')
                schema=cur.execute('SELECT current_schema()').fetchone()[0]
                admin_literal = sql.Literal(admin_role).as_string(conn) if admin_role else "''"
                cur.execute(SCHEMA_SQL.replace('__GOVERNANCE_SCHEMA__',sql.Identifier(schema).as_string(conn))
                                        .replace('__ADMIN_ROLE__',admin_literal))
                if enable_rls:
                    cur.execute(RLS_SETUP_SQL.replace('__ADMIN_ROLE__',admin_literal))
                if application_role:
                    cur.execute(sql.SQL('GRANT USAGE ON SCHEMA {} TO {}').format(sql.Identifier(schema),sql.Identifier(application_role)))
                    cur.execute(sql.SQL('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {}').format(sql.Identifier(schema),sql.Identifier(application_role)))
                    cur.execute(sql.SQL('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {} TO {}').format(sql.Identifier(schema),sql.Identifier(application_role)))
                    for function in ("invalidate_knowledge_source(TEXT,TEXT,TEXT,TIMESTAMPTZ)", "read_authorized_knowledge_candidate(UUID)"):
                        cur.execute(sql.SQL('GRANT EXECUTE ON FUNCTION {}.' + function + ' TO {}').format(sql.Identifier(schema),sql.Identifier(application_role)))
                return compute_schema_fingerprint(conn, admin_role=admin_role or '')

    def verify_schema(self, conn: psycopg.Connection) -> None:
        """Refuse to run against a schema whose metadata fingerprint drifted from v2."""
        actual = compute_schema_fingerprint(conn, admin_role=self.admin_role or '')
        if actual != SCHEMA_FINGERPRINT_V2:
            raise KnowledgeSchemaError(
                f'schema fingerprint mismatch: expected {SCHEMA_FINGERPRINT_V2}, measured {actual}')

    @contextmanager
    def admin_transaction(self, *, tenant_id: str, domain: str) -> Iterator[psycopg.Connection]:
        """One governed admin transaction on the dedicated admin connection.

        The connection adopts the dedicated admin role and binds the transaction
        local app.tenant/app.domain/app.admin_context='true' GUCs; the v2 schema
        fingerprint is verified before the transaction body runs.
        """
        if not self.admin_dsn:
            raise KnowledgeError('admin transactions require a configured admin_dsn')
        conn = psycopg.connect(self.admin_dsn)
        try:
            if self.admin_role:
                conn.execute(sql.SQL('SET LOCAL ROLE {}').format(sql.Identifier(self.admin_role)))
            conn.execute("SELECT set_config('app.tenant',%s,true)", (tenant_id,))
            conn.execute("SELECT set_config('app.domain',%s,true)", (domain,))
            conn.execute("SELECT set_config('app.admin_context','true',true)")
            self.verify_schema(conn)
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def set_session_identity(self, conn: psycopg.Connection, actor: TrustedActor,
                             *, processing_acl: tuple[str, ...] = ()) -> None:
        """Install only authenticated service context, transaction-local and fail closed.

        processing_acl is for a trusted processing service reading isolated candidates;
        it is never inferred for ordinary readers.
        """
        if processing_acl and (Role.KNOWLEDGE_PROCESSOR not in actor.roles or
                               any(token != f'{actor.domain}:restricted-candidate' for token in processing_acl)):
            raise KnowledgeError('processing access requires the authenticated processor role and exact restricted domain token')
        with conn.cursor() as cur:
            for key, value in (('tenant',actor.tenant_id),('domain',actor.domain),
                               ('subjects',list((actor.subject_id,*processing_acl))),('purposes',list(actor.purposes)),
                               ('subject',actor.subject_id),('roles',[role.value for role in actor.roles])):
                if isinstance(value,list):
                    cur.execute("SELECT set_config(%s, %s::text[]::text, true)",('app.'+key,value))
                else:
                    cur.execute("SELECT set_config(%s, %s, true)",('app.'+key,value))

    def save_source(self, conn: psycopg.Connection, source: Source) -> None:
        """Persist a trusted source. Fails if invalid."""
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO knowledge_sources (
                    tenant_id, domain, source_id, version, source_kind,
                    acl, purpose, observed_at, retention_until, independence_verified
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, domain, source_id, version) DO NOTHING
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
                    source.independence_verified,
                ),
            )
            row=cur.execute('''SELECT source_kind,acl,purpose,observed_at,retention_until,independence_verified,withdrawn
                FROM knowledge_sources WHERE (tenant_id,domain,source_id,version)=(%s,%s,%s,%s)''',source.key).fetchone()
            expected=(source.source_kind.value,set(source.acl),source.purpose,source.observed_at,source.retention_until,source.independence_verified,False)
            actual=(row[0],set(row[1]),*row[2:]) if row else None
            if actual!=expected:
                raise KnowledgeError('source metadata changes require a new version; withdrawn sources cannot revive')

    def save_entity(self, conn: psycopg.Connection, entity: Entity, acl: frozenset[str], purpose: str) -> None:
        """Persist an entity definition."""
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO knowledge_entities (
                    entity_id, tenant_id, domain, entity_type, name, acl, purpose
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, domain, entity_type, name) DO NOTHING
                """,
                (
                    entity.entity_id,
                    entity.tenant_id,
                    entity.domain,
                    entity.entity_type,
                    entity.name, list(acl), purpose,
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
                    content_sha256, char_start, char_end, acl, purpose
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id,domain,source_id,version,content_sha256,char_start,char_end)
                DO UPDATE SET content_sha256=EXCLUDED.content_sha256 RETURNING evidence_id
                """,
                (
                    evidence.source.tenant_id,
                    evidence.source.domain,
                    evidence.source.source_id,
                    evidence.source.version,
                    evidence.content_sha256,
                    evidence.start,
                    evidence.end, list(evidence.source.acl), evidence.source.purpose,
                ),
            )
            row = cur.fetchone()
            if not row:
                raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "failed to insert evidence")
            return row[0]

    def save_claim(self, conn: psycopg.Connection, claim: Claim, acl: frozenset[str], purpose: str) -> UUID:
        """Persist a semantic relation claim between two entities."""
        self.save_entity(conn, claim.subject, acl, purpose)
        self.save_entity(conn, claim.object, acl, purpose)
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO knowledge_claims (
                    tenant_id, domain, subject_id, predicate, object_id, polarity, modality, acl, purpose
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
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
                    claim.modality.value, list(acl), purpose,
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
        if not candidate.evidence or candidate.purpose != candidate.evidence[0].source.purpose or candidate.state != CandidateState.PROPOSED:
            raise KnowledgeError('only evidence-backed proposed candidates can be inserted')
        if any((ev.source.tenant_id,ev.source.domain,ev.source.purpose) !=
               (candidate.claim.subject.tenant_id,candidate.claim.subject.domain,candidate.purpose) for ev in candidate.evidence):
            raise KnowledgeError('candidate evidence scope mismatch')
        if not candidate.acl or not candidate.acl <= frozenset.intersection(*(ev.source.acl for ev in candidate.evidence)):
            raise KnowledgeError('candidate ACL exceeds sources')
        claim_id = self.save_claim(conn, candidate.claim, candidate.acl, candidate.purpose)
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO knowledge_candidates (
                    candidate_id, claim_id, tenant_id, domain,
                    acl, purpose, state, rejection_reason
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (candidate_id) DO NOTHING
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
                        INSERT INTO candidate_evidence_links (candidate_id, evidence_id,tenant_id,domain,acl,purpose)
                        VALUES (%s, %s,%s,%s,%s,%s)
                        ON CONFLICT DO NOTHING
                        """,
                        (candidate.candidate_id, eid,candidate.claim.subject.tenant_id,candidate.claim.subject.domain,list(candidate.acl),candidate.purpose),
                    )
        return claim_id

    def publish_transactional(
        self,
        *,
        candidate_id: UUID,
        candidate_version: int,
        intended_use: str,
        consumer_audiences: list[str] | tuple[str, ...],
        valid_until: Any,
        admin_action_id: UUID,
        idempotency_key: str | None,
        source_bindings: list[tuple[str, str, UUID]] | tuple[tuple[str, str, UUID], ...],
    ) -> str:
        """Publish one candidate version bound to a succeeded publish admin action.

        The publication row, every contributing-source governance binding and the
        KNOWNLEDGE_PUBLISHED outbox event commit atomically through the dedicated
        admin connection. Retrying with the same idempotency key returns the
        committed publication_id without producing a duplicate outbox event.
        """
        if not (self.admin_dsn and self.admin_role and self.tenant_id and self.domain):
            raise KnowledgeError('publication requires a bound admin connection, admin role and tenant/domain scope')
        try:
            with self.admin_transaction(tenant_id=self.tenant_id, domain=self.domain) as conn:
                return self.publish_in_transaction(
                    conn, candidate_id=candidate_id, candidate_version=candidate_version,
                    intended_use=intended_use, consumer_audiences=consumer_audiences,
                    valid_until=valid_until, admin_action_id=admin_action_id,
                    idempotency_key=idempotency_key, source_bindings=source_bindings)
        except psycopg.errors.UniqueViolation:
            if idempotency_key is None:
                raise
        # A concurrent retry of the same idempotent request won the unique index;
        # return the already-committed publication instead of raising.
        with self.admin_transaction(tenant_id=self.tenant_id, domain=self.domain) as conn:
            row = conn.execute(
                'SELECT publication_id FROM knowledge_publications '
                'WHERE candidate_id=%s AND candidate_version=%s AND idempotency_key=%s',
                (candidate_id, candidate_version, idempotency_key)).fetchone()
        if row is None:
            raise KnowledgeError('publication idempotency conflict without a committed publication')
        return str(row[0])

    def publish_in_transaction(
        self, conn: psycopg.Connection, *, candidate_id: UUID, candidate_version: int,
        intended_use: str, consumer_audiences: list[str] | tuple[str, ...],
        valid_until: Any, admin_action_id: UUID, idempotency_key: str | None,
        source_bindings: list[tuple[str, str, UUID]] | tuple[tuple[str, str, UUID], ...],
    ) -> str:
        """Write publication, bindings and outbox in the caller's admin transaction.

        The caller owns locking, admission and the action record. No commit or
        exception recovery may split those writes from this publication.
        """
        if not (self.admin_dsn and self.admin_role and self.tenant_id and self.domain):
            raise KnowledgeError('publication requires a bound admin connection, admin role and tenant/domain scope')
        bindings = [tuple(binding) for binding in source_bindings]
        with conn.cursor() as cur:
            if idempotency_key is not None:
                row = cur.execute(
                    'SELECT publication_id FROM knowledge_publications '
                    'WHERE candidate_id=%s AND candidate_version=%s AND idempotency_key=%s',
                    (candidate_id, candidate_version, idempotency_key)).fetchone()
                if row is not None:
                    return str(row[0])
            publication_id = uuid4()
            for source_id, source_version, governance_version_id in bindings:
                cur.execute(
                    'INSERT INTO knowledge_publication_sources(publication_id,tenant_id,domain,'
                    'source_id,source_version,governance_version_id) VALUES(%s,%s,%s,%s,%s,%s)',
                    (publication_id, self.tenant_id, self.domain, source_id, source_version,
                     governance_version_id))
            cur.execute(
                'INSERT INTO knowledge_publications(publication_id,candidate_id,claim_id,tenant_id,'
                'domain,acl,purpose,candidate_version,intended_use,consumer_audiences,published_at,'
                'valid_until,admin_action_id,idempotency_key) '
                'SELECT %s,c.candidate_id,c.claim_id,c.tenant_id,c.domain,%s,%s,%s,%s,%s,'
                'clock_timestamp(),%s,%s,%s FROM knowledge_candidates c WHERE c.candidate_id=%s',
                (publication_id, list(consumer_audiences), intended_use, candidate_version,
                 intended_use, list(consumer_audiences), valid_until, admin_action_id,
                 idempotency_key, candidate_id))
            if cur.rowcount != 1:
                raise KnowledgeError('publication candidate version unavailable')
            payload = {
                'publication_id': str(publication_id),
                'candidate_id': str(candidate_id),
                'candidate_version': candidate_version,
                'intended_use': intended_use,
                'consumer_audiences': list(consumer_audiences),
                'governance_version_ids': [str(binding[2]) for binding in bindings],
                'asset_lineage': {
                    'source_bindings': [
                        {'source_id': str(source_id), 'source_version': str(source_version),
                         'governance_version_id': str(governance_version_id)}
                        for source_id, source_version, governance_version_id in bindings]},
                'valid_until': valid_until.isoformat(),
            }
            cur.execute(
                'INSERT INTO knowledge_outbox(event_type,aggregate_type,aggregate_id,tenant_id,domain,'
                'acl,purpose,payload,status) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                ('KNOWLEDGE_PUBLISHED', 'Publication', publication_id, self.tenant_id, self.domain,
                 list(consumer_audiences), intended_use, json.dumps(payload), 'pending'))
            return str(publication_id)

    def revoke_transactional(
        self,
        conn: psycopg.Connection,
        tombstone: Tombstone,
    ) -> None:
        """Revoke a publication and write outbox tombstone in ONE transaction (K-12, K-13)."""
        with conn.cursor() as cur:
            role_row = cur.execute("SELECT current_setting('app.roles',true)::text[]").fetchone()
            if not role_row or Role.DATA_STEWARD.value not in (role_row[0] or []) or not tombstone.reason.strip():
                raise KnowledgeError('revocation requires authenticated stewardship')
            # 1. Update candidate state to withdrawn
            cur.execute(
                """
                UPDATE knowledge_candidates
                SET state = %s, updated_at = CURRENT_TIMESTAMP
                WHERE candidate_id = %s
                """,
                (CandidateState.WITHDRAWN.value, tombstone.candidate_id),
            )
            cur.execute('UPDATE knowledge_consumer_assets SET active=false WHERE publication_id=%s',
                        (tombstone.publication_id,))
            # 2. Insert tombstone
            cur.execute(
                """
                INSERT INTO knowledge_tombstones (
                    publication_id, candidate_id, tenant_id, domain, reason, effective_at,acl,purpose
                ) SELECT %s,%s,%s,%s,%s,%s,acl,purpose FROM knowledge_publications WHERE publication_id=%s
                ON CONFLICT(publication_id) DO NOTHING
                """,
                (
                    tombstone.publication_id,
                    tombstone.candidate_id,
                    tombstone.tenant_id,
                    tombstone.domain,
                    tombstone.reason,
                    tombstone.effective_at, tombstone.publication_id,
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
                    domain, payload, status,acl,purpose
                ) SELECT %s,%s,%s,%s,%s,%s,%s,acl,purpose FROM knowledge_publications WHERE publication_id=%s
                ON CONFLICT(aggregate_id,event_type) DO NOTHING
                """,
                (
                    "KNOWLEDGE_REVOKED",
                    "Publication",
                    tombstone.publication_id,
                    tombstone.tenant_id,
                    tombstone.domain,
                    json.dumps(outbox_payload),
                    "pending", tombstone.publication_id,
                ),
            )

    def record_consumer_receipt(self, conn: psycopg.Connection, consumer_id: str,
                                event_id: UUID, domain: str, action: str) -> None:
        """Idempotent durable acknowledgment, called after actual consumer application."""
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO consumer_receipts(consumer_id,event_id,tenant_id,domain,acl,purpose,action,status)
                SELECT %s,outbox_id,tenant_id,domain,acl,purpose,%s,'confirmed'
                FROM knowledge_outbox WHERE outbox_id=%s AND domain=%s
                ON CONFLICT(consumer_id,event_id,action) DO NOTHING""",(consumer_id,action,event_id,domain))

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

    def load_candidate(self, conn: psycopg.Connection, candidate_id: UUID) -> Candidate:
        """Read normalized semantics only within an authorized candidate context.

        Shared descriptors retain their original RLS; they are not broadened to
        service all later candidate audiences. The fixed database function first
        locks every contributing source before authorization. The caller's
        transaction retains those locks through commit, so source withdrawal
        cannot commit halfway through the authorized descriptor read.
        """
        try:
            payload=conn.execute('SELECT read_authorized_knowledge_candidate(%s)',(candidate_id,)).fetchone()[0]
        except psycopg.errors.InsufficientPrivilege:
            raise KnowledgeError('candidate unavailable to actor or source inactive') from None
        from datetime import datetime
        def entity(e):
            return Entity(UUID(e['entity_id']),e['tenant_id'],e['domain'],e['entity_type'],e['name'])
        try:
            c=payload['claim']
            claim=Claim(entity(c['subject']),Predicate(c['predicate']),entity(c['object']),Polarity(c['polarity']),Modality(c['modality']))
            evidence=[]
            for item in payload['evidence']:
                source=item['source']
                evidence.append(Evidence(Source(source['tenant_id'],source['domain'],source['source_id'],source['version'],
                    SourceKind(source['source_kind']),frozenset(source['acl']),source['purpose'],
                    datetime.fromisoformat(source['observed_at']),datetime.fromisoformat(source['retention_until']),
                    source['independence_verified']),item['content_sha256'],item['start'],item['end']))
            return Candidate(UUID(payload['candidate_id']),claim,tuple(evidence),frozenset(payload['acl']),payload['purpose'],
                             CandidateState(payload['state']),rejection_reason=payload['rejection_reason'])
        except (ValueError,TypeError,KeyError):
            raise KnowledgeError('invalid authoritative candidate contract') from None

    def reject_transactional(self, conn: psycopg.Connection, candidate_id: UUID, reason: str) -> None:
        if not reason.strip():
            raise KnowledgeError('rejection requires reason')
        row=conn.execute("UPDATE knowledge_candidates SET state='rejected',rejection_reason=%s,updated_at=CURRENT_TIMESTAMP WHERE candidate_id=%s AND state='proposed' RETURNING candidate_id",
                         (reason,candidate_id)).fetchone()
        if row is None:
            raise KnowledgeError('only authoritative proposed candidates can be rejected')

    def load_publication(self, conn: psycopg.Connection, publication_id: UUID) -> Publication:
        row = conn.cursor(row_factory=dict_row).execute('SELECT * FROM knowledge_publications WHERE publication_id=%s',
                           (publication_id,)).fetchone()
        if row is None or conn.execute('SELECT 1 FROM knowledge_tombstones WHERE publication_id=%s',(publication_id,)).fetchone():
            raise KnowledgeError('publication unavailable or withdrawn')
        candidate = self.load_candidate(conn,row['candidate_id'])
        if candidate.state != CandidateState.PUBLISHED:
            raise KnowledgeError('publication candidate inactive')
        return Publication(publication_id,candidate.candidate_id,candidate.claim,candidate.evidence,
            frozenset(row['acl']),row['purpose'],row['published_at'],row['valid_until'])

    def invalidate_source(self, conn: psycopg.Connection, source: Source, reason: str, now) -> tuple[Tombstone,...]:
        """Restricted source management channel, without granting reads of hidden derivatives.

        The fixed definer function validates the caller's source stewardship and
        returns identifiers only; cross-source assets remain under their read ACL.
        """
        rows=conn.execute('SELECT * FROM invalidate_knowledge_source(%s,%s,%s,%s)',
                          (source.source_id,source.version,reason,now)).fetchall()
        return tuple(Tombstone(row[0],row[1],source.tenant_id,source.domain,reason,now) for row in rows)

    def expire_sources(self, conn: psycopg.Connection, now) -> tuple[Tombstone,...]:
        # A batch must acquire all source locks before derivative mutation, in
        # the same identity order as candidate reads.
        rows = conn.cursor(row_factory=dict_row).execute('''SELECT * FROM knowledge_sources
            WHERE retention_until<=%s AND NOT withdrawn
            ORDER BY tenant_id,domain,source_id,version FOR UPDATE''',(now,)).fetchall()
        result=[]
        for row in rows:
            source=Source(row['tenant_id'],row['domain'],row['source_id'],row['version'],SourceKind(row['source_kind']),
                          frozenset(row['acl']),row['purpose'],row['observed_at'],row['retention_until'],row['independence_verified'])
            result.extend(self.invalidate_source(conn,source,'retention_expired',now))
        return tuple(result)
