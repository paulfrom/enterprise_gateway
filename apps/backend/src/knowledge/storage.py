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
from dataclasses import replace

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
    TrustedActor,
)

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
 updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(tenant_id,domain,claim_id) REFERENCES knowledge_claims(tenant_id,domain,claim_id),
 UNIQUE(tenant_id,domain,candidate_id));
CREATE TABLE candidate_evidence_links (
 candidate_id UUID NOT NULL,evidence_id UUID NOT NULL,tenant_id TEXT NOT NULL,domain TEXT NOT NULL,
 acl TEXT[] NOT NULL,purpose TEXT NOT NULL,PRIMARY KEY(candidate_id,evidence_id),
 FOREIGN KEY(tenant_id,domain,candidate_id) REFERENCES knowledge_candidates(tenant_id,domain,candidate_id),
 FOREIGN KEY(tenant_id,domain,evidence_id) REFERENCES knowledge_evidence(tenant_id,domain,evidence_id));
CREATE TABLE knowledge_approvals (
 approval_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),candidate_id UUID NOT NULL,
 tenant_id TEXT NOT NULL,domain TEXT NOT NULL,acl TEXT[] NOT NULL,purpose TEXT NOT NULL,
 reviewer_id TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('security_reviewer','business_reviewer')),
 verification_ref TEXT NOT NULL CHECK(length(trim(verification_ref))>0),approved_at TIMESTAMPTZ NOT NULL,
 FOREIGN KEY(tenant_id,domain,candidate_id) REFERENCES knowledge_candidates(tenant_id,domain,candidate_id),
 UNIQUE(candidate_id,reviewer_id),UNIQUE(candidate_id,role));
CREATE TABLE knowledge_publications (
 publication_id UUID PRIMARY KEY,candidate_id UUID NOT NULL,claim_id UUID NOT NULL,
 tenant_id TEXT NOT NULL,domain TEXT NOT NULL,acl TEXT[] NOT NULL,purpose TEXT NOT NULL,
 published_at TIMESTAMPTZ NOT NULL,valid_until TIMESTAMPTZ NOT NULL,
 FOREIGN KEY(tenant_id,domain,candidate_id) REFERENCES knowledge_candidates(tenant_id,domain,candidate_id),
 FOREIGN KEY(tenant_id,domain,claim_id) REFERENCES knowledge_claims(tenant_id,domain,claim_id),
 UNIQUE(candidate_id),UNIQUE(tenant_id,domain,publication_id));
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
 FOREIGN KEY(tenant_id,domain,event_id) REFERENCES knowledge_outbox(tenant_id,domain,outbox_id),
 UNIQUE(consumer_id,event_id,action));
CREATE TABLE knowledge_consumer_assets (
 consumer_id TEXT NOT NULL,publication_id UUID NOT NULL,tenant_id TEXT NOT NULL,domain TEXT NOT NULL,
 acl TEXT[] NOT NULL,purpose TEXT NOT NULL,active BOOLEAN NOT NULL,
 PRIMARY KEY(consumer_id,publication_id),
 FOREIGN KEY(tenant_id,domain,publication_id) REFERENCES knowledge_publications(tenant_id,domain,publication_id));
CREATE TABLE knowledge_observations (
 dedup_key TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,domain TEXT NOT NULL,acl TEXT[] NOT NULL,purpose TEXT NOT NULL,
 source_id TEXT NOT NULL,source_version TEXT NOT NULL,candidate_ids UUID[] NOT NULL,
 encrypted_observation BYTEA NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(tenant_id,domain,source_id,source_version) REFERENCES knowledge_sources(tenant_id,domain,source_id,version));

CREATE FUNCTION enforce_publication_admission() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE candidate_state TEXT; fact_modality TEXT; fact_predicate TEXT; approval_count INT;
        source_count INT; admitted_sources INT; earliest_deadline TIMESTAMPTZ;
        candidate_acl TEXT[]; candidate_purpose TEXT;
BEGIN
 IF NOT ('publisher'=ANY(COALESCE(nullif(current_setting('app.roles',true),'')::text[],ARRAY[]::text[]))) THEN
   RAISE EXCEPTION 'authenticated publisher required' USING ERRCODE='42501';
 END IF;
 SELECT c.state,k.modality,k.predicate,c.acl,c.purpose INTO candidate_state,fact_modality,fact_predicate,candidate_acl,candidate_purpose
 FROM knowledge_candidates c JOIN knowledge_claims k USING(claim_id)
 WHERE (c.tenant_id,c.domain,c.candidate_id,c.claim_id)=(NEW.tenant_id,NEW.domain,NEW.candidate_id,NEW.claim_id);
 SELECT count(*) INTO approval_count FROM knowledge_approvals WHERE candidate_id=NEW.candidate_id AND approved_at<=NEW.published_at;
 SELECT count(*) INTO source_count FROM candidate_evidence_links WHERE candidate_id=NEW.candidate_id;
 SELECT count(*),min(s.retention_until) INTO admitted_sources,earliest_deadline
 FROM candidate_evidence_links l JOIN knowledge_evidence e USING(evidence_id) JOIN knowledge_sources s
 ON (s.tenant_id,s.domain,s.source_id,s.version)=(e.tenant_id,e.domain,e.source_id,e.version)
 WHERE l.candidate_id=NEW.candidate_id AND NOT s.withdrawn AND s.observed_at<=NEW.published_at
 AND s.retention_until>NEW.published_at;
 IF candidate_state IS NULL OR candidate_state NOT IN ('approved','published') OR fact_modality IS DISTINCT FROM 'asserted' OR fact_predicate='co_occurs_with'
 OR approval_count<>2 OR source_count=0 OR source_count<>admitted_sources
 OR NEW.valid_until>earliest_deadline OR NEW.valid_until<=NEW.published_at
 OR NOT (NEW.acl<@candidate_acl) OR NEW.purpose IS DISTINCT FROM candidate_purpose THEN
   RAISE EXCEPTION 'verified active fact required' USING ERRCODE='23514';
 END IF;
 IF NOT EXISTS (SELECT 1 FROM candidate_evidence_links l JOIN knowledge_evidence e USING(evidence_id)
 JOIN knowledge_sources s ON (s.tenant_id,s.domain,s.source_id,s.version)=(e.tenant_id,e.domain,e.source_id,e.version)
 WHERE l.candidate_id=NEW.candidate_id AND s.source_kind<>'model_output') THEN
   RAISE EXCEPTION 'model-only evidence cannot publish' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER enforce_publication_admission BEFORE INSERT ON knowledge_publications
 FOR EACH ROW EXECUTE FUNCTION enforce_publication_admission();
CREATE FUNCTION enforce_reviewer_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.reviewer_id IS DISTINCT FROM current_setting('app.subject',true)
 OR NOT (NEW.role=ANY(COALESCE(nullif(current_setting('app.roles',true),'')::text[],ARRAY[]::text[]))) THEN
   RAISE EXCEPTION 'authenticated reviewer required' USING ERRCODE='42501';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM knowledge_candidates WHERE candidate_id=NEW.candidate_id AND state='proposed') THEN
   RAISE EXCEPTION 'proposed candidate required' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER enforce_reviewer_identity BEFORE INSERT ON knowledge_approvals
 FOR EACH ROW EXECUTE FUNCTION enforce_reviewer_identity();

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
 UPDATE knowledge_candidates SET state='withdrawn',acl=ARRAY[]::text[] WHERE candidate_id=ANY(candidate_ids);
 UPDATE knowledge_claims k SET acl=COALESCE((SELECT array_agg(token) FROM (
   SELECT token FROM knowledge_candidates c CROSS JOIN LATERAL unnest(c.acl) token
   WHERE c.claim_id=k.claim_id AND c.state NOT IN ('withdrawn','rejected') AND token=ANY(k.acl) GROUP BY token
   HAVING count(DISTINCT c.candidate_id)=(SELECT count(*) FROM knowledge_candidates c2 WHERE c2.claim_id=k.claim_id
                                          AND c2.state NOT IN ('withdrawn','rejected'))) permitted),ARRAY[]::text[])
 WHERE k.claim_id=ANY(claim_ids);
 UPDATE knowledge_entities entity SET acl=COALESCE((SELECT array_agg(token) FROM (
   SELECT token FROM knowledge_claims k CROSS JOIN LATERAL unnest(k.acl) token
   WHERE entity.entity_id IN (k.subject_id,k.object_id) AND cardinality(k.acl)>0 AND token=ANY(entity.acl) GROUP BY token
   HAVING count(DISTINCT k.claim_id)=(SELECT count(*) FROM knowledge_claims k2 WHERE entity.entity_id IN (k2.subject_id,k2.object_id)
                                      AND cardinality(k2.acl)>0)) permitted),ARRAY[]::text[])
 WHERE entity.entity_id=ANY(entity_ids);
 UPDATE candidate_evidence_links SET acl=ARRAY[]::text[] WHERE candidate_id=ANY(candidate_ids);
 UPDATE knowledge_approvals SET acl=ARRAY[]::text[] WHERE candidate_id=ANY(candidate_ids);
 UPDATE knowledge_publications SET acl=ARRAY[]::text[] WHERE candidate_id=ANY(candidate_ids);
 UPDATE knowledge_evidence SET acl=ARRAY[]::text[] WHERE (tenant_id,domain,source_id,version)=(caller_tenant,caller_domain,p_source_id,p_version);
 UPDATE knowledge_observations SET acl=ARRAY[]::text[] WHERE (tenant_id,domain,source_id,source_version)=(caller_tenant,caller_domain,p_source_id,p_version);
 UPDATE knowledge_sources SET withdrawn=true WHERE (tenant_id,domain,source_id,version)=(caller_tenant,caller_domain,p_source_id,p_version);
END $$;
REVOKE ALL ON FUNCTION invalidate_knowledge_source(TEXT,TEXT,TEXT,TIMESTAMPTZ) FROM PUBLIC;

CREATE FUNCTION read_authorized_knowledge_candidate(p_candidate_id UUID) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,__GOVERNANCE_SCHEMA__ AS $$
DECLARE candidate_row RECORD; claim_row RECORD; subject_row RECORD; object_row RECORD;
        linked_count INT; admitted_count INT; evidence_payload JSONB; approval_payload JSONB;
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
 IF candidate_row IS NULL OR NOT (candidate_row.acl && caller_subjects)
 OR NOT (candidate_row.purpose=ANY(caller_purposes)) THEN
   RAISE EXCEPTION 'candidate context access denied' USING ERRCODE='42501';
 END IF;
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
 SELECT COALESCE(jsonb_agg(jsonb_build_object('reviewer_id',a.reviewer_id,'role',a.role,
   'verification_ref',a.verification_ref,'approved_at',a.approved_at)
   ORDER BY CASE a.role WHEN 'security_reviewer' THEN 0 ELSE 1 END),'[]'::jsonb) INTO approval_payload
 FROM knowledge_approvals a WHERE a.candidate_id=p_candidate_id;
 RETURN jsonb_build_object('candidate_id',candidate_row.candidate_id,'state',candidate_row.state,
   'acl',candidate_row.acl,'purpose',candidate_row.purpose,'rejection_reason',candidate_row.rejection_reason,
   'claim',jsonb_build_object('predicate',claim_row.predicate,'polarity',claim_row.polarity,'modality',claim_row.modality,
     'subject',jsonb_build_object('entity_id',subject_row.entity_id,'tenant_id',subject_row.tenant_id,'domain',subject_row.domain,
       'entity_type',subject_row.entity_type,'name',subject_row.name),
     'object',jsonb_build_object('entity_id',object_row.entity_id,'tenant_id',object_row.tenant_id,'domain',object_row.domain,
       'entity_type',object_row.entity_type,'name',object_row.name)),
   'evidence',evidence_payload,'approvals',approval_payload);
END $$;
REVOKE ALL ON FUNCTION read_authorized_knowledge_candidate(UUID) FROM PUBLIC;
"""

_ASSET_TABLES = ('knowledge_sources','knowledge_entities','knowledge_evidence','knowledge_claims',
 'knowledge_candidates','candidate_evidence_links','knowledge_approvals','knowledge_publications',
 'knowledge_tombstones','knowledge_outbox','consumer_receipts','knowledge_observations','knowledge_consumer_assets')
_SCOPE_POLICY = """tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[]))"""
RLS_SETUP_SQL = '\n'.join(
 f'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY; ALTER TABLE {table} FORCE ROW LEVEL SECURITY; '
 f'CREATE POLICY governed_access ON {table} USING ({_SCOPE_POLICY}) WITH CHECK ({_SCOPE_POLICY});'
 for table in _ASSET_TABLES)


class PostgresKnowledgeStorage:
    """Relational knowledge repository implementing K-04, K-12, K-14."""

    def __init__(self, connection_uri: str) -> None:
        self.connection_uri = connection_uri

    def init_database(self, enable_rls: bool = True) -> None:
        """Create tables and optionally set up Row Level Security."""
        with psycopg.connect(self.connection_uri, autocommit=True) as conn:
            with conn.cursor() as cur:
                from psycopg import sql
                owner=cur.execute('SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user').fetchone()
                if not owner or not owner[0]:
                    raise KnowledgeError('fixed governed functions require a controlled RLS-bypassing owner; application roles must not bypass')
                schema=cur.execute('SELECT current_schema()').fetchone()[0]
                cur.execute(SCHEMA_SQL.replace('__GOVERNANCE_SCHEMA__',sql.Identifier(schema).as_string(conn)))
                if enable_rls:
                    cur.execute(RLS_SETUP_SQL)

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

    def save_approval(
        self,
        conn: psycopg.Connection,
        candidate_id: UUID,
        approval: Approval,
    ) -> None:
        """Record an approval signature."""
        with conn.cursor() as cur:
            current = cur.execute("SELECT current_setting('app.subject',true),current_setting('app.roles',true)::text[]").fetchone()
            if not current or current[0] != approval.reviewer_id or approval.role.value not in current[1] or not approval.verification_ref.strip():
                raise KnowledgeError('approval requires authenticated reviewer and verification')
            cur.execute(
                """
                INSERT INTO knowledge_approvals (
                    candidate_id, reviewer_id, role, verification_ref, approved_at,tenant_id,domain,acl,purpose
                ) SELECT %s,%s,%s,%s,%s,tenant_id,domain,acl,purpose FROM knowledge_candidates WHERE candidate_id=%s
                """,
                (
                    candidate_id,
                    approval.reviewer_id,
                    approval.role.value,
                    approval.verification_ref,
                    approval.approved_at, candidate_id,
                ),
            )
            if cur.rowcount != 1:
                raise KnowledgeError('unknown or unauthorized candidate')
            cur.execute("""UPDATE knowledge_candidates SET state='approved' WHERE candidate_id=%s
                AND state='proposed' AND (SELECT count(*) FROM knowledge_approvals WHERE candidate_id=%s)=2""",
                (candidate_id,candidate_id))

    def publish_transactional(
        self,
        conn: psycopg.Connection,
        publication: Publication,
        claim_id: UUID,
    ) -> None:
        """Publish a candidate and insert an outbox event in ONE atomic transaction (K-12)."""
        with conn.cursor() as cur:
            role_row = cur.execute("SELECT current_setting('app.roles',true)::text[]").fetchone()
            if not role_row or Role.PUBLISHER.value not in (role_row[0] or []):
                raise KnowledgeError('publication requires authenticated publisher')
            check = cur.execute("""SELECT c.state,k.modality,k.predicate,
                (SELECT count(*) FROM knowledge_approvals a WHERE a.candidate_id=c.candidate_id),
                (SELECT min(s.retention_until) FROM candidate_evidence_links l JOIN knowledge_evidence e USING(evidence_id)
                 JOIN knowledge_sources s ON (s.tenant_id,s.domain,s.source_id,s.version)=(e.tenant_id,e.domain,e.source_id,e.version)
                 WHERE l.candidate_id=c.candidate_id AND NOT s.withdrawn)
                FROM knowledge_candidates c JOIN knowledge_claims k USING(claim_id)
                WHERE c.candidate_id=%s AND c.claim_id=%s FOR UPDATE OF c""",
                (publication.candidate_id,claim_id)).fetchone()
            if not check or check[0]!='approved' or check[1]!='asserted' or check[2]=='co_occurs_with' or check[3]!=2 or not check[4] or publication.valid_until>check[4]:
                raise KnowledgeError('publication requires verified active facts and bounded retention')
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
                    domain, payload, status,acl,purpose
                ) VALUES (%s, %s, %s, %s, %s, %s, %s,%s,%s)
                """,
                (
                    "KNOWLEDGE_PUBLISHED",
                    "Publication",
                    publication.publication_id,
                    publication.claim.subject.tenant_id,
                    publication.claim.subject.domain,
                    json.dumps(outbox_payload),
                    "pending", list(publication.acl),publication.purpose,
                ),
            )

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
            approvals=tuple(Approval(a['reviewer_id'],Role(a['role']),a['verification_ref'],datetime.fromisoformat(a['approved_at']))
                            for a in payload['approvals'])
            return Candidate(UUID(payload['candidate_id']),claim,tuple(evidence),frozenset(payload['acl']),payload['purpose'],
                             CandidateState(payload['state']),approvals,payload['rejection_reason'])
        except (ValueError,TypeError,KeyError):
            raise KnowledgeError('invalid authoritative candidate contract') from None

    def reject_transactional(self, conn: psycopg.Connection, candidate_id: UUID, reason: str) -> None:
        if not reason.strip():
            raise KnowledgeError('rejection requires reason')
        roles=conn.execute("SELECT current_setting('app.roles',true)::text[]").fetchone()[0] or []
        if Role.BUSINESS_REVIEWER.value not in roles:
            raise KnowledgeError('rejection requires authenticated business reviewer')
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
