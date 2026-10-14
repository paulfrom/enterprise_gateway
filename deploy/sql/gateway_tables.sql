-- Gateway v4: manually execute in the existing shared database.
-- Database, schema, logins and service grants are managed by infrastructure.
-- Creates project tables and their required constraints, indexes, functions, trigger and policies.
-- Existing tables/data are never dropped or reset.
-- Existing knowledge administration login: gw_knowledge_admin
BEGIN;
SET LOCAL search_path TO "public";

CREATE TABLE IF NOT EXISTS entity_aliases (
 tenant_id TEXT NOT NULL, domain TEXT NOT NULL, alias_name TEXT NOT NULL,
 canonical_name TEXT NOT NULL, entity_type TEXT NOT NULL, canonical_id UUID NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(tenant_id,domain,alias_name));

CREATE TABLE IF NOT EXISTS knowledge_sources (
 tenant_id TEXT NOT NULL, domain TEXT NOT NULL, source_id TEXT NOT NULL, version TEXT NOT NULL,
 source_kind TEXT NOT NULL, acl TEXT[] NOT NULL CHECK(cardinality(acl)>0), purpose TEXT NOT NULL,
 observed_at TIMESTAMPTZ NOT NULL, retention_until TIMESTAMPTZ NOT NULL CHECK(retention_until>observed_at),
 independence_verified BOOLEAN NOT NULL DEFAULT FALSE, withdrawn BOOLEAN NOT NULL DEFAULT FALSE,
 PRIMARY KEY(tenant_id,domain,source_id,version));
CREATE TABLE IF NOT EXISTS knowledge_entities (
 entity_id UUID PRIMARY KEY, tenant_id TEXT NOT NULL, domain TEXT NOT NULL,
 entity_type TEXT NOT NULL, name TEXT NOT NULL, acl TEXT[] NOT NULL, purpose TEXT NOT NULL,
 UNIQUE(tenant_id,domain,entity_id), UNIQUE(tenant_id,domain,entity_type,name));
CREATE TABLE IF NOT EXISTS knowledge_evidence (
 evidence_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id TEXT NOT NULL, domain TEXT NOT NULL,
 source_id TEXT NOT NULL, version TEXT NOT NULL, content_sha256 CHAR(64) NOT NULL,
 char_start INT NOT NULL, char_end INT NOT NULL, acl TEXT[] NOT NULL, purpose TEXT NOT NULL,
 FOREIGN KEY(tenant_id,domain,source_id,version) REFERENCES knowledge_sources(tenant_id,domain,source_id,version),
 UNIQUE(tenant_id,domain,evidence_id), UNIQUE(tenant_id,domain,source_id,version,content_sha256,char_start,char_end),
 CHECK(char_start>=0 AND char_end>char_start));
CREATE TABLE IF NOT EXISTS knowledge_claims (
 claim_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),tenant_id TEXT NOT NULL,domain TEXT NOT NULL,
 subject_id UUID NOT NULL,predicate TEXT NOT NULL,object_id UUID NOT NULL,
 polarity TEXT NOT NULL,modality TEXT NOT NULL,acl TEXT[] NOT NULL,purpose TEXT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(tenant_id,domain,subject_id) REFERENCES knowledge_entities(tenant_id,domain,entity_id),
 FOREIGN KEY(tenant_id,domain,object_id) REFERENCES knowledge_entities(tenant_id,domain,entity_id),
 UNIQUE(tenant_id,domain,claim_id),UNIQUE(tenant_id,domain,subject_id,predicate,object_id,polarity,modality));
CREATE TABLE IF NOT EXISTS knowledge_candidates (
 candidate_id UUID PRIMARY KEY,claim_id UUID NOT NULL,tenant_id TEXT NOT NULL,domain TEXT NOT NULL,
 acl TEXT[] NOT NULL,purpose TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'proposed',rejection_reason TEXT,
 candidate_version INTEGER NOT NULL DEFAULT 1,derived_from UUID,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(tenant_id,domain,claim_id) REFERENCES knowledge_claims(tenant_id,domain,claim_id),
 UNIQUE(tenant_id,domain,candidate_id));
CREATE TABLE IF NOT EXISTS candidate_evidence_links (
 candidate_id UUID NOT NULL,evidence_id UUID NOT NULL,tenant_id TEXT NOT NULL,domain TEXT NOT NULL,
 acl TEXT[] NOT NULL,purpose TEXT NOT NULL,PRIMARY KEY(candidate_id,evidence_id),
 FOREIGN KEY(tenant_id,domain,candidate_id) REFERENCES knowledge_candidates(tenant_id,domain,candidate_id),
 FOREIGN KEY(tenant_id,domain,evidence_id) REFERENCES knowledge_evidence(tenant_id,domain,evidence_id));
CREATE TABLE IF NOT EXISTS knowledge_admin_actions (
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
CREATE TABLE IF NOT EXISTS knowledge_governance_versions (
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
CREATE TABLE IF NOT EXISTS knowledge_publications (
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
CREATE UNIQUE INDEX IF NOT EXISTS knowledge_publications_idempotency
    ON knowledge_publications(candidate_id, candidate_version, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE TABLE IF NOT EXISTS knowledge_publication_sources (
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
CREATE TABLE IF NOT EXISTS knowledge_tombstones (
 tombstone_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),publication_id UUID NOT NULL,candidate_id UUID NOT NULL,
 tenant_id TEXT NOT NULL,domain TEXT NOT NULL,acl TEXT[] NOT NULL,purpose TEXT NOT NULL,reason TEXT NOT NULL,
 effective_at TIMESTAMPTZ NOT NULL,UNIQUE(publication_id),
 FOREIGN KEY(tenant_id,domain,publication_id) REFERENCES knowledge_publications(tenant_id,domain,publication_id));
CREATE TABLE IF NOT EXISTS knowledge_outbox (
 outbox_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),event_type TEXT NOT NULL,aggregate_type TEXT NOT NULL,
 aggregate_id UUID NOT NULL,tenant_id TEXT NOT NULL,domain TEXT NOT NULL,acl TEXT[] NOT NULL,purpose TEXT NOT NULL,
 payload JSONB NOT NULL,status TEXT NOT NULL DEFAULT 'pending',
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,processed_at TIMESTAMPTZ,
 UNIQUE(tenant_id,domain,outbox_id),UNIQUE(aggregate_id,event_type));
CREATE TABLE IF NOT EXISTS consumer_receipts (
 receipt_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),consumer_id TEXT NOT NULL,event_id UUID NOT NULL,
 tenant_id TEXT NOT NULL,domain TEXT NOT NULL,acl TEXT[] NOT NULL,purpose TEXT NOT NULL,
 action TEXT NOT NULL,received_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,status TEXT NOT NULL,
 delivery_result TEXT,last_error_code TEXT,
 FOREIGN KEY(tenant_id,domain,event_id) REFERENCES knowledge_outbox(tenant_id,domain,outbox_id),
 UNIQUE(consumer_id,event_id,action));
CREATE TABLE IF NOT EXISTS knowledge_consumer_assets (
 consumer_id TEXT NOT NULL,publication_id UUID NOT NULL,tenant_id TEXT NOT NULL,domain TEXT NOT NULL,
 acl TEXT[] NOT NULL,purpose TEXT NOT NULL,active BOOLEAN NOT NULL,
 asset_version INTEGER NOT NULL DEFAULT 1,asset_kind TEXT NOT NULL,intended_use TEXT NOT NULL,
 lineage JSONB NOT NULL DEFAULT '{}',
 PRIMARY KEY(consumer_id,publication_id),
 FOREIGN KEY(tenant_id,domain,publication_id) REFERENCES knowledge_publications(tenant_id,domain,publication_id));
CREATE TABLE IF NOT EXISTS knowledge_observations (
 dedup_key TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,domain TEXT NOT NULL,acl TEXT[] NOT NULL,purpose TEXT NOT NULL,
 source_id TEXT NOT NULL,source_version TEXT NOT NULL,candidate_ids UUID[] NOT NULL,
 encrypted_observation BYTEA NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(tenant_id,domain,source_id,source_version) REFERENCES knowledge_sources(tenant_id,domain,source_id,version));

CREATE OR REPLACE FUNCTION enforce_publication_admission() RETURNS trigger LANGUAGE plpgsql AS $$
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
    IF current_user <> 'gw_knowledge_admin' THEN
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
DO $gateway_trigger$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='enforce_publication_admission' AND tgrelid=to_regclass('knowledge_publications')) THEN
  EXECUTE $gateway_trigger_statement$CREATE TRIGGER enforce_publication_admission BEFORE INSERT ON knowledge_publications
 FOR EACH ROW EXECUTE FUNCTION enforce_publication_admission();$gateway_trigger_statement$;
 END IF;
END $gateway_trigger$;

CREATE OR REPLACE FUNCTION invalidate_knowledge_source(p_source_id TEXT,p_version TEXT,p_reason TEXT,p_effective TIMESTAMPTZ)
RETURNS TABLE(out_publication_id UUID,out_candidate_id UUID) LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,"public" AS $$
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

CREATE OR REPLACE FUNCTION read_authorized_knowledge_candidate(p_candidate_id UUID) RETURNS JSONB
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,"public" AS $$
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

ALTER TABLE knowledge_sources ENABLE ROW LEVEL SECURITY; ALTER TABLE knowledge_sources FORCE ROW LEVEL SECURITY; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='governed_access' AND polrelid=to_regclass('knowledge_sources')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY governed_access ON knowledge_sources USING (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[]))) WITH CHECK (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[])));$gateway_policy_statement$;
 END IF;
END $gateway_policy$; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='admin_access' AND polrelid=to_regclass('knowledge_sources')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY admin_access ON knowledge_sources USING (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),'')) WITH CHECK (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),''));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE knowledge_entities ENABLE ROW LEVEL SECURITY; ALTER TABLE knowledge_entities FORCE ROW LEVEL SECURITY; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='governed_access' AND polrelid=to_regclass('knowledge_entities')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY governed_access ON knowledge_entities USING (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[]))) WITH CHECK (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[])));$gateway_policy_statement$;
 END IF;
END $gateway_policy$; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='admin_access' AND polrelid=to_regclass('knowledge_entities')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY admin_access ON knowledge_entities USING (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),'')) WITH CHECK (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),''));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE knowledge_evidence ENABLE ROW LEVEL SECURITY; ALTER TABLE knowledge_evidence FORCE ROW LEVEL SECURITY; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='governed_access' AND polrelid=to_regclass('knowledge_evidence')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY governed_access ON knowledge_evidence USING (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[]))) WITH CHECK (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[])));$gateway_policy_statement$;
 END IF;
END $gateway_policy$; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='admin_access' AND polrelid=to_regclass('knowledge_evidence')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY admin_access ON knowledge_evidence USING (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),'')) WITH CHECK (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),''));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE knowledge_claims ENABLE ROW LEVEL SECURITY; ALTER TABLE knowledge_claims FORCE ROW LEVEL SECURITY; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='governed_access' AND polrelid=to_regclass('knowledge_claims')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY governed_access ON knowledge_claims USING (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[]))) WITH CHECK (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[])));$gateway_policy_statement$;
 END IF;
END $gateway_policy$; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='admin_access' AND polrelid=to_regclass('knowledge_claims')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY admin_access ON knowledge_claims USING (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),'')) WITH CHECK (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),''));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE knowledge_candidates ENABLE ROW LEVEL SECURITY; ALTER TABLE knowledge_candidates FORCE ROW LEVEL SECURITY; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='governed_access' AND polrelid=to_regclass('knowledge_candidates')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY governed_access ON knowledge_candidates USING (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[]))) WITH CHECK (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[])));$gateway_policy_statement$;
 END IF;
END $gateway_policy$; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='admin_access' AND polrelid=to_regclass('knowledge_candidates')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY admin_access ON knowledge_candidates USING (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),'')) WITH CHECK (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),''));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE candidate_evidence_links ENABLE ROW LEVEL SECURITY; ALTER TABLE candidate_evidence_links FORCE ROW LEVEL SECURITY; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='governed_access' AND polrelid=to_regclass('candidate_evidence_links')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY governed_access ON candidate_evidence_links USING (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[]))) WITH CHECK (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[])));$gateway_policy_statement$;
 END IF;
END $gateway_policy$; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='admin_access' AND polrelid=to_regclass('candidate_evidence_links')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY admin_access ON candidate_evidence_links USING (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),'')) WITH CHECK (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),''));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE knowledge_publications ENABLE ROW LEVEL SECURITY; ALTER TABLE knowledge_publications FORCE ROW LEVEL SECURITY; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='governed_access' AND polrelid=to_regclass('knowledge_publications')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY governed_access ON knowledge_publications USING (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[]))) WITH CHECK (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[])));$gateway_policy_statement$;
 END IF;
END $gateway_policy$; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='admin_access' AND polrelid=to_regclass('knowledge_publications')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY admin_access ON knowledge_publications USING (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),'')) WITH CHECK (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),''));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE knowledge_tombstones ENABLE ROW LEVEL SECURITY; ALTER TABLE knowledge_tombstones FORCE ROW LEVEL SECURITY; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='governed_access' AND polrelid=to_regclass('knowledge_tombstones')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY governed_access ON knowledge_tombstones USING (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[]))) WITH CHECK (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[])));$gateway_policy_statement$;
 END IF;
END $gateway_policy$; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='admin_access' AND polrelid=to_regclass('knowledge_tombstones')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY admin_access ON knowledge_tombstones USING (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),'')) WITH CHECK (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),''));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE knowledge_outbox ENABLE ROW LEVEL SECURITY; ALTER TABLE knowledge_outbox FORCE ROW LEVEL SECURITY; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='governed_access' AND polrelid=to_regclass('knowledge_outbox')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY governed_access ON knowledge_outbox USING (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[]))) WITH CHECK (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[])));$gateway_policy_statement$;
 END IF;
END $gateway_policy$; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='admin_access' AND polrelid=to_regclass('knowledge_outbox')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY admin_access ON knowledge_outbox USING (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),'')) WITH CHECK (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),''));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE consumer_receipts ENABLE ROW LEVEL SECURITY; ALTER TABLE consumer_receipts FORCE ROW LEVEL SECURITY; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='governed_access' AND polrelid=to_regclass('consumer_receipts')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY governed_access ON consumer_receipts USING (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[]))) WITH CHECK (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[])));$gateway_policy_statement$;
 END IF;
END $gateway_policy$; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='admin_access' AND polrelid=to_regclass('consumer_receipts')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY admin_access ON consumer_receipts USING (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),'')) WITH CHECK (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),''));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE knowledge_observations ENABLE ROW LEVEL SECURITY; ALTER TABLE knowledge_observations FORCE ROW LEVEL SECURITY; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='governed_access' AND polrelid=to_regclass('knowledge_observations')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY governed_access ON knowledge_observations USING (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[]))) WITH CHECK (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[])));$gateway_policy_statement$;
 END IF;
END $gateway_policy$; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='admin_access' AND polrelid=to_regclass('knowledge_observations')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY admin_access ON knowledge_observations USING (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),'')) WITH CHECK (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),''));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE knowledge_consumer_assets ENABLE ROW LEVEL SECURITY; ALTER TABLE knowledge_consumer_assets FORCE ROW LEVEL SECURITY; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='governed_access' AND polrelid=to_regclass('knowledge_consumer_assets')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY governed_access ON knowledge_consumer_assets USING (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[]))) WITH CHECK (tenant_id = nullif(current_setting('app.tenant',true),'')
 AND domain = nullif(current_setting('app.domain',true),'')
 AND acl && COALESCE(nullif(current_setting('app.subjects',true),'')::text[], ARRAY[]::text[])
 AND purpose = ANY(COALESCE(nullif(current_setting('app.purposes',true),'')::text[], ARRAY[]::text[])));$gateway_policy_statement$;
 END IF;
END $gateway_policy$; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='admin_access' AND polrelid=to_regclass('knowledge_consumer_assets')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY admin_access ON knowledge_consumer_assets USING (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),'')) WITH CHECK (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),''));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE knowledge_admin_actions ENABLE ROW LEVEL SECURITY; ALTER TABLE knowledge_admin_actions FORCE ROW LEVEL SECURITY; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='admin_access' AND polrelid=to_regclass('knowledge_admin_actions')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY admin_access ON knowledge_admin_actions USING (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),'')) WITH CHECK (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),''));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE knowledge_governance_versions ENABLE ROW LEVEL SECURITY; ALTER TABLE knowledge_governance_versions FORCE ROW LEVEL SECURITY; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='admin_access' AND polrelid=to_regclass('knowledge_governance_versions')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY admin_access ON knowledge_governance_versions USING (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),'')) WITH CHECK (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),''));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE knowledge_publication_sources ENABLE ROW LEVEL SECURITY; ALTER TABLE knowledge_publication_sources FORCE ROW LEVEL SECURITY; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='admin_access' AND polrelid=to_regclass('knowledge_publication_sources')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY admin_access ON knowledge_publication_sources USING (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),'')) WITH CHECK (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),''));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE entity_aliases ENABLE ROW LEVEL SECURITY; ALTER TABLE entity_aliases FORCE ROW LEVEL SECURITY; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='admin_access' AND polrelid=to_regclass('entity_aliases')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY admin_access ON entity_aliases USING (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),'')) WITH CHECK (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),''));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;

CREATE TABLE IF NOT EXISTS request_records (
 request_id UUID PRIMARY KEY,
 tenant_id TEXT NOT NULL,
 domain TEXT NOT NULL,
 protocol TEXT NOT NULL CHECK(protocol IN ('deepseek-chat-completions','claude-messages')),
 model TEXT NOT NULL CHECK(length(model) BETWEEN 1 AND 256),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 expires_at TIMESTAMPTZ NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('processing','completed','blocked','failed','partial')),
 error_code TEXT CHECK(error_code IS NULL OR error_code IN ('ACCESS_DENIED','ADMISSION_LIMIT_EXCEEDED','AUDIT_ACCESS_REJECTED','AUDIT_EVIDENCE_CORRUPTED','AUDIT_RECORD_NOT_FOUND','AUDIT_RECORD_UNAVAILABLE','AUDIT_WATERMARK_BLOCKED','AUDIT_WRITE_FAILED','AUTH_EXPIRED','CATEGORY_NOT_APPROVED','CLIENT_DISCONNECTED','COLLECTION_NOT_AUTHORIZED','CONTRACT_VIOLATION','CORRUPTED_PACKAGE','DATASET_CONTAMINATION','DECRYPTION_FAILED','DETECTION_FAILED','DETECTION_INCOMPLETE','DICTIONARY_CONFLICT','DICTIONARY_INVALID','DUPLICATE_JSON_KEY','DUPLICATE_POLICY_KEY','EMPTY_ENTITY','EVENT_INVALID','EVIDENCE_GATE_FAILED','FUTURE_DATED_AUTH','HISTORY_UNAVAILABLE','INFERENCE_QUEUE_FULL','INFERENCE_TIMEOUT','INTERNAL_ERROR','INTERNAL_FAILURE','INVALID_CIPHERTEXT','INVALID_CLASSIFICATION','INVALID_DETECTOR_RESULTS','INVALID_ENTITY_TYPE','INVALID_HMAC_KEY','INVALID_IDENTITY','INVALID_KEY_VERSION','INVALID_MANIFEST','INVALID_PAYLOAD','INVALID_RECOGNIZER','INVALID_REGISTRY','INVALID_SAMPLE','INVALID_SCOPE','INVALID_SPAN','INVALID_TEMPLATE','INVALID_TEXT','INVALID_TEXT_LENGTH','INVALID_UNICODE','INVALID_UPSTREAM','INVALID_UTF8','INVALID_WRAPPED_KEY','KMS_UNAVAILABLE','LOCAL_ONLY_DATA','MALFORMED_JSON','MALFORMED_TOKEN','MAPPING_LIFECYCLE','MAPPING_NOT_ACTIVE','MISSING_CATEGORY','MISSING_IDENTITY','MISSING_REQUIRED_ROLE','NER_EVALUATION_FAILED','NER_MODEL_INVALID','NER_OFFSET_UNRECOVERABLE','OBSERVABILITY_VIOLATION','POLICY_NESTING_TOO_DEEP','POLICY_NOT_JSON','POLICY_NOT_OBJECT','POLICY_REJECTED','POLICY_VALIDATION_FAILED','PROTOCOL_VIOLATION','REGISTRY_PARSE_FAILED','RELAY_SUBMIT_FAILED','RESERVED_TOKEN_LITERAL','SCOPE_MISMATCH','SECRET_DETECTED','SECRET_LEAKAGE_HARD_FAILURE','SPOOL_FULL','SPOOL_WRITE_FAILED','STREAM_FAILED','STREAM_INTERRUPTED','STREAM_PROTECTION_FAILED','STREAM_TRANSPORT_FAILED','THRESHOLD_NOT_MET','TOKEN_COLLISION','UNAPPROVED_THRESHOLDS','UNAUTHORIZED_PURPOSE','UNCLASSIFIED_DATA','UNKNOWN_CATEGORY','UNKNOWN_DETECTOR','UNKNOWN_TOKEN','UNSAFE_REPLACEMENT','UNSUPPORTED_PROTOCOL','UNTRUSTED_HEADER_REJECTED','UPSTREAM_BINDING_VIOLATION','UPSTREAM_ERROR','UPSTREAM_FAILED','UPSTREAM_FAILURE','VERSION_MISMATCH')),
 UNIQUE(tenant_id,domain,request_id),
 CHECK(expires_at>created_at)
);
CREATE INDEX IF NOT EXISTS request_records_scope_time ON request_records(tenant_id,domain,created_at DESC,request_id DESC);
CREATE INDEX IF NOT EXISTS request_records_expiry ON request_records(tenant_id,domain,expires_at);
CREATE TABLE IF NOT EXISTS request_stage_contents (
 tenant_id TEXT NOT NULL,
 domain TEXT NOT NULL,
 request_id UUID NOT NULL,
 stage TEXT NOT NULL CHECK(stage IN ('input','redacted','upstream','restored')),
 state TEXT NOT NULL CHECK(state IN ('complete','partial')),
 media_type TEXT NOT NULL CHECK(media_type IN ('application/json','text/event-stream')),
 envelope BYTEA NOT NULL,
 PRIMARY KEY(request_id,stage),
 FOREIGN KEY(tenant_id,domain,request_id) REFERENCES request_records(tenant_id,domain,request_id) ON DELETE CASCADE
);


ALTER TABLE request_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE request_records FORCE ROW LEVEL SECURITY;
ALTER TABLE request_stage_contents ENABLE ROW LEVEL SECURITY;
ALTER TABLE request_stage_contents FORCE ROW LEVEL SECURITY;
DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='history_read' AND polrelid=to_regclass('request_records')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY history_read ON request_records FOR SELECT USING (
 tenant_id=current_setting('request_history.tenant',true) AND domain=current_setting('request_history.domain',true) AND ((current_setting('request_history.mode',true) IN ('reader','writer') AND expires_at>clock_timestamp())
 OR (current_setting('request_history.mode',true)='purger' AND expires_at<=clock_timestamp())));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='history_insert' AND polrelid=to_regclass('request_records')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY history_insert ON request_records FOR INSERT WITH CHECK (
 tenant_id=current_setting('request_history.tenant',true) AND domain=current_setting('request_history.domain',true) AND current_setting('request_history.mode',true)='writer' AND status='processing' AND expires_at>clock_timestamp());$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='history_update' AND polrelid=to_regclass('request_records')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY history_update ON request_records FOR UPDATE USING (
 tenant_id=current_setting('request_history.tenant',true) AND domain=current_setting('request_history.domain',true) AND current_setting('request_history.mode',true)='writer' AND expires_at>clock_timestamp())
 WITH CHECK (tenant_id=current_setting('request_history.tenant',true) AND domain=current_setting('request_history.domain',true) AND current_setting('request_history.mode',true)='writer' AND expires_at>clock_timestamp());$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='history_purge' AND polrelid=to_regclass('request_records')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY history_purge ON request_records FOR DELETE USING (
 tenant_id=current_setting('request_history.tenant',true) AND domain=current_setting('request_history.domain',true) AND current_setting('request_history.mode',true)='purger' AND expires_at<=clock_timestamp());$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='stage_read' AND polrelid=to_regclass('request_stage_contents')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY stage_read ON request_stage_contents FOR SELECT USING (
 tenant_id=current_setting('request_history.tenant',true) AND domain=current_setting('request_history.domain',true) AND current_setting('request_history.mode',true) IN ('reader','writer') AND EXISTS (
 SELECT 1 FROM request_records r WHERE r.request_id=request_stage_contents.request_id));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='stage_insert' AND polrelid=to_regclass('request_stage_contents')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY stage_insert ON request_stage_contents FOR INSERT WITH CHECK (
 tenant_id=current_setting('request_history.tenant',true) AND domain=current_setting('request_history.domain',true) AND current_setting('request_history.mode',true)='writer' AND EXISTS (SELECT 1 FROM request_records r
 WHERE r.request_id=request_stage_contents.request_id AND r.status='processing'));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='stage_update' AND polrelid=to_regclass('request_stage_contents')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY stage_update ON request_stage_contents FOR UPDATE USING (
 tenant_id=current_setting('request_history.tenant',true) AND domain=current_setting('request_history.domain',true) AND current_setting('request_history.mode',true)='writer' AND EXISTS (SELECT 1 FROM request_records r
 WHERE r.request_id=request_stage_contents.request_id AND r.status='processing'))
 WITH CHECK (tenant_id=current_setting('request_history.tenant',true) AND domain=current_setting('request_history.domain',true) AND current_setting('request_history.mode',true)='writer' AND EXISTS (SELECT 1 FROM request_records r
 WHERE r.request_id=request_stage_contents.request_id AND r.status='processing'));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;


CREATE TABLE IF NOT EXISTS redaction_dictionary_versions (
 tenant_id TEXT NOT NULL, domain TEXT NOT NULL, revision BIGINT NOT NULL CHECK (revision > 0),
 dictionary_id TEXT NOT NULL CHECK (btrim(dictionary_id) <> ''),
 sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
 entries JSONB NOT NULL CHECK (jsonb_typeof(entries) = 'array' AND jsonb_array_length(entries) BETWEEN 1 AND 20000),
 created_by TEXT NOT NULL CHECK (btrim(created_by) <> ''), created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, domain, revision)
);
CREATE TABLE IF NOT EXISTS redaction_dictionary_state (
 tenant_id TEXT NOT NULL, domain TEXT NOT NULL,
 dictionary_id TEXT NOT NULL CHECK (btrim(dictionary_id) <> ''),
 revision BIGINT NOT NULL CHECK (revision > 0),
 published_revision BIGINT NOT NULL CHECK (published_revision > 0 AND published_revision <= revision),
 updated_by TEXT NOT NULL CHECK (btrim(updated_by) <> ''), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 PRIMARY KEY (tenant_id, domain),
 FOREIGN KEY (tenant_id, domain, published_revision) REFERENCES redaction_dictionary_versions(tenant_id, domain, revision)
);
CREATE TABLE IF NOT EXISTS redaction_dictionary_entries (
 entry_id UUID PRIMARY KEY, tenant_id TEXT NOT NULL, domain TEXT NOT NULL,
 text TEXT NOT NULL CHECK (btrim(text) <> '' AND char_length(text) <= 512),
 entity_type TEXT NOT NULL CHECK (entity_type ~ '^[A-Z][A-Z0-9_]{0,31}$'),
 enabled BOOLEAN NOT NULL DEFAULT true,
 updated_by TEXT NOT NULL CHECK (btrim(updated_by) <> ''), updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE (tenant_id, domain, text),
 FOREIGN KEY (tenant_id, domain) REFERENCES redaction_dictionary_state(tenant_id, domain)
);
CREATE INDEX IF NOT EXISTS redaction_dictionary_entries_scope ON redaction_dictionary_entries(tenant_id, domain, text, entry_id);
CREATE TABLE IF NOT EXISTS redaction_dictionary_changes (
 change_id UUID PRIMARY KEY, tenant_id TEXT NOT NULL, domain TEXT NOT NULL,
 revision BIGINT NOT NULL CHECK (revision > 0),
 action TEXT NOT NULL CHECK (action IN ('create', 'update', 'delete', 'publish')),
 entry_id UUID, actor_id TEXT NOT NULL CHECK (btrim(actor_id) <> ''),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 FOREIGN KEY (tenant_id, domain) REFERENCES redaction_dictionary_state(tenant_id, domain)
);
CREATE OR REPLACE FUNCTION enforce_dictionary_version_immutable() RETURNS trigger
 LANGUAGE plpgsql SET search_path = pg_catalog AS $dictionary_immutable$
 BEGIN
  RAISE EXCEPTION 'Published dictionary versions are immutable';
 END;
 $dictionary_immutable$;
DO $gateway_trigger$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='dictionary_version_immutable' AND tgrelid=to_regclass('redaction_dictionary_versions')) THEN
  EXECUTE $gateway_trigger_statement$CREATE TRIGGER dictionary_version_immutable BEFORE UPDATE OR DELETE ON redaction_dictionary_versions
 FOR EACH ROW EXECUTE FUNCTION enforce_dictionary_version_immutable();$gateway_trigger_statement$;
 END IF;
END $gateway_trigger$;

ALTER TABLE redaction_dictionary_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE redaction_dictionary_state FORCE ROW LEVEL SECURITY;
DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='dictionary_admin_scope' AND polrelid=to_regclass('redaction_dictionary_state')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY dictionary_admin_scope ON redaction_dictionary_state FOR ALL USING (
 current_user = 'gw_knowledge_admin'
 AND tenant_id = current_setting('app.tenant', true)
 AND domain = current_setting('app.domain', true)
 AND current_setting('app.admin_context', true) = 'true'
) WITH CHECK (
 current_user = 'gw_knowledge_admin'
 AND tenant_id = current_setting('app.tenant', true)
 AND domain = current_setting('app.domain', true)
 AND current_setting('app.admin_context', true) = 'true'
);$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE redaction_dictionary_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE redaction_dictionary_entries FORCE ROW LEVEL SECURITY;
DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='dictionary_admin_scope' AND polrelid=to_regclass('redaction_dictionary_entries')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY dictionary_admin_scope ON redaction_dictionary_entries FOR ALL USING (
 current_user = 'gw_knowledge_admin'
 AND tenant_id = current_setting('app.tenant', true)
 AND domain = current_setting('app.domain', true)
 AND current_setting('app.admin_context', true) = 'true'
) WITH CHECK (
 current_user = 'gw_knowledge_admin'
 AND tenant_id = current_setting('app.tenant', true)
 AND domain = current_setting('app.domain', true)
 AND current_setting('app.admin_context', true) = 'true'
);$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE redaction_dictionary_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE redaction_dictionary_versions FORCE ROW LEVEL SECURITY;
DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='dictionary_admin_scope' AND polrelid=to_regclass('redaction_dictionary_versions')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY dictionary_admin_scope ON redaction_dictionary_versions FOR ALL USING (
 current_user = 'gw_knowledge_admin'
 AND tenant_id = current_setting('app.tenant', true)
 AND domain = current_setting('app.domain', true)
 AND current_setting('app.admin_context', true) = 'true'
) WITH CHECK (
 current_user = 'gw_knowledge_admin'
 AND tenant_id = current_setting('app.tenant', true)
 AND domain = current_setting('app.domain', true)
 AND current_setting('app.admin_context', true) = 'true'
);$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
ALTER TABLE redaction_dictionary_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE redaction_dictionary_changes FORCE ROW LEVEL SECURITY;
DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='dictionary_admin_scope' AND polrelid=to_regclass('redaction_dictionary_changes')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY dictionary_admin_scope ON redaction_dictionary_changes FOR ALL USING (
 current_user = 'gw_knowledge_admin'
 AND tenant_id = current_setting('app.tenant', true)
 AND domain = current_setting('app.domain', true)
 AND current_setting('app.admin_context', true) = 'true'
) WITH CHECK (
 current_user = 'gw_knowledge_admin'
 AND tenant_id = current_setting('app.tenant', true)
 AND domain = current_setting('app.domain', true)
 AND current_setting('app.admin_context', true) = 'true'
);$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
COMMIT;
