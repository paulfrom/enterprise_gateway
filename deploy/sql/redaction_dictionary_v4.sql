-- Gateway v4: manually execute in the existing shared database.
-- Database, schema, logins and service grants are managed by infrastructure.
-- Creates project tables and their required constraints, indexes, functions, trigger and policies.
-- Existing tables/data are never dropped or reset.
-- Existing knowledge administration login: gw_knowledge_admin
BEGIN;
SET LOCAL search_path TO "public";

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
