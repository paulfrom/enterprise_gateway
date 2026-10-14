-- Gateway v3: manually execute in the existing shared database.
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

ALTER TABLE entity_aliases ENABLE ROW LEVEL SECURITY; ALTER TABLE entity_aliases FORCE ROW LEVEL SECURITY; DO $gateway_policy$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_policy WHERE polname='admin_access' AND polrelid=to_regclass('entity_aliases')) THEN
  EXECUTE $gateway_policy_statement$CREATE POLICY admin_access ON entity_aliases USING (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),'')) WITH CHECK (current_user = 'gw_knowledge_admin' AND nullif(current_setting('app.admin_context',true),'') = 'true' AND tenant_id = nullif(current_setting('app.tenant',true),'') AND domain = nullif(current_setting('app.domain',true),''));$gateway_policy_statement$;
 END IF;
END $gateway_policy$;
COMMIT;
