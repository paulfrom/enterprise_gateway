"""Real PostgreSQL startup checks for the independent consumer."""
import unittest
import secrets
from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

from knowledge.storage import PostgresKnowledgeStorage
import start_knowledge_worker as launcher
from tests.pg_support import get_admin_dsn, get_test_dsn, prepare_test_database, test_configuration


class WorkerDatabaseGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        prepare_test_database()

    def test_restricted_application_role_and_all_forced_rls_assets_are_accepted(self):
        launcher._validate_database(PostgresKnowledgeStorage(get_test_dsn()))

    def test_administrative_login_cannot_hide_behind_restricted_role(self):
        options = "-c search_path=" + test_configuration()["schema"] + " -c role=" + test_configuration()["application_role"]
        dsn = make_conninfo(get_admin_dsn(), options=options)
        with self.assertRaises(launcher.WorkerConfigurationError) as rejected:
            launcher._validate_database(PostgresKnowledgeStorage(dsn))
        self.assertIn("application_session_identity_mismatch", str(rejected.exception))

    def test_application_cannot_be_a_member_of_an_unflagged_table_owner(self):
        # New test-only roles, one table in this process's fresh isolated schema.
        # Existing role grants and deployed tables are never modified.
        owner = "gw_owner_" + uuid4().hex
        application = "gw_app_" + uuid4().hex
        password = secrets.token_urlsafe(40)
        schema = test_configuration()["schema"]
        created = []
        with psycopg.connect(get_admin_dsn(), autocommit=True) as admin:
            original_owner, database = admin.execute("SELECT current_user,current_database()").fetchone()
            try:
                admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(owner)))
                created.append(owner)
                admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(application), sql.Literal(password)))
                created.append(application)
                admin.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(sql.Identifier(database), sql.Identifier(application)))
                admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(schema), sql.Identifier(application)))
                admin.execute(sql.SQL("GRANT {} TO {}").format(sql.Identifier(owner), sql.Identifier(application)))
                admin.execute(sql.SQL("ALTER TABLE knowledge_publications OWNER TO {}").format(sql.Identifier(owner)))
                dsn = make_conninfo(get_admin_dsn(), user=application, password=password,
                                   options="-c search_path=" + schema)
                with self.assertRaises(launcher.WorkerConfigurationError):
                    launcher._validate_database(PostgresKnowledgeStorage(dsn))
            finally:
                admin.execute(sql.SQL("ALTER TABLE knowledge_publications OWNER TO {}").format(sql.Identifier(original_owner)))
                if application in created:
                    admin.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM {}").format(sql.Identifier(schema), sql.Identifier(application)))
                    admin.execute(sql.SQL("REVOKE CONNECT ON DATABASE {} FROM {}").format(sql.Identifier(database), sql.Identifier(application)))
                    admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(application)))
                if owner in created:
                    admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(owner)))

    def test_noncore_asset_without_forced_rls_is_rejected(self):
        # This process owns a fresh isolated schema. No deployed table is touched.
        with psycopg.connect(get_admin_dsn(), autocommit=True) as admin:
            admin.execute("ALTER TABLE knowledge_publications NO FORCE ROW LEVEL SECURITY")
            try:
                with self.assertRaises(launcher.WorkerConfigurationError):
                    launcher._validate_database(PostgresKnowledgeStorage(get_test_dsn()))
            finally:
                admin.execute("ALTER TABLE knowledge_publications FORCE ROW LEVEL SECURITY")


if __name__ == "__main__":
    unittest.main()
