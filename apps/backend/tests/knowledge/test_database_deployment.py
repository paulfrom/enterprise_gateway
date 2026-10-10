"""Explicit new-schema deployment, rollback and real restricted-role RLS checks."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from uuid import uuid4

import psycopg

from knowledge.knowledge import KnowledgeError, Role, Source, SourceKind, TrustedActor
from knowledge.storage import PostgresKnowledgeStorage, _ASSET_TABLES
from knowledge.database_security import DatabaseRoleError, assert_restricted_application_role
from scripts.prepare_knowledge_database import DatabasePreparationError, load_configuration, main, prepare_database


class ApplicationRoleBoundaryTests(unittest.TestCase):
    def connection(self, *, global_membership=False, session_user="synthetic-app",
                   authenticated_user="synthetic-app", flags=frozenset(), reachable_flags=frozenset()):
        # Return only columns actually requested, as PostgreSQL does: omitted
        # session/replication fields cannot accidentally be checked by a mock.
        conn = MagicMock()
        conn.info.user = authenticated_user
        role = {"current_user": "synthetic-app", "session_user": session_user,
                **{name: name in flags for name in
                   ("rolsuper", "rolbypassrls", "rolcreaterole", "rolcreatedb", "rolreplication")}}

        def execute(statement):
            if statement.startswith("SELECT current_user,"):
                columns = statement.partition(" FROM ")[0].removeprefix("SELECT ").split(",")
                row = tuple(role[column] for column in columns)
            elif "left(r.rolname,3)='pg_'" in statement:
                row = (global_membership,)
            else:
                row = (any("r." + flag in statement for flag in reachable_flags),)
            cursor = MagicMock()
            cursor.fetchone.return_value = row
            return cursor

        conn.execute.side_effect = execute
        return conn

    def test_unflagged_global_role_membership_rejected(self):
        conn = self.connection(global_membership=True)
        with self.assertRaisesRegex(DatabaseRoleError, "application_has_global_predefined_role"):
            assert_restricted_application_role(conn, "synthetic-app")
        query = conn.execute.call_args_list[-1].args[0]
        self.assertIn("pg_roles", query)
        self.assertIn("pg_has_role(current_user,r.oid,'MEMBER')", query)
        self.assertIn("left(r.rolname,3)='pg_'", query)

    def test_application_without_flagged_or_global_memberships_accepted(self):
        conn = self.connection(global_membership=False)
        assert_restricted_application_role(conn, "synthetic-app")

    def test_indirect_privileged_role_membership_rejected(self):
        conn = self.connection(reachable_flags=frozenset({"rolsuper"}))
        with self.assertRaisesRegex(DatabaseRoleError, "application_can_assume_privileged_role"):
            assert_restricted_application_role(conn, "synthetic-app")

    def test_unexpected_login_identity_rejected(self):
        conn = self.connection(global_membership=False)
        with self.assertRaisesRegex(DatabaseRoleError, "application_role_is_not_restricted"):
            assert_restricted_application_role(conn, "different-app")

    def test_worker_without_expected_identity_still_checks_global_membership(self):
        conn = self.connection(global_membership=True)
        with self.assertRaisesRegex(DatabaseRoleError, "application_has_global_predefined_role"):
            assert_restricted_application_role(conn)

    def test_session_role_override_rejected(self):
        conn = self.connection(session_user="authenticated-admin", authenticated_user="authenticated-admin")
        with self.assertRaisesRegex(DatabaseRoleError, "application_session_identity_mismatch"):
            assert_restricted_application_role(conn)

    def test_libpq_authentication_identity_override_rejected(self):
        conn = self.connection(authenticated_user="authenticated-admin")
        with self.assertRaisesRegex(DatabaseRoleError, "application_session_identity_mismatch"):
            assert_restricted_application_role(conn)

    def test_each_administrative_role_flag_rejected(self):
        for flag in ("rolsuper", "rolbypassrls", "rolcreaterole", "rolcreatedb", "rolreplication"):
            with self.subTest(flag=flag):
                conn = self.connection(flags=frozenset({flag}))
                with self.assertRaisesRegex(DatabaseRoleError, "application_role_is_not_restricted"):
                    assert_restricted_application_role(conn)

    def test_reachable_replication_role_rejected(self):
        conn = self.connection(reachable_flags=frozenset({"rolreplication"}))
        with self.assertRaisesRegex(DatabaseRoleError, "application_can_assume_privileged_role"):
            assert_restricted_application_role(conn)


class DatabasePreparationCliTests(unittest.TestCase):
    def test_admin_role_is_optional_and_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            base = dict(schema="gw_test_cli", application_role="synthetic-role",
                        admin_dsn="unused", app_dsn="unused")
            for label, admin_role, expected in (
                    ("absent", None, None),
                    ("valid", "gw_admin_role", "gw_admin_role"),
                    ("uppercase", "Gw_Admin", "invalid_admin_role"),
                    ("pg_reserved", "pg_monitor", "reserved_admin_role"),
                    ("non_string", 42, "invalid_admin_role")):
                with self.subTest(label=label):
                    config = Path(directory) / f"input-{label}.json"
                    payload = dict(base)
                    if admin_role is not None:
                        payload["admin_role"] = admin_role
                    config.write_text(json.dumps(payload), encoding="utf-8")
                    if expected is None or expected == "invalid_admin_role" or expected == "reserved_admin_role":
                        if expected is None:
                            self.assertNotIn("admin_role", load_configuration(config))
                        else:
                            with self.assertRaisesRegex(DatabasePreparationError, expected):
                                load_configuration(config)
                    else:
                        self.assertEqual(expected, load_configuration(config)["admin_role"])

    def test_connection_error_redacted_and_own_empty_reservation_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "input.json"
            output = Path(directory) / "output.json"
            config.write_text(json.dumps(dict(schema="gw_test_cli", application_role="synthetic-role",
                                             admin_dsn="unused", app_dsn="unused")), encoding="utf-8")
            stream = io.StringIO()
            with redirect_stdout(stream), patch("scripts.prepare_knowledge_database.prepare_database",
                                                  side_effect=psycopg.OperationalError("secret-password-sentinel")):
                self.assertEqual(1, main(["--config", str(config), "--output-config", str(output)]))
            self.assertFalse(output.exists())
            self.assertNotIn("secret-password-sentinel", stream.getvalue())
            self.assertIn("OperationalError", stream.getvalue())

    def test_existing_output_secret_not_overwritten_or_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "existing.json"
            output.write_text("existing-secret-sentinel", encoding="utf-8")
            stream = io.StringIO()
            with redirect_stdout(stream), patch("scripts.prepare_knowledge_database.prepare_database") as prepare:
                self.assertEqual(1, main(["--config", "unused", "--output-config", str(output)]))
            prepare.assert_not_called()
            self.assertEqual("existing-secret-sentinel", output.read_text(encoding="utf-8"))
            self.assertNotIn("existing-secret-sentinel", stream.getvalue())


class DatabaseDeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.environ.get("GATEWAY_DATABASE_DEPLOYMENT_CONFIG")
        if not path:
            raise unittest.SkipTest("Explicit private remote deployment configuration required")
        cls.base = load_configuration(Path(path))

    def config(self):
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        return dict(self.base, schema="gw_test_" + stamp + "_" + uuid4().hex[:12])

    def test_fresh_schema_forced_rls_and_cross_scope_access(self):
        config, report = prepare_database(self.config())
        self.assertTrue(report["forced_rls"])
        self.assertEqual(len(_ASSET_TABLES), report["asset_count"])
        storage = PostgresKnowledgeStorage(config["app_dsn"])
        actor = TrustedActor("synthetic-processor", "deployment-test", "synthetic-domain",
                             frozenset({Role.KNOWLEDGE_PROCESSOR}), frozenset({"knowledge"}))
        now = datetime.now(timezone.utc)
        source = Source(actor.tenant_id, actor.domain, "synthetic-source", "v1", SourceKind.DOCUMENT,
                        frozenset({actor.subject_id}), "knowledge", now, now + timedelta(hours=1), False)
        with psycopg.connect(config["app_dsn"]) as conn:
            storage.set_session_identity(conn, actor)
            storage.save_source(conn, source)
        for changed in (replace(actor, tenant_id="different-tenant"), replace(actor, domain="different-domain"),
                        replace(actor, subject_id="different-subject"), replace(actor, purposes=frozenset({"other"}))):
            with self.subTest(scope=changed), psycopg.connect(config["app_dsn"]) as conn:
                storage.set_session_identity(conn, changed)
                self.assertEqual(0, conn.execute("SELECT count(*) FROM knowledge_sources").fetchone()[0])
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    storage.save_source(conn, replace(source, source_id="cross-scope-attempt"))
        with psycopg.connect(config["app_dsn"]) as conn:
            self.assertEqual(0, conn.execute("SELECT count(*) FROM knowledge_sources").fetchone()[0])
            storage.set_session_identity(conn, actor)
            self.assertEqual(1, conn.execute("SELECT count(*) FROM knowledge_sources").fetchone()[0])
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                conn.execute("ALTER TABLE knowledge_sources DISABLE ROW LEVEL SECURITY")
        with self.assertRaises(KnowledgeError):
            storage.init_database()

    def test_existing_namespace_rejected_without_modification(self):
        bound, _ = prepare_database(self.config())
        with psycopg.connect(bound["admin_dsn"]) as conn:
            before = conn.execute("SELECT count(*) FROM pg_class WHERE relnamespace=current_schema()::regnamespace").fetchone()[0]
        with self.assertRaisesRegex(DatabasePreparationError, "namespace_already_exists"):
            prepare_database(bound)
        with psycopg.connect(bound["admin_dsn"]) as conn:
            self.assertEqual(before, conn.execute("SELECT count(*) FROM pg_class WHERE relnamespace=current_schema()::regnamespace").fetchone()[0])

    def test_ddl_failure_rolls_back_the_entire_new_namespace(self):
        config = self.config()
        with patch("scripts.prepare_knowledge_database.RLS_SETUP_SQL", "SELECT 1/0"):
            with self.assertRaises(psycopg.errors.DivisionByZero):
                prepare_database(config)
        with psycopg.connect(config["admin_dsn"]) as conn:
            self.assertFalse(conn.execute("SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=%s)", (config["schema"],)).fetchone()[0])

    def test_privileged_application_denied_before_namespace_creation(self):
        config = self.config()
        with psycopg.connect(config["admin_dsn"]) as conn:
            admin_role = conn.execute("SELECT current_user").fetchone()[0]
        config.update(app_dsn=config["admin_dsn"], application_role=admin_role)
        with self.assertRaisesRegex(DatabaseRoleError, "application_role_is_not_restricted"):
            prepare_database(config)
        with psycopg.connect(config["admin_dsn"]) as conn:
            self.assertFalse(conn.execute("SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=%s)", (config["schema"],)).fetchone()[0])


if __name__ == "__main__":
    unittest.main()
