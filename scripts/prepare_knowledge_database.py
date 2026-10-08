"""Explicit, transactional initialization of a new knowledge database namespace.

Credentials are read only from the supplied private JSON file. Existing schemas
are refused; this is neither an upgrade tool nor a destructive test reset.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from knowledge.storage import RLS_SETUP_SQL, SCHEMA_SQL, _ASSET_TABLES
from knowledge.database_security import DatabaseRoleError, assert_restricted_application_role


class DatabasePreparationError(RuntimeError):
    """Safe public failure reason, without server messages or credentials."""


def load_configuration(path: Path) -> dict[str, str]:
    config = json.loads(path.read_text(encoding="utf-8-sig"))
    fields = ("schema", "application_role", "admin_dsn", "app_dsn")
    if not isinstance(config, dict) or any(
        not isinstance(config.get(key), str) or not config[key].strip() for key in fields
    ):
        raise DatabasePreparationError("incomplete_private_configuration")
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", config["schema"]):
        raise DatabasePreparationError("invalid_namespace")
    if config["schema"].startswith("pg_") or config["schema"] in {"public", "information_schema"}:
        raise DatabasePreparationError("reserved_namespace")
    return {key: config[key] for key in fields}


def prepare_database(config: dict[str, str]) -> tuple[dict[str, str], dict]:
    """Create one new namespace, current DDL, grants and forced RLS atomically."""
    schema, role = config["schema"], config["application_role"]
    # These sessions ignore configured search_path until a new schema is owned.
    admin_dsn = make_conninfo(config["admin_dsn"], options="", connect_timeout=10)
    app_dsn = make_conninfo(config["app_dsn"], options="", connect_timeout=10)
    with psycopg.connect(admin_dsn) as admin, psycopg.connect(app_dsn) as app:
        admin_row = admin.execute(
            "SELECT current_user,rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user"
        ).fetchone()
        if not admin_row or not admin_row[1]:
            raise DatabasePreparationError("governed_functions_require_controlled_owner")
        assert_restricted_application_role(app, role)
        identity_sql = "SELECT current_database(),inet_server_addr()::text,inet_server_port()"
        if admin.execute(identity_sql).fetchone() != app.execute(identity_sql).fetchone():
            raise DatabasePreparationError("connections_target_different_databases")
        if admin.execute("SELECT pg_has_role(%s,%s,'MEMBER')", (role, admin_row[0])).fetchone()[0]:
            raise DatabasePreparationError("application_can_assume_owner")
        if admin.execute("SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname=%s)", (schema,)).fetchone()[0]:
            raise DatabasePreparationError("namespace_already_exists")
        # PostgreSQL transactional DDL means every write below rolls back on error.
        admin.execute(sql.SQL("CREATE SCHEMA {} AUTHORIZATION CURRENT_USER").format(sql.Identifier(schema)))
        admin.execute(sql.SQL("SET LOCAL search_path TO {}").format(sql.Identifier(schema)))
        # Exact schema/RLS contracts used by PostgresKnowledgeStorage.init_database.
        admin.execute(SCHEMA_SQL.replace("__GOVERNANCE_SCHEMA__", sql.Identifier(schema).as_string(admin)))
        admin.execute(RLS_SETUP_SQL)
        admin.execute(sql.SQL("REVOKE ALL ON SCHEMA {} FROM PUBLIC").format(sql.Identifier(schema)))
        admin.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(sql.Identifier(schema), sql.Identifier(role)))
        admin.execute(sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {}").format(sql.Identifier(schema), sql.Identifier(role)))
        admin.execute(sql.SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {} TO {}").format(sql.Identifier(schema), sql.Identifier(role)))
        for function in ("invalidate_knowledge_source(TEXT,TEXT,TEXT,TIMESTAMPTZ)", "read_authorized_knowledge_candidate(UUID)"):
            # Function names/signatures are fixed trusted SQL, identifiers remain quoted.
            admin.execute(sql.SQL("GRANT EXECUTE ON FUNCTION {}." + function + " TO {}").format(sql.Identifier(schema), sql.Identifier(role)))
        rows = admin.execute(
            "SELECT relname,relrowsecurity,relforcerowsecurity,pg_get_userbyid(relowner) "
            "FROM pg_class WHERE relnamespace=%s::regnamespace AND relname=ANY(%s)",
            (schema, list(_ASSET_TABLES)),
        ).fetchall()
        if len(rows) != len(_ASSET_TABLES) or any(not enabled or not forced or owner == role for _, enabled, forced, owner in rows):
            raise DatabasePreparationError("asset_rls_or_ownership_invalid")
        ssl = admin.execute("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()").fetchone()
        version = admin.info.server_version
    bound = dict(config, admin_dsn=make_conninfo(admin_dsn, options="-c search_path=" + schema),
                 app_dsn=make_conninfo(app_dsn, options="-c search_path=" + schema))
    return bound, {"initialized": True, "server_version": version, "tls": bool(ssl and ssl[0]),
                   "asset_count": len(rows), "forced_rls": True, "application_restricted": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="Private JSON: schema, application_role, admin_dsn, app_dsn")
    parser.add_argument("--output-config", required=True, type=Path, help="New private file with schema-bound worker/test DSNs")
    args = parser.parse_args(argv)
    created_identity = None
    try:
        # Reserve the private output before DB mutation; never overwrite a secret file.
        with args.output_config.open("x", encoding="utf-8") as output:
            stat = os.fstat(output.fileno())
            created_identity = (stat.st_dev, stat.st_ino)
            os.chmod(args.output_config, 0o600)
            config = load_configuration(args.config)
            bound, report = prepare_database(config)
            json.dump(bound, output, indent=2)
            output.flush()
            os.fsync(output.fileno())
        print(json.dumps(report, sort_keys=True))
        return 0
    except (DatabasePreparationError, DatabaseRoleError) as exc:
        print(json.dumps({"initialized": False, "reason": str(exc)}))
    except Exception as exc:
        # No psycopg error text: it can contain addresses, identities or credentials.
        print(json.dumps({"initialized": False, "reason": "preparation_failed", "error_type": type(exc).__name__}))
    finally:
        # Remove only this invocation's still-empty reservation. Existing secret
        # files and a completed/partly-written output are never removed.
        if created_identity is not None:
            try:
                stat = args.output_config.stat()
                if stat.st_size == 0 and (stat.st_dev, stat.st_ino) == created_identity:
                    args.output_config.unlink()
            except OSError:
                pass
    return 1


if __name__ == "__main__":
    sys.exit(main())
