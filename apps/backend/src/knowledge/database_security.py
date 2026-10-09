"""One least-privilege gate for schema-bound knowledge application sessions."""
from __future__ import annotations

import psycopg


class DatabaseRoleError(RuntimeError):
    """Static public role-validation failure, without connection details."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def assert_restricted_application_role(
    conn: psycopg.Connection, expected_role: str | None = None,
) -> None:
    """Reject identity switching, administrative flags and reachable global roles.

    MEMBER tests direct and indirect grants, including roles that can be reached
    with SET ROLE despite NOINHERIT. Predefined pg_* capabilities must never be
    granted to this dedicated schema-bound application. The SQL effective and
    session identities must match the actual libpq login; service connections
    do not support role or session-authorization switching.
    """
    row = conn.execute(
        "SELECT current_user,session_user,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication "
        "FROM pg_roles WHERE rolname=current_user"
    ).fetchone()
    if not row:
        raise DatabaseRoleError("application_role_is_not_restricted")
    if row[0] != row[1] or row[0] != conn.info.user:
        raise DatabaseRoleError("application_session_identity_mismatch")
    if (expected_role is not None and row[0] != expected_role) or any(row[2:]):
        raise DatabaseRoleError("application_role_is_not_restricted")
    reachable = conn.execute(
        "SELECT EXISTS(SELECT 1 FROM pg_roles r WHERE "
        "(r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication) "
        "AND pg_has_role(current_user,r.oid,'MEMBER'))"
    ).fetchone()[0]
    if reachable:
        raise DatabaseRoleError("application_can_assume_privileged_role")
    # Predefined roles grant files/programs, all-data access, administration or
    # monitoring without any flags above. Catalog lookup covers installed roles
    # without requiring particular role names to exist in a PostgreSQL version.
    global_role = conn.execute(
        "SELECT EXISTS(SELECT 1 FROM pg_roles r WHERE left(r.rolname,3)='pg_' "
        "AND pg_has_role(current_user,r.oid,'MEMBER'))"
    ).fetchone()[0]
    if global_role:
        raise DatabaseRoleError("application_has_global_predefined_role")
