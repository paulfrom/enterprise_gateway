"""Consume encrypted observations into restricted PostgreSQL candidates.

Uses the gateway's state keys/spool and master; never provisions keys, initializes
database schema, calls a model, assigns ownership, or publishes knowledge.
Database schema and a nonowner/non-bypass service account must already exist.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time

# Resolve the repository's source packages even when invoked outside the repo.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

import psycopg

from infra.file_kms import FileKmsProvider
from infra.errors import SafetyError
from knowledge.knowledge import Role, TrustedActor
from knowledge.database_security import DatabaseRoleError, assert_restricted_application_role
from knowledge.storage import PostgresKnowledgeStorage, _ASSET_TABLES
from knowledge.worker import KnowledgeWorker, PostgresKnowledgeSink


class WorkerConfigurationError(ValueError):
    """Static errors only: credentials, DSNs and underlying failures are not logged."""


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise WorkerConfigurationError(f"{name} is required")
    return value


def _secret(name: str) -> str:
    value = os.environ.get(name, "").strip()
    filename = os.environ.get(name + "_FILE", "").strip()
    if bool(value) == bool(filename):
        raise WorkerConfigurationError(f"set exactly one of {name} and {name}_FILE")
    if filename:
        try:
            value = Path(filename).read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            raise WorkerConfigurationError(f"{name}_FILE cannot be read") from None
    if not value:
        raise WorkerConfigurationError(f"{name} must not be empty")
    return value


def _validate_database(storage: PostgresKnowledgeStorage) -> None:
    with psycopg.connect(storage.connection_uri, connect_timeout=5) as conn:
        try:
            assert_restricted_application_role(conn)
        except DatabaseRoleError as exc:
            raise WorkerConfigurationError("worker PostgreSQL role refused: " + exc.reason) from None
        for table in _ASSET_TABLES:
            row = conn.execute("""SELECT relrowsecurity,relforcerowsecurity,
                       pg_has_role(current_user,relowner,'MEMBER')
                       FROM pg_class WHERE oid=to_regclass(%s)""", (table,)).fetchone()
            if row is None or not row[0] or not row[1] or row[2]:
                raise WorkerConfigurationError("worker requires existing forced-RLS tables owned by a separate role")


def build_worker() -> KnowledgeWorker:
    """Validate existing deployment inputs and assemble the existing local worker."""
    state = Path(_required("GATEWAY_STATE_DIR"))
    if not (state / "keys").is_dir() or not (state / "spool").is_dir():
        raise WorkerConfigurationError("existing gateway keys and spool directories are required")
    try:
        master = bytes.fromhex(_secret("GATEWAY_KMS_MASTER_KEY"))
    except ValueError:
        raise WorkerConfigurationError("GATEWAY_KMS_MASTER_KEY must encode 32 bytes in hex") from None
    if len(master) != 32:
        raise WorkerConfigurationError("GATEWAY_KMS_MASTER_KEY must encode 32 bytes in hex")
    actor = TrustedActor(_required("GATEWAY_KNOWLEDGE_WORKER_SUBJECT"),
                         _required("GATEWAY_PROCESSING_TENANT"),
                         _required("GATEWAY_PROCESSING_DOMAIN"),
                         frozenset({Role.KNOWLEDGE_PROCESSOR}),
                         frozenset({"knowledge-accumulation"}))
    kms = FileKmsProvider(state / "keys", master)
    storage = PostgresKnowledgeStorage(_secret("GATEWAY_KNOWLEDGE_PG_DSN"))
    _validate_database(storage)
    sink = PostgresKnowledgeSink(storage, actor, kms,
                                processing_acl=(f"{actor.domain}:restricted-candidate",))
    return KnowledgeWorker(state / "spool", kms, sink)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="perform one confirmed relay pass")
    parser.add_argument("--interval-seconds", type=float, default=5,
                        help="positive delay between successful passes (default 5)")
    args = parser.parse_args(argv)
    if not 0 < args.interval_seconds < float("inf"):
        parser.error("interval-seconds must be finite and positive")
    try:
        worker = build_worker()
    except WorkerConfigurationError as exc:
        print(f"knowledge worker configuration rejected: {exc}", file=sys.stderr)
        return 2
    except Exception:
        print("knowledge worker startup rejected", file=sys.stderr)
        return 2
    try:
        while True:
            stats = worker.run_once()
            print(json.dumps({"submitted": stats.submitted, "skipped": stats.skipped,
                              "failed": stats.failed, "quarantined": stats.quarantined}), flush=True)
            if stats.quarantined:
                return 1
            if args.once:
                return 1 if stats.failed else 0
            time.sleep(args.interval_seconds)
    except KeyboardInterrupt:
        return 0
    except SafetyError as exc:
        print(f"knowledge worker pass rejected: {exc.code.value}", file=sys.stderr)
        return 1
    except Exception:
        print("knowledge worker pass rejected", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
