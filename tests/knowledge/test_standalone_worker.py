"""Actual consumer entrypoint, persistent local keys, and isolated real PostgreSQL."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

import psycopg

from infra.envelope_crypto import decrypt_record, parse_record
from infra.errors import SafetyCode, SafetyError
from infra.file_kms import FileKmsProvider
from infra.spool import CollectionMode, SpoolWriter
from infra.spool_relay import compute_dedup_key
from knowledge.knowledge import CandidateState, Role, TrustedActor
from knowledge.knowledge_events import ObservationEvent, build_gateway_observation, serialize_event
from knowledge.storage import PostgresKnowledgeStorage
from protocol.identity import ByokAuthenticator
import start_knowledge_worker as launcher
from tests.pg_support import get_test_dsn, prepare_test_database


class WorkerConfigurationTests(unittest.TestCase):
    def test_direct_script_help_without_pythonpath_or_environment_from_other_cwd(self):
        script = Path(launcher.__file__).resolve()
        env = {name: value for name, value in os.environ.items()
               if name != "PYTHONPATH" and not name.startswith("GATEWAY_")}
        with tempfile.TemporaryDirectory() as cwd:
            result = subprocess.run([sys.executable, str(script), "--help"], env=env,
                                    cwd=cwd, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--once", result.stdout)

    def test_missing_inputs_and_conflicting_secret_sources_reject(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(launcher.WorkerConfigurationError):
                launcher.build_worker()
            os.environ["GATEWAY_KMS_MASTER_KEY"] = "synthetic"
            os.environ["GATEWAY_KMS_MASTER_KEY_FILE"] = "unused"
            with self.assertRaises(launcher.WorkerConfigurationError):
                launcher._secret("GATEWAY_KMS_MASTER_KEY")

    def test_failure_output_is_static_and_contains_no_dsn(self):
        from io import StringIO
        capture = StringIO()
        with patch.object(launcher, "build_worker", side_effect=RuntimeError("synthetic-credential-canary")), \
                patch("sys.stderr", capture):
            self.assertEqual(launcher.main(["--once"]), 2)
        self.assertNotIn("synthetic-credential-canary", capture.getvalue())


class StandaloneWorkerPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        prepare_test_database()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        (self.state / "spool").mkdir()
        self.master = bytes(range(32))
        self.kms = FileKmsProvider(self.state / "keys", self.master)
        self.kms.provision(purpose="knowledge-accumulation:knowledge-spool", bucket="synthetic-retention")
        self.writer = SpoolWriter(self.state / "spool", self.kms)
        self.domain = "standalone-" + uuid4().hex
        self.tenant = "synthetic-tenant"
        self.subject = "controlled-local-knowledge-worker"
        self.env = dict(os.environ,
                        GATEWAY_STATE_DIR=str(self.state),
                        GATEWAY_KMS_MASTER_KEY=self.master.hex(),
                        GATEWAY_PROCESSING_DOMAIN=self.domain,
                        GATEWAY_PROCESSING_TENANT=self.tenant,
                        GATEWAY_KNOWLEDGE_WORKER_SUBJECT=self.subject,
                        GATEWAY_KNOWLEDGE_PG_DSN=get_test_dsn(),
                        PYTHONPATH="src")
        self.env.pop("GATEWAY_KMS_MASTER_KEY_FILE", None)
        self.env.pop("GATEWAY_KNOWLEDGE_PG_DSN_FILE", None)
        self.actor = TrustedActor(self.subject, self.tenant, self.domain,
                                  frozenset({Role.KNOWLEDGE_PROCESSOR}), frozenset({"knowledge-accumulation"}))
        self.storage = PostgresKnowledgeStorage(get_test_dsn())

    def event(self, text="甲公司向乙公司采购设备。"):
        source = ByokAuthenticator(domain=self.domain, tenant_id=self.tenant,
                                   correlation_key=bytes([25]) * 32).authenticate(
                                       {"Authorization": "Bearer synthetic-provider-key"})
        now = datetime.now(timezone.utc)
        return build_gateway_observation(tenant=self.tenant, domain=self.domain,
            request_id="synthetic-request", evidence_text=text,
            evidence_digest=sha256(text.encode()).hexdigest(), observed_at=now,
            retention_until=now + timedelta(days=1), retention_policy="synthetic-retention",
            source_context=source)

    def child(self):
        return subprocess.run([sys.executable, "start_knowledge_worker.py", "--once"],
                              env=self.env, capture_output=True, text=True, timeout=30)

    def scoped(self, conn):
        self.storage.set_session_identity(conn, self.actor,
                                          processing_acl=(f"{self.domain}:restricted-candidate",))

    def test_confirmed_spool_removal_retains_encrypted_minimal_evidence(self):
        event = self.event()
        self.writer.collect(event, mode=CollectionMode.REQUIRED)
        result = self.child()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["submitted"], 1)
        self.assertEqual(list((self.state / "spool").glob("*.env.json")), [])
        self.assertNotIn(event.evidence_text, result.stdout + result.stderr)
        self.assertNotIn("synthetic-provider-key", result.stdout + result.stderr)
        with psycopg.connect(get_test_dsn()) as conn:
            self.scoped(conn)
            column = conn.execute("""SELECT data_type,is_nullable FROM information_schema.columns
                WHERE table_schema=current_schema() AND table_name='knowledge_observations'
                AND column_name='encrypted_observation'""").fetchone()
            self.assertEqual(column, ("bytea", "NO"))
            stored = conn.execute("SELECT encrypted_observation FROM knowledge_observations WHERE dedup_key=%s",
                                  (compute_dedup_key(event),)).fetchone()[0]
            # Check ordinary stored rows; no table contains the original fragment in plaintext.
            for table in ("knowledge_observations", "knowledge_sources", "knowledge_evidence",
                          "knowledge_candidates", "knowledge_claims", "knowledge_entities"):
                rows = conn.execute(f"SELECT row_to_json(t)::text FROM {table} t").fetchall()
                self.assertTrue(all(event.evidence_text not in row[0] for row in rows))
            ordinary = TrustedActor("ordinary-reader", self.tenant, self.domain, frozenset(),
                                    frozenset({"knowledge-accumulation"}))
            self.storage.set_session_identity(conn, ordinary)
            self.assertEqual(conn.execute("SELECT count(*) FROM knowledge_observations").fetchone()[0], 0)
        self.assertIsInstance(stored, bytes)
        self.assertNotIn(event.evidence_text.encode(), stored)
        self.assertNotIn(b"synthetic-provider-key", stored)
        record = parse_record(stored)
        self.assertEqual(record.record_id, "obs-" + compute_dedup_key(event))
        self.assertEqual(record.domain, event.domain)
        self.assertEqual(record.bucket, event.retention_policy)
        self.assertEqual(record.purpose, event.purpose + ":knowledge-spool")
        # Reopen keys after the child exits: exact source, ACL, deadlines, versions and trust survive.
        reopened = FileKmsProvider(self.state / "keys", self.master)
        recovered = ObservationEvent.model_validate_json(decrypt_record(reopened, record))
        self.assertEqual(serialize_event(recovered), serialize_event(event))
        self.assertEqual(recovered.source_provenance, "unverified")
        self.assertEqual(recovered.ownership_status, "unassigned")
        with self.assertRaises(SafetyError):
            decrypt_record(FileKmsProvider(self.state / "keys", bytes([99]) * 32), record)
        self.writer.collect(event, mode=CollectionMode.REQUIRED)
        replay = self.child()
        self.assertEqual(replay.returncode, 0, replay.stderr)
        self.assertEqual(json.loads(replay.stdout)["skipped"], 1)
        with psycopg.connect(get_test_dsn()) as conn:
            self.scoped(conn)
            row = conn.execute("SELECT encrypted_observation FROM knowledge_observations WHERE dedup_key=%s",
                               (compute_dedup_key(event),)).fetchall()
            self.assertEqual(row, [(stored,)])

    def test_observation_without_extractable_candidates_retains_original_fragment(self):
        event = self.event("请查询今天的天气。")
        self.writer.collect(event, mode=CollectionMode.REQUIRED)
        result = self.child()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["submitted"], 1)
        self.assertEqual(list((self.state / "spool").glob("*.env.json")), [])
        with psycopg.connect(get_test_dsn()) as conn:
            self.scoped(conn)
            ids, stored = conn.execute("""SELECT candidate_ids,encrypted_observation
                FROM knowledge_observations WHERE dedup_key=%s""", (compute_dedup_key(event),)).fetchone()
            self.assertEqual(ids, [])
            self.assertEqual(conn.execute("SELECT count(*) FROM knowledge_candidates").fetchone()[0], 0)
        plaintext = decrypt_record(FileKmsProvider(self.state / "keys", self.master), parse_record(stored))
        self.assertEqual(plaintext, serialize_event(event))

    def test_encryption_failure_keeps_spool_and_writes_no_database_rows(self):
        event = self.event()
        self.writer.collect(event, mode=CollectionMode.REQUIRED)
        with patch.dict(os.environ, self.env, clear=True):
            worker = launcher.build_worker()
        with patch("knowledge.worker.encrypt_record", side_effect=SafetyError(SafetyCode.KMS_UNAVAILABLE)):
            with self.assertRaises(SafetyError):
                worker.run_once()
        self.assertEqual(len(list((self.state / "spool").glob("*.env.json"))), 1)
        with psycopg.connect(get_test_dsn()) as conn:
            self.scoped(conn)
            self.assertEqual(conn.execute("SELECT count(*) FROM knowledge_observations").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM knowledge_sources").fetchone()[0], 0)
        recovered = self.child()
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual(json.loads(recovered.stdout)["submitted"], 1)

    def test_database_failure_rolls_back_ciphertext_source_and_candidates_keeps_spool(self):
        event = self.event()
        self.writer.collect(event, mode=CollectionMode.REQUIRED)
        with patch.dict(os.environ, self.env, clear=True):
            worker = launcher.build_worker()
        def fail_in_database(conn, *_args):
            conn.execute("SELECT 1/0")
        with patch.object(PostgresKnowledgeStorage, "save_candidate", side_effect=fail_in_database):
            with self.assertRaises(SafetyError):
                worker.run_once()
        self.assertEqual(len(list((self.state / "spool").glob("*.env.json"))), 1)
        with psycopg.connect(get_test_dsn()) as conn:
            self.scoped(conn)
            for table in ("knowledge_observations", "knowledge_sources", "knowledge_evidence", "knowledge_candidates"):
                self.assertEqual(conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)
        recovered = self.child()
        self.assertEqual(recovered.returncode, 0, recovered.stderr)
        self.assertEqual(json.loads(recovered.stdout)["submitted"], 1)

    def test_real_entrypoint_restart_replay_is_durable_restricted_and_unverified(self):
        event = self.event()
        self.assertFalse(event.source_independence_verified)
        self.assertEqual(event.acl, frozenset({f"{self.domain}:restricted-candidate"}))
        self.writer.collect(event, mode=CollectionMode.REQUIRED)
        first = self.child()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(json.loads(first.stdout)["submitted"], 1)
        with psycopg.connect(get_test_dsn()) as conn:
            self.scoped(conn)
            ids = conn.execute("SELECT candidate_ids FROM knowledge_observations WHERE dedup_key=%s",
                               (compute_dedup_key(event),)).fetchone()[0]
            self.assertEqual(len(ids), 1)
            candidate = self.storage.load_candidate(conn, ids[0])
            self.assertEqual(candidate.state, CandidateState.PROPOSED)
            self.assertEqual(candidate.independent_source_count, 0)
            self.assertFalse(candidate.evidence[0].source.independence_verified)
            self.assertEqual(candidate.acl, event.acl)
            self.assertEqual(candidate.claim.subject.name, "乙公司")
            self.assertEqual(candidate.claim.object.name, "甲公司")
            self.assertEqual(conn.execute("SELECT count(*) FROM knowledge_publications").fetchone()[0], 0)
        # A separate process reads retained keys and recognizes replay, with no double contribution.
        self.writer.collect(event, mode=CollectionMode.REQUIRED)
        replay = self.child()
        self.assertEqual(replay.returncode, 0, replay.stderr)
        self.assertEqual(json.loads(replay.stdout)["skipped"], 1)
        self.assertEqual(list((self.state / "spool").glob("*.env.json")), [])
        with psycopg.connect(get_test_dsn()) as conn:
            self.scoped(conn)
            self.assertEqual(conn.execute("SELECT count(*) FROM knowledge_observations").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT count(*) FROM knowledge_candidates").fetchone()[0], 1)
            ordinary = TrustedActor("ordinary-reader", self.tenant, self.domain, frozenset(),
                                    frozenset({"knowledge-accumulation"}))
            self.storage.set_session_identity(conn, ordinary)
            self.assertEqual(conn.execute("SELECT count(*) FROM knowledge_candidates").fetchone()[0], 0)

    def test_missing_key_is_not_provisioned_by_consumer(self):
        event = self.event()
        self.writer.collect(event, mode=CollectionMode.REQUIRED)
        next((self.state / "keys").glob("*.key.json")).unlink()
        result = self.child()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(list((self.state / "keys").glob("*.key.json")), [])
        self.assertEqual(len(list((self.state / "spool").glob("*.env.json"))), 1)
