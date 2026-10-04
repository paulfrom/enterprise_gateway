"""Release intent ledger tests: permit granting strictly bounded by durable fsync."""

import dataclasses
import errno
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from pydantic import ValidationError

from audit.audit_intent import ReleaseIntent, ReleasePermit, commit_release_intent
from infra.errors import SafetyCode, SafetyError

FIXTURES = Path(__file__).parent / "fixtures" / "intent"
DW = "infra.durable_write"

RECORDED_AT = datetime(2026, 10, 3, 13, 2, 11, tzinfo=timezone.utc)


def fixture_meta():
    return json.loads((FIXTURES / "release_versions.json").read_text(encoding="utf-8"))


def make_intent(**overrides):
    meta = fixture_meta()
    fields = {
        "intent_id": "intent-20261003-0001",
        "recorded_at": RECORDED_AT,
        "domain": meta["domain"],
        "category": meta["category"],
        "policy_version": meta["policy_version"],
        "package_version": meta["package_version"],
        "purpose": meta["purpose"],
    }
    fields.update(overrides)
    return ReleaseIntent(**fields)


class CommitSuccessTests(unittest.TestCase):
    def test_commit_returns_permit_and_file_roundtrips(self):
        with tempfile.TemporaryDirectory() as d:
            intent = make_intent()
            permit = commit_release_intent(d, intent)
            self.assertIsInstance(permit, ReleasePermit)
            self.assertTrue(permit.path.exists())
            raw = permit.path.read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), permit.sha256)
            payload = json.loads(raw.decode("utf-8"))
            self.assertEqual(payload["intent_id"], intent.intent_id)
            self.assertEqual(payload["policy_version"], intent.policy_version)
            self.assertEqual(payload["package_version"], intent.package_version)
            self.assertEqual(payload["purpose"], intent.purpose)
            self.assertEqual(payload["recorded_at"], "2026-10-03T13:02:11Z")

    def test_serialization_is_canonical_and_deterministic(self):
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            p1 = commit_release_intent(d1, make_intent())
            p2 = commit_release_intent(d2, make_intent())
            self.assertEqual(p1.sha256, p2.sha256)

    def test_intent_schema_has_no_body_field_and_forbids_extras(self):
        with self.assertRaises(ValidationError):
            make_intent(prompt="CNRY-A01-body-77aa11")  # extra field rejected
        with self.assertRaises(ValidationError):
            make_intent(intent_id="bad/id")
        with self.assertRaises(ValidationError):
            make_intent(recorded_at=datetime(2026, 10, 3, 13, 2, 11))  # naive clock
        body_fields = {"content", "prompt", "body", "text", "payload"}
        self.assertFalse(body_fields & set(ReleaseIntent.model_fields))

    def test_permit_handle_is_immutable(self):
        with tempfile.TemporaryDirectory() as d:
            permit = commit_release_intent(d, make_intent())
            with self.assertRaises(dataclasses.FrozenInstanceError):
                permit.sha256 = "tampered"  # type: ignore[misc]


class CommitFailureTests(unittest.TestCase):
    def _assert_no_permit_no_file(self, directory, ctx):
        exc = ctx.exception
        self.assertIsInstance(exc, SafetyError)
        self.assertEqual(exc.code, SafetyCode.AUDIT_WRITE_FAILED)
        self.assertIsNone(exc.__cause__)
        self.assertIsNone(exc.__context__)
        self.assertNotIn(make_intent().intent_id, str(exc))
        self.assertEqual(list(Path(directory).iterdir()), [])  # no committed, no tmp

    def test_fsync_failure_blocks_permit(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch(f"{DW}._flush_and_fsync", side_effect=OSError(errno.EIO, "fsync failed")):
                with self.assertRaises(SafetyError) as ctx:
                    commit_release_intent(d, make_intent())
            self._assert_no_permit_no_file(d, ctx)

    def test_write_failure_enospc_blocks_permit(self):
        with tempfile.TemporaryDirectory() as d:
            def boom(fileobj, data):
                raise OSError(errno.ENOSPC, "No space left on device")
            with mock.patch(f"{DW}._write_all", side_effect=boom):
                with self.assertRaises(SafetyError) as ctx:
                    commit_release_intent(d, make_intent())
            self._assert_no_permit_no_file(d, ctx)

    def test_rename_failure_blocks_permit(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch(f"{DW}._replace", side_effect=OSError(errno.EPERM, "rename denied")):
                with self.assertRaises(SafetyError) as ctx:
                    commit_release_intent(d, make_intent())
            self._assert_no_permit_no_file(d, ctx)

    def test_tempfile_creation_failure_blocks_permit(self):
        # mkstemp itself can fail (ACL denial, directory removed after the
        # pre-check, fd exhaustion); the failure must surface as the
        # controlled contract code, never as a raw OSError.
        with tempfile.TemporaryDirectory() as d:
            with mock.patch(
                f"{DW}.tempfile.mkstemp", side_effect=PermissionError(errno.EACCES, "denied")
            ):
                with self.assertRaises(SafetyError) as ctx:
                    commit_release_intent(d, make_intent())
            self._assert_no_permit_no_file(d, ctx)

    def test_directory_fsync_failure_blocks_permit(self):
        # The intent file may be on disk (documented residual), but no permit
        # is issued and retrying re-commits idempotently.
        with tempfile.TemporaryDirectory() as d:
            with mock.patch(f"{DW}._fsync_directory", side_effect=OSError(errno.EIO, "dir fsync")):
                with self.assertRaises(SafetyError) as ctx:
                    commit_release_intent(d, make_intent())
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_WRITE_FAILED)
            permit = commit_release_intent(d, make_intent())  # retry succeeds
            self.assertTrue(permit.path.exists())

    def test_overwrite_intent_with_different_payload_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            commit_release_intent(d, make_intent(purpose="first-purpose"))
            with self.assertRaises(SafetyError) as ctx:
                commit_release_intent(d, make_intent(purpose="different-purpose"))
            self.assertEqual(ctx.exception.code, SafetyCode.CONTRACT_VIOLATION)


if __name__ == "__main__":
    unittest.main()
