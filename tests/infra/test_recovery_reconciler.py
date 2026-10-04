"""Recovery reconciler tests: crash leftovers stay unknown, real results survive."""

import errno
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from pydantic import ValidationError

from audit.audit_intent import ReleaseIntent, commit_release_intent
from infra.durable_write import DurableWriteError
from infra.errors import SafetyCode, SafetyError
from infra import recovery_reconciler as rr

DW = "infra.durable_write"
RECORDED_AT = datetime(2026, 10, 4, 8, 5, 0, tzinfo=timezone.utc)


def make_intent(intent_id="intent-20261004-0001", **overrides):
    fields = {
        "intent_id": intent_id,
        "recorded_at": RECORDED_AT,
        "domain": "hr",
        "category": "employee-roster",
        "policy_version": "policy-v1",
        "package_version": "pkg-v1",
        "purpose": "payroll-sync",
    }
    fields.update(overrides)
    return ReleaseIntent(**fields)


def make_result(intent_id="intent-20261004-0001", outcome="SENT", recorded_at=None):
    return rr.SendResult(
        intent_id=intent_id,
        outcome=outcome,
        recorded_at=recorded_at or datetime(2026, 10, 4, 8, 6, 0, tzinfo=timezone.utc),
    )


def read_canonical(path):
    return json.loads(Path(path).read_bytes().decode("utf-8"))


def snapshot(directory):
    return {p.name: p.read_bytes() for p in Path(directory).iterdir() if p.is_file()}


def assert_clean_controlled(self, ctx, code, canary=None):
    exc = ctx.exception
    self.assertIsInstance(exc, SafetyError)
    self.assertEqual(exc.code, code)
    self.assertIsNone(exc.__cause__)
    self.assertIsNone(exc.__context__)
    if canary is not None:
        self.assertNotIn(canary, str(exc))


class RecordSendResultTests(unittest.TestCase):
    def test_record_result_commits_durable_document(self):
        with tempfile.TemporaryDirectory() as d:
            result = make_result()
            path = rr.record_send_result(d, result)
            self.assertTrue(path.exists())
            self.assertEqual(path.name, "intent-20261004-0001.result.json")
            payload = read_canonical(path)
            self.assertEqual(payload["intent_id"], result.intent_id)
            self.assertEqual(payload["outcome"], "SENT")
            self.assertEqual(payload["recorded_at"], "2026-10-04T08:06:00Z")

    def test_serialization_is_canonical_and_deterministic(self):
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            p1 = rr.record_send_result(d1, make_result())
            p2 = rr.record_send_result(d2, make_result())
            self.assertEqual(p1.read_bytes(), p2.read_bytes())
            self.assertEqual(
                p1.read_bytes(),
                b'{"intent_id":"intent-20261004-0001","outcome":"SENT",'
                b'"recorded_at":"2026-10-04T08:06:00Z"}',
            )

    def test_failed_outcome_is_recorded_verbatim(self):
        with tempfile.TemporaryDirectory() as d:
            path = rr.record_send_result(d, make_result(outcome="FAILED"))
            self.assertEqual(read_canonical(path)["outcome"], "FAILED")

    def test_result_schema_rejects_extras_bad_token_unknown_outcome_naive_clock(self):
        fields = make_result().model_dump()
        fields["extra"] = "CNRY-A06-extra-41bb"
        with self.assertRaises(ValidationError):
            rr.SendResult.model_validate(fields)
        with self.assertRaises(ValidationError):
            make_result(intent_id="bad/id")
        with self.assertRaises(ValidationError):
            make_result(outcome="MAYBE")
        with self.assertRaises(ValidationError):
            make_result(recorded_at=datetime(2026, 10, 4, 8, 6, 0))  # naive clock

    def test_duplicate_registration_is_refused_and_first_outcome_survives(self):
        canary = "CNRY-A06-dup-b3a9"
        with tempfile.TemporaryDirectory() as d:
            first = rr.record_send_result(d, make_result(intent_id=canary, outcome="SENT"))
            with self.assertRaises(SafetyError) as ctx:
                rr.record_send_result(d, make_result(intent_id=canary, outcome="FAILED"))
            assert_clean_controlled(self, ctx, SafetyCode.CONTRACT_VIOLATION, canary)
            self.assertEqual(read_canonical(first)["outcome"], "SENT")

    def test_write_failure_enospc_blocks_record(self):
        with tempfile.TemporaryDirectory() as d:
            def boom(fileobj, data):
                raise OSError(errno.ENOSPC, "No space left on device")
            with mock.patch(f"{DW}._write_all", side_effect=boom):
                with self.assertRaises(SafetyError) as ctx:
                    rr.record_send_result(d, make_result())
            assert_clean_controlled(self, ctx, SafetyCode.AUDIT_WRITE_FAILED)
            self.assertEqual(list(Path(d).iterdir()), [])


class ReconcileCrashScenarioTests(unittest.TestCase):
    def test_kill_before_intent_leaves_nothing_to_reconcile(self):
        with tempfile.TemporaryDirectory() as d:
            summary = rr.reconcile_after_crash(d)
            self.assertEqual(summary.scanned_intents, 0)
            self.assertEqual((summary.confirmed, summary.marked_unknown, summary.already_adjudicated), (0, 0, 0))
            self.assertEqual(list(Path(d).iterdir()), [])

    def test_kill_after_intent_before_send_marks_result_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            commit_release_intent(d, make_intent("aaa-intent-20261004"))
            summary = rr.reconcile_after_crash(d)
            self.assertEqual(summary.scanned_intents, 1)
            self.assertEqual(summary.marked_unknown, 1)
            self.assertEqual(summary.confirmed, 0)
            # no result is fabricated
            self.assertFalse((Path(d) / "aaa-intent-20261004.result.json").exists())
            payload = read_canonical(Path(d) / "aaa-intent-20261004.reconcile.json")
            self.assertEqual(payload["adjudication"], "RESULT_UNKNOWN")
            self.assertIsNone(payload["outcome"])
            self.assertEqual(payload["intent_id"], "aaa-intent-20261004")

    def test_kill_after_send_preserves_real_sent_result(self):
        with tempfile.TemporaryDirectory() as d:
            commit_release_intent(d, make_intent())
            result_path = rr.record_send_result(d, make_result(outcome="SENT"))
            result_bytes = result_path.read_bytes()
            summary = rr.reconcile_after_crash(d)
            self.assertEqual((summary.confirmed, summary.marked_unknown), (1, 0))
            payload = read_canonical(Path(d) / "intent-20261004-0001.reconcile.json")
            self.assertEqual(payload["adjudication"], "RESULT_CONFIRMED")
            self.assertEqual(payload["outcome"], "SENT")
            # the real result record is never rewritten
            self.assertEqual(result_path.read_bytes(), result_bytes)

    def test_kill_after_send_preserves_real_failed_result(self):
        with tempfile.TemporaryDirectory() as d:
            commit_release_intent(d, make_intent())
            rr.record_send_result(d, make_result(outcome="FAILED"))
            summary = rr.reconcile_after_crash(d)
            self.assertEqual(summary.confirmed, 1)
            payload = read_canonical(Path(d) / "intent-20261004-0001.reconcile.json")
            self.assertEqual(payload["outcome"], "FAILED")

    def test_missing_ledger_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SafetyError) as ctx:
                rr.reconcile_after_crash(Path(d) / "no-such-ledger")
            assert_clean_controlled(self, ctx, SafetyCode.CONTRACT_VIOLATION)


class ReconcileIdempotencyTests(unittest.TestCase):
    def test_reentry_produces_identical_ledger(self):
        with tempfile.TemporaryDirectory() as d:
            commit_release_intent(d, make_intent("aaa-intent"))
            commit_release_intent(d, make_intent("bbb-intent"))
            rr.record_send_result(d, make_result(intent_id="bbb-intent", outcome="SENT"))
            first = rr.reconcile_after_crash(d)
            self.assertEqual((first.confirmed, first.marked_unknown), (1, 1))
            ledger = snapshot(d)
            second = rr.reconcile_after_crash(d)
            self.assertEqual(second.already_adjudicated, 2)
            self.assertEqual((second.confirmed, second.marked_unknown), (0, 0))
            self.assertEqual(snapshot(d), ledger)  # no rewrite, no re-judgment

    def test_late_result_does_not_rejudge_unknown_verdict(self):
        with tempfile.TemporaryDirectory() as d:
            commit_release_intent(d, make_intent())
            rr.reconcile_after_crash(d)
            rr.record_send_result(d, make_result(outcome="SENT"))
            summary = rr.reconcile_after_crash(d)
            self.assertEqual(summary.already_adjudicated, 1)
            payload = read_canonical(Path(d) / "intent-20261004-0001.reconcile.json")
            self.assertEqual(payload["adjudication"], "RESULT_UNKNOWN")
            self.assertIsNone(payload["outcome"])

    def test_partial_write_failure_resumes_without_rejudging(self):
        with tempfile.TemporaryDirectory() as d:
            commit_release_intent(d, make_intent("aaa-intent"))
            commit_release_intent(d, make_intent("bbb-intent"))
            real_commit = rr.durable_commit

            def flaky(directory, filename, data, **kwargs):
                if filename.startswith("bbb"):
                    raise DurableWriteError("injected crash")
                return real_commit(directory, filename, data, **kwargs)

            with mock.patch.object(rr, "durable_commit", side_effect=flaky):
                with self.assertRaises(SafetyError) as ctx:
                    rr.reconcile_after_crash(d)
            assert_clean_controlled(self, ctx, SafetyCode.AUDIT_WRITE_FAILED)
            self.assertTrue((Path(d) / "aaa-intent.reconcile.json").exists())
            self.assertFalse((Path(d) / "bbb-intent.reconcile.json").exists())
            resume = rr.reconcile_after_crash(d)
            self.assertEqual((resume.already_adjudicated, resume.marked_unknown), (1, 1))


class ReconcileCorruptionTests(unittest.TestCase):
    def test_malformed_intent_is_quarantined_and_run_aborts_before_any_adjudication(self):
        with tempfile.TemporaryDirectory() as d:
            corrupt_id = "CNRY-A06-corrupt-9d41"
            commit_release_intent(d, make_intent("aaa-intent"))
            (Path(d) / f"{corrupt_id}.intent.json").write_bytes(b"{not json")
            with self.assertRaises(SafetyError) as ctx:
                rr.reconcile_after_crash(d)
            assert_clean_controlled(self, ctx, SafetyCode.CONTRACT_VIOLATION, corrupt_id)
            self.assertFalse((Path(d) / f"{corrupt_id}.intent.json").exists())
            self.assertTrue((Path(d) / f"{corrupt_id}.intent.quarantined").exists())
            # never adjudicated as unknown, healthy sibling untouched
            self.assertFalse((Path(d) / f"{corrupt_id}.reconcile.json").exists())
            self.assertFalse((Path(d) / "aaa-intent.reconcile.json").exists())
            # re-entry no longer trips on the quarantined document
            summary = rr.reconcile_after_crash(d)
            self.assertEqual((summary.scanned_intents, summary.marked_unknown), (1, 1))

    def test_intent_with_missing_fields_is_quarantined(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "half.intent.json").write_bytes(
                json.dumps({"intent_id": "half"}).encode("utf-8")
            )
            with self.assertRaises(SafetyError) as ctx:
                rr.reconcile_after_crash(d)
            assert_clean_controlled(self, ctx, SafetyCode.CONTRACT_VIOLATION)
            self.assertTrue((Path(d) / "half.intent.quarantined").exists())

    def test_intent_filename_payload_id_mismatch_is_quarantined(self):
        with tempfile.TemporaryDirectory() as d:
            data = json.dumps(
                {"intent_id": "payload-id", "recorded_at": "2026-10-04T08:05:00Z",
                 "domain": "hr", "category": "c", "policy_version": "v1",
                 "package_version": "v1", "purpose": "p"},
                sort_keys=True,
            ).encode("utf-8")
            (Path(d) / "file-id.intent.json").write_bytes(data)
            with self.assertRaises(SafetyError) as ctx:
                rr.reconcile_after_crash(d)
            assert_clean_controlled(self, ctx, SafetyCode.CONTRACT_VIOLATION)
            self.assertTrue((Path(d) / "file-id.intent.quarantined").exists())

    def test_quarantine_rename_failure_still_aborts_controlled(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "broken.intent.json").write_bytes(b"\xff\xfe")
            with mock.patch.object(rr, "_quarantine", side_effect=OSError(errno.EPERM, "denied")):
                with self.assertRaises(SafetyError) as ctx:
                    rr.reconcile_after_crash(d)
            assert_clean_controlled(self, ctx, SafetyCode.CONTRACT_VIOLATION)
            self.assertTrue((Path(d) / "broken.intent.json").exists())
            self.assertEqual([p.name for p in Path(d).iterdir()], ["broken.intent.json"])

    def test_orphan_result_for_unknown_intent_is_refused(self):
        canary = "CNRY-A06-orphan-2e77"
        with tempfile.TemporaryDirectory() as d:
            commit_release_intent(d, make_intent("aaa-intent"))
            rr.record_send_result(d, make_result(intent_id=canary, outcome="SENT"))
            with self.assertRaises(SafetyError) as ctx:
                rr.reconcile_after_crash(d)
            assert_clean_controlled(self, ctx, SafetyCode.CONTRACT_VIOLATION, canary)
            self.assertFalse((Path(d) / "aaa-intent.reconcile.json").exists())

    def test_result_filename_payload_id_mismatch_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            commit_release_intent(d, make_intent("aaa-intent"))
            payload = json.dumps(
                {"intent_id": "other-id", "outcome": "SENT",
                 "recorded_at": "2026-10-04T08:06:00Z"},
                sort_keys=True,
            ).encode("utf-8")
            (Path(d) / "aaa-intent.result.json").write_bytes(payload)
            with self.assertRaises(SafetyError) as ctx:
                rr.reconcile_after_crash(d)
            assert_clean_controlled(self, ctx, SafetyCode.CONTRACT_VIOLATION)
            self.assertFalse((Path(d) / "aaa-intent.reconcile.json").exists())

    def test_corrupt_result_document_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            commit_release_intent(d, make_intent("aaa-intent"))
            (Path(d) / "aaa-intent.result.json").write_bytes(b"not-json-at-all")
            with self.assertRaises(SafetyError) as ctx:
                rr.reconcile_after_crash(d)
            assert_clean_controlled(self, ctx, SafetyCode.CONTRACT_VIOLATION)
            self.assertFalse((Path(d) / "aaa-intent.reconcile.json").exists())

    def test_corrupt_result_is_never_quarantined(self):
        with tempfile.TemporaryDirectory() as d:
            commit_release_intent(d, make_intent("aaa-intent"))
            (Path(d) / "aaa-intent.result.json").write_bytes(b"garbage")
            with self.assertRaises(SafetyError):
                rr.reconcile_after_crash(d)
            self.assertTrue((Path(d) / "aaa-intent.result.json").exists())
            self.assertFalse((Path(d) / "aaa-intent.result.quarantined").exists())

    def test_corrupt_or_empty_reconcile_document_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            commit_release_intent(d, make_intent("aaa-intent"))
            reconcile_path = Path(d) / "aaa-intent.reconcile.json"
            reconcile_path.write_bytes(b"")
            with self.assertRaises(SafetyError) as ctx:
                rr.reconcile_after_crash(d)
            assert_clean_controlled(self, ctx, SafetyCode.CONTRACT_VIOLATION)


if __name__ == "__main__":
    unittest.main()
