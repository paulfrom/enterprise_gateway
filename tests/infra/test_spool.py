"""Encrypted spool tests: encrypt-then-durable-commit, explicit backpressure, no silent loss."""

import errno
import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from infra.envelope_crypto import (
    KmsProvider,
    KmsUnavailableError,
    StaticTestKmsProvider,
    decrypt_record,
    parse_record,
)
from infra.errors import SafetyCode, SafetyError
from knowledge.knowledge import SourceKind
from knowledge.knowledge_events import build_observation_event, event_sha256, serialize_event
from infra.spool import CollectionMode, GapRecord, SpoolPermit, SpoolWriter

FIXTURES = Path(__file__).parent / "fixtures" / "spool"
DW = "infra.durable_write"

CANARY_TEXT = "integration-lead@example.invalid"  # marker from the K-01 synthetic source excerpt


def spool_limits():
    return json.loads((FIXTURES / "spool_limits.json").read_text(encoding="utf-8"))


def build_event():
    return build_observation_event(
        tenant="tenant-acme",
        domain="scope-procurement",
        source_id="src-contract-alpha",
        source_version="v3",
        source_kind=SourceKind.DOCUMENT,
        evidence_digest="ab" * 32,
        evidence_offset=7,
        observed_at=datetime(2026, 10, 3, 13, 2, 11, tzinfo=timezone.utc),
        purpose="supplier-relationship-management",
        retention_policy="bucket-180d",
        acl=frozenset({"steward-01"}),
        extraction_version="extract-1.4.0",
    )


def make_writer(directory, kms=None, **limits):
    base = spool_limits()
    base.update(limits)
    return SpoolWriter(directory, kms if kms is not None else StaticTestKmsProvider(),
                       max_total_bytes=base["max_total_bytes"], max_files=base["max_files"])


class RequiredCollectionTests(unittest.TestCase):
    def test_required_collect_returns_permit_and_roundtrips(self):
        kms = StaticTestKmsProvider()
        with tempfile.TemporaryDirectory() as d:
            writer = make_writer(d, kms)
            event = build_event()
            permit = writer.collect(event, mode=CollectionMode.REQUIRED)
            self.assertIsInstance(permit, SpoolPermit)
            raw = permit.path.read_bytes()
            self.assertEqual(len(raw), permit.bytes_written)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), permit.ciphertext_sha256)
            # A-02 reuse: the on-disk envelope decrypts back to the event bytes.
            plaintext = decrypt_record(kms, parse_record(raw))
            self.assertEqual(plaintext, serialize_event(event))

    def test_spool_bytes_contain_no_plaintext_event_fields(self):
        with tempfile.TemporaryDirectory() as d:
            writer = make_writer(d)
            event = build_event()
            permit = writer.collect(event, mode=CollectionMode.REQUIRED)
            raw = permit.path.read_bytes()
            for marker in (b"tenant-acme", b"src-contract-alpha", b"steward-01",
                           b"ab" * 32, CANARY_TEXT.encode("utf-8")):
                self.assertNotIn(marker, raw)
            self.assertNotIn("evidence_ref".encode(), raw)

    def test_tampered_ciphertext_fails_authentication(self):
        kms = StaticTestKmsProvider()
        with tempfile.TemporaryDirectory() as d:
            permit = make_writer(d, kms).collect(build_event(), mode=CollectionMode.REQUIRED)
            payload = json.loads(permit.path.read_bytes().decode("utf-8"))
            ciphertext = payload["ciphertext"]
            payload["ciphertext"] = ("0" if ciphertext[0] != "0" else "1") + ciphertext[1:]
            tampered = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=False).encode("utf-8")
            with self.assertRaises(SafetyError) as ctx:
                decrypt_record(kms, parse_record(tampered))
            self.assertEqual(ctx.exception.code, SafetyCode.DECRYPTION_FAILED)

    def test_deterministic_record_id_for_same_event(self):
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            p1 = make_writer(d1).collect(build_event(), mode=CollectionMode.REQUIRED)
            p2 = make_writer(d2).collect(build_event(), mode=CollectionMode.REQUIRED)
            self.assertEqual(p1.record_id, p2.record_id)


class RequiredFailureTests(unittest.TestCase):
    def test_write_failure_blocks_permit(self):
        with tempfile.TemporaryDirectory() as d:
            writer = make_writer(d)
            with mock.patch(f"{DW}._flush_and_fsync", side_effect=OSError(errno.EIO, "fsync failed")):
                with self.assertRaises(SafetyError) as ctx:
                    writer.collect(build_event(), mode=CollectionMode.REQUIRED)
            self.assertEqual(ctx.exception.code, SafetyCode.SPOOL_WRITE_FAILED)
            self.assertEqual(list(Path(d).iterdir()), [])  # no spool file, no tmp

    def test_rename_failure_blocks_permit(self):
        with tempfile.TemporaryDirectory() as d:
            writer = make_writer(d)
            with mock.patch(f"{DW}._replace", side_effect=OSError(errno.EPERM, "rename denied")):
                with self.assertRaises(SafetyError) as ctx:
                    writer.collect(build_event(), mode=CollectionMode.REQUIRED)
            self.assertEqual(ctx.exception.code, SafetyCode.SPOOL_WRITE_FAILED)
            self.assertEqual(list(Path(d).iterdir()), [])

    def test_file_count_watermark_blocks_permit(self):
        with tempfile.TemporaryDirectory() as d:
            writer = make_writer(d, max_files=1)
            writer.collect(build_event(), mode=CollectionMode.REQUIRED)
            with self.assertRaises(SafetyError) as ctx:
                writer.collect(build_event(), mode=CollectionMode.REQUIRED)
            self.assertEqual(ctx.exception.code, SafetyCode.SPOOL_FULL)
            self.assertEqual(len(list(Path(d).iterdir())), 1)  # nothing new written

    def test_byte_watermark_blocks_permit(self):
        with tempfile.TemporaryDirectory() as d:
            writer = make_writer(d, max_total_bytes=200)  # one envelope exceeds it
            with self.assertRaises(SafetyError) as ctx:
                writer.collect(build_event(), mode=CollectionMode.REQUIRED)
            self.assertEqual(ctx.exception.code, SafetyCode.SPOOL_FULL)
            self.assertEqual(list(Path(d).iterdir()), [])

    def test_kms_unavailable_propagates_in_required_mode(self):
        class DownKms(KmsProvider):
            def wrap(self, dek: bytes, *, purpose: str, bucket: str) -> bytes:
                raise KmsUnavailableError("down")
            def unwrap(self, wrapped_dek: bytes, *, purpose: str, bucket: str) -> bytes:
                raise KmsUnavailableError("down")

        with tempfile.TemporaryDirectory() as d:
            writer = make_writer(d, DownKms())
            with self.assertRaises(SafetyError) as ctx:
                writer.collect(build_event(), mode=CollectionMode.REQUIRED)
            self.assertEqual(ctx.exception.code, SafetyCode.KMS_UNAVAILABLE)


class OptionalGapPolicyTests(unittest.TestCase):
    def test_optional_success_returns_permit(self):
        with tempfile.TemporaryDirectory() as d:
            permit = make_writer(d).collect(build_event(), mode=CollectionMode.OPTIONAL_WITH_GAP_POLICY)
            self.assertIsInstance(permit, SpoolPermit)

    def test_optional_full_spool_records_gap_instead_of_silent_loss(self):
        with tempfile.TemporaryDirectory() as d:
            writer = make_writer(d, max_files=1)
            writer.collect(build_event(), mode=CollectionMode.OPTIONAL_WITH_GAP_POLICY)
            gap = writer.collect(build_event(), mode=CollectionMode.OPTIONAL_WITH_GAP_POLICY)
            self.assertIsInstance(gap, GapRecord)
            self.assertEqual(gap.reason, SafetyCode.SPOOL_FULL)
            self.assertEqual(gap.mode, CollectionMode.OPTIONAL_WITH_GAP_POLICY)
            gap_raw = gap.gap_path.read_bytes()
            gap_payload = json.loads(gap_raw.decode("utf-8"))
            self.assertEqual(gap_payload["kind"], "gap_record")
            self.assertEqual(gap_payload["event_sha256"], event_sha256(build_event()))
            self.assertEqual(gap_payload["reason"], "SPOOL_FULL")
            # Gap metadata is minimal: no content, no event fields.
            self.assertNotIn(CANARY_TEXT.encode("utf-8"), gap_raw)
            self.assertNotIn(b"src-contract-alpha", gap_raw)
            self.assertNotIn(b"tenant-acme", gap_raw)

    def test_optional_write_failure_records_gap(self):
        with tempfile.TemporaryDirectory() as d:
            writer = make_writer(d)

            def fail_first_rename(src, dst):
                fail_first_rename.calls += 1
                if fail_first_rename.calls == 1:
                    raise OSError(errno.EPERM, "rename denied")
                os.replace(src, dst)
            fail_first_rename.calls = 0

            with mock.patch(f"{DW}._replace", side_effect=fail_first_rename):
                gap = writer.collect(build_event(), mode=CollectionMode.OPTIONAL_WITH_GAP_POLICY)
            self.assertEqual(gap.reason, SafetyCode.SPOOL_WRITE_FAILED)
            self.assertTrue(gap.gap_path.exists())

    def test_optional_tempfile_creation_failure_records_gap(self):
        # mkstemp-stage failures (ACL denial etc.) must also land in a
        # GapRecord, never escape as a raw OSError bypassing the gap policy.
        with tempfile.TemporaryDirectory() as d:
            writer = make_writer(d)
            real_mkstemp = tempfile.mkstemp

            def fail_first_mkstemp(*args, **kwargs):
                fail_first_mkstemp.calls += 1
                if fail_first_mkstemp.calls == 1:
                    raise PermissionError(errno.EACCES, "denied")
                return real_mkstemp(*args, **kwargs)
            fail_first_mkstemp.calls = 0

            with mock.patch(f"{DW}.tempfile.mkstemp", side_effect=fail_first_mkstemp):
                gap = writer.collect(build_event(), mode=CollectionMode.OPTIONAL_WITH_GAP_POLICY)
            self.assertIsInstance(gap, GapRecord)
            self.assertEqual(gap.reason, SafetyCode.SPOOL_WRITE_FAILED)
            self.assertTrue(gap.gap_path.exists())

    def test_unrecordable_gap_raises_instead_of_silence(self):
        # If even the gap metadata cannot be persisted, silent loss is
        # forbidden: the failure must surface as SPOOL_WRITE_FAILED.
        with tempfile.TemporaryDirectory() as d:
            writer = make_writer(d)
            with mock.patch(f"{DW}._flush_and_fsync", side_effect=OSError(errno.EIO, "fsync failed")):
                with self.assertRaises(SafetyError) as ctx:
                    writer.collect(build_event(), mode=CollectionMode.OPTIONAL_WITH_GAP_POLICY)
            self.assertEqual(ctx.exception.code, SafetyCode.SPOOL_WRITE_FAILED)
            self.assertIn("gap_record", str(ctx.exception))

    def test_mode_is_explicit_per_call(self):
        with tempfile.TemporaryDirectory() as d:
            writer = make_writer(d)
            with self.assertRaises(TypeError):
                writer.collect(build_event())  # type: ignore[call-arg]
            with self.assertRaises(TypeError):
                writer.collect("not-an-event", mode=CollectionMode.REQUIRED)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
