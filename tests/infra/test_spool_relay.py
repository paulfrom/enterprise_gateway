"""Spool relay tests: at-least-once + idempotent dedup + post-ack delete.

Covers the three relay stages with real failure injection: read-stage
corruption → quarantine; submit-stage sink failure → RELAY_SUBMIT_FAILED with
the file retained and retry-safe recovery; confirm-stage crash between submit
and delete → redelivery resolves through has_contributed without double
contribution. Canary checks assert no public message, stat field, or
quarantined byte carries business plaintext.
"""

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
    encrypt_record,
    parse_record,
    serialize_record,
)
from infra.errors import SafetyCode, SafetyError
from knowledge.knowledge import SourceKind
from knowledge.knowledge_events import (
    build_observation_event,
    serialize_event,
)
from infra.spool import CollectionMode, GapRecord, SpoolWriter
from infra.spool_relay import (
    InMemoryLedgerSink,
    LedgerSink,
    SpoolRelay,
    compute_dedup_key,
)

FIXTURES = Path(__file__).parent / "fixtures" / "spool" / "relay"
RELAY = "infra.spool_relay"

CANARY_TEXT = "integration-lead@example.invalid"  # marker from the K-01 synthetic source excerpt
SOURCE_MARKERS = (b"src-synthetic-alpha", b"src-synthetic-beta", b"src-synthetic-gamma",
                  b"tenant-acme", b"steward-01", CANARY_TEXT.encode("utf-8"))
OBSERVED_AT = datetime(2026, 10, 3, 14, 15, 0, tzinfo=timezone.utc)


def build_events():
    specs = json.loads((FIXTURES / "relay_events.json").read_text(encoding="utf-8"))["events"]
    return [
        build_observation_event(
            tenant=spec["tenant"],
            domain=spec["domain"],
            source_id=spec["source_id"],
            source_version=spec["source_version"],
            source_kind=SourceKind(spec["source_kind"]),
            evidence_digest=spec["evidence_digest"],
            evidence_offset=spec["evidence_offset"],
            observed_at=OBSERVED_AT,
            purpose=spec["purpose"],
            retention_policy=spec["retention_policy"],
            acl=frozenset(spec["acl"]),
            extraction_version=spec["extraction_version"],
        )
        for spec in specs
    ]


def make_spool(directory, kms, events, **writer_limits):
    writer = SpoolWriter(directory, kms, **writer_limits)
    for event in events:
        writer.collect(event, mode=CollectionMode.REQUIRED)
    return writer


def spool_record_files(directory):
    return sorted(p for p in Path(directory).iterdir()
                  if p.is_file() and p.name.endswith(".env.json"))


def expected_dedup_key(event):
    """Independent re-derivation of the documented dedup-key format."""
    preimage = json.dumps(
        {
            "source_id": event.source_id,
            "source_version": event.source_version,
            "evidence_digest": event.evidence_ref.digest,
            "evidence_offset": event.evidence_ref.offset,
            "event_sha256": hashlib.sha256(serialize_event(event)).hexdigest(),
        },
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(preimage).hexdigest()


class OneShotSink(InMemoryLedgerSink):
    """Test sink that raises on the first submit, then behaves normally."""

    def __init__(self):
        super().__init__()
        self._armed = True

    def submit(self, event, dedup_key):
        if self._armed:
            self._armed = False
            raise RuntimeError("injected sink outage")
        super().submit(event, dedup_key)


class FlakyKmsProvider(KmsProvider):
    """Test double: the first unwrap signals a transient KMS outage, later
    unwraps recover by delegating to a real synthetic provider (whose KEKs
    also served the wraps during spool writing)."""

    def __init__(self):
        self._inner = StaticTestKmsProvider()
        self._armed = True

    def wrap(self, dek, *, purpose, bucket):
        return self._inner.wrap(dek, purpose=purpose, bucket=bucket)

    def unwrap(self, wrapped_dek, *, purpose, bucket):
        if self._armed:
            self._armed = False
            raise KmsUnavailableError("synthetic transient outage")
        return self._inner.unwrap(wrapped_dek, purpose=purpose, bucket=bucket)


class DedupKeyAndContractTests(unittest.TestCase):
    def test_dedup_key_matches_documented_canonical_format(self):
        for event in build_events():
            self.assertEqual(compute_dedup_key(event), expected_dedup_key(event))
            self.assertEqual(compute_dedup_key(event), compute_dedup_key(event))

    def test_dedup_key_separates_version_offset_and_content(self):
        base = build_events()[0]
        variants = [
            base.model_copy(update={"source_version": "v4"}),
            base.model_copy(update={"evidence_ref": base.evidence_ref.model_copy(update={"offset": 12})}),
            base.model_copy(update={"purpose": "other-purpose"}),
        ]
        for variant in variants:
            self.assertNotEqual(compute_dedup_key(base), compute_dedup_key(variant))

    def test_ledger_sink_is_abstract(self):
        with self.assertRaises(TypeError):
            LedgerSink()

    def test_relay_rejects_wrong_component_types(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(TypeError):
                SpoolRelay(d, StaticTestKmsProvider(), sink="not-a-sink")  # type: ignore[arg-type]
            with self.assertRaises(TypeError):
                SpoolRelay(d, kms="not-a-kms", sink=InMemoryLedgerSink())  # type: ignore[arg-type]

    def test_relay_requires_existing_spool_directory(self):
        with tempfile.TemporaryDirectory() as d:
            relay = SpoolRelay(Path(d) / "missing", StaticTestKmsProvider(), InMemoryLedgerSink())
            with self.assertRaises(FileNotFoundError):
                relay.relay_once()


class PositiveRelayTests(unittest.TestCase):
    def test_three_events_relay_contributes_exactly_once_and_clears_spool(self):
        kms = StaticTestKmsProvider()
        events = build_events()
        with tempfile.TemporaryDirectory() as d:
            make_spool(d, kms, events)
            sink = InMemoryLedgerSink()
            stats = SpoolRelay(d, kms, sink).relay_once()
            self.assertEqual((stats.submitted, stats.skipped, stats.failed, stats.quarantined),
                             (3, 0, 0, 0))
            self.assertEqual(sink.contribution_count, 3)
            for event in events:
                self.assertTrue(sink.has_contributed(compute_dedup_key(event)))
            self.assertEqual(sorted(sink.contributed_events(), key=lambda e: e.source_id),
                             sorted(events, key=lambda e: e.source_id))
            self.assertEqual(spool_record_files(d), [])  # confirmed → direct delete

    def test_second_relay_over_respooled_events_skips_all_and_count_is_unchanged(self):
        # Historical redelivery of identical events must not add contributions.
        kms = StaticTestKmsProvider()
        events = build_events()
        with tempfile.TemporaryDirectory() as d:
            writer = make_spool(d, kms, events)
            relay = SpoolRelay(d, kms, InMemoryLedgerSink())
            relay.relay_once()
            for event in events:  # re-spool identical content (same record ids)
                writer.collect(event, mode=CollectionMode.REQUIRED)
            self.assertEqual(len(spool_record_files(d)), 3)
            stats = relay.relay_once()
            self.assertEqual((stats.submitted, stats.skipped, stats.failed, stats.quarantined),
                             (0, 3, 0, 0))
            self.assertEqual(relay._sink.contribution_count, 3)
            self.assertEqual(spool_record_files(d), [])

    def test_spool_bytes_stay_encrypted_and_roundtrip_to_the_event(self):
        kms = StaticTestKmsProvider()
        event = build_events()[0]
        with tempfile.TemporaryDirectory() as d:
            writer = SpoolWriter(d, kms)
            permit = writer.collect(event, mode=CollectionMode.REQUIRED)
            raw = permit.path.read_bytes()
            for marker in SOURCE_MARKERS:
                self.assertNotIn(marker, raw)
            self.assertEqual(decrypt_record(kms, parse_record(raw)), serialize_event(event))


class SubmitFailureTests(unittest.TestCase):
    def test_submit_failure_keeps_file_records_failure_and_recovers_without_duplicate(self):
        kms = StaticTestKmsProvider()
        events = build_events()
        with tempfile.TemporaryDirectory() as d:
            make_spool(d, kms, events)
            sink = OneShotSink()
            relay = SpoolRelay(d, kms, sink)
            with self.assertRaises(SafetyError) as ctx:
                relay.relay_once()
            self.assertEqual(ctx.exception.code, SafetyCode.RELAY_SUBMIT_FAILED)
            # Canary: the public message is the bare code — no business text.
            self.assertEqual(str(ctx.exception), "RELAY_SUBMIT_FAILED")
            for marker in SOURCE_MARKERS:
                self.assertNotIn(marker, str(ctx.exception).encode("utf-8"))
            stats = ctx.exception.stats
            self.assertEqual((stats.submitted, stats.failed), (2, 1))
            self.assertEqual(stats.failures[0].code, SafetyCode.RELAY_SUBMIT_FAILED)
            self.assertEqual(sink.contribution_count, 2)  # the failed key never contributed
            self.assertEqual(len(spool_record_files(d)), 1)  # no confirmation, file retained

            stats = relay.relay_once()  # outage over: retry contributes the retained file once
            self.assertEqual((stats.submitted, stats.skipped, stats.failed), (1, 0, 0))
            self.assertEqual(sink.contribution_count, 3)
            self.assertEqual(spool_record_files(d), [])

    def test_failed_pass_still_processes_remaining_files(self):
        kms = StaticTestKmsProvider()
        events = build_events()
        with tempfile.TemporaryDirectory() as d:
            make_spool(d, kms, events)
            sink = OneShotSink()
            with self.assertRaises(SafetyError) as ctx:
                SpoolRelay(d, kms, sink).relay_once()
            self.assertEqual(ctx.exception.stats.submitted, 2)  # others not blocked


class ReadStageFailureTests(unittest.TestCase):
    def test_kms_outage_at_read_stage_keeps_files_fails_pass_and_recovers(self):
        # A transient KMS outage must not drain the spool into quarantine:
        # the failed record stays retryable and the pass reports
        # RELAY_SUBMIT_FAILED. The double recovers after its first unwrap,
        # so the same pass relays the remaining records normally.
        kms = FlakyKmsProvider()
        events = build_events()
        with tempfile.TemporaryDirectory() as d:
            make_spool(d, kms, events)
            sink = InMemoryLedgerSink()
            relay = SpoolRelay(d, kms, sink)
            with self.assertRaises(SafetyError) as ctx:
                relay.relay_once()
            self.assertEqual(ctx.exception.code, SafetyCode.RELAY_SUBMIT_FAILED)
            # Canary: the public message is the bare code — no business text.
            self.assertEqual(str(ctx.exception), "RELAY_SUBMIT_FAILED")
            for marker in SOURCE_MARKERS:
                self.assertNotIn(marker, str(ctx.exception).encode("utf-8"))
            stats = ctx.exception.stats
            self.assertEqual((stats.submitted, stats.skipped, stats.failed, stats.quarantined),
                             (2, 0, 1, 0))
            self.assertTrue(all(f.code == SafetyCode.RELAY_SUBMIT_FAILED
                                for f in stats.failures))
            # Canary: failure accounting carries codes and file names only.
            for marker in SOURCE_MARKERS:
                self.assertNotIn(marker, repr(stats).encode("utf-8"))
            self.assertEqual(sink.contribution_count, 2)  # outage hit one record
            self.assertEqual(len(spool_record_files(d)), 1)  # transient: kept
            quarantine_dir = relay.quarantine_directory
            self.assertTrue(not quarantine_dir.exists()
                            or not any(quarantine_dir.iterdir()))

            # KMS healthy again: the retained record relays exactly once.
            stats = relay.relay_once()
            self.assertEqual((stats.submitted, stats.skipped, stats.failed, stats.quarantined),
                             (1, 0, 0, 0))
            self.assertEqual(sink.contribution_count, 3)
            self.assertEqual(spool_record_files(d), [])

    def test_unreadable_spool_file_is_retained_counted_and_recovers(self):
        # An OSError while reading the record (file vanished after listing)
        # is retryable infrastructure failure, not quarantine material.
        kms = StaticTestKmsProvider()
        event = build_events()[0]
        with tempfile.TemporaryDirectory() as d:
            make_spool(d, kms, [event])
            sink = InMemoryLedgerSink()
            relay = SpoolRelay(d, kms, sink)
            with mock.patch.object(Path, "read_bytes",
                                   side_effect=OSError(errno.EIO,
                                                       "simulated unreadable record")):
                with self.assertRaises(SafetyError) as ctx:
                    relay.relay_once()
            self.assertEqual(ctx.exception.code, SafetyCode.RELAY_SUBMIT_FAILED)
            self.assertEqual(str(ctx.exception), "RELAY_SUBMIT_FAILED")
            for marker in SOURCE_MARKERS:
                self.assertNotIn(marker, str(ctx.exception).encode("utf-8"))
            stats = ctx.exception.stats
            self.assertEqual((stats.submitted, stats.failed, stats.quarantined), (0, 1, 0))
            self.assertEqual(stats.failures[0].code, SafetyCode.RELAY_SUBMIT_FAILED)
            for marker in SOURCE_MARKERS:
                self.assertNotIn(marker, repr(stats).encode("utf-8"))
            self.assertEqual(sink.contribution_count, 0)
            self.assertEqual(len(spool_record_files(d)), 1)  # retained, retryable
            quarantine_dir = relay.quarantine_directory
            self.assertTrue(not quarantine_dir.exists()
                            or not any(quarantine_dir.iterdir()))

            # Once the read succeeds the same record contributes exactly once.
            stats = relay.relay_once()
            self.assertEqual((stats.submitted, stats.skipped, stats.failed), (1, 0, 0))
            self.assertEqual(sink.contribution_count, 1)
            self.assertEqual(spool_record_files(d), [])


class ConfirmStageCrashTests(unittest.TestCase):
    def test_crash_between_submit_and_delete_replays_without_duplicate_contribution(self):
        kms = StaticTestKmsProvider()
        event = build_events()[0]
        with tempfile.TemporaryDirectory() as d:
            make_spool(d, kms, [event])
            sink = InMemoryLedgerSink()
            relay = SpoolRelay(d, kms, sink)

            real_remove = os.remove

            def crash_once(path):
                crash_once.calls += 1
                if crash_once.calls == 1:
                    raise OSError(errno.EIO, "simulated crash after submit, before delete")
                real_remove(path)
            crash_once.calls = 0

            with mock.patch(f"{RELAY}._confirm_remove", side_effect=crash_once):
                with self.assertRaises(SafetyError) as ctx:
                    relay.relay_once()
            self.assertEqual(ctx.exception.code, SafetyCode.RELAY_SUBMIT_FAILED)
            stats = ctx.exception.stats
            self.assertEqual((stats.submitted, stats.failed), (1, 1))
            self.assertEqual(sink.contribution_count, 1)  # submit WAS acked before the crash
            self.assertEqual(len(spool_record_files(d)), 1)  # unconfirmed: file kept

            # Redelivery: dedup hit skips re-submit (the sink raises on duplicate
            # submit, so a resubmit would explode) and only completes the delete.
            stats = relay.relay_once()
            self.assertEqual((stats.submitted, stats.skipped, stats.failed), (0, 1, 0))
            self.assertEqual(sink.contribution_count, 1)  # 同事件只贡献一次
            self.assertEqual(spool_record_files(d), [])

    def test_partial_confirm_crash_does_not_block_other_records(self):
        kms = StaticTestKmsProvider()
        events = build_events()[:2]
        with tempfile.TemporaryDirectory() as d:
            make_spool(d, kms, events)
            sink = InMemoryLedgerSink()
            relay = SpoolRelay(d, kms, sink)

            real_remove = os.remove

            def crash_on_first(path):
                crash_on_first.calls += 1
                if crash_on_first.calls == 1:
                    raise OSError(errno.EIO, "crash on first confirm")
                real_remove(path)
            crash_on_first.calls = 0

            with mock.patch(f"{RELAY}._confirm_remove", side_effect=crash_on_first):
                with self.assertRaises(SafetyError) as ctx:
                    relay.relay_once()
            stats = ctx.exception.stats
            self.assertEqual((stats.submitted, stats.failed), (2, 1))
            self.assertEqual(sink.contribution_count, 2)
            self.assertEqual(len(spool_record_files(d)), 1)

            stats = relay.relay_once()
            self.assertEqual((stats.submitted, stats.skipped), (0, 1))
            self.assertEqual(sink.contribution_count, 2)
            self.assertEqual(spool_record_files(d), [])


class QuarantineTests(unittest.TestCase):
    def test_tampered_record_is_quarantined_not_submitted_not_deleted(self):
        kms = StaticTestKmsProvider()
        event = build_events()[0]
        with tempfile.TemporaryDirectory() as d:
            writer = SpoolWriter(d, kms)
            permit = writer.collect(event, mode=CollectionMode.REQUIRED)
            payload = json.loads(permit.path.read_bytes().decode("utf-8"))
            ciphertext = payload["ciphertext"]
            payload["ciphertext"] = ("0" if ciphertext[0] != "0" else "1") + ciphertext[1:]
            permit.path.write_text(json.dumps(payload, sort_keys=True,
                                              separators=(",", ":"), ensure_ascii=False),
                                   encoding="utf-8")
            sink = InMemoryLedgerSink()
            relay = SpoolRelay(d, kms, sink)
            stats = relay.relay_once()  # quarantine is final: no raise
            self.assertEqual((stats.submitted, stats.failed, stats.quarantined), (0, 0, 1))
            self.assertEqual(stats.quarantined_records[0].code, SafetyCode.DECRYPTION_FAILED)
            self.assertEqual(sink.contribution_count, 0)
            self.assertEqual(spool_record_files(d), [])
            quarantined = stats.quarantined_records[0].quarantine_path
            self.assertTrue(quarantined.exists())
            self.assertEqual(quarantined.parent, relay.quarantine_directory)
            # Canary: the quarantined blob is still ciphertext-only.
            raw = quarantined.read_bytes()
            for marker in SOURCE_MARKERS:
                self.assertNotIn(marker, raw)

    def test_invalid_event_payload_is_quarantined_as_event_invalid(self):
        kms = StaticTestKmsProvider()
        with tempfile.TemporaryDirectory() as d:
            record = encrypt_record(
                kms,
                json.dumps({"not": "an observation event"}).encode("utf-8"),
                domain="scope-procurement", bucket="bucket-180d",
                record_id="evt-" + "0" * 32, purpose="p:knowledge-spool",
            )
            (Path(d) / "evt-00000000000000000000000000000000.env.json").write_bytes(
                serialize_record(record))
            sink = InMemoryLedgerSink()
            relay = SpoolRelay(d, kms, sink)
            stats = relay.relay_once()
            self.assertEqual((stats.submitted, stats.failed, stats.quarantined), (0, 0, 1))
            self.assertEqual(stats.quarantined_records[0].code, SafetyCode.EVENT_INVALID)
            self.assertEqual(sink.contribution_count, 0)
            self.assertTrue(stats.quarantined_records[0].quarantine_path.exists())

    def test_gap_records_and_tmp_residuals_are_not_relayed(self):
        kms = StaticTestKmsProvider()
        event = build_events()[0]
        with tempfile.TemporaryDirectory() as d:
            writer = SpoolWriter(d, kms, max_files=1)
            writer.collect(event, mode=CollectionMode.REQUIRED)
            gap = writer.collect(event, mode=CollectionMode.OPTIONAL_WITH_GAP_POLICY)
            self.assertIsInstance(gap, GapRecord)
            tmp_residual = Path(d) / ".evt-deadbeef.residual.tmp"
            tmp_residual.write_bytes(b"crash leftover")
            sink = InMemoryLedgerSink()
            stats = SpoolRelay(d, kms, sink).relay_once()
            self.assertEqual((stats.submitted, stats.skipped, stats.quarantined), (1, 0, 0))
            self.assertTrue(gap.gap_path.exists())  # gap metadata is not a ledger contribution
            self.assertTrue(tmp_residual.exists())
            self.assertEqual(spool_record_files(d), [])

    def test_misbound_envelope_is_quarantined_not_submitted(self):
        kms = StaticTestKmsProvider()
        event = build_events()[0]
        # Encrypt event under a different domain in the envelope
        record = encrypt_record(
            kms, serialize_event(event),
            domain="different-domain",
            bucket=event.retention_policy,
            record_id="misbound-evt-001",
            purpose=f"{event.purpose}:knowledge_spool",
        )
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "misbound-evt-001.env.json").write_bytes(serialize_record(record))
            sink = InMemoryLedgerSink()
            stats = SpoolRelay(d, kms, sink).relay_once()
            self.assertEqual((stats.submitted, stats.failed, stats.quarantined), (0, 0, 1))
            self.assertEqual(sink.contribution_count, 0)
            self.assertEqual(stats.quarantined_records[0].code, SafetyCode.SCOPE_MISMATCH)


if __name__ == "__main__":
    unittest.main()
