"""B2 admin direct-read contract tests: no release without paired durable traces.

The service is assembled exactly as T4 will assemble it: a controlled catalog
directory, a fixed evidence root, a synthetic in-memory KMS provider, an
injected session-revalidation callback, one fixed review purpose, and an
independent access-event directory. Every rejection path must return no
plaintext; attempt and result events are separate durable_commit files with
fixed codes and never carry plaintext or key material.
"""

import hashlib
import json
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from audit.admin_reader import AdminAuditContext, AdminReviewService
from audit.audit_intent import ReleaseIntent, commit_release_intent
from audit.catalog import AuditCatalogBuilder
from infra.durable_write import DurableWriteError, durable_commit
from infra.envelope_crypto import (
    StaticTestKmsProvider,
    decrypt_record,
    encrypt_record,
    serialize_record,
)
from infra.errors import SafetyCode, SafetyError

RECORDED_AT = datetime(2026, 10, 9, 8, 30, 0, tzinfo=timezone.utc)
RETENTION_UNTIL = datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
RETENTION_PAST = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
LIFECYCLE_POLICY = "lifecycle-pol-2026.10"
TENANT = "tenant-hr"
DOMAIN = "scope-hr"
CATEGORY = "hr-inference"
INTENT_PURPOSE = "egress-audit"
EVIDENCE_PURPOSE = "original-text-retention"
BUCKET = "egress-original-30d"
POLICY_VERSION = "pol-2026.09-hr"
PACKAGE_VERSION = "pkg-8fbb791"
CANARY = b"CNRY-B2-reader-body-77be"
OTHER_PURPOSE = "other-evidence-purpose"
STORE = "audit._store"
AR = "audit.admin_reader"


def fixed_lifecycle(record_id: str):
    return (RETENTION_UNTIL, LIFECYCLE_POLICY)


def make_context(**overrides) -> AdminAuditContext:
    fields = {
        "actor_id": "admin",
        "session_digest": "ab" * 32,
        "tenant_id": TENANT,
        "domain": DOMAIN,
        "deadline": time.monotonic() + 60.0,
    }
    fields.update(overrides)
    return AdminAuditContext(**fields)


def make_service(
    tmp,
    *,
    kms=None,
    revalidate=None,
    review_purpose: str = EVIDENCE_PURPOSE,
) -> AdminReviewService:
    roots = Path(tmp)
    return AdminReviewService(
        catalog_directory=roots / "catalog",
        evidence_root=roots / "evidence",
        kms=kms or StaticTestKmsProvider(),
        revalidate=revalidate if revalidate is not None else (lambda: None),
        review_purpose=review_purpose,
        access_log_directory=roots / "access-log",
    )


def write_record(
    tmp,
    kms,
    *,
    record_id: str,
    tenant_id: str = TENANT,
    domain: str = DOMAIN,
    bucket: str = BUCKET,
    purpose: str = EVIDENCE_PURPOSE,
    plaintext: bytes = CANARY,
    retention_until=RETENTION_UNTIL,
    lifecycle_policy: str = LIFECYCLE_POLICY,
) -> bytes:
    roots = Path(tmp)
    (roots / "intent").mkdir(parents=True, exist_ok=True)
    (roots / "evidence").mkdir(parents=True, exist_ok=True)
    intent = ReleaseIntent(
        intent_id=f"intent-{record_id}",
        recorded_at=RECORDED_AT,
        domain=domain,
        category=CATEGORY,
        policy_version=POLICY_VERSION,
        package_version=PACKAGE_VERSION,
        purpose=INTENT_PURPOSE,
        tenant_id=tenant_id,
        evidence_record_id=record_id,
        evidence_retention_until=retention_until,
        evidence_lifecycle_policy_version=lifecycle_policy,
    )
    commit_release_intent(roots / "intent", intent)
    record = encrypt_record(
        kms, plaintext, domain=domain, bucket=bucket, record_id=record_id, purpose=purpose
    )
    data = serialize_record(record)
    durable_commit(roots / "evidence", f"{record_id}.evidence.json", data)
    return data


def build_catalog(tmp, *, lifecycle=fixed_lifecycle) -> int:
    roots = Path(tmp)
    builder = AuditCatalogBuilder(
        intent_root=roots / "intent",
        evidence_root=roots / "evidence",
        catalog_directory=roots / "catalog",
        lifecycle=lifecycle,
    )
    return builder.build_once()


def read_events(access_log_dir) -> list[dict]:
    events = []
    for path in sorted(Path(access_log_dir).glob("*.json")):
        events.append(json.loads(path.read_bytes()))
    events.sort(key=lambda event: event["at"])
    return events


def hand_craft_catalog(tmp, *, record_id, sha256_hex, tenant_id=TENANT, domain=DOMAIN,
                       purpose=EVIDENCE_PURPOSE, bucket=BUCKET,
                       evidence_path=None, status="available",
                       retention_until=RETENTION_UNTIL) -> None:
    """Write a catalog entry file directly (simulates catalog/evidence desync)."""
    roots = Path(tmp)
    catalog_dir = roots / "catalog"
    catalog_dir.mkdir(parents=True, exist_ok=True)
    body = {
        "format_version": 1,
        "record_id": record_id,
        "tenant_id": tenant_id,
        "domain": domain,
        "purpose": purpose,
        "bucket": bucket,
        "intent_id": f"intent-{record_id}",
        "evidence_path": evidence_path or f"{record_id}.evidence.json",
        "evidence_sha256": sha256_hex,
        "bytes_written": 1,
        "created_at": RECORDED_AT.isoformat(),
        "retention_until": retention_until.isoformat(),
        "lifecycle_policy_version": LIFECYCLE_POLICY,
        "status": status,
    }
    durable_commit(catalog_dir, f"{record_id}.catalog.json",
                   json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8"))


class ReaderSuccessTests(unittest.TestCase):
    def test_read_success_releases_and_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms = StaticTestKmsProvider()
            write_record(tmp, kms, record_id="ev-b2-r1")
            self.assertEqual(build_catalog(tmp), 1)
            calls: list[str] = []

            def revalidate() -> None:
                calls.append("checked")

            service = make_service(tmp, kms=kms, revalidate=revalidate)
            plaintext = service.read_plaintext("ev-b2-r1", context=make_context())
            self.assertEqual(plaintext, CANARY)
            self.assertEqual(calls, ["checked", "checked"])  # before and after decrypt
            events = read_events(Path(tmp) / "access-log")
            self.assertEqual([event["event"] for event in events],
                             ["AUDIT_READ_ATTEMPTED", "AUDIT_READ_RELEASED"])
            attempt, released = events
            for event in events:
                self.assertEqual(event["actor"], "admin")
                self.assertEqual(event["session_digest"], "ab" * 32)
                self.assertEqual(event["tenant_id"], TENANT)
                self.assertEqual(event["domain"], DOMAIN)
                self.assertEqual(event["record_sha256"],
                                 hashlib.sha256(b"ev-b2-r1").hexdigest())
            self.assertEqual(released["attempt_at"], attempt["at"])
            # Traces never carry plaintext or key material.
            kek_hex = kms.kek_for(EVIDENCE_PURPOSE, BUCKET).hex()
            for path in (Path(tmp) / "access-log").glob("*.json"):
                raw = path.read_bytes()
                self.assertNotIn(CANARY, raw)
                self.assertNotIn(kek_hex.encode(), raw)

    def test_list_and_get_return_metadata_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms = StaticTestKmsProvider()
            write_record(tmp, kms, record_id="ev-b2-a1")
            write_record(tmp, kms, record_id="ev-b2-a2", tenant_id="tenant-legal")
            self.assertEqual(build_catalog(tmp), 2)
            service = make_service(tmp, kms=kms)
            entries, cursor = service.list_records(tenant_id=TENANT, domain=DOMAIN)
            self.assertIsNone(cursor)
            self.assertEqual([entry.record_id for entry in entries], ["ev-b2-a1"])
            entry = entries[0]
            self.assertEqual(entry.tenant_id, TENANT)
            self.assertEqual(entry.domain, DOMAIN)
            self.assertEqual(entry.purpose, EVIDENCE_PURPOSE)
            self.assertEqual(entry.evidence_path, "ev-b2-a1.evidence.json")
            got = service.get_record("ev-b2-a1", tenant_id=TENANT, domain=DOMAIN)
            self.assertEqual(got, entry)
            kek_hex = kms.kek_for(EVIDENCE_PURPOSE, BUCKET).hex()
            for path in Path(tmp, "catalog").glob("*.json"):
                raw = path.read_bytes()
                self.assertNotIn(CANARY, raw)
                self.assertNotIn(kek_hex.encode(), raw)

    def test_list_records_pagination_is_stable_and_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms = StaticTestKmsProvider()
            for record_id in ("ev-b2-c3", "ev-b2-c1", "ev-b2-c2"):
                write_record(tmp, kms, record_id=record_id)
            self.assertEqual(build_catalog(tmp), 3)
            service = make_service(tmp, kms=kms)
            page_one, cursor = service.list_records(tenant_id=TENANT, domain=DOMAIN, limit=2)
            self.assertEqual([entry.record_id for entry in page_one], ["ev-b2-c1", "ev-b2-c2"])
            self.assertEqual(cursor, "ev-b2-c2")
            page_two, cursor = service.list_records(tenant_id=TENANT, domain=DOMAIN,
                                                    limit=2, cursor=cursor)
            self.assertEqual([entry.record_id for entry in page_two], ["ev-b2-c3"])
            self.assertIsNone(cursor)
            # Page size above the cap is clamped, not honoured.
            all_entries, cursor = service.list_records(tenant_id=TENANT, domain=DOMAIN,
                                                       limit=500)
            self.assertEqual(len(all_entries), 3)
            self.assertIsNone(cursor)
            with self.assertRaises(SafetyError) as ctx:
                service.list_records(tenant_id=TENANT, domain=DOMAIN, limit=0)
            self.assertEqual(ctx.exception.code, SafetyCode.CONTRACT_VIOLATION)
            with self.assertRaises(SafetyError) as ctx:
                service.list_records(tenant_id=TENANT, domain=DOMAIN, cursor="../escape")
            self.assertEqual(ctx.exception.code, SafetyCode.CONTRACT_VIOLATION)

    def test_list_records_filters_by_review_purpose_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms = StaticTestKmsProvider()
            write_record(tmp, kms, record_id="ev-b2-p1")
            write_record(tmp, kms, record_id="ev-b2-p2", purpose=OTHER_PURPOSE)
            self.assertEqual(build_catalog(tmp), 2)
            service = make_service(tmp, kms=kms)
            entries, _ = service.list_records(tenant_id=TENANT, domain=DOMAIN)
            self.assertEqual([entry.record_id for entry in entries], ["ev-b2-p1"])
            with self.assertRaises(SafetyError) as ctx:
                service.get_record("ev-b2-p2", tenant_id=TENANT, domain=DOMAIN)
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_RECORD_NOT_FOUND)


class ReaderRejectionTests(unittest.TestCase):
    def test_unknown_record_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms = StaticTestKmsProvider()
            write_record(tmp, kms, record_id="ev-b2-r1")
            self.assertEqual(build_catalog(tmp), 1)
            service = make_service(tmp, kms=kms)
            with self.assertRaises(SafetyError) as ctx:
                service.read_plaintext("ev-b2-missing", context=make_context())
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_RECORD_NOT_FOUND)
            self.assertEqual(read_events(Path(tmp) / "access-log"), [])

    def test_catalog_missing_record_is_invisible_even_with_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms = StaticTestKmsProvider()
            write_record(tmp, kms, record_id="ev-b2-r1")
            service = make_service(tmp, kms=kms)  # builder never ran
            with self.assertRaises(SafetyError) as ctx:
                service.read_plaintext("ev-b2-r1", context=make_context())
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_RECORD_NOT_FOUND)
            entries, _ = service.list_records(tenant_id=TENANT, domain=DOMAIN)
            self.assertEqual(entries, [])
            self.assertEqual(read_events(Path(tmp) / "access-log"), [])

    def test_wrong_scope_is_not_found(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms = StaticTestKmsProvider()
            write_record(tmp, kms, record_id="ev-b2-r1")
            self.assertEqual(build_catalog(tmp), 1)
            service = make_service(tmp, kms=kms)
            with self.assertRaises(SafetyError) as ctx:
                service.read_plaintext("ev-b2-r1", context=make_context(tenant_id="tenant-x"))
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_RECORD_NOT_FOUND)
            with self.assertRaises(SafetyError) as ctx:
                service.get_record("ev-b2-r1", tenant_id=TENANT, domain="scope-other")
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_RECORD_NOT_FOUND)

    def test_expired_record_is_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms = StaticTestKmsProvider()
            write_record(tmp, kms, record_id="ev-b2-r1", retention_until=RETENTION_PAST)
            self.assertEqual(build_catalog(tmp), 1)
            service = make_service(tmp, kms=kms)
            entry = service.get_record("ev-b2-r1", tenant_id=TENANT, domain=DOMAIN)
            self.assertEqual(entry.status, "expired")
            with self.assertRaises(SafetyError) as ctx:
                service.read_plaintext("ev-b2-r1", context=make_context())
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_RECORD_UNAVAILABLE)
            self.assertEqual(read_events(Path(tmp) / "access-log"), [])

    def test_revalidate_failure_at_first_checkpoint_blocks_before_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms = StaticTestKmsProvider()
            write_record(tmp, kms, record_id="ev-b2-r1")
            self.assertEqual(build_catalog(tmp), 1)

            def revalidate() -> None:
                raise SafetyError(SafetyCode.AUDIT_ACCESS_REJECTED, "session revoked")

            service = make_service(tmp, kms=kms, revalidate=revalidate)
            with self.assertRaises(SafetyError) as ctx:
                service.read_plaintext("ev-b2-r1", context=make_context())
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_ACCESS_REJECTED)
            self.assertEqual(read_events(Path(tmp) / "access-log"), [])

    def test_revalidate_failure_after_decrypt_blocks_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms = StaticTestKmsProvider()
            write_record(tmp, kms, record_id="ev-b2-r1")
            self.assertEqual(build_catalog(tmp), 1)
            calls = {"count": 0}

            def revalidate() -> None:
                calls["count"] += 1
                if calls["count"] >= 2:
                    raise SafetyError(SafetyCode.AUDIT_ACCESS_REJECTED, "idle expired")

            service = make_service(tmp, kms=kms, revalidate=revalidate)
            with self.assertRaises(SafetyError) as ctx:
                service.read_plaintext("ev-b2-r1", context=make_context())
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_ACCESS_REJECTED)
            events = read_events(Path(tmp) / "access-log")
            self.assertEqual([event["event"] for event in events],
                             ["AUDIT_READ_ATTEMPTED", "AUDIT_READ_REJECTED:session_expired"])

    def test_deadline_already_spent_blocks_before_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms = StaticTestKmsProvider()
            write_record(tmp, kms, record_id="ev-b2-r1")
            self.assertEqual(build_catalog(tmp), 1)
            service = make_service(tmp, kms=kms)
            with self.assertRaises(SafetyError) as ctx:
                service.read_plaintext("ev-b2-r1", context=make_context(deadline=time.monotonic() - 1))
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_ACCESS_REJECTED)
            self.assertEqual(read_events(Path(tmp) / "access-log"), [])

    def test_slow_kms_blowing_deadline_discards_plaintext(self):
        with tempfile.TemporaryDirectory() as tmp:

            class SlowKms(StaticTestKmsProvider):
                def unwrap(self, wrapped_dek, *, purpose, bucket):
                    time.sleep(0.2)
                    return super().unwrap(wrapped_dek, purpose=purpose, bucket=bucket)

            kms = SlowKms()
            write_record(tmp, kms, record_id="ev-b2-r1")
            self.assertEqual(build_catalog(tmp), 1)
            service = make_service(tmp, kms=kms, revalidate=lambda: None)
            with self.assertRaises(SafetyError) as ctx:
                service.read_plaintext(
                    "ev-b2-r1",
                    context=make_context(deadline=time.monotonic() + 0.05),
                )
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_ACCESS_REJECTED)
            events = read_events(Path(tmp) / "access-log")
            self.assertEqual([event["event"] for event in events],
                             ["AUDIT_READ_ATTEMPTED", "AUDIT_READ_REJECTED:deadline_exceeded"])


class ReaderCorruptionTests(unittest.TestCase):
    def _stack(self, tmp):
        kms = StaticTestKmsProvider()
        data = write_record(tmp, kms, record_id="ev-b2-r1")
        self.assertEqual(build_catalog(tmp), 1)
        return kms, Path(tmp) / "evidence" / "ev-b2-r1.evidence.json"

    def test_sha_mismatch_not_released(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms, evidence_path = self._stack(tmp)
            document = json.loads(evidence_path.read_bytes())
            ciphertext = document["ciphertext"]
            document["ciphertext"] = format(int(ciphertext[0], 16) ^ 1, "x") + ciphertext[1:]
            evidence_path.write_bytes(json.dumps(document, sort_keys=True).encode("utf-8"))
            service = make_service(tmp, kms=kms)
            with self.assertRaises(SafetyError) as ctx:
                service.read_plaintext("ev-b2-r1", context=make_context())
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_EVIDENCE_CORRUPTED)
            self.assertEqual(read_events(Path(tmp) / "access-log")[-1]["event"],
                             "AUDIT_READ_REJECTED:evidence_corrupted")

    def test_missing_evidence_file_not_released(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms, evidence_path = self._stack(tmp)
            evidence_path.unlink()
            service = make_service(tmp, kms=kms)
            with self.assertRaises(SafetyError) as ctx:
                service.read_plaintext("ev-b2-r1", context=make_context())
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_EVIDENCE_CORRUPTED)
            self.assertEqual(read_events(Path(tmp) / "access-log")[-1]["event"],
                             "AUDIT_READ_REJECTED:evidence_corrupted")

    def test_symlink_escape_not_released(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms, evidence_path = self._stack(tmp)
            outside = Path(tmp) / "outside-evidence.json"
            outside.write_bytes(evidence_path.read_bytes())
            evidence_path.unlink()
            evidence_path.symlink_to(outside)
            service = make_service(tmp, kms=kms)
            with self.assertRaises(SafetyError) as ctx:
                service.read_plaintext("ev-b2-r1", context=make_context())
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_EVIDENCE_CORRUPTED)
            self.assertEqual(read_events(Path(tmp) / "access-log")[-1]["event"],
                             "AUDIT_READ_REJECTED:evidence_corrupted")

    def test_wrong_aad_not_released(self):
        # Catalog/evidence desync: the stored digest matches the file on disk,
        # but the envelope header was produced for another domain. The reader
        # re-verifies the header against the catalog and refuses.
        with tempfile.TemporaryDirectory() as tmp:
            kms = StaticTestKmsProvider()
            evidence_dir = Path(tmp) / "evidence"
            evidence_dir.mkdir(parents=True)
            record = encrypt_record(
                kms, CANARY, domain="scope-other", bucket=BUCKET,
                record_id="ev-b2-r1", purpose=EVIDENCE_PURPOSE,
            )
            data = serialize_record(record)
            durable_commit(evidence_dir, "ev-b2-r1.evidence.json", data)
            hand_craft_catalog(tmp, record_id="ev-b2-r1",
                               sha256_hex=hashlib.sha256(data).hexdigest())
            service = make_service(tmp, kms=kms)
            with self.assertRaises(SafetyError) as ctx:
                service.read_plaintext("ev-b2-r1", context=make_context())
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_EVIDENCE_CORRUPTED)
            self.assertEqual(read_events(Path(tmp) / "access-log")[-1]["event"],
                             "AUDIT_READ_REJECTED:aad_mismatch")

    def test_traversing_evidence_path_stays_invisible(self):
        # A poisoned catalog document never reaches the filesystem layer:
        # it fails strict parsing, so the record is not found, not released.
        with tempfile.TemporaryDirectory() as tmp:
            kms = StaticTestKmsProvider()
            evidence_dir = Path(tmp) / "evidence"
            evidence_dir.mkdir(parents=True)
            record = encrypt_record(
                kms, CANARY, domain=DOMAIN, bucket=BUCKET,
                record_id="ev-b2-r1", purpose=EVIDENCE_PURPOSE,
            )
            data = serialize_record(record)
            durable_commit(evidence_dir, "escape.evidence.json", data)
            hand_craft_catalog(tmp, record_id="ev-b2-r1",
                               sha256_hex=hashlib.sha256(data).hexdigest(),
                               evidence_path="../escape.evidence.json")
            service = make_service(tmp, kms=kms)
            with self.assertRaises(SafetyError) as ctx:
                service.read_plaintext("ev-b2-r1", context=make_context())
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_RECORD_NOT_FOUND)
            self.assertEqual(read_events(Path(tmp) / "access-log"), [])


class ReaderTraceFailureTests(unittest.TestCase):
    def _stack(self, tmp, kms=None):
        kms = kms or StaticTestKmsProvider()
        write_record(tmp, kms, record_id="ev-b2-r1")
        self.assertEqual(build_catalog(tmp), 1)
        return kms

    def test_attempt_trace_failure_blocks_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms = self._stack(tmp)
            service = make_service(tmp, kms=kms)
            with mock.patch(f"{STORE}.durable_commit", side_effect=DurableWriteError("ENOSPC")):
                with self.assertRaises(SafetyError) as ctx:
                    service.read_plaintext("ev-b2-r1", context=make_context())
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_WRITE_FAILED)
            self.assertIsNone(ctx.exception.__cause__)
            self.assertIsNone(ctx.exception.__context__)

    def test_result_trace_failure_blocks_release_after_decrypt(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms = self._stack(tmp)
            service = make_service(tmp, kms=kms)
            real_commit = durable_commit
            calls = {"count": 0}

            def flaky(directory, filename, data, **kwargs):
                calls["count"] += 1
                if calls["count"] >= 2:
                    raise DurableWriteError("ENOSPC on result trace")
                return real_commit(directory, filename, data, **kwargs)

            with mock.patch(f"{STORE}.durable_commit", side_effect=flaky):
                with self.assertRaises(SafetyError) as ctx:
                    service.read_plaintext("ev-b2-r1", context=make_context())
            # Decryption succeeded; the failed result trace still blocks release.
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_WRITE_FAILED)
            events = read_events(Path(tmp) / "access-log")
            self.assertEqual([event["event"] for event in events], ["AUDIT_READ_ATTEMPTED"])

    def test_access_log_quota_exhaustion_blocks_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms = self._stack(tmp)
            service = make_service(tmp, kms=kms)
            with mock.patch(f"{AR}.MAX_ACCESS_LOG_BYTES", 64):
                with self.assertRaises(SafetyError) as ctx:
                    service.read_plaintext("ev-b2-r1", context=make_context())
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_WRITE_FAILED)


class ContractTests(unittest.TestCase):
    def test_context_validation(self):
        with self.assertRaises(ValueError):
            make_context(actor_id="")
        with self.assertRaises(ValueError):
            make_context(session_digest="x" * 300)
        with self.assertRaises(ValueError):
            make_context(deadline=float("nan"))

    def test_constructor_type_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(TypeError):
                make_service(tmp, kms=object())
            with self.assertRaises(TypeError):
                make_service(tmp, revalidate="not-callable")
            with self.assertRaises(ValueError):
                make_service(tmp, review_purpose="  ")

    def test_read_plaintext_requires_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms = StaticTestKmsProvider()
            write_record(tmp, kms, record_id="ev-b2-r1")
            self.assertEqual(build_catalog(tmp), 1)
            service = make_service(tmp, kms=kms)
            with self.assertRaises(TypeError):
                service.read_plaintext("ev-b2-r1", context="not-a-context")  # type: ignore[arg-type]

    def test_decryption_failure_is_traced_and_not_released(self):
        with tempfile.TemporaryDirectory() as tmp:
            kms = StaticTestKmsProvider()
            write_record(tmp, kms, record_id="ev-b2-r1")
            self.assertEqual(build_catalog(tmp), 1)
            # A different KMS (different KEKs) authenticates nothing.
            other = StaticTestKmsProvider()
            service = make_service(tmp, kms=other)
            with self.assertRaises(SafetyError) as ctx:
                service.read_plaintext("ev-b2-r1", context=make_context())
            self.assertEqual(ctx.exception.code, SafetyCode.DECRYPTION_FAILED)
            events = read_events(Path(tmp) / "access-log")
            self.assertEqual([event["event"] for event in events],
                             ["AUDIT_READ_ATTEMPTED", "AUDIT_READ_REJECTED:decryption_failed"])


if __name__ == "__main__":
    unittest.main()
