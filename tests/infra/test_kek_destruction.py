"""Executable KEK-destruction contract tests; synthetic keys, injected faults only."""

import os
import tempfile
import traceback
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from infra.envelope_crypto import (
    KmsUnavailableError,
    decrypt_record,
    encrypt_record,
)
from infra.errors import SafetyCode, SafetyError
from infra.kek_destruction import (
    CopyRole,
    DestructionReport,
    KekCopy,
    KekCopyRegistry,
    LocalKekCopyStore,
    RetentionPolicy,
    run_kek_destruction_job,
)

FIXTURES = Path(__file__).parent / "fixtures" / "kek"
CANARY = "CNRY-A05-note-9e41b7"

PURPOSE = "evidence-retention"
BUCKET = "bucket-180d"
OTHER_BUCKET = "bucket-365d"
OTHER_PURPOSE = "audit-retention"
DOMAIN = "scope-hr"
RECORD_ID = "rec-90031"

LOCATIONS = (
    ("loc-primary-vault", CopyRole.PRIMARY),
    ("loc-backup-site", CopyRole.BACKUP),
    ("loc-edge-cache", CopyRole.CACHE),
    ("loc-recovery-archive", CopyRole.RECOVERY),
)


def fixture_plaintext():
    return (FIXTURES / "plaintext.txt").read_bytes()


class FixedDuePolicy(RetentionPolicy):
    """Test policy with caller-supplied due-ness; no retention numbers invented."""

    def __init__(self, due: bool) -> None:
        self._due = due

    def is_due(self, purpose, bucket, *, now):
        return self._due


class AgePolicy(RetentionPolicy):
    """Caller-supplied numbers: bucket created at ``created_at``, retained ``max_age``."""

    def __init__(self, created_at: datetime, max_age: timedelta) -> None:
        self._created_at = created_at
        self._max_age = max_age

    def is_due(self, purpose, bucket, *, now):
        return now - self._created_at >= self._max_age


class FakeClock:
    """Monotonic injectable clock; each call advances one tick."""

    def __init__(self, start: datetime, tick: timedelta = timedelta(seconds=1)) -> None:
        self._next = start
        self._tick = tick

    def __call__(self) -> datetime:
        current = self._next
        self._next += self._tick
        return current


class FailingDestroyStore(LocalKekCopyStore):
    """Injected fault: the copy's key service fails destruction while enabled."""

    def __init__(self, keks=None) -> None:
        super().__init__(keks=keks)
        self.fail_destroy = False

    def destroy(self, purpose, bucket, *, at):
        if self.fail_destroy:
            raise KmsUnavailableError("synthetic destroy outage")
        return super().destroy(purpose, bucket, at=at)


class NonDestructiveStore(LocalKekCopyStore):
    """Injected fault: the copy pretends to destroy but keeps the material."""

    def destroy(self, purpose, bucket, *, at):
        self._destroyed.add((purpose, bucket))
        self._destroyed_at[(purpose, bucket)] = at
        return at


def build_catalog(keks=None):
    """Four-copy registry, every copy holding the same synthetic bucket KEK."""
    registry = KekCopyRegistry()
    stores = {}
    for location_id, role in LOCATIONS:
        store = LocalKekCopyStore(keks=keks)
        registry.register(KekCopy(location_id=location_id, role=role), store)
        stores[location_id] = store
    return registry, stores


def build_catalog_with_faulty_copy(faulty_cls, fault_location="loc-backup-site"):
    registry = KekCopyRegistry()
    stores = {}
    for location_id, role in LOCATIONS:
        store = faulty_cls()
        registry.register(KekCopy(location_id=location_id, role=role), store)
        stores[location_id] = store
    return registry, stores


def provision_all(stores, kek):
    for store in stores.values():
        store.provision(PURPOSE, BUCKET, kek)


def seal_record(kek):
    """Seal a real record under the bucket KEK via a provisioned copy."""
    sealer = LocalKekCopyStore(keks={(PURPOSE, BUCKET): kek})
    return encrypt_record(
        sealer,
        fixture_plaintext(),
        domain=DOMAIN,
        bucket=BUCKET,
        record_id=RECORD_ID,
        purpose=PURPOSE,
    )


def fresh_kek():
    return os.urandom(32)


def run_job(registry, record, *, policy=None, clock=None, purpose=PURPOSE, bucket=BUCKET):
    return run_kek_destruction_job(
        purpose=purpose,
        bucket=bucket,
        policy=FixedDuePolicy(True) if policy is None else policy,
        registry=registry,
        sealed_record=record,
        now=clock,
    )


def assert_no_leak(testcase, exc, *, kek=None):
    rendered = f"{exc!r} {exc} {''.join(traceback.format_tb(exc.__traceback__))}"
    testcase.assertNotIn(CANARY, rendered)
    testcase.assertNotIn(fixture_plaintext().decode("utf-8")[:24], rendered)
    if kek is not None:
        testcase.assertNotIn(kek.hex(), rendered)
        testcase.assertNotIn(repr(kek), rendered)
    testcase.assertIsNone(exc.__cause__)
    testcase.assertIsNone(exc.__context__)


class PositivePathTests(unittest.TestCase):
    def test_all_copies_destroyed_and_report_complete(self):
        kek = fresh_kek()
        registry, stores = build_catalog()
        provision_all(stores, kek)
        record = seal_record(kek)
        clock = FakeClock(datetime(2031, 4, 1, tzinfo=timezone.utc))

        report = run_job(registry, record, clock=clock)

        self.assertIsInstance(report, DestructionReport)
        self.assertEqual(report.purpose, PURPOSE)
        self.assertEqual(report.bucket, BUCKET)
        self.assertEqual(len(report.copies), len(LOCATIONS))
        self.assertEqual(
            [entry.location_id for entry in report.copies],
            [location_id for location_id, _ in LOCATIONS],
        )
        for entry, (_, role) in zip(report.copies, LOCATIONS):
            self.assertEqual(entry.role, role)
            self.assertEqual(entry.verification, SafetyCode.DECRYPTION_FAILED)
            self.assertFalse(entry.resumed)
            self.assertIsInstance(entry.destroyed_at, datetime)
        stamps = [entry.destroyed_at for entry in report.copies]
        self.assertEqual(len(set(stamps)), len(stamps))
        self.assertTrue(all(stamp < report.completed_at for stamp in stamps))

    def test_pre_destruction_every_copy_decrypts_sealed_record(self):
        kek = fresh_kek()
        registry, stores = build_catalog()
        provision_all(stores, kek)
        record = seal_record(kek)
        for location_id, _ in LOCATIONS:
            with self.subTest(location=location_id):
                self.assertEqual(decrypt_record(stores[location_id], record), fixture_plaintext())

    def test_post_destruction_no_copy_decrypts_and_encrypt_fails(self):
        kek = fresh_kek()
        registry, stores = build_catalog()
        provision_all(stores, kek)
        record = seal_record(kek)
        run_job(registry, record)

        for location_id, _ in LOCATIONS:
            with self.subTest(location=location_id):
                with self.assertRaises(SafetyError) as caught:
                    decrypt_record(stores[location_id], record)
                self.assertEqual(caught.exception.code, SafetyCode.DECRYPTION_FAILED)
                with self.assertRaises(SafetyError) as wrap_caught:
                    encrypt_record(
                        stores[location_id],
                        b"new body",
                        domain=DOMAIN,
                        bucket=BUCKET,
                        record_id="rec-new",
                        purpose=PURPOSE,
                    )
                self.assertEqual(wrap_caught.exception.code, SafetyCode.KMS_UNAVAILABLE)

    def test_policy_numbers_are_injected_by_caller(self):
        kek = fresh_kek()
        registry, stores = build_catalog()
        provision_all(stores, kek)
        record = seal_record(kek)
        created = datetime(2030, 1, 1, tzinfo=timezone.utc)
        policy = AgePolicy(created, timedelta(days=180))
        early_clock = FakeClock(created + timedelta(days=179))
        with self.assertRaises(SafetyError) as caught:
            run_job(registry, record, policy=policy, clock=early_clock)
        self.assertEqual(caught.exception.code, SafetyCode.CONTRACT_VIOLATION)
        due_clock = FakeClock(created + timedelta(days=180))
        report = run_job(registry, record, policy=policy, clock=due_clock)
        self.assertEqual(len(report.copies), len(LOCATIONS))


class RefusalTests(unittest.TestCase):
    def setUp(self):
        self.kek = fresh_kek()
        self.registry, self.stores = build_catalog()
        provision_all(self.stores, self.kek)
        self.record = seal_record(self.kek)

    def assert_refused_and_copies_intact(self, caught):
        self.assertEqual(caught.exception.code, SafetyCode.CONTRACT_VIOLATION)
        assert_no_leak(self, caught.exception, kek=self.kek)
        for location_id, _ in LOCATIONS:
            self.assertEqual(
                decrypt_record(self.stores[location_id], self.record),
                fixture_plaintext(),
            )

    def test_missing_policy_refused(self):
        with self.assertRaises(SafetyError) as caught:
            run_kek_destruction_job(
                purpose=PURPOSE,
                bucket=BUCKET,
                policy=None,
                registry=self.registry,
                sealed_record=self.record,
            )
        self.assert_refused_and_copies_intact(caught)

    def test_missing_registry_refused(self):
        with self.assertRaises(SafetyError) as caught:
            run_kek_destruction_job(
                purpose=PURPOSE,
                bucket=BUCKET,
                policy=FixedDuePolicy(True),
                registry=None,
                sealed_record=self.record,
            )
        self.assertEqual(caught.exception.code, SafetyCode.CONTRACT_VIOLATION)
        assert_no_leak(self, caught.exception, kek=self.kek)

    def test_empty_registry_refused(self):
        with self.assertRaises(SafetyError) as caught:
            run_job(KekCopyRegistry(), self.record)
        self.assert_refused_and_copies_intact(caught)

    def test_not_due_bucket_refused(self):
        with self.assertRaises(SafetyError) as caught:
            run_job(self.registry, self.record, policy=FixedDuePolicy(False))
        self.assert_refused_and_copies_intact(caught)

    def test_sealed_record_bucket_mismatch_refused(self):
        other = seal_record(self.kek)
        with self.assertRaises(SafetyError) as caught:
            run_job(self.registry, other, bucket=OTHER_BUCKET)
        self.assert_refused_and_copies_intact(caught)

    def test_sealed_record_purpose_mismatch_refused(self):
        kek = fresh_kek()
        sealer = LocalKekCopyStore(keks={(OTHER_PURPOSE, BUCKET): kek})
        other = encrypt_record(
            sealer,
            fixture_plaintext(),
            domain=DOMAIN,
            bucket=BUCKET,
            record_id=RECORD_ID,
            purpose=OTHER_PURPOSE,
        )
        with self.assertRaises(SafetyError) as caught:
            run_job(self.registry, other, purpose=OTHER_PURPOSE)
        self.assert_refused_and_copies_intact(caught)

    def test_blank_selector_refused(self):
        for purpose, bucket in (("", BUCKET), (PURPOSE, " "), ("  ", "x")):
            with self.subTest(purpose=purpose, bucket=bucket):
                with self.assertRaises(SafetyError) as caught:
                    run_job(self.registry, self.record, purpose=purpose, bucket=bucket)
                self.assert_refused_and_copies_intact(caught)

    def test_duplicate_location_refused(self):
        with self.assertRaises(SafetyError) as caught:
            self.registry.register(KekCopy(location_id="loc-primary-vault", role=CopyRole.BACKUP), LocalKekCopyStore())
        self.assertEqual(caught.exception.code, SafetyCode.CONTRACT_VIOLATION)
        assert_no_leak(self, caught.exception, kek=self.kek)

    def test_wrong_types_rejected(self):
        with self.assertRaises(TypeError):
            run_kek_destruction_job(
                purpose=PURPOSE,
                bucket=BUCKET,
                policy=object(),
                registry=self.registry,
                sealed_record=self.record,
            )
        with self.assertRaises(TypeError):
            run_kek_destruction_job(
                purpose=PURPOSE,
                bucket=BUCKET,
                policy=FixedDuePolicy(True),
                registry=object(),
                sealed_record=self.record,
            )
        with self.assertRaises(TypeError):
            run_kek_destruction_job(
                purpose=PURPOSE,
                bucket=BUCKET,
                policy=FixedDuePolicy(True),
                registry=self.registry,
                sealed_record={"not": "a record"},
            )


class FailureInjectionTests(unittest.TestCase):
    def test_copy_destroy_outage_aborts_without_report(self):
        kek = fresh_kek()
        registry, stores = build_catalog_with_faulty_copy(FailingDestroyStore)
        provision_all(stores, kek)
        record = seal_record(kek)
        stores["loc-backup-site"].fail_destroy = True

        with self.assertRaises(SafetyError) as caught:
            run_job(registry, record)
        self.assertEqual(caught.exception.code, SafetyCode.KMS_UNAVAILABLE)
        assert_no_leak(self, caught.exception, kek=kek)

        destroyed = stores["loc-primary-vault"]
        untouched = stores["loc-recovery-archive"]
        with self.assertRaises(SafetyError) as post:
            decrypt_record(destroyed, record)
        self.assertEqual(post.exception.code, SafetyCode.DECRYPTION_FAILED)
        self.assertEqual(decrypt_record(untouched, record), fixture_plaintext())

    def test_copy_still_decrypts_after_destroy_aborts(self):
        kek = fresh_kek()
        registry, stores = build_catalog_with_faulty_copy(NonDestructiveStore, "loc-edge-cache")
        provision_all(stores, kek)
        record = seal_record(kek)

        with self.assertRaises(SafetyError) as caught:
            run_job(registry, record)
        self.assertEqual(caught.exception.code, SafetyCode.KMS_UNAVAILABLE)
        assert_no_leak(self, caught.exception, kek=kek)
        self.assertEqual(decrypt_record(stores["loc-edge-cache"], record), fixture_plaintext())

    def test_destroyed_copy_that_decrypts_on_resume_aborts(self):
        kek = fresh_kek()
        registry, stores = build_catalog()
        provision_all(stores, kek)
        record = seal_record(kek)
        run_job(registry, record)
        stores["loc-primary-vault"]._keks[(PURPOSE, BUCKET)] = kek  # sabotage: material restored
        with self.assertRaises(SafetyError) as caught:
            run_job(registry, record)
        self.assertEqual(caught.exception.code, SafetyCode.KMS_UNAVAILABLE)
        assert_no_leak(self, caught.exception, kek=kek)


class ResumeTests(unittest.TestCase):
    def test_crash_mid_job_resumes_to_completion(self):
        kek = fresh_kek()
        registry, stores = build_catalog_with_faulty_copy(FailingDestroyStore)
        provision_all(stores, kek)
        record = seal_record(kek)
        failing = stores["loc-backup-site"]
        failing.fail_destroy = True
        start = datetime(2031, 4, 1, tzinfo=timezone.utc)
        first_clock = FakeClock(start)

        with self.assertRaises(SafetyError) as caught:
            run_job(registry, record, clock=first_clock)
        self.assertEqual(caught.exception.code, SafetyCode.KMS_UNAVAILABLE)

        first_stamp = stores["loc-primary-vault"].destruction_time(PURPOSE, BUCKET)
        self.assertIsNotNone(first_stamp)
        self.assertFalse(stores["loc-edge-cache"].is_destroyed(PURPOSE, BUCKET))

        failing.fail_destroy = False
        second_clock = FakeClock(start + timedelta(hours=2))
        report = run_job(registry, record, clock=second_clock)

        self.assertEqual(len(report.copies), len(LOCATIONS))
        by_location = {entry.location_id: entry for entry in report.copies}
        self.assertTrue(by_location["loc-primary-vault"].resumed)
        self.assertEqual(by_location["loc-primary-vault"].destroyed_at, first_stamp)
        for location_id, _ in LOCATIONS[1:]:
            self.assertFalse(by_location[location_id].resumed)
        self.assertTrue(all(entry.verification == SafetyCode.DECRYPTION_FAILED for entry in report.copies))
        with self.assertRaises(SafetyError) as post:
            decrypt_record(stores["loc-primary-vault"], record)
        self.assertEqual(post.exception.code, SafetyCode.DECRYPTION_FAILED)

    def test_repeated_successful_runs_stay_idempotent(self):
        kek = fresh_kek()
        registry, stores = build_catalog()
        provision_all(stores, kek)
        record = seal_record(kek)
        first = run_job(registry, record)
        second = run_job(registry, record)
        self.assertTrue(all(entry.resumed for entry in second.copies))
        self.assertEqual(
            [entry.destroyed_at for entry in first.copies],
            [entry.destroyed_at for entry in second.copies],
        )


class LocalStorageTests(unittest.TestCase):
    def test_job_writes_nothing_to_disk(self):
        kek = fresh_kek()
        registry, stores = build_catalog()
        provision_all(stores, kek)
        record = seal_record(kek)
        previous = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                os.chdir(tmp)
                report = run_job(registry, record)
            finally:
                os.chdir(previous)
            self.assertEqual(len(report.copies), len(LOCATIONS))
            written = [name for _root, _dirs, files in os.walk(tmp) for name in files]
            self.assertEqual(written, [])

    def test_store_destroy_is_idempotent(self):
        store = LocalKekCopyStore()
        at = datetime(2031, 4, 1, tzinfo=timezone.utc)
        first = store.destroy(PURPOSE, BUCKET, at=at)
        second = store.destroy(PURPOSE, BUCKET, at=at + timedelta(days=1))
        self.assertEqual(first, second)
        self.assertTrue(store.is_destroyed(PURPOSE, BUCKET))


class LeakTests(unittest.TestCase):
    def test_report_and_errors_carry_no_material_or_plaintext(self):
        kek = fresh_kek()
        registry, stores = build_catalog()
        provision_all(stores, kek)
        record = seal_record(kek)
        report = run_job(registry, record)
        rendered = repr(report) + str(report)
        self.assertNotIn(CANARY, rendered)
        self.assertNotIn(fixture_plaintext().decode("utf-8")[:24], rendered)
        self.assertNotIn(kek.hex(), rendered)

    def test_controlled_errors_have_no_chain_and_no_canary(self):
        kek = fresh_kek()
        registry, stores = build_catalog_with_faulty_copy(FailingDestroyStore)
        provision_all(stores, kek)
        record = seal_record(kek)
        stores["loc-backup-site"].fail_destroy = True
        attempts = [
            lambda: run_job(registry, record),
            lambda: run_job(registry, record, policy=None),
            lambda: run_job(KekCopyRegistry(), record),
            lambda: run_job(registry, record, policy=FixedDuePolicy(False)),
            lambda: run_job(registry, seal_record(kek), bucket=OTHER_BUCKET),
        ]
        for attempt in attempts:
            with self.assertRaises(SafetyError) as caught:
                attempt()
            assert_no_leak(self, caught.exception, kek=kek)


if __name__ == "__main__":
    unittest.main()
