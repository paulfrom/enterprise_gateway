"""B2 catalog-builder contract tests: trusted links only, idempotent rescans.

The builder is a controlled background primitive: it scans only the
assembler-fixed intent/evidence roots, accepts a record only when the
persisted intent carries the exact server-preallocated evidence record_id
link and the evidence on disk verifies against it, and appends one durable
catalog file per record_id. Orphans (legacy intents without a record_id
link, cross-linked or tampered evidence, symlink escapes) never reach the
catalog and never count as success. Every evidence body is a synthetic
canary; the KMS provider is synthetic and in-memory.
"""

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from audit.audit_intent import ReleaseIntent, commit_release_intent
from audit.catalog import AuditCatalogBuilder, CatalogEntry
from infra.durable_write import DurableWriteError, durable_commit
from infra.envelope_crypto import StaticTestKmsProvider, encrypt_record, serialize_record
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
CANARY = b"CNRY-B2-catalog-body-41cd"
STORE = "audit._store"


def fixed_lifecycle(record_id: str):
    return (RETENTION_UNTIL, LIFECYCLE_POLICY)


def make_intent(
    intent_dir,
    *,
    intent_id: str = "intent-b2-0001",
    tenant_id: str | None = TENANT,
    domain: str = DOMAIN,
    record_id: str | None = "ev-b2-0001",
    retention_until: datetime | None = RETENTION_UNTIL,
    lifecycle_policy: str | None = LIFECYCLE_POLICY,
    recorded_at: datetime = RECORDED_AT,
) -> ReleaseIntent:
    if record_id is None:
        retention_until = None
        lifecycle_policy = None
    intent = ReleaseIntent(
        intent_id=intent_id,
        recorded_at=recorded_at,
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
    return commit_release_intent(intent_dir, intent)


def write_evidence(
    evidence_dir,
    kms,
    *,
    record_id: str = "ev-b2-0001",
    domain: str = DOMAIN,
    bucket: str = BUCKET,
    purpose: str = EVIDENCE_PURPOSE,
    plaintext: bytes = CANARY,
) -> bytes:
    record = encrypt_record(
        kms, plaintext, domain=domain, bucket=bucket, record_id=record_id, purpose=purpose
    )
    data = serialize_record(record)
    durable_commit(evidence_dir, f"{record_id}.evidence.json", data)
    return data


def make_builder(tmp, *, lifecycle=fixed_lifecycle, batch_limit: int = 200) -> AuditCatalogBuilder:
    roots = Path(tmp)
    return AuditCatalogBuilder(
        intent_root=roots / "intent",
        evidence_root=roots / "evidence",
        catalog_directory=roots / "catalog",
        lifecycle=lifecycle,
        batch_limit=batch_limit,
    )


def prepare_roots(tmp) -> tuple[Path, Path, Path]:
    roots = Path(tmp)
    intent_dir = roots / "intent"
    evidence_dir = roots / "evidence"
    catalog_dir = roots / "catalog"
    intent_dir.mkdir(parents=True)
    evidence_dir.mkdir(parents=True)
    return intent_dir, evidence_dir, catalog_dir


def read_catalog_entry(catalog_dir, record_id: str) -> dict:
    raw = (Path(catalog_dir) / f"{record_id}.catalog.json").read_bytes()
    return json.loads(raw)


class BuilderPositiveTests(unittest.TestCase):
    def test_builder_idempotent_rescan(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_dir, evidence_dir, _ = prepare_roots(tmp)
            kms = StaticTestKmsProvider()
            make_intent(intent_dir)
            write_evidence(evidence_dir, kms)
            builder = make_builder(tmp)
            self.assertEqual(builder.build_once(), 1)
            self.assertEqual(builder.build_once(), 0)  # rescan does not duplicate
            self.assertEqual(builder.backlog(), 0)
            # A fresh builder over the same on-disk catalog rescans to zero too.
            restarted = make_builder(tmp)
            self.assertEqual(restarted.build_once(), 0)
            self.assertEqual(restarted.backlog(), 0)

    def test_catalog_entry_carries_trusted_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_dir, evidence_dir, catalog_dir = prepare_roots(tmp)
            kms = StaticTestKmsProvider()
            permit = make_intent(intent_dir)
            data = write_evidence(evidence_dir, kms)
            builder = make_builder(tmp)
            self.assertEqual(builder.build_once(), 1)
            document = read_catalog_entry(catalog_dir, "ev-b2-0001")
            self.assertEqual(document["format_version"], 1)
            self.assertEqual(document["tenant_id"], TENANT)
            self.assertEqual(document["record_id"], "ev-b2-0001")
            self.assertEqual(document["purpose"], EVIDENCE_PURPOSE)
            self.assertEqual(document["domain"], DOMAIN)
            self.assertEqual(document["bucket"], BUCKET)
            self.assertEqual(document["intent_id"], permit.intent_id)
            self.assertEqual(document["evidence_path"], "ev-b2-0001.evidence.json")
            self.assertEqual(document["evidence_sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(document["bytes_written"], len(data))
            self.assertEqual(document["created_at"], RECORDED_AT.isoformat())
            self.assertEqual(document["retention_until"], RETENTION_UNTIL.isoformat())
            self.assertEqual(document["lifecycle_policy_version"], LIFECYCLE_POLICY)
            self.assertEqual(document["status"], "available")

    def test_builder_falls_back_to_injected_lifecycle_for_legacy_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_dir, evidence_dir, catalog_dir = prepare_roots(tmp)
            kms = StaticTestKmsProvider()
            make_intent(intent_dir, retention_until=None, lifecycle_policy=None)
            write_evidence(evidence_dir, kms)
            calls: list[str] = []

            def lifecycle(record_id: str):
                calls.append(record_id)
                return (RETENTION_UNTIL, LIFECYCLE_POLICY)

            builder = make_builder(tmp, lifecycle=lifecycle)
            self.assertEqual(builder.build_once(), 1)
            self.assertEqual(calls, ["ev-b2-0001"])
            document = read_catalog_entry(catalog_dir, "ev-b2-0001")
            self.assertEqual(document["retention_until"], RETENTION_UNTIL.isoformat())
            self.assertEqual(document["lifecycle_policy_version"], LIFECYCLE_POLICY)

    def test_builder_marks_past_retention_expired(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_dir, evidence_dir, catalog_dir = prepare_roots(tmp)
            kms = StaticTestKmsProvider()
            make_intent(intent_dir, retention_until=RETENTION_PAST)
            write_evidence(evidence_dir, kms)
            self.assertEqual(make_builder(tmp).build_once(), 1)
            document = read_catalog_entry(catalog_dir, "ev-b2-0001")
            self.assertEqual(document["status"], "expired")

    def test_builder_batch_limit_and_backlog_progression(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_dir, evidence_dir, _ = prepare_roots(tmp)
            kms = StaticTestKmsProvider()
            for index in range(3):
                record_id = f"ev-b2-00{index}"
                make_intent(intent_dir, intent_id=f"intent-b2-00{index}", record_id=record_id)
                write_evidence(evidence_dir, kms, record_id=record_id)
            builder = make_builder(tmp, batch_limit=2)
            self.assertEqual(builder.build_once(), 2)
            self.assertEqual(builder.backlog(), 1)
            self.assertEqual(builder.build_once(), 1)
            self.assertEqual(builder.backlog(), 0)
            self.assertEqual(builder.build_once(), 0)


class BuilderOrphanTests(unittest.TestCase):
    """No trusted link, no catalog entry, no success count, no backlog debt."""

    def test_builder_rejects_orphan_without_trusted_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_dir, evidence_dir, catalog_dir = prepare_roots(tmp)
            kms = StaticTestKmsProvider()
            # Legacy intent: no server-preallocated record_id link at all.
            make_intent(intent_dir, intent_id="intent-b2-legacy", record_id=None)
            write_evidence(evidence_dir, kms, record_id="ev-b2-legacy")
            # Cross-linked: intent claims ev-alpha, file holds record ev-beta.
            make_intent(
                intent_dir, intent_id="intent-b2-cross", record_id="ev-b2-alpha"
            )
            record = encrypt_record(
                kms, CANARY, domain=DOMAIN, bucket=BUCKET,
                record_id="ev-b2-beta", purpose=EVIDENCE_PURPOSE,
            )
            durable_commit(evidence_dir, "ev-b2-alpha.evidence.json", serialize_record(record))
            # Domain-incoherent evidence: right record_id, wrong domain.
            make_intent(
                intent_dir, intent_id="intent-b2-domain", record_id="ev-b2-dom"
            )
            write_evidence(evidence_dir, kms, record_id="ev-b2-dom", domain="scope-other")
            # Symlink escape: the evidence name resolves outside the evidence root.
            make_intent(
                intent_dir, intent_id="intent-b2-link", record_id="ev-b2-link"
            )
            outside = Path(tmp) / "outside-evidence.json"
            outside.write_bytes(serialize_record(record))
            (evidence_dir / "ev-b2-link.evidence.json").symlink_to(outside)
            builder = make_builder(tmp)
            self.assertEqual(builder.build_once(), 0)
            self.assertEqual(builder.backlog(), 0)
            self.assertEqual(list(Path(catalog_dir).glob("*.catalog.json")), [])

    def test_builder_rejects_intent_without_tenant_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_dir, evidence_dir, catalog_dir = prepare_roots(tmp)
            kms = StaticTestKmsProvider()
            make_intent(intent_dir, tenant_id=None)
            write_evidence(evidence_dir, kms)
            builder = make_builder(tmp)
            self.assertEqual(builder.build_once(), 0)
            self.assertEqual(builder.backlog(), 0)
            self.assertEqual(list(Path(catalog_dir).glob("*.catalog.json")), [])

    def test_builder_skips_corrupt_intent_and_evidence_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_dir, evidence_dir, catalog_dir = prepare_roots(tmp)
            kms = StaticTestKmsProvider()
            make_intent(intent_dir)
            write_evidence(evidence_dir, kms)
            (intent_dir / "garbage.intent.json").write_bytes(b"{not json")
            (evidence_dir / "garbage.evidence.json").write_bytes(b"not an envelope")
            (intent_dir / "stray.txt").write_bytes(b"ignored")
            builder = make_builder(tmp)
            self.assertEqual(builder.build_once(), 1)
            self.assertEqual(builder.backlog(), 0)

    def test_backlog_counts_only_trusted_uncatalogued_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_dir, evidence_dir, _ = prepare_roots(tmp)
            kms = StaticTestKmsProvider()
            make_intent(intent_dir, intent_id="intent-b2-a", record_id="ev-b2-a")
            write_evidence(evidence_dir, kms, record_id="ev-b2-a")
            make_intent(intent_dir, intent_id="intent-b2-legacy", record_id=None)
            write_evidence(evidence_dir, kms, record_id="ev-b2-legacy")
            builder = make_builder(tmp)
            self.assertEqual(builder.backlog(), 1)
            self.assertEqual(builder.build_once(), 1)
            self.assertEqual(builder.backlog(), 0)


class BuilderFailureTests(unittest.TestCase):
    def test_catalog_write_failure_reports_without_fabrication(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_dir, evidence_dir, catalog_dir = prepare_roots(tmp)
            kms = StaticTestKmsProvider()
            make_intent(intent_dir)
            write_evidence(evidence_dir, kms)
            builder = make_builder(tmp)
            with mock.patch(f"{STORE}.durable_commit", side_effect=DurableWriteError("ENOSPC")):
                with self.assertRaises(SafetyError) as ctx:
                    builder.build_once()
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_WRITE_FAILED)
            self.assertIsNone(ctx.exception.__cause__)
            self.assertIsNone(ctx.exception.__context__)
            self.assertEqual(list(Path(catalog_dir).glob("*.catalog.json")), [])

    def test_catalog_quota_exhaustion_reports_write_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent_dir, evidence_dir, catalog_dir = prepare_roots(tmp)
            kms = StaticTestKmsProvider()
            make_intent(intent_dir)
            write_evidence(evidence_dir, kms)
            builder = make_builder(tmp)
            with mock.patch("audit.catalog.MAX_CATALOG_BYTES", 128):
                with self.assertRaises(SafetyError) as ctx:
                    builder.build_once()
            self.assertEqual(ctx.exception.code, SafetyCode.AUDIT_WRITE_FAILED)
            self.assertEqual(list(Path(catalog_dir).glob("*.catalog.json")), [])

    def test_lifecycle_is_only_policy_source_for_missing_fields(self):
        # A record_id the injected policy refuses to cover stays invisible;
        # the builder must not invent retention from client-side values.
        with tempfile.TemporaryDirectory() as tmp:
            intent_dir, evidence_dir, catalog_dir = prepare_roots(tmp)
            kms = StaticTestKmsProvider()
            make_intent(intent_dir, retention_until=None, lifecycle_policy=None)
            write_evidence(evidence_dir, kms)

            def no_policy(record_id: str):
                raise LookupError(record_id)

            builder = make_builder(tmp, lifecycle=no_policy)
            with self.assertRaises(LookupError):
                builder.build_once()
            self.assertEqual(list(Path(catalog_dir).glob("*.catalog.json")), [])


class IntentExtensionTests(unittest.TestCase):
    """The T3 submission-surface extension keeps old intents readable."""

    def test_legacy_intent_without_evidence_fields_still_commits(self):
        with tempfile.TemporaryDirectory() as tmp:
            intent = ReleaseIntent(
                intent_id="intent-b2-old",
                recorded_at=RECORDED_AT,
                domain=DOMAIN,
                category=CATEGORY,
                policy_version=POLICY_VERSION,
                package_version=PACKAGE_VERSION,
                purpose=INTENT_PURPOSE,
                tenant_id=TENANT,
            )
            permit = commit_release_intent(tmp, intent)
            document = json.loads(permit.path.read_bytes())
            self.assertNotIn("evidence_record_id", document)
            reparsed = ReleaseIntent.model_validate_json(permit.path.read_bytes())
            self.assertIsNone(reparsed.evidence_record_id)
            self.assertIsNone(reparsed.evidence_retention_until)
            self.assertIsNone(reparsed.evidence_lifecycle_policy_version)

    def test_extended_intent_persists_all_evidence_fields_in_one_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_intent(tmp)
            document = json.loads((Path(tmp) / "intent-b2-0001.intent.json").read_bytes())
            self.assertEqual(document["evidence_record_id"], "ev-b2-0001")
            self.assertEqual(
                datetime.fromisoformat(document["evidence_retention_until"]),
                RETENTION_UNTIL,
            )
            self.assertEqual(document["evidence_lifecycle_policy_version"], LIFECYCLE_POLICY)
            self.assertEqual(
                set(document),
                {
                    "intent_id", "recorded_at", "domain", "category", "policy_version",
                    "package_version", "purpose", "tenant_id", "evidence_record_id",
                    "evidence_retention_until", "evidence_lifecycle_policy_version",
                },
            )

    def test_unsafe_evidence_record_id_rejected_before_any_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                make_intent(tmp, record_id="../escape")
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_retention_without_record_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                ReleaseIntent(
                    intent_id="intent-b2-bad",
                    recorded_at=RECORDED_AT,
                    domain=DOMAIN,
                    category=CATEGORY,
                    policy_version=POLICY_VERSION,
                    package_version=PACKAGE_VERSION,
                    purpose=INTENT_PURPOSE,
                    tenant_id=TENANT,
                    evidence_retention_until=RETENTION_UNTIL,
                )
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_naive_retention_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                make_intent(tmp, retention_until=datetime(2030, 1, 1))


class CatalogEntryContractTests(unittest.TestCase):
    def test_entry_dataclass_is_frozen_with_frozen_field_order(self):
        entry = CatalogEntry(
            tenant_id=TENANT,
            record_id="ev-b2-0001",
            purpose=EVIDENCE_PURPOSE,
            domain=DOMAIN,
            bucket=BUCKET,
            intent_id="intent-b2-0001",
            evidence_path="ev-b2-0001.evidence.json",
            evidence_sha256="a" * 64,
            bytes_written=1234,
            created_at=RECORDED_AT,
            retention_until=RETENTION_UNTIL,
            lifecycle_policy_version=LIFECYCLE_POLICY,
            status="available",
        )
        self.assertEqual(entry.record_id, "ev-b2-0001")
        with self.assertRaises(AttributeError):
            entry.status = "purged"  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
