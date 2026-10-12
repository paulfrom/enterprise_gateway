"""Unit tests for upstream standardized knowledge ingestion framework and TODO contracts."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest

from knowledge.ingestion import (
    DocumentKnowledgeImporter,
    IngestionBatch,
    IngestionSourceMeta,
    IngestionValidationSeverity,
    MasterDataImporter,
    RawEntityItem,
    RawRelationItem,
    TrustedToolImporter,
)
from knowledge.knowledge import KnowledgeError, Modality, Polarity, SourceKind


class TestIngestionFramework(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime.now(timezone.utc)
        self.meta = IngestionSourceMeta(
            tenant_id="tenant-corp",
            domain="corp.test",
            source_kind=SourceKind.MASTER_DATA,
            source_id="erp-sync-01",
            version="2026.10",
            purpose="procurement-graph",
            acl=frozenset({"corp.test:dept-procurement"}),
            observed_at=self.now,
            retention_until=self.now + timedelta(days=90),
            author="erp_connector",
        )

    def test_raw_entity_and_relation_validation(self) -> None:
        entity = RawEntityItem(
            name="甲科技有限责任公司",
            entity_type="ORG",
            external_id="ORG-1001",
            aliases=("甲科技", "Jia Corp"),
            confidence=0.98,
        )
        self.assertEqual("甲科技有限责任公司", entity.name)
        self.assertEqual(2, len(entity.aliases))

        with self.assertRaises(KnowledgeError):
            RawEntityItem(name="", entity_type="ORG")

        with self.assertRaises(KnowledgeError):
            RawEntityItem(name="甲科技", entity_type="ORG", confidence=1.5)

        relation = RawRelationItem(
            subject_name_or_id="乙制造",
            predicate="supplies",
            object_name_or_id="甲科技",
            polarity=Polarity.POSITIVE,
            modality=Modality.ASSERTED,
            evidence_text="甲科技向乙制造采购原材料",
            evidence_start=0,
            evidence_end=12,
        )
        self.assertEqual("supplies", relation.predicate)

        with self.assertRaises(KnowledgeError):
            RawRelationItem(
                subject_name_or_id="乙制造",
                predicate="supplies",
                object_name_or_id="甲科技",
                evidence_start=5,
                evidence_end=None,  # Asymmetric span interval
            )

    def test_master_data_importer_validation(self) -> None:
        importer = MasterDataImporter(tenant_id="tenant-corp", domain="corp.test")
        entity = RawEntityItem(name="甲科技", entity_type="ORG")
        batch = IngestionBatch(meta=self.meta, entities=(entity,), relations=())

        report = importer.validate_batch(batch)
        self.assertTrue(report.is_valid)
        self.assertEqual(0, report.error_count)

        # Ingest raises NotImplementedError with TODO as expected
        with self.assertRaises(NotImplementedError) as ctx:
            importer.ingest(batch)
        self.assertIn("TODO", str(ctx.exception))

    def test_master_data_importer_rejects_wrong_kind(self) -> None:
        importer = MasterDataImporter(tenant_id="tenant-corp", domain="corp.test")
        wrong_meta = IngestionSourceMeta(
            tenant_id="tenant-corp",
            domain="corp.test",
            source_kind=SourceKind.DOCUMENT,  # Mismatch
            source_id="doc-01",
            version="v1",
            purpose="procurement-graph",
            acl=frozenset({"corp.test:dept-procurement"}),
            observed_at=self.now,
            retention_until=self.now + timedelta(days=90),
        )
        batch = IngestionBatch(meta=wrong_meta, entities=(), relations=())
        report = importer.validate_batch(batch)
        self.assertFalse(report.is_valid)
        self.assertTrue(any(i.code == "INVALID_SOURCE_KIND" for i in report.issues))

    def test_document_importer_validation(self) -> None:
        importer = DocumentKnowledgeImporter(tenant_id="tenant-corp", domain="corp.test")
        doc_meta = IngestionSourceMeta(
            tenant_id="tenant-corp",
            domain="corp.test",
            source_kind=SourceKind.DOCUMENT,
            source_id="contract-01",
            version="v1",
            purpose="procurement-graph",
            acl=frozenset({"corp.test:dept-procurement"}),
            observed_at=self.now,
            retention_until=self.now + timedelta(days=90),
        )
        # Relation missing evidence span
        rel_no_span = RawRelationItem(
            subject_name_or_id="乙制造",
            predicate="supplies",
            object_name_or_id="甲科技",
        )
        batch = IngestionBatch(meta=doc_meta, entities=(), relations=(rel_no_span,))
        report = importer.validate_batch(batch)
        self.assertFalse(report.is_valid)
        self.assertTrue(any(i.code == "MISSING_EVIDENCE_SPAN" for i in report.issues))


if __name__ == "__main__":
    unittest.main()
