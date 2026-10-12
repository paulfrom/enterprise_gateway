"""Tests for business relation local extraction (K-05, K-11) and Phase 2 enhancements."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
import unittest
from uuid import uuid4

from knowledge.extractor import (
    RelationExtractor,
    Stage1EntityAligner,
    Stage2RelationExtractor,
    Stage3AttributeExtractor,
)
from knowledge.knowledge import (
    Candidate,
    Entity,
    KnowledgeError,
    Modality,
    Polarity,
    Predicate,
    Source,
    SourceKind,
)


class TestRelationExtractor(unittest.TestCase):
    def setUp(self) -> None:
        self.domain = "corp.test"
        self.model_pkg_path = Path("apps/backend/models/bert4ner-base-chinese-onnx")
        self.extractor = RelationExtractor(self.domain)
        self.now = datetime.now(timezone.utc)
        self.source = Source(
            tenant_id="tenant-corp",
            domain=self.domain,
            source_id="doc-01",
            version="v1",
            source_kind=SourceKind.USER_ASSERTION,
            acl=frozenset({f"{self.domain}:team-procurement"}),
            purpose="procurement-knowledge",
            observed_at=self.now,
            retention_until=self.now + timedelta(days=30),
        )
        self.ent_jia = Entity(uuid4(), "tenant-corp", self.domain, "ORG", "甲公司")
        self.ent_yi = Entity(uuid4(), "tenant-corp", self.domain, "ORG", "乙公司")

    def test_k11_positive_assertion_procurement_direction(self) -> None:
        """K-11: '甲公司向乙公司采购设备' correctly assigns 乙公司 as supplier and 甲公司 as customer."""
        text = "经双方友好协商，甲公司向乙公司采购设备五台。"
        digest = sha256(text.encode()).hexdigest()
        candidates = self.extractor.extract_from_text(
            text, self.source, [self.ent_jia, self.ent_yi], digest
        )
        self.assertEqual(1, len(candidates))
        candidate = candidates[0]
        claim = candidate.claim

        self.assertEqual("乙公司", claim.subject.name)
        self.assertEqual(Predicate.SUPPLIES, claim.predicate)
        self.assertEqual("甲公司", claim.object.name)
        self.assertEqual(Polarity.POSITIVE, claim.polarity)
        self.assertEqual(Modality.ASSERTED, claim.modality)
        self.assertEqual(1, len(candidate.evidence))
        # Verify evidence span integrity
        ev = candidate.evidence[0]
        self.assertEqual(text[ev.start : ev.end], "甲公司向乙公司采购设备五台")

    def test_k11_negation_detection(self) -> None:
        """K-11: '甲公司未向乙公司采购设备' yields Polarity.NEGATIVE."""
        text = "核查发现，甲公司未向乙公司采购设备，网传信息不实。"
        digest = sha256(text.encode()).hexdigest()
        candidates = self.extractor.extract_from_text(
            text, self.source, [self.ent_jia, self.ent_yi], digest
        )
        self.assertEqual(1, len(candidates))
        self.assertEqual(Polarity.NEGATIVE, candidates[0].claim.polarity)
        self.assertEqual(Modality.ASSERTED, candidates[0].claim.modality)

    def test_negation_debunking_and_rumor_correction(self) -> None:
        """Test negation adverbs, debunking contexts, and correction semantics."""
        for text, expected_polarity, expected_modality in [
            ("经核实，甲公司从未向乙公司采购设备，报道严重失实。", Polarity.NEGATIVE, Modality.HYPOTHETICAL),
            ("针对传言，甲公司并未向乙公司订购服务器，纯属谣言。", Polarity.NEGATIVE, Modality.HYPOTHETICAL),
            ("甲公司并不向乙公司采购软件，相关说法并不属实。", Polarity.NEGATIVE, Modality.ASSERTED),
            ("市场监管查明，甲公司绝非向乙公司采购芯片，内容不实。", Polarity.NEGATIVE, Modality.ASSERTED),
        ]:
            with self.subTest(text=text):
                digest = sha256(text.encode()).hexdigest()
                candidates = self.extractor.extract_from_text(
                    text, self.source, [self.ent_jia, self.ent_yi], digest
                )
                self.assertEqual(1, len(candidates))
                self.assertEqual(expected_polarity, candidates[0].claim.polarity)
                self.assertEqual(expected_modality, candidates[0].claim.modality)

    def test_k11_hypothetical_and_planning(self) -> None:
        """K-11: Planning keywords yield Modality.HYPOTHETICAL."""
        for text in [
            "根据下半年规划，甲公司计划向乙公司采购设备。",
            "如果预算通过，甲公司拟向乙公司订购服务器。",
            "甲公司打算向乙公司购入配件，目前正在商讨阶段。",
            "预计甲公司准备向乙公司采购原材料。",
        ]:
            with self.subTest(text=text):
                digest = sha256(text.encode()).hexdigest()
                candidates = self.extractor.extract_from_text(
                    text, self.source, [self.ent_jia, self.ent_yi], digest
                )
                self.assertEqual(1, len(candidates))
                self.assertEqual(Polarity.POSITIVE, candidates[0].claim.polarity)
                self.assertEqual(Modality.HYPOTHETICAL, candidates[0].claim.modality)

    def test_k11_question_modality(self) -> None:
        """K-11: Question syntax yields Modality.QUESTION."""
        for text in [
            "请问甲公司向乙公司采购设备吗？",
            "请查询甲公司是否向乙公司订购芯片？",
            "甲公司能否向乙公司采购设备五台？",
        ]:
            with self.subTest(text=text):
                digest = sha256(text.encode()).hexdigest()
                candidates = self.extractor.extract_from_text(
                    text, self.source, [self.ent_jia, self.ent_yi], digest
                )
                self.assertEqual(1, len(candidates))
                self.assertEqual(Modality.QUESTION, candidates[0].claim.modality)

    def test_k11_model_output_cannot_self_certify(self) -> None:
        """K-11: SourceKind.MODEL_OUTPUT is marked Modality.HYPOTHETICAL, not ASSERTED."""
        model_source = Source(
            tenant_id="tenant-corp",
            domain=self.domain,
            source_id="model-resp-01",
            version="v1",
            source_kind=SourceKind.MODEL_OUTPUT,
            acl=frozenset({f"{self.domain}:team-procurement"}),
            purpose="procurement-knowledge",
            observed_at=self.now,
            retention_until=self.now + timedelta(days=30),
        )
        text = "甲公司向乙公司采购设备。"
        digest = sha256(text.encode()).hexdigest()
        candidates = self.extractor.extract_from_text(
            text, model_source, [self.ent_jia, self.ent_yi], digest
        )
        self.assertEqual(1, len(candidates))
        self.assertEqual(Modality.HYPOTHETICAL, candidates[0].claim.modality)

    def test_k05_co_occurrence_does_not_become_procurement_fact(self) -> None:
        """K-05: Entities appearing in text without supplies predicate only produce CO_OCCURS_WITH."""
        text = "甲公司与乙公司联合出席了全球新能源汽车峰会。"
        digest = sha256(text.encode()).hexdigest()
        # Relation extraction must NOT produce supplies
        supplies_candidates = self.extractor.extract_from_text(
            text, self.source, [self.ent_jia, self.ent_yi], digest
        )
        self.assertEqual(0, len(supplies_candidates))

        # Co-occurrence extractor produces CO_OCCURS_WITH only
        co_candidates = self.extractor.extract_co_occurrences(
            text, self.source, [self.ent_jia, self.ent_yi], digest
        )
        self.assertEqual(1, len(co_candidates))
        self.assertEqual(Predicate.CO_OCCURS_WITH, co_candidates[0].claim.predicate)

    def test_stage1_ner_and_entity_alignment(self) -> None:
        """Test Stage 1 entity recognition, alias resolution, and UUID5 canonical alignment."""
        aligner = Stage1EntityAligner(self.domain, model_package_path=self.model_pkg_path)
        text = "甲科技有限责任公司向乙集团采购设备。"
        mentions = aligner.recognize_mentions(text)
        self.assertGreaterEqual(len(mentions), 2)
        mention_names = {m.name for m in mentions}
        self.assertIn("甲科技有限责任公司", mention_names)
        self.assertIn("乙集团", mention_names)

        # Test canonical alignment with alias mapping
        alias_map = {"甲科技有限责任公司": "甲公司", "乙集团": "乙公司"}
        aligned = aligner.align_entities(
            mentions, [self.ent_jia], tenant_id="tenant-corp", alias_map=alias_map
        )
        aligned_names = {e.name for e in aligned}
        self.assertIn("甲公司", aligned_names)
        self.assertIn("乙公司", aligned_names)

    def test_stage2_confidence_scoring_gate(self) -> None:
        """Test Stage 2 confidence gate filtering out candidates below threshold."""
        strict_extractor = RelationExtractor(self.domain, confidence_threshold=0.95)
        text = "甲公司向乙公司采购设备五台。"
        digest = sha256(text.encode()).hexdigest()
        # Default user assertion gives 0.85, below strict 0.95 threshold
        candidates = strict_extractor.extract_from_text(
            text, self.source, [self.ent_jia, self.ent_yi], digest
        )
        self.assertEqual(0, len(candidates))

        # Master data source gives boost to 1.0, passing 0.95 gate
        md_source = Source(
            tenant_id="tenant-corp",
            domain=self.domain,
            source_id="md-01",
            version="v1",
            source_kind=SourceKind.MASTER_DATA,
            acl=frozenset({f"{self.domain}:team-procurement"}),
            purpose="procurement-knowledge",
            observed_at=self.now,
            retention_until=self.now + timedelta(days=30),
        )
        md_candidates = strict_extractor.extract_from_text(
            text, md_source, [self.ent_jia, self.ent_yi], digest
        )
        self.assertEqual(1, len(md_candidates))
        self.assertGreaterEqual(md_candidates[0].confidence, 0.95)

    def test_stage3_semantic_attribute_extraction(self) -> None:
        """Test Stage 3 extraction of amount and product semantic edge attributes."""
        text = "甲公司向乙公司采购高性能服务器，合同金额500万元。"
        digest = sha256(text.encode()).hexdigest()
        candidates = self.extractor.extract_from_text(
            text, self.source, [self.ent_jia, self.ent_yi], digest
        )
        self.assertEqual(1, len(candidates))
        candidate = candidates[0]
        self.assertEqual("500万元", candidate.properties.get("amount"))
        self.assertEqual("高性能服务器", candidate.properties.get("product"))


if __name__ == "__main__":
    unittest.main()
