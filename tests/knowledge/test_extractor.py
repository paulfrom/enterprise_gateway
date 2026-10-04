"""Tests for business relation local extraction (K-05, K-11)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import unittest
from uuid import uuid4

from knowledge.extractor import RelationExtractor
from knowledge.knowledge import (
    Modality,
    Polarity,
    Predicate,
    Source,
    SourceKind,
    Entity,
)


class TestRelationExtractor(unittest.TestCase):
    def setUp(self) -> None:
        self.domain = "corp.test"
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

    def test_k11_hypothetical_and_planning(self) -> None:
        """K-11: Planning keywords yield Modality.HYPOTHETICAL."""
        text = "根据下半年规划，甲公司计划向乙公司采购设备。"
        digest = sha256(text.encode()).hexdigest()
        candidates = self.extractor.extract_from_text(
            text, self.source, [self.ent_jia, self.ent_yi], digest
        )
        self.assertEqual(1, len(candidates))
        self.assertEqual(Polarity.POSITIVE, candidates[0].claim.polarity)
        self.assertEqual(Modality.HYPOTHETICAL, candidates[0].claim.modality)

    def test_k11_question_modality(self) -> None:
        """K-11: Question syntax yields Modality.QUESTION."""
        text = "请问甲公司向乙公司采购设备吗？"
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


if __name__ == "__main__":
    unittest.main()
