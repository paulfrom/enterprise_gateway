"""Tests for OpenSPG semantic property graph constraints, schema guard, and rule engine (Phase 3)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import unittest
from uuid import UUID, NAMESPACE_DNS, uuid4, uuid5

from knowledge.knowledge import (
    Candidate,
    CandidateState,
    Claim,
    Entity,
    Evidence,
    KnowledgeError,
    Modality,
    Polarity,
    Predicate,
    Source,
    SourceKind,
)
from knowledge.spg import (
    BUILTIN_PREDICATE_SCHEMAS,
    CoOccurrenceIsolator,
    ConflictReport,
    EntityAliasManager,
    EntityResolver,
    MutualExclusionEngine,
    PredicateSchema,
    SchemaGuard,
    SchemaGuardViolation,
    TimeWindow,
    derive_entity_uuid,
)


class TestOpenSPGConstraints(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant_id = "tenant-corp"
        self.domain = "corp.test"
        self.now = datetime.now(timezone.utc)
        self.source = Source(
            tenant_id=self.tenant_id,
            domain=self.domain,
            source_id="src-01",
            version="v1",
            source_kind=SourceKind.MASTER_DATA,
            acl=frozenset({f"{self.domain}:team-procurement"}),
            purpose="procurement-knowledge",
            observed_at=self.now,
            retention_until=self.now + timedelta(days=30),
        )
        self.org_a = Entity(
            entity_id=derive_entity_uuid(self.tenant_id, self.domain, "ORG", "甲公司"),
            tenant_id=self.tenant_id,
            domain=self.domain,
            entity_type="ORG",
            name="甲公司",
        )
        self.org_b = Entity(
            entity_id=derive_entity_uuid(self.tenant_id, self.domain, "ORG", "乙公司"),
            tenant_id=self.tenant_id,
            domain=self.domain,
            entity_type="ORG",
            name="乙公司",
        )
        self.person_p = Entity(
            entity_id=derive_entity_uuid(self.tenant_id, self.domain, "PERSON", "张三"),
            tenant_id=self.tenant_id,
            domain=self.domain,
            entity_type="PERSON",
            name="张三",
        )
        self.product_x = Entity(
            entity_id=derive_entity_uuid(self.tenant_id, self.domain, "PRODUCT", "安全网关"),
            tenant_id=self.tenant_id,
            domain=self.domain,
            entity_type="PRODUCT",
            name="安全网关",
        )

    def test_spg_schema_guard_domain_range_enforcement(self) -> None:
        """SchemaGuard enforces Domain and Range typed constraints."""
        guard = SchemaGuard()

        # Valid triple: ORG supplies ORG
        valid_claim = Claim(
            subject=self.org_b,
            predicate=Predicate.SUPPLIES,
            object=self.org_a,
        )
        guard.guard_claim(valid_claim)

        # Invalid triple: PERSON supplies ORG -> Domain violation
        invalid_domain_claim = Claim(
            subject=self.person_p,
            predicate=Predicate.SUPPLIES,
            object=self.org_a,
        )
        with self.assertRaises(SchemaGuardViolation) as cm:
            guard.guard_claim(invalid_domain_claim)
        self.assertEqual("DOMAIN_MISMATCH", cm.exception.violation_type)

        # Invalid triple: ORG supplies PERSON -> Range violation
        invalid_range_claim = Claim(
            subject=self.org_b,
            predicate=Predicate.SUPPLIES,
            object=self.person_p,
        )
        with self.assertRaises(SchemaGuardViolation) as cm2:
            guard.guard_claim(invalid_range_claim)
        self.assertEqual("RANGE_MISMATCH", cm2.exception.violation_type)

    def test_spg_schema_guard_works_on(self) -> None:
        """Predicate WORKS_ON allows PERSON -> PRODUCT/PROJECT only."""
        guard = SchemaGuard()

        # Valid: PERSON works_on PRODUCT
        guard.guard_claim(Claim(self.person_p, Predicate.WORKS_ON, self.product_x))

        # Invalid: ORG works_on PRODUCT
        with self.assertRaises(SchemaGuardViolation):
            guard.guard_claim(Claim(self.org_a, Predicate.WORKS_ON, self.product_x))

    def test_spg_schema_guard_attribute_constraints(self) -> None:
        """SchemaGuard validates typed attribute schemas."""
        guard = SchemaGuard()
        claim = Claim(self.org_b, Predicate.SUPPLIES, self.org_a)

        # Valid attributes
        guard.guard_claim(claim, {"contract_id": "CNT-1234", "amount": 500000.0, "effective_year": 2026})

        # Invalid attribute type: effective_year not int
        with self.assertRaises(SchemaGuardViolation):
            guard.guard_claim(claim, {"effective_year": "2026"})

    def test_mutual_exclusion_positive_negative_conflict(self) -> None:
        """MutualExclusionEngine marks conflicting positive and negative assertions as DISPUTED."""
        engine = MutualExclusionEngine()

        ev1 = Evidence(self.source, "a" * 64, 0, 10)
        c_pos = Candidate(
            candidate_id=uuid4(),
            claim=Claim(self.org_b, Predicate.SUPPLIES, self.org_a, polarity=Polarity.POSITIVE),
            evidence=(ev1,),
            acl=self.source.acl,
            purpose=self.source.purpose,
        )
        c_neg = Candidate(
            candidate_id=uuid4(),
            claim=Claim(self.org_b, Predicate.SUPPLIES, self.org_a, polarity=Polarity.NEGATIVE),
            evidence=(ev1,),
            acl=self.source.acl,
            purpose=self.source.purpose,
        )

        conflict = engine.check_conflict(c_neg, [c_pos])
        self.assertTrue(conflict.has_conflict)
        self.assertEqual("POLARITY_MUTUAL_EXCLUSION", conflict.conflict_type)

        evaluated = engine.evaluate_and_tag(c_neg, [c_pos])
        self.assertEqual(CandidateState.DISPUTED, evaluated.state)
        self.assertIn("DISPUTED", evaluated.rejection_reason or "")

    def test_co_occurrence_isolation(self) -> None:
        """CoOccurrenceIsolator degrades claims without verbal cues to Predicate.CO_OCCURS_WITH."""
        isolator = CoOccurrenceIsolator()
        text = "甲公司和乙公司联合参加了行业研讨会。"
        claim = Claim(self.org_b, Predicate.SUPPLIES, self.org_a)
        cand = Candidate(
            candidate_id=uuid4(),
            claim=claim,
            evidence=(Evidence(self.source, sha256(text.encode()).hexdigest(), 0, len(text)),),
            acl=self.source.acl,
            purpose=self.source.purpose,
        )

        isolated = isolator.isolate(cand, text)
        self.assertEqual(Predicate.CO_OCCURS_WITH, isolated.claim.predicate)

        # When explicit cue is present, it does NOT degrade
        text_with_cue = "甲公司向乙公司采购核心服务器。"
        cand_with_cue = Candidate(
            candidate_id=uuid4(),
            claim=claim,
            evidence=(Evidence(self.source, sha256(text_with_cue.encode()).hexdigest(), 0, len(text_with_cue)),),
            acl=self.source.acl,
            purpose=self.source.purpose,
        )
        kept = isolator.isolate(cand_with_cue, text_with_cue)
        self.assertEqual(Predicate.SUPPLIES, kept.claim.predicate)

    def test_entity_alias_chain_resolution_and_uuid5(self) -> None:
        """EntityAliasManager supports transitive chain resolution, rename tracking, and UUID5 derivation."""
        manager = EntityAliasManager()

        # Register alias chain: 甲小号 -> 甲科技 -> 甲科技有限责任公司
        manager.register_alias(self.tenant_id, self.domain, "甲小号", "甲科技", "ORG")
        manager.register_alias(self.tenant_id, self.domain, "甲科技", "甲科技有限责任公司", "ORG")

        canon = manager.resolve_canonical_name(self.tenant_id, self.domain, "甲小号")
        self.assertEqual("甲科技有限责任公司", canon)

        # Authoritative rename
        manager.record_rename(
            self.tenant_id,
            self.domain,
            old_canonical="甲科技有限责任公司",
            new_canonical="甲科技集团股份有限公司",
            entity_type="ORG",
            reason="上市更名",
        )

        resolved_after_rename = manager.resolve_canonical_name(self.tenant_id, self.domain, "甲小号")
        self.assertEqual("甲科技集团股份有限公司", resolved_after_rename)

        # Verify deterministic UUID5
        ent = manager.resolve_entity(self.tenant_id, self.domain, "甲小号", "ORG")
        expected_uuid = uuid5(
            NAMESPACE_DNS,
            f"{self.tenant_id}:{self.domain}:ORG:甲科技集团股份有限公司",
        )
        self.assertEqual(expected_uuid, ent.entity_id)


if __name__ == "__main__":
    unittest.main()
