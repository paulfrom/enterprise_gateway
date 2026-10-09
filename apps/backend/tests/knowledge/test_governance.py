"""Tests for knowledge governance, review state machine, ACL scoping, and compilation (K-06, K-07, K-08, K-09, K-13)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import unittest
from uuid import uuid4

from detection.dictionary import compile_dictionary
from knowledge.governance import KnowledgeGovernanceService
from knowledge.knowledge import (
    Approval,
    Candidate,
    CandidateState,
    Claim,
    Entity,
    Evidence,
    KnowledgeError,
    Modality,
    Polarity,
    Predicate,
    Role,
    Source,
    SourceKind,
    TrustedActor,
)


class TestKnowledgeGovernance(unittest.TestCase):
    def setUp(self) -> None:
        self.domain = "corp.test"
        self.service = KnowledgeGovernanceService(self.domain)
        self.now = datetime.now(timezone.utc)

        self.sec_reviewer = TrustedActor(
            subject_id="sec-01",
            tenant_id="tenant-corp",
            domain=self.domain,
            roles=frozenset({Role.SECURITY_REVIEWER}),
            purposes=frozenset({"procurement"}),
        )
        self.biz_reviewer = TrustedActor(
            subject_id="biz-01",
            tenant_id="tenant-corp",
            domain=self.domain,
            roles=frozenset({Role.BUSINESS_REVIEWER}),
            purposes=frozenset({"procurement"}),
        )
        self.publisher = TrustedActor(
            subject_id="pub-01",
            tenant_id="tenant-corp",
            domain=self.domain,
            roles=frozenset({Role.PUBLISHER}),
            purposes=frozenset({"procurement"}),
        )
        self.steward = TrustedActor(
            subject_id="steward-01",
            tenant_id="tenant-corp",
            domain=self.domain,
            roles=frozenset({Role.DATA_STEWARD}),
            purposes=frozenset({"procurement"}),
        )

        self.source1 = Source(
            tenant_id="tenant-corp",
            domain=self.domain,
            source_id="src-01",
            version="v1",
            source_kind=SourceKind.USER_ASSERTION,
            acl=frozenset({f"{self.domain}:team-a", f"{self.domain}:team-b", "sec-01", "biz-01", "pub-01", "steward-01", "user-allowed"}),
            purpose="procurement",
            observed_at=self.now,
            retention_until=self.now + timedelta(days=60),
        )
        self.source2 = Source(
            tenant_id="tenant-corp",
            domain=self.domain,
            source_id="src-02",
            version="v1",
            source_kind=SourceKind.DOCUMENT,
            acl=frozenset({f"{self.domain}:team-b", f"{self.domain}:team-c"}),
            purpose="procurement",
            observed_at=self.now,
            retention_until=self.now + timedelta(days=60),
        )

        self.ent_jia = Entity(uuid4(), "tenant-corp", self.domain, "ORG", "甲公司")
        self.ent_yi = Entity(uuid4(), "tenant-corp", self.domain, "ORG", "乙公司")
        self.claim = Claim(self.ent_yi, Predicate.SUPPLIES, self.ent_jia)

    def approve(self, candidate):
        c = self.service.approve_candidate(candidate,self.sec_reviewer,Role.SECURITY_REVIEWER,'security/verified')
        return self.service.approve_candidate(c,self.biz_reviewer,Role.BUSINESS_REVIEWER,'business/verified')

    def test_k07_derived_acl_is_strict_intersection(self) -> None:
        """K-07: Derivative knowledge ACL is intersection of source ACLs, never union."""
        ev1 = Evidence(self.source1, "a" * 64, 0, 10)
        ev2 = Evidence(self.source2, "b" * 64, 0, 10)

        derived_acl = self.service.compute_derived_acl([ev1, ev2])
        # Intersection of {team-a, team-b} and {team-b, team-c} is {team-b}
        self.assertEqual(frozenset({f"{self.domain}:team-b"}), derived_acl)

        # Empty intersection fails closed
        source_disjoint = Source(
            tenant_id="tenant-corp",
            domain=self.domain,
            source_id="src-03",
            version="v1",
            source_kind=SourceKind.DOCUMENT,
            acl=frozenset({f"{self.domain}:team-z"}),
            purpose="procurement",
            observed_at=self.now,
            retention_until=self.now + timedelta(days=60),
        )
        ev_disjoint = Evidence(source_disjoint, "c" * 64, 0, 10)
        with self.assertRaises(KnowledgeError):
            self.service.compute_derived_acl([ev1, ev_disjoint])

    def test_k06_two_reviewer_state_machine_and_publishing(self) -> None:
        """K-06: Candidate requires two distinct reviewers before publishing."""
        ev = Evidence(self.source1, "a" * 64, 0, 10)
        candidate = Candidate(
            candidate_id=uuid4(),
            claim=self.claim,
            evidence=(ev,),
            acl=self.source1.acl,
            purpose="procurement",
        )
        self.assertEqual(CandidateState.PROPOSED, candidate.state)

        # 1. First review (Security)
        c1 = self.service.approve_candidate(
            candidate, self.sec_reviewer, Role.SECURITY_REVIEWER, "audit-sec"
        )
        self.assertEqual(CandidateState.PROPOSED, c1.state)
        self.assertEqual(1, len(c1.approvals))

        # Duplicate approval from same reviewer fails
        with self.assertRaises(KnowledgeError):
            self.service.approve_candidate(
                c1, self.sec_reviewer, Role.BUSINESS_REVIEWER, "audit-dup"
            )

        # Cannot publish while still PROPOSED
        with self.assertRaises(KnowledgeError):
            self.service.publish_candidate(
                c1, self.publisher, self.now + timedelta(days=90)
            )

        # 2. Second review (Business)
        c2 = self.service.approve_candidate(
            c1, self.biz_reviewer, Role.BUSINESS_REVIEWER, "audit-biz"
        )
        self.assertEqual(CandidateState.APPROVED, c2.state)
        self.assertEqual(2, len(c2.approvals))

        # 3. Publish approved candidate
        pub, published_candidate = self.service.publish_candidate(
            c2, self.publisher, self.now + timedelta(days=90)
        )
        self.assertEqual(CandidateState.PUBLISHED, published_candidate.state)
        self.assertEqual("乙公司", pub.claim.subject.name)
        self.assertEqual("甲公司", pub.claim.object.name)

    def test_k08_versioned_jsonl_export_with_acl_filtering(self) -> None:
        """K-08: Authorized consumer can only see publications matching their ACL."""
        ev = Evidence(self.source1, "a" * 64, 0, 10)
        candidate = Candidate(
            candidate_id=uuid4(),
            claim=self.claim,
            evidence=(ev,),
            acl=self.source1.acl - {"user-allowed"},
            purpose="procurement",
            state=CandidateState.PROPOSED,
        )
        candidate = self.approve(candidate)
        pub, _ = self.service.publish_candidate(
            candidate, self.publisher, self.now + timedelta(days=90)
        )

        # Consumer with team-secret token
        authorized_consumer = TrustedActor(
            subject_id="user-allowed",
            tenant_id="tenant-corp",
            domain=self.domain,
            roles=frozenset(),
            purposes=frozenset({"procurement"}),
        )
        # Manually mock matching subject_id in ACL
        candidate_with_user = Candidate(
            candidate_id=uuid4(),
            claim=self.claim,
            evidence=(ev,),
            acl=self.source1.acl,
            purpose="procurement",
            state=CandidateState.PROPOSED,
        )
        candidate_with_user = self.approve(candidate_with_user)
        pub2, _ = self.service.publish_candidate(
            candidate_with_user, self.publisher, self.now + timedelta(days=90)
        )

        # Export for authorized consumer
        jsonl = self.service.export_versioned_jsonl([pub, pub2], authorized_consumer, "v1.0")
        lines = [line for line in jsonl.splitlines() if line.strip()]
        # Only pub2 is visible to user-allowed! pub (team-secret) is excluded!
        self.assertEqual(1, len(lines))
        record = json.loads(lines[0])
        self.assertEqual("乙公司", record["subject"]["name"])
        self.assertEqual("甲公司", record["object"]["name"])

    def test_k09_compile_approved_dictionary_package(self) -> None:
        """K-09: Approved publications compile cleanly into dictionary payload."""
        ev = Evidence(self.source1, "a" * 64, 0, 10)
        candidate = Candidate(
            candidate_id=uuid4(),
            claim=self.claim,
            evidence=(ev,),
            acl=self.source1.acl,
            purpose="procurement",
            state=CandidateState.PROPOSED,
        )
        candidate = self.approve(candidate)
        pub, _ = self.service.publish_candidate(
            candidate, self.publisher, self.now + timedelta(days=90)
        )

        dict_payload = self.service.compile_approved_dictionary_payload(
            "dict-kb-01", "v1.0.0", [pub], consumer=self.publisher
        )
        self.assertEqual("dict-kb-01", dict_payload["dictionary_id"])
        self.assertEqual("v1.0.0", dict_payload["version"])
        self.assertEqual(self.domain, dict_payload["domain"])
        # Contains both entities from the claim
        names = [e["text"] for e in dict_payload["entries"]]
        self.assertIn("甲公司", names)
        self.assertIn("乙公司", names)

        # Verify it can be compiled by the actual dictionary compiler!
        compiled = compile_dictionary(dict_payload)
        self.assertEqual("dict-kb-01", compiled.dictionary_id)
        self.assertEqual(2, len(compiled.entries))

    def test_k13_revocation_and_tombstone(self) -> None:
        """K-13: Stewards can revoke publications, emitting tombstones."""
        ev = Evidence(self.source1, "a" * 64, 0, 10)
        candidate = Candidate(
            candidate_id=uuid4(),
            claim=self.claim,
            evidence=(ev,),
            acl=self.source1.acl,
            purpose="procurement",
            state=CandidateState.PROPOSED,
        )
        candidate = self.approve(candidate)
        pub, _ = self.service.publish_candidate(
            candidate, self.publisher, self.now + timedelta(days=90)
        )

        tombstone = self.service.revoke_publication(
            pub, self.steward, "Source data was deleted by user request"
        )
        self.assertEqual(pub.publication_id, tombstone.publication_id)
        self.assertEqual(pub.candidate_id, tombstone.candidate_id)
        self.assertEqual("Source data was deleted by user request", tombstone.reason)


if __name__ == "__main__":
    unittest.main()
