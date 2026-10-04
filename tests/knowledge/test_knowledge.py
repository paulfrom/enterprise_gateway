"""Synthetic domain checks; these do not validate storage, IAM, or extraction."""

import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import UUID

from protocol.identity import TrustedIdentity
from knowledge.knowledge import (
    CandidateState, Claim, Entity, Evidence, KnowledgeError, KnowledgeLedger,
    Modality, Polarity, Predicate, Role, Source, SourceKind, TrustedActor,
)


class KnowledgeTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 2, tzinfo=timezone.utc)
        self.acl = frozenset({"security", "business", "publisher", "reader", "steward"})
        self.source = Source("tenant-a", "procurement", "contract-1", "v1",
                             SourceKind.DOCUMENT, self.acl, "enterprise_knowledge",
                             self.now, self.now + timedelta(days=30), independence_verified=True)
        self.evidence = Evidence(self.source, sha256("合成供应关系".encode()).hexdigest(), 0, 6)
        self.supplier = Entity(UUID(int=1), "tenant-a", "procurement", "organization", "合成供应商甲")
        self.customer = Entity(UUID(int=2), "tenant-a", "procurement", "organization", "合成企业乙")
        self.claim = Claim(self.supplier, Predicate.SUPPLIES, self.customer)
        self.ledger = KnowledgeLedger()

    def actor(self, subject, *roles):
        return TrustedActor(subject, "tenant-a", "procurement", frozenset(roles),
                            frozenset({"enterprise_knowledge"}))

    def proposed(self, claim=None, evidence=None):
        return self.ledger.propose(claim or self.claim, evidence or (self.evidence,), self.now)

    def approved(self, candidate):
        self.ledger.approve(candidate.candidate_id,
                            self.actor("security", Role.SECURITY_REVIEWER),
                            Role.SECURITY_REVIEWER, "review/security/1", self.now)
        return self.ledger.approve(candidate.candidate_id,
                                   self.actor("business", Role.BUSINESS_REVIEWER),
                                   Role.BUSINESS_REVIEWER, "review/business/1", self.now)

    def publish(self, candidate):
        return self.ledger.publish(candidate.candidate_id, self.actor("publisher", Role.PUBLISHER), self.now)

    def test_synthetic_approval_publish_read_and_withdraw_loop(self):
        candidate = self.proposed()
        self.assertEqual(CandidateState.PROPOSED, candidate.state)
        self.assertEqual(CandidateState.APPROVED, self.approved(candidate).state)
        publication = self.publish(candidate)
        self.assertEqual("合成供应商甲", publication.claim.subject.name)
        self.assertEqual(publication, self.ledger.read_publication(publication.publication_id,
                                                                  self.actor("reader"), self.now))
        tombstones = self.ledger.withdraw_source("contract-1", "v1", self.actor("steward", Role.DATA_STEWARD),
                                                 "source permission withdrawn", self.now)
        self.assertEqual(publication.publication_id, tombstones[0].publication_id)
        self.assertEqual((), self.ledger.withdraw_source("contract-1", "v1", self.actor("steward", Role.DATA_STEWARD),
                                                        "retry", self.now))
        with self.assertRaises(KnowledgeError):
            self.ledger.read_publication(publication.publication_id, self.actor("reader"), self.now)
        with self.assertRaises(KnowledgeError):
            self.proposed()

    def test_retry_and_repeated_history_do_not_inflate_sources(self):
        candidate = self.proposed(evidence=(self.evidence, self.evidence))
        retried = self.proposed()
        self.assertEqual(candidate.candidate_id, retried.candidate_id)
        self.assertEqual(1, len(candidate.evidence))
        self.assertEqual(1, candidate.independent_source_count)
        another_span = replace(self.evidence, start=8, end=14)
        same_source = self.proposed(evidence=(self.evidence, another_span))
        self.assertEqual(1, same_source.independent_source_count)

    def test_conflicting_retry_is_rejected(self):
        self.proposed()
        with self.assertRaises(KnowledgeError):
            self.proposed(evidence=(replace(self.evidence, content_sha256="f" * 64),))
        with self.assertRaises(KnowledgeError):
            self.proposed(evidence=(replace(self.evidence, source=replace(self.source, acl=frozenset({"reader"}))),))
        with self.assertRaises(KnowledgeError):
            self.proposed(claim=replace(self.claim, subject=replace(self.supplier, name="different company")))

    def test_acl_intersection_and_denied_reader(self):
        narrower = replace(self.source, source_id="contract-2", acl=self.acl - {"reader"})
        candidate = self.proposed(evidence=(self.evidence, replace(self.evidence, source=narrower)))
        self.assertEqual(self.acl - {"reader"}, candidate.acl)
        self.assertEqual(2, candidate.independent_source_count)
        self.approved(candidate)
        publication = self.publish(candidate)
        with self.assertRaises(KnowledgeError):
            self.ledger.read_publication(publication.publication_id, self.actor("reader"), self.now)

    def test_empty_acl_intersection_and_scope_mismatch_are_denied(self):
        other_acl = replace(self.source, source_id="contract-2", acl=frozenset({"outsider"}))
        with self.assertRaises(KnowledgeError):
            self.proposed(evidence=(self.evidence, replace(self.evidence, source=other_acl)))
        for field, value in (("tenant_id", "tenant-b"), ("domain", "finance")):
            with self.subTest(field=field), self.assertRaises(KnowledgeError):
                self.proposed(evidence=(replace(self.evidence, source=replace(self.source, **{field: value})),))
        with self.assertRaises(KnowledgeError):
            Claim(self.supplier, Predicate.SUPPLIES, replace(self.customer, tenant_id="tenant-b"))

    def test_publish_requires_two_distinct_reviewers(self):
        candidate = self.proposed()
        with self.assertRaises(KnowledgeError):
            self.publish(candidate)
        actor = self.actor("security", Role.SECURITY_REVIEWER, Role.BUSINESS_REVIEWER)
        self.ledger.approve(candidate.candidate_id, actor, Role.SECURITY_REVIEWER, "verified", self.now)
        with self.assertRaises(KnowledgeError):
            self.ledger.approve(candidate.candidate_id, actor, Role.BUSINESS_REVIEWER, "verified", self.now)
        with self.assertRaises(KnowledgeError):
            self.publish(candidate)

    def test_roles_purpose_and_actor_scope_are_enforced(self):
        candidate = self.proposed()
        actor = self.actor("security", Role.SECURITY_REVIEWER)
        for invalid in (replace(actor, roles=frozenset()), replace(actor, purposes=frozenset()),
                        replace(actor, tenant_id="tenant-b"), replace(actor, domain="finance"),
                        replace(actor, subject_id="outsider")):
            with self.subTest(actor=invalid), self.assertRaises(KnowledgeError):
                self.ledger.approve(candidate.candidate_id, invalid, Role.SECURITY_REVIEWER, "verified", self.now)
        with self.assertRaises(KnowledgeError):
            self.ledger.approve(candidate.candidate_id, actor, Role.SECURITY_REVIEWER, "", self.now)

    def test_reader_and_publisher_cannot_cross_purpose_or_scope(self):
        candidate = self.proposed()
        self.approved(candidate)
        with self.assertRaises(KnowledgeError):
            self.ledger.publish(candidate.candidate_id, self.actor("publisher"), self.now)
        publication = self.publish(candidate)
        reader = self.actor("reader")
        for invalid in (replace(reader, tenant_id="tenant-b"), replace(reader, domain="finance"),
                        replace(reader, purposes=frozenset()), replace(reader, subject_id="outsider")):
            with self.subTest(actor=invalid), self.assertRaises(KnowledgeError):
                self.ledger.read_publication(publication.publication_id, invalid, self.now)

    def test_different_purpose_and_unauthorized_withdrawal_are_denied(self):
        other_purpose = replace(self.source, source_id="contract-2", purpose="other-purpose")
        with self.assertRaises(KnowledgeError):
            self.proposed(evidence=(self.evidence, replace(self.evidence, source=other_purpose)))
        self.proposed()
        with self.assertRaises(KnowledgeError):
            self.ledger.withdraw_source("contract-1", "v1", self.actor("steward"), "reason", self.now)

    def test_model_only_cooccurrence_and_hypothetical_cannot_publish(self):
        cases = ((self.claim, (replace(self.evidence, source=replace(self.source, source_kind=SourceKind.MODEL_OUTPUT)),)),
                 (replace(self.claim, predicate=Predicate.CO_OCCURS_WITH), (self.evidence,)),
                 (replace(self.claim, modality=Modality.HYPOTHETICAL), (self.evidence,)),
                 (replace(self.claim, modality=Modality.QUESTION), (self.evidence,)))
        for claim, evidence in cases:
            with self.subTest(claim=claim):
                self.ledger = KnowledgeLedger()
                candidate = self.proposed(claim, evidence)
                self.approved(candidate)
                with self.assertRaises(KnowledgeError):
                    self.publish(candidate)

    def test_negated_claim_stays_explicitly_negative(self):
        candidate = self.proposed(replace(self.claim, polarity=Polarity.NEGATIVE))
        self.approved(candidate)
        self.assertEqual(Polarity.NEGATIVE, self.publish(candidate).claim.polarity)

    def test_expiry_denies_reads_and_emits_tombstone_once(self):
        candidate = self.proposed()
        self.approved(candidate)
        publication = self.publish(candidate)
        expiry = self.source.retention_until
        with self.assertRaises(KnowledgeError):
            self.ledger.read_publication(publication.publication_id, self.actor("reader"), expiry)
        self.assertEqual(1, len(self.ledger.expire(expiry)))
        self.assertEqual((), self.ledger.expire(expiry))

    def test_expired_evidence_blocks_proposal_and_approval(self):
        candidate = self.proposed()
        expiry = self.source.retention_until
        with self.assertRaises(KnowledgeError):
            self.ledger.propose(self.claim, (self.evidence,), expiry)
        with self.assertRaises(KnowledgeError):
            self.ledger.approve(candidate.candidate_id, self.actor("security", Role.SECURITY_REVIEWER),
                                Role.SECURITY_REVIEWER, "verified", expiry)

    def test_rejection_prevents_publication(self):
        candidate = self.proposed()
        rejected = self.ledger.reject(candidate.candidate_id, self.actor("business", Role.BUSINESS_REVIEWER),
                                       "unsupported relation", self.now)
        self.assertEqual(CandidateState.REJECTED, rejected.state)
        self.assertEqual("unsupported relation", rejected.rejection_reason)
        with self.assertRaises(KnowledgeError):
            self.publish(candidate)

    def test_unknown_ids_raise_controlled_errors(self):
        unknown = UUID(int=999)
        operations = (
            lambda: self.ledger.approve(unknown, self.actor("security", Role.SECURITY_REVIEWER),
                                        Role.SECURITY_REVIEWER, "ref", self.now),
            lambda: self.ledger.reject(unknown, self.actor("business", Role.BUSINESS_REVIEWER), "reason", self.now),
            lambda: self.ledger.publish(unknown, self.actor("publisher", Role.PUBLISHER), self.now),
            lambda: self.ledger.read_publication(unknown, self.actor("reader"), self.now),
            lambda: self.ledger.withdraw_source("no-such-source", "v1",
                                                self.actor("steward", Role.DATA_STEWARD), "reason", self.now),
        )
        for operation in operations:
            with self.subTest(operation=operation), self.assertRaises(KnowledgeError):
                operation()

    def test_contract_rejects_untyped_values_bad_offsets_and_missing_policy(self):
        invalid_contracts = (
            lambda: replace(self.source, acl=frozenset()),
            lambda: replace(self.source, purpose=""),
            lambda: replace(self.source, observed_at=self.now.replace(tzinfo=None)),
            lambda: replace(self.source, source_kind="document"),
            lambda: replace(self.evidence, start=-1),
            lambda: replace(self.evidence, end=0),
            lambda: replace(self.evidence, content_sha256="invalid"),
            lambda: replace(self.claim, predicate="supplies"),
            lambda: replace(self.actor("security"), roles=frozenset({"security_reviewer"})),
            lambda: replace(self.actor("reader"), subject_id=""),
        )
        for construct in invalid_contracts:
            with self.assertRaises(KnowledgeError):
                construct()


class TrustedActorFromIdentityTests(unittest.TestCase):
    """TrustedActor.from_identity maps knowledge-domain roles from contract identities."""

    def _identity(self, roles: frozenset[str]) -> TrustedIdentity:
        return TrustedIdentity(
            subject_id="user-1001",
            tenant_id="tenant-alpha",
            domain="finance-ops",
            roles=roles,
            purposes=frozenset({"invoice_processing"}),
            source_acl=frozenset({"user-1001"}),
            auth_source="mTLS",
            authenticated_at=datetime(2026, 10, 3, 10, 0, 0, tzinfo=timezone.utc),
            expires_at=datetime(2026, 10, 3, 11, 0, 0, tzinfo=timezone.utc),
        )

    def test_known_roles_are_preserved(self) -> None:
        identity = self._identity(frozenset({"caller", "business_reviewer"}))
        actor = TrustedActor.from_identity(identity)
        self.assertIsInstance(actor, TrustedActor)
        self.assertEqual(actor.subject_id, "user-1001")
        self.assertEqual(actor.tenant_id, "tenant-alpha")
        self.assertEqual(actor.domain, "finance-ops")
        self.assertIn(Role.BUSINESS_REVIEWER, actor.roles)
        self.assertNotIn("caller", actor.roles)
        self.assertEqual(actor.purposes, identity.purposes)

    def test_unknown_roles_are_dropped_to_empty_set(self) -> None:
        identity = self._identity(frozenset({"caller"}))
        actor = TrustedActor.from_identity(identity)
        self.assertEqual(actor.roles, frozenset())
        self.assertEqual(actor.subject_id, "user-1001")


if __name__ == "__main__":
    unittest.main()
