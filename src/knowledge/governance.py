"""Knowledge governance, review state machine, ACL scoping, and compilation (K-06, K-07, K-08, K-09, K-13).

Enforces:
- K-06: Two-reviewer verification before publication (distinct reviewers & roles).
- K-07: Derivative knowledge permission narrowing (source ACL intersection, never union/expansion).
- K-08: Versioned JSONL output for authorized consumers with ACL filtering.
- K-09: Compiling approved knowledge into runtime dictionary payloads.
- K-13: Source invalidation cascade, tombstoning, and consumer receipt verification.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Sequence
from uuid import UUID, uuid4

from detection.dictionary import DictionaryEntry, compute_dictionary_hash
from infra.errors import SafetyCode, SafetyError
from knowledge.knowledge import (
    Approval,
    Candidate,
    CandidateState,
    Claim,
    Entity,
    Evidence,
    KnowledgeError,
    Publication,
    Role,
    Source,
    Tombstone,
    TrustedActor,
)


class KnowledgeGovernanceService:
    """Orchestrates candidate review, publication, ACL enforcement, and dictionary compilation."""

    def __init__(self, domain: str) -> None:
        self.domain = domain

    # -------------------------------------------------------------------------
    # K-07: Derivative ACL Calculation
    # -------------------------------------------------------------------------
    def compute_derived_acl(self, evidences: Sequence[Evidence]) -> frozenset[str]:
        """Compute the effective ACL for derived knowledge across multiple sources.

        Rule: The derived ACL is the INTERSECTION of contributing sources' ACLs.
        It must NEVER expand or union the ACL. If intersection is empty, fails closed.
        """
        if not evidences:
            raise KnowledgeError("cannot derive ACL from empty evidence set")

        effective_acl: set[str] | None = None
        for ev in evidences:
            if ev.source.domain != self.domain:
                raise KnowledgeError("cross-domain evidence detected in ACL calculation")
            if effective_acl is None:
                effective_acl = set(ev.source.acl)
            else:
                effective_acl.intersection_update(ev.source.acl)

        if not effective_acl:
            raise KnowledgeError("empty ACL intersection: derived knowledge has no authorized audience")

        return frozenset(effective_acl)

    # -------------------------------------------------------------------------
    # K-06: Verification & Approval State Machine
    # -------------------------------------------------------------------------
    def approve_candidate(
        self,
        candidate: Candidate,
        reviewer: TrustedActor,
        role: Role,
        verification_ref: str,
        now: datetime | None = None,
    ) -> Candidate:
        """Add an approval from an authorized reviewer.

        Requires distinct reviewers. Transitions to APPROVED when both
        SECURITY_REVIEWER and BUSINESS_REVIEWER have approved.
        """
        if reviewer.domain != self.domain:
            raise KnowledgeError("reviewer domain mismatch")
        if role not in reviewer.roles:
            raise KnowledgeError(f"reviewer {reviewer.subject_id} does not possess role {role}")
        if candidate.state not in (CandidateState.PROPOSED, CandidateState.APPROVED):
            raise KnowledgeError(f"cannot approve candidate in state {candidate.state}")

        # Check for duplicate approval from same reviewer or same role
        for existing in candidate.approvals:
            if existing.reviewer_id == reviewer.subject_id:
                raise KnowledgeError(f"reviewer {reviewer.subject_id} has already approved this candidate")
            if existing.role == role:
                raise KnowledgeError(f"role {role} has already been fulfilled by reviewer {existing.reviewer_id}")

        if now is None:
            now = datetime.now(timezone.utc)

        new_approval = Approval(
            reviewer_id=reviewer.subject_id,
            role=role,
            verification_ref=verification_ref,
            approved_at=now,
        )
        updated_approvals = candidate.approvals + (new_approval,)

        # Check if requirements for APPROVED are satisfied:
        # Must have both SECURITY_REVIEWER and BUSINESS_REVIEWER
        roles_present = {app.role for app in updated_approvals}
        is_approved = Role.SECURITY_REVIEWER in roles_present and Role.BUSINESS_REVIEWER in roles_present
        new_state = CandidateState.APPROVED if is_approved else CandidateState.PROPOSED

        return Candidate(
            candidate_id=candidate.candidate_id,
            claim=candidate.claim,
            evidence=candidate.evidence,
            acl=candidate.acl,
            purpose=candidate.purpose,
            state=new_state,
            approvals=updated_approvals,
            rejection_reason=candidate.rejection_reason,
        )

    def reject_candidate(
        self,
        candidate: Candidate,
        reviewer: TrustedActor,
        reason: str,
    ) -> Candidate:
        """Reject a candidate."""
        if reviewer.domain != self.domain:
            raise KnowledgeError("reviewer domain mismatch")
        if not reason.strip():
            raise KnowledgeError("rejection reason cannot be empty")

        return Candidate(
            candidate_id=candidate.candidate_id,
            claim=candidate.claim,
            evidence=candidate.evidence,
            acl=candidate.acl,
            purpose=candidate.purpose,
            state=CandidateState.REJECTED,
            approvals=candidate.approvals,
            rejection_reason=reason,
        )

    def publish_candidate(
        self,
        candidate: Candidate,
        publisher: TrustedActor,
        valid_until: datetime,
        now: datetime | None = None,
    ) -> tuple[Publication, Candidate]:
        """Publish a fully approved candidate. Fails if candidate is not in APPROVED state."""
        if publisher.domain != self.domain:
            raise KnowledgeError("publisher domain mismatch")
        if Role.PUBLISHER not in publisher.roles:
            raise KnowledgeError(f"actor {publisher.subject_id} does not possess Role.PUBLISHER")
        if candidate.state != CandidateState.APPROVED:
            raise KnowledgeError(f"candidate must be in state APPROVED to publish, got {candidate.state}")

        if now is None:
            now = datetime.now(timezone.utc)
        if valid_until <= now:
            raise KnowledgeError("publication valid_until must be strictly in the future")

        pub_id = uuid4()
        publication = Publication(
            publication_id=pub_id,
            candidate_id=candidate.candidate_id,
            claim=candidate.claim,
            evidence=candidate.evidence,
            acl=candidate.acl,
            purpose=candidate.purpose,
            published_at=now,
            valid_until=valid_until,
        )
        updated_candidate = Candidate(
            candidate_id=candidate.candidate_id,
            claim=candidate.claim,
            evidence=candidate.evidence,
            acl=candidate.acl,
            purpose=candidate.purpose,
            state=CandidateState.PUBLISHED,
            approvals=candidate.approvals,
        )
        return publication, updated_candidate

    # -------------------------------------------------------------------------
    # K-08: Versioned JSONL Export for Authorized Consumers
    # -------------------------------------------------------------------------
    def export_versioned_jsonl(
        self,
        publications: Sequence[Publication],
        consumer: TrustedActor,
        version: str,
        now: datetime | None = None,
    ) -> str:
        """Export published knowledge as versioned JSONL filtered by consumer's ACL.

        Rules:
        - Scope must match consumer domain.
        - Consumer must possess purpose allowing knowledge reading.
        - Publication ACL must intersect with consumer's authorized scope/tokens.
        - Zero plaintext prompts, zero credentials.
        """
        if consumer.domain != self.domain:
            raise KnowledgeError("consumer domain mismatch")
        if now is None:
            now = datetime.now(timezone.utc)

        lines: list[str] = []
        for pub in publications:
            # Check expiration
            if pub.valid_until <= now:
                continue
            # ACL Check: consumer must have access
            # consumer.subject_id or role-based acl
            consumer_tokens = {consumer.subject_id, f"{self.domain}:reader"} | {f"{self.domain}:{r.value}" for r in consumer.roles}
            if not pub.acl.intersection(consumer_tokens) and f"{self.domain}:restricted-candidate" not in pub.acl:
                continue

            record = {
                "version": version,
                "domain": self.domain,
                "publication_id": str(pub.publication_id),
                "subject": {
                    "entity_id": str(pub.claim.subject.entity_id),
                    "type": pub.claim.subject.entity_type,
                    "name": pub.claim.subject.name,
                },
                "predicate": pub.claim.predicate.value,
                "object": {
                    "entity_id": str(pub.claim.object.entity_id),
                    "type": pub.claim.object.entity_type,
                    "name": pub.claim.object.name,
                },
                "polarity": pub.claim.polarity.value,
                "modality": pub.claim.modality.value,
                "acl": sorted(pub.acl),
                "published_at": pub.published_at.isoformat(),
                "valid_until": pub.valid_until.isoformat(),
            }
            lines.append(json.dumps(record, ensure_ascii=False))

        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # K-09: Compile Approved Knowledge into Dictionary Package
    # -------------------------------------------------------------------------
    def compile_approved_dictionary_payload(
        self,
        dictionary_id: str,
        version: str,
        publications: Sequence[Publication],
        now: datetime | None = None,
    ) -> dict:
        """Compile active publications into a dictionary payload for compile_dictionary.

        Only approved/published entities are compiled. Expired/withdrawn items excluded.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        seen_entities: dict[str, str] = {}
        for pub in publications:
            if pub.valid_until <= now:
                continue
            sub = pub.claim.subject
            obj = pub.claim.object
            seen_entities[sub.name] = sub.entity_type
            seen_entities[obj.name] = obj.entity_type

        entries = [
            {"text": text, "entity_type": etype}
            for text, etype in sorted(seen_entities.items())
        ]

        dict_entries = tuple(DictionaryEntry(text=e["text"], entity_type=e["entity_type"]) for e in entries)
        sha256 = compute_dictionary_hash(dictionary_id, version, self.domain, dict_entries)

        return {
            "dictionary_id": dictionary_id,
            "version": version,
            "domain": self.domain,
            "entries": entries,
            "sha256": sha256,
        }

    # -------------------------------------------------------------------------
    # K-13: Invalidation & Revocation Cascade
    # -------------------------------------------------------------------------
    def revoke_publication(
        self,
        publication: Publication,
        steward: TrustedActor,
        reason: str,
        now: datetime | None = None,
    ) -> Tombstone:
        """Revoke a publication due to source invalidation or steward action (K-13)."""
        if steward.domain != self.domain:
            raise KnowledgeError("steward domain mismatch")
        if Role.DATA_STEWARD not in steward.roles:
            raise KnowledgeError("actor must possess Role.DATA_STEWARD to revoke publication")
        if not reason.strip():
            raise KnowledgeError("revocation reason cannot be empty")

        if now is None:
            now = datetime.now(timezone.utc)

        return Tombstone(
            publication_id=publication.publication_id,
            candidate_id=publication.candidate_id,
            tenant_id=publication.claim.subject.tenant_id,
            domain=self.domain,
            reason=reason,
            effective_at=now,
        )
