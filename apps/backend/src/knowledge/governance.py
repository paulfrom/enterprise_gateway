"""Knowledge governance, ACL scoping, publication, and compilation (K-07, K-08, K-09, K-13).

Enforces:
- K-07: Derivative knowledge permission narrowing (source ACL intersection, never union/expansion).
- K-08: Versioned JSONL output for authorized consumers with ACL filtering.
- K-09: Compiling approved knowledge into runtime dictionary payloads.
- K-13: Source invalidation cascade, tombstoning, and consumer receipt verification.

Schema v2 removed the persisted two-reviewer approval flow; persisted governance
mutations are bound to single-admin actions (see knowledge.storage). The local
in-memory review bookkeeping below only supports non-persistent unit flows.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Sequence
from uuid import UUID, uuid4
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from knowledge.storage import PostgresKnowledgeStorage

from detection.dictionary import DictionaryEntry, compute_dictionary_hash
from infra.errors import SafetyCode, SafetyError
from knowledge.knowledge import (
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
    Modality,
    Predicate,
    SourceKind,
)


class KnowledgeGovernanceService:
    """Orchestrates candidate review, publication, ACL enforcement, and dictionary compilation."""

    def __init__(self, domain: str, storage: PostgresKnowledgeStorage | None = None) -> None:
        self.domain = domain
        self.storage = storage
        self._approvals: dict[UUID, frozenset[Role]] = {}
        self._reviewers: dict[UUID, frozenset[str]] = {}
        self._publications: dict[UUID, Publication] = {}
        self._revoked: set[UUID] = set()
        self._withdrawn_sources: set[tuple] = set()

    def _validate(self, item: Candidate | Publication, now: datetime) -> None:
        scope = (item.claim.subject.tenant_id, self.domain)
        if now.tzinfo is None or (item.claim.subject.tenant_id, item.claim.subject.domain) != scope:
            raise KnowledgeError('invalid time or scope')
        if not item.evidence or not item.purpose:
            raise KnowledgeError('evidence and purpose required')
        for ev in item.evidence:
            if (ev.source.tenant_id, ev.source.domain) != scope or ev.source.purpose != item.purpose:
                raise KnowledgeError('evidence scope or purpose mismatch')
            if ev.source.observed_at > now or ev.source.retention_until <= now or ev.source.key in self._withdrawn_sources:
                raise KnowledgeError('source inactive')
        derived = frozenset.intersection(*(ev.source.acl for ev in item.evidence))
        if not item.acl or not item.acl <= derived:
            raise KnowledgeError('asset ACL exceeds source access')

    def _authorize(self, item: Candidate | Publication, actor: TrustedActor, role: Role) -> None:
        if (actor.tenant_id, actor.domain) != (item.claim.subject.tenant_id, self.domain):
            raise KnowledgeError('actor scope mismatch')
        if role not in actor.roles or actor.subject_id not in item.acl or item.purpose not in actor.purposes:
            raise KnowledgeError('actor lacks role, source access, or purpose')

    def _stored_candidate(self, candidate: Candidate, actor: TrustedActor) -> None:
        if self.storage:
            import psycopg
            with psycopg.connect(self.storage.connection_uri) as conn:
                self.storage.set_session_identity(conn, actor)
                stored = self.storage.load_candidate(conn,candidate.candidate_id)
            if stored != candidate:
                raise KnowledgeError('candidate differs from authoritative repository')

    def _active_publication(self, pub: Publication, now: datetime, actor: TrustedActor) -> bool:
        if self.storage:
            import psycopg
            try:
                with psycopg.connect(self.storage.connection_uri) as conn:
                    self.storage.set_session_identity(conn,actor)
                    stored = self.storage.load_publication(conn,pub.publication_id)
                if stored != pub:
                    return False
            except KnowledgeError:
                return False
        elif self._publications.get(pub.publication_id) != pub:
            return False
        if pub.publication_id in self._revoked or pub.valid_until <= now:
            return False
        try:
            self._validate(pub, now)
        except KnowledgeError:
            return False
        return True

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
        tenant = evidences[0].source.tenant_id
        purpose = evidences[0].source.purpose
        for ev in evidences:
            if ev.source.domain != self.domain or ev.source.tenant_id != tenant or ev.source.purpose != purpose:
                raise KnowledgeError("cross-domain evidence detected in ACL calculation")
            if effective_acl is None:
                effective_acl = set(ev.source.acl)
            else:
                effective_acl.intersection_update(ev.source.acl)

        if not effective_acl:
            raise KnowledgeError("empty ACL intersection: derived knowledge has no authorized audience")

        return frozenset(effective_acl)

    # -------------------------------------------------------------------------
    # Local (non-persistent) review bookkeeping for unit flows
    # -------------------------------------------------------------------------
    def approve_candidate(
        self,
        candidate: Candidate,
        reviewer: TrustedActor,
        role: Role,
        verification_ref: str,
        now: datetime | None = None,
    ) -> Candidate:
        """Record one verified review for non-persistent governance flows.

        The persisted two-reviewer approval table was removed with schema v2;
        durable governance mutations are recorded as single-admin actions. This
        in-memory bookkeeping remains only for callers without storage.
        """
        now = now or datetime.now(timezone.utc)
        self._validate(candidate, now)
        self._authorize(candidate, reviewer, role)
        self._stored_candidate(candidate,reviewer)
        if self.storage:
            raise KnowledgeError('persistent review approval requires the admin governance flow bound to schema v2')
        if role not in (Role.SECURITY_REVIEWER, Role.BUSINESS_REVIEWER) or not verification_ref.strip():
            raise KnowledgeError('review requires approved role and verification record')
        if candidate.state != CandidateState.PROPOSED:
            raise KnowledgeError(f"cannot approve candidate in state {candidate.state}")

        recorded_roles = self._approvals.setdefault(candidate.candidate_id, frozenset())
        recorded_reviewers = self._reviewers.setdefault(candidate.candidate_id, frozenset())
        if reviewer.subject_id in recorded_reviewers:
            raise KnowledgeError(f"reviewer {reviewer.subject_id} has already approved this candidate")
        if role in recorded_roles:
            raise KnowledgeError(f"role {role} has already been fulfilled for this candidate")
        updated_roles = frozenset((*recorded_roles, role))
        self._approvals[candidate.candidate_id] = updated_roles
        self._reviewers[candidate.candidate_id] = frozenset((*recorded_reviewers, reviewer.subject_id))

        new_state = CandidateState.APPROVED if updated_roles == {Role.SECURITY_REVIEWER, Role.BUSINESS_REVIEWER} else CandidateState.PROPOSED
        return Candidate(
            candidate_id=candidate.candidate_id,
            claim=candidate.claim,
            evidence=candidate.evidence,
            acl=candidate.acl,
            purpose=candidate.purpose,
            state=new_state,
            rejection_reason=candidate.rejection_reason,
        )

    def reject_candidate(
        self,
        candidate: Candidate,
        reviewer: TrustedActor,
        reason: str,
    ) -> Candidate:
        """Reject a candidate."""
        self._validate(candidate, datetime.now(timezone.utc))
        self._authorize(candidate, reviewer, Role.BUSINESS_REVIEWER)
        self._stored_candidate(candidate,reviewer)
        if candidate.state != CandidateState.PROPOSED:
            raise KnowledgeError('only proposed candidates can be rejected')
        if not reason.strip():
            raise KnowledgeError("rejection reason cannot be empty")
        if self.storage:
            import psycopg
            with psycopg.connect(self.storage.connection_uri) as conn:
                self.storage.set_session_identity(conn,reviewer)
                self.storage.reject_transactional(conn,candidate.candidate_id,reason)

        return Candidate(
            candidate_id=candidate.candidate_id,
            claim=candidate.claim,
            evidence=candidate.evidence,
            acl=candidate.acl,
            purpose=candidate.purpose,
            state=CandidateState.REJECTED,
            rejection_reason=reason,
        )

    def publish_candidate(
        self,
        candidate: Candidate,
        publisher: TrustedActor,
        valid_until: datetime,
        now: datetime | None = None,
    ) -> tuple[Publication, Candidate]:
        """Publish a verified candidate. Fails if the candidate is not active."""
        now = now or datetime.now(timezone.utc)
        self._validate(candidate, now)
        self._authorize(candidate, publisher, Role.PUBLISHER)
        self._stored_candidate(candidate,publisher)
        if candidate.state in (CandidateState.REJECTED, CandidateState.WITHDRAWN):
            raise KnowledgeError(f"candidate must be active to publish, got {candidate.state}")
        recorded = self._approvals.get(candidate.candidate_id, frozenset())
        if candidate.state != CandidateState.APPROVED or recorded != {Role.SECURITY_REVIEWER, Role.BUSINESS_REVIEWER}:
            raise KnowledgeError('publication requires verified distinct reviews')

        if now is None:
            now = datetime.now(timezone.utc)
        if valid_until <= now:
            raise KnowledgeError("publication valid_until must be strictly in the future")
        if candidate.claim.modality != Modality.ASSERTED or candidate.claim.predicate == Predicate.CO_OCCURS_WITH:
            raise KnowledgeError('only verified asserted business facts publish')
        if all(ev.source.source_kind == SourceKind.MODEL_OUTPUT for ev in candidate.evidence):
            raise KnowledgeError('model-only evidence cannot establish facts')
        if any(pub.candidate_id == candidate.candidate_id for pub in self._publications.values()):
            raise KnowledgeError('candidate already published or withdrawn')
        valid_until = min(valid_until, *(ev.source.retention_until for ev in candidate.evidence))

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
        )
        if self.storage:
            raise KnowledgeError('persistent publication requires the admin governance flow bound to schema v2')
        self._publications[pub_id] = publication
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
            if not self._active_publication(pub, now, consumer):
                continue
            # ACL Check: consumer must have access
            # consumer.subject_id or role-based acl
            if (consumer.tenant_id, consumer.domain) != (pub.claim.subject.tenant_id, self.domain) or pub.purpose not in consumer.purposes or consumer.subject_id not in pub.acl:
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
        *, consumer: TrustedActor,
    ) -> dict:
        """Compile active publications into a dictionary payload for compile_dictionary.

        Only approved/published entities are compiled. Expired/withdrawn items excluded.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        seen_entities: dict[str, str] = {}
        for pub in publications:
            if not self._active_publication(pub, now, consumer):
                continue
            if (consumer.tenant_id, consumer.domain) != (pub.claim.subject.tenant_id, self.domain) or consumer.subject_id not in pub.acl or pub.purpose not in consumer.purposes:
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
        self._authorize(publication, steward, Role.DATA_STEWARD)
        if not reason.strip():
            raise KnowledgeError("revocation reason cannot be empty")

        if now is None:
            now = datetime.now(timezone.utc)

        tombstone = Tombstone(
            publication_id=publication.publication_id,
            candidate_id=publication.candidate_id,
            tenant_id=publication.claim.subject.tenant_id,
            domain=self.domain,
            reason=reason,
            effective_at=now,
        )
        if self.storage:
            import psycopg
            with psycopg.connect(self.storage.connection_uri) as conn:
                self.storage.set_session_identity(conn,steward)
                self.storage.revoke_transactional(conn,tombstone)
        self._revoked.add(publication.publication_id)
        return tombstone

    def withdraw_source(self, source: Source, steward: TrustedActor, reason: str,
                        now: datetime | None = None) -> tuple[Tombstone, ...]:
        now = now or datetime.now(timezone.utc)
        if (source.tenant_id, source.domain) != (steward.tenant_id, steward.domain) or steward.domain != self.domain:
            raise KnowledgeError('steward scope mismatch')
        if Role.DATA_STEWARD not in steward.roles or steward.subject_id not in source.acl or source.purpose not in steward.purposes or not reason.strip():
            raise KnowledgeError('withdrawal requires authorized stewardship')
        if self.storage:
            import psycopg
            with psycopg.connect(self.storage.connection_uri) as conn:
                self.storage.set_session_identity(conn,steward)
                result = self.storage.invalidate_source(conn,source,reason,now)
            self._withdrawn_sources.add(source.key)
            return result
        self._withdrawn_sources.add(source.key)
        return tuple(self.revoke_publication(pub, steward, reason, now) for pub in self._publications.values()
                     if pub.publication_id not in self._revoked and any(ev.source.key == source.key for ev in pub.evidence))
