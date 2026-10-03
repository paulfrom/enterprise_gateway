"""In-memory knowledge domain prototype; no persistence, collection, or IAM.

Callers must authenticate identities and verify source metadata before constructing
these contracts. Real entity names and relation claims remain sensitive data.
Publication requires two distinct reviewers; consumers must apply tombstones.
"""

from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4


class KnowledgeError(ValueError):
    """A domain or authorization invariant was violated."""


class SourceKind(StrEnum):
    MASTER_DATA = "master_data"
    TRUSTED_TOOL = "trusted_tool"
    DOCUMENT = "document"
    USER_ASSERTION = "user_assertion"
    MODEL_OUTPUT = "model_output"


class Predicate(StrEnum):
    SUPPLIES = "supplies"
    OWNED_BY = "owned_by"
    PARTY_TO = "party_to"
    WORKS_ON = "works_on"
    CO_OCCURS_WITH = "co_occurs_with"


class Polarity(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"


class Modality(StrEnum):
    ASSERTED = "asserted"
    HYPOTHETICAL = "hypothetical"
    QUESTION = "question"


class CandidateState(StrEnum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    PUBLISHED = "published"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"


class Role(StrEnum):
    SECURITY_REVIEWER = "security_reviewer"
    BUSINESS_REVIEWER = "business_reviewer"
    PUBLISHER = "publisher"
    DATA_STEWARD = "data_steward"


def _time(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise KnowledgeError("timestamps must include a timezone")


@dataclass(frozen=True)
class TrustedActor:
    """An authenticated upstream identity, never values copied from user text."""

    subject_id: str
    tenant_id: str
    domain: str
    roles: frozenset[Role]
    purposes: frozenset[str]

    def __post_init__(self) -> None:
        if not all((self.subject_id, self.tenant_id, self.domain)):
            raise KnowledgeError("trusted identity requires a subject and scope")
        if not isinstance(self.roles, frozenset) or any(not isinstance(role, Role) for role in self.roles):
            raise KnowledgeError("trusted roles must be a typed immutable set")
        if not isinstance(self.purposes, frozenset) or any(not purpose for purpose in self.purposes):
            raise KnowledgeError("authorized purposes must be an immutable set")


@dataclass(frozen=True)
class Source:
    tenant_id: str
    domain: str
    source_id: str
    version: str
    source_kind: SourceKind
    acl: frozenset[str]
    purpose: str
    observed_at: datetime
    retention_until: datetime

    def __post_init__(self) -> None:
        _time(self.observed_at)
        _time(self.retention_until)
        if not all((self.tenant_id, self.domain, self.source_id, self.version, self.purpose)):
            raise KnowledgeError("source identity and purpose are required")
        if not isinstance(self.source_kind, SourceKind):
            raise KnowledgeError("source_kind must be typed")
        if not isinstance(self.acl, frozenset) or not self.acl or any(not s for s in self.acl):
            raise KnowledgeError("source ACL must be a nonempty immutable subject set")
        if self.retention_until <= self.observed_at:
            raise KnowledgeError("retention must end after observation")

    @property
    def key(self) -> tuple[str, str, str, str]:
        return self.tenant_id, self.domain, self.source_id, self.version


@dataclass(frozen=True)
class Evidence:
    source: Source
    content_sha256: str
    start: int
    end: int

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise KnowledgeError("evidence uses a nonempty half-open character span")
        if len(self.content_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.content_sha256):
            raise KnowledgeError("evidence digest must be lowercase SHA-256 hex")

    @property
    def key(self) -> tuple:
        return (*self.source.key, self.start, self.end)


@dataclass(frozen=True)
class Entity:
    """An assigned stable UUID; names and aliases never define identity."""

    entity_id: UUID
    tenant_id: str
    domain: str
    entity_type: str
    name: str

    def __post_init__(self) -> None:
        if not isinstance(self.entity_id, UUID) or not all((self.tenant_id, self.domain, self.entity_type, self.name)):
            raise KnowledgeError("entity requires a stable UUID, scope, type, and name")


@dataclass(frozen=True)
class Claim:
    subject: Entity
    predicate: Predicate
    object: Entity
    polarity: Polarity = Polarity.POSITIVE
    modality: Modality = Modality.ASSERTED

    def __post_init__(self) -> None:
        if (self.subject.tenant_id, self.subject.domain) != (self.object.tenant_id, self.object.domain):
            raise KnowledgeError("cross-scope entity relations are forbidden")
        if not isinstance(self.predicate, Predicate) or not isinstance(self.polarity, Polarity) or not isinstance(self.modality, Modality):
            raise KnowledgeError("predicate, polarity, and modality must be typed")

    @property
    def key(self) -> tuple:
        return (self.subject.tenant_id, self.subject.domain, str(self.subject.entity_id),
                self.predicate.value, str(self.object.entity_id), self.polarity.value,
                self.modality.value)


@dataclass(frozen=True)
class Approval:
    reviewer_id: str
    role: Role
    verification_ref: str
    approved_at: datetime


@dataclass(frozen=True)
class Candidate:
    candidate_id: UUID
    claim: Claim
    evidence: tuple[Evidence, ...]
    acl: frozenset[str]
    purpose: str
    state: CandidateState = CandidateState.PROPOSED
    approvals: tuple[Approval, ...] = ()
    rejection_reason: str | None = None

    @property
    def independent_source_count(self) -> int:
        return len({item.source.key for item in self.evidence})


@dataclass(frozen=True)
class Publication:
    publication_id: UUID
    candidate_id: UUID
    claim: Claim
    evidence: tuple[Evidence, ...]
    acl: frozenset[str]
    purpose: str
    published_at: datetime
    valid_until: datetime


@dataclass(frozen=True)
class Tombstone:
    publication_id: UUID
    candidate_id: UUID
    tenant_id: str
    domain: str
    reason: str
    effective_at: datetime


class KnowledgeLedger:
    """Single-process synthetic verification core; not a durable repository.

    Each proposal has an immutable evidence set. Retries of the same observation
    set return its original candidate and cannot increase source counts. Digests
    describe evidence; this core cannot verify unseen source content or signatures.
    """

    def __init__(self) -> None:
        self._candidates: dict[UUID, Candidate] = {}
        self._proposal_keys: dict[tuple, UUID] = {}
        self._observations: dict[tuple, Evidence] = {}
        self._sources: dict[tuple, Source] = {}
        self._withdrawn_sources: set[tuple] = set()
        self._publications: dict[UUID, Publication] = {}
        self._tombstones: list[Tombstone] = []

    @property
    def tombstones(self) -> tuple[Tombstone, ...]:
        return tuple(self._tombstones)

    def _candidate(self, candidate_id: UUID) -> Candidate:
        candidate = self._candidates.get(candidate_id)
        if candidate is None:
            raise KnowledgeError("unknown candidate")
        return candidate

    def _publication(self, publication_id: UUID) -> Publication:
        publication = self._publications.get(publication_id)
        if publication is None:
            raise KnowledgeError("unknown publication")
        return publication

    def propose(self, claim: Claim, evidence: tuple[Evidence, ...], now: datetime) -> Candidate:
        _time(now)
        if not evidence:
            raise KnowledgeError("a candidate requires evidence")
        unique: dict[tuple, Evidence] = {}
        source_versions: dict[tuple, Source] = {}
        for item in evidence:
            source = item.source
            if (source.tenant_id, source.domain) != (claim.subject.tenant_id, claim.subject.domain):
                raise KnowledgeError("evidence must match the claim scope")
            if source.observed_at > now or source.retention_until <= now or source.key in self._withdrawn_sources:
                raise KnowledgeError("evidence is future-dated, expired, or withdrawn")
            prior_source = source_versions.get(source.key, self._sources.get(source.key))
            if prior_source is not None and prior_source != source:
                raise KnowledgeError("source metadata changes require a new version")
            observation_key = (item.key, claim.key)
            prior = unique.get(item.key, self._observations.get(observation_key))
            if prior is not None and prior != item:
                raise KnowledgeError("conflicting evidence for the same observation")
            source_versions[source.key] = source
            unique[item.key] = item
        items = tuple(unique[key] for key in sorted(unique))
        purposes = {item.source.purpose for item in items}
        acl = frozenset.intersection(*(item.source.acl for item in items))
        if len(purposes) != 1 or not acl:
            raise KnowledgeError("evidence needs one purpose and a nonempty ACL intersection")
        proposal_key = (claim.key, tuple(item.key for item in items))
        if proposal_key in self._proposal_keys:
            existing = self._candidates[self._proposal_keys[proposal_key]]
            if existing.claim != claim:
                raise KnowledgeError("retry changed immutable claim metadata")
            return existing
        candidate = Candidate(uuid4(), claim, items, acl, purposes.pop())
        self._sources.update(source_versions)
        self._observations.update({(item.key, claim.key): item for item in items})
        self._candidates[candidate.candidate_id] = candidate
        self._proposal_keys[proposal_key] = candidate.candidate_id
        return candidate

    def _live(self, candidate: Candidate, now: datetime) -> None:
        _time(now)
        if candidate.state in (CandidateState.REJECTED, CandidateState.WITHDRAWN):
            raise KnowledgeError("candidate is inactive")
        if any(item.source.observed_at > now or item.source.retention_until <= now or item.source.key in self._withdrawn_sources
               for item in candidate.evidence):
            raise KnowledgeError("candidate evidence is future-dated, expired, or withdrawn")
        if any(approval.approved_at > now for approval in candidate.approvals):
            raise KnowledgeError("command predates an existing review")

    def _authorize(self, candidate: Candidate, actor: TrustedActor, role: Role) -> None:
        if (actor.tenant_id, actor.domain) != (candidate.claim.subject.tenant_id, candidate.claim.subject.domain):
            raise KnowledgeError("actor scope mismatch")
        if role not in actor.roles or actor.subject_id not in candidate.acl or candidate.purpose not in actor.purposes:
            raise KnowledgeError("actor lacks role, source access, or purpose authorization")

    def approve(self, candidate_id: UUID, actor: TrustedActor, role: Role,
                verification_ref: str, now: datetime) -> Candidate:
        candidate = self._candidate(candidate_id)
        self._live(candidate, now)
        if candidate.state != CandidateState.PROPOSED:
            raise KnowledgeError("only proposed candidates accept reviews")
        if role not in (Role.SECURITY_REVIEWER, Role.BUSINESS_REVIEWER):
            raise KnowledgeError("a security or business review is required")
        self._authorize(candidate, actor, role)
        if not verification_ref.strip():
            raise KnowledgeError("review requires an external verification record")
        if any(review.reviewer_id == actor.subject_id or review.role == role for review in candidate.approvals):
            raise KnowledgeError("reviews require distinct people and distinct roles")
        approvals = (*candidate.approvals, Approval(actor.subject_id, role, verification_ref, now))
        candidate = replace(candidate, approvals=approvals,
                            state=CandidateState.APPROVED if len(approvals) == 2 else CandidateState.PROPOSED)
        self._candidates[candidate_id] = candidate
        return candidate

    def reject(self, candidate_id: UUID, actor: TrustedActor, reason: str, now: datetime) -> Candidate:
        candidate = self._candidate(candidate_id)
        self._live(candidate, now)
        if candidate.state != CandidateState.PROPOSED or not reason.strip():
            raise KnowledgeError("only proposed candidates can be rejected with a reason")
        self._authorize(candidate, actor, Role.BUSINESS_REVIEWER)
        candidate = replace(candidate, state=CandidateState.REJECTED, rejection_reason=reason)
        self._candidates[candidate_id] = candidate
        return candidate

    def publish(self, candidate_id: UUID, actor: TrustedActor, now: datetime) -> Publication:
        candidate = self._candidate(candidate_id)
        self._live(candidate, now)
        self._authorize(candidate, actor, Role.PUBLISHER)
        if candidate.state != CandidateState.APPROVED:
            raise KnowledgeError("publication requires two verified approvals")
        if candidate.claim.predicate == Predicate.CO_OCCURS_WITH or candidate.claim.modality != Modality.ASSERTED:
            raise KnowledgeError("co-occurrence and hypothetical content remain candidates")
        if all(item.source.source_kind == SourceKind.MODEL_OUTPUT for item in candidate.evidence):
            raise KnowledgeError("model-only evidence cannot establish a published claim")
        publication = Publication(uuid4(), candidate_id, candidate.claim, candidate.evidence,
                                  candidate.acl, candidate.purpose, now,
                                  min(item.source.retention_until for item in candidate.evidence))
        self._publications[publication.publication_id] = publication
        self._candidates[candidate_id] = replace(candidate, state=CandidateState.PUBLISHED)
        return publication

    def read_publication(self, publication_id: UUID, actor: TrustedActor, now: datetime) -> Publication:
        publication = self._publication(publication_id)
        candidate = self._candidate(publication.candidate_id)
        self._live(candidate, now)
        if (actor.tenant_id, actor.domain) != (candidate.claim.subject.tenant_id, candidate.claim.subject.domain):
            raise KnowledgeError("reader scope mismatch")
        if actor.subject_id not in publication.acl or publication.purpose not in actor.purposes:
            raise KnowledgeError("reader lacks source access or purpose authorization")
        return publication

    def _invalidate(self, source_keys: set[tuple], reason: str, now: datetime) -> tuple[Tombstone, ...]:
        created = []
        for candidate_id, candidate in tuple(self._candidates.items()):
            if candidate.state == CandidateState.WITHDRAWN or not any(item.source.key in source_keys for item in candidate.evidence):
                continue
            self._candidates[candidate_id] = replace(candidate, state=CandidateState.WITHDRAWN)
            for publication in self._publications.values():
                if publication.candidate_id == candidate_id:
                    tombstone = Tombstone(publication.publication_id, candidate_id,
                                          candidate.claim.subject.tenant_id, candidate.claim.subject.domain,
                                          reason, now)
                    self._tombstones.append(tombstone)
                    created.append(tombstone)
        return tuple(created)

    def withdraw_source(self, source_id: str, version: str, actor: TrustedActor,
                        reason: str, now: datetime) -> tuple[Tombstone, ...]:
        _time(now)
        key = (actor.tenant_id, actor.domain, source_id, version)
        source = self._sources.get(key)
        if source is None:
            raise KnowledgeError("unknown source")
        if Role.DATA_STEWARD not in actor.roles or actor.subject_id not in source.acl or source.purpose not in actor.purposes or not reason.strip():
            raise KnowledgeError("source withdrawal requires authorized stewardship and a reason")
        self._withdrawn_sources.add(key)
        return self._invalidate({key}, reason, now)

    def expire(self, now: datetime) -> tuple[Tombstone, ...]:
        """Internal scheduler command; downstream delivery is outside this core."""
        _time(now)
        expired = {key for key, source in self._sources.items() if source.retention_until <= now}
        return self._invalidate(expired, "retention_expired", now)
