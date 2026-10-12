"""OpenSPG semantic property graph constraints, schema guard, and rule engine.

Implements Phase 3 requirements from docs/knowledge-graph-design.md:
1. PredicateSchema: Domain and Range strong type constraints, attribute schemas, and inverted predicates.
2. SchemaGuard: Type guard that marks invalid triples as illegal and blocks propagation.
3. MutualExclusionEngine: Positive/Negative mutual exclusion detection within time windows,
   marking disputed facts as DISPUTED and blocking automatic publication.
4. CoOccurrenceIsolator: Strict degradation of unlinked co-occurring entities to Predicate.CO_OCCURS_WITH.
5. EntityAliasManager & EntityResolver: Deterministic UUID5 identity derivation (NAMESPACE_DNS)
   and transitive alias chain resolution with merge tracking and historical rename audit.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Iterable, Mapping, Sequence, TYPE_CHECKING
from uuid import NAMESPACE_DNS, UUID, uuid5

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
    Publication,
)

if TYPE_CHECKING:
    import psycopg
    from knowledge.storage import PostgresKnowledgeStorage


def derive_entity_uuid(
    tenant_id: str, domain: str, entity_type: str, canonical_name: str
) -> UUID:
    """Derive authoritative deterministic UUID5 identifier for an entity.

    Formula from design spec §5.2:
    UUID5(NAMESPACE_DNS, tenant_id + ":" + domain + ":" + entity_type + ":" + canonical_name)
    """
    if not tenant_id or not domain or not entity_type or not canonical_name:
        raise KnowledgeError(
            "derive_entity_uuid requires non-empty tenant_id, domain, entity_type, and canonical_name"
        )
    key = f"{tenant_id}:{domain}:{entity_type}:{canonical_name}"
    return uuid5(NAMESPACE_DNS, key)


# -----------------------------------------------------------------------------
# 1. SPG Predicate Schema & Schema Guard
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class AttributeConstraint:
    """Constraint on an edge/relation attribute."""

    name: str
    attr_type: type | str
    required: bool = False
    description: str = ""


@dataclass(frozen=True)
class PredicateSchema:
    """SPG schema specification for a relation predicate.

    Enforces Domain (allowed subject entity types) and Range (allowed object
    entity types), attribute typing, and optional reciprocal predicate mapping.
    """

    predicate: str
    domain: tuple[str, ...]
    range: tuple[str, ...]
    attributes: Mapping[str, type | str] = field(default_factory=dict)
    inverted_predicate: str | None = None
    description: str = ""

    def __post_init__(self) -> None:
        if not self.predicate or not self.predicate.strip():
            raise KnowledgeError("predicate name must not be blank")
        if not self.domain:
            raise KnowledgeError(
                f"predicate '{self.predicate}' must define at least one domain entity type"
            )
        if not self.range:
            raise KnowledgeError(
                f"predicate '{self.predicate}' must define at least one range entity type"
            )


# Builtin standard predicate schemas defined in docs/knowledge-graph-design.md §5.1
BUILTIN_PREDICATE_SCHEMAS: dict[str, PredicateSchema] = {
    Predicate.SUPPLIES.value: PredicateSchema(
        predicate=Predicate.SUPPLIES.value,
        domain=("ORG",),
        range=("ORG",),
        attributes={
            "contract_id": "string",
            "amount": "float",
            "effective_year": "int",
        },
        inverted_predicate="supplied_by",
        description="Organization supplies products or services to another organization",
    ),
    "supplied_by": PredicateSchema(
        predicate="supplied_by",
        domain=("ORG",),
        range=("ORG",),
        attributes={
            "contract_id": "string",
            "amount": "float",
            "effective_year": "int",
        },
        inverted_predicate=Predicate.SUPPLIES.value,
        description="Organization is supplied by another organization",
    ),
    Predicate.WORKS_ON.value: PredicateSchema(
        predicate=Predicate.WORKS_ON.value,
        domain=("PERSON",),
        range=("PROJECT", "PRODUCT"),
        attributes={"role": "string", "since": "date"},
        description="Person works on a project or product",
    ),
    Predicate.OWNED_BY.value: PredicateSchema(
        predicate=Predicate.OWNED_BY.value,
        domain=("ORG", "PRODUCT", "PROJECT"),
        range=("ORG", "PERSON"),
        description="Entity ownership or parent organization relation",
    ),
    Predicate.PARTY_TO.value: PredicateSchema(
        predicate=Predicate.PARTY_TO.value,
        domain=("ORG", "PERSON"),
        range=("PROJECT", "CONTRACT", "AGREEMENT", "ORG"),
        description="Entity is a party to a contract, agreement, or initiative",
    ),
    Predicate.CO_OCCURS_WITH.value: PredicateSchema(
        predicate=Predicate.CO_OCCURS_WITH.value,
        domain=("*",),
        range=("*",),
        description="Fallback non-asserted co-occurrence relation between any entities",
    ),
}


class SchemaGuardViolation(KnowledgeError):
    """Raised when a relation triple or attribute set violates the SPG predicate schema."""

    def __init__(
        self,
        message: str,
        *,
        predicate: str = "",
        violation_type: str = "SCHEMA_VIOLATION",
    ) -> None:
        self.predicate = predicate
        self.violation_type = violation_type
        super().__init__(message)


class SchemaGuard:
    """Type guard for OpenSPG predicates, enforcing Domain and Range constraints."""

    def __init__(
        self,
        schemas: Iterable[PredicateSchema] | None = None,
        *,
        allow_unknown_predicates: bool = False,
    ) -> None:
        self._schemas: dict[str, PredicateSchema] = dict(BUILTIN_PREDICATE_SCHEMAS)
        if schemas:
            for s in schemas:
                self.register(s)
        self.allow_unknown_predicates = allow_unknown_predicates

    def register(self, schema: PredicateSchema) -> None:
        """Register or override a predicate schema."""
        self._schemas[schema.predicate] = schema

    def get_schema(self, predicate: str | Predicate) -> PredicateSchema | None:
        val = predicate.value if isinstance(predicate, Predicate) else str(predicate)
        return self._schemas.get(val)

    def validate_types(
        self,
        subject_type: str,
        predicate: str | Predicate,
        object_type: str,
        properties: Mapping[str, Any] | None = None,
    ) -> tuple[bool, str | None]:
        """Validate whether subject_type and object_type are allowed for predicate.

        Returns (True, None) on success or (False, reason) on failure.
        """
        pred_val = predicate.value if isinstance(predicate, Predicate) else str(predicate)
        schema = self.get_schema(pred_val)
        if schema is None:
            if self.allow_unknown_predicates:
                return True, None
            return (
                False,
                f"Unknown predicate '{pred_val}': not registered in SPG schema whitelist",
            )

        # Domain check
        if "*" not in schema.domain and subject_type not in schema.domain:
            return (
                False,
                f"Subject type '{subject_type}' violates domain of predicate '{pred_val}'; "
                f"expected one of {schema.domain}",
            )

        # Range check
        if "*" not in schema.range and object_type not in schema.range:
            return (
                False,
                f"Object type '{object_type}' violates range of predicate '{pred_val}'; "
                f"expected one of {schema.range}",
            )

        # Attribute validation (if properties supplied)
        if properties and schema.attributes:
            for attr_name, attr_val in properties.items():
                expected_type = schema.attributes.get(attr_name)
                if expected_type is not None and attr_val is not None:
                    if expected_type in ("int", int) and not isinstance(attr_val, int):
                        return (
                            False,
                            f"Attribute '{attr_name}' must be an integer, got {type(attr_val).__name__}",
                        )
                    if expected_type in ("float", float) and not isinstance(
                        attr_val, (int, float)
                    ):
                        return (
                            False,
                            f"Attribute '{attr_name}' must be numeric, got {type(attr_val).__name__}",
                        )
                    if expected_type in ("string", "str", str) and not isinstance(
                        attr_val, str
                    ):
                        return (
                            False,
                            f"Attribute '{attr_name}' must be a string, got {type(attr_val).__name__}",
                        )

        return True, None

    def guard_claim(
        self, claim: Claim, properties: Mapping[str, Any] | None = None
    ) -> None:
        """Enforce domain/range constraints on a Claim.

        Raises SchemaGuardViolation on failure.
        """
        ok, reason = self.validate_types(
            claim.subject.entity_type,
            claim.predicate,
            claim.object.entity_type,
            properties,
        )
        if not ok:
            pred_val = (
                claim.predicate.value
                if isinstance(claim.predicate, Predicate)
                else str(claim.predicate)
            )
            v_type = (
                "UNKNOWN_PREDICATE"
                if "Unknown predicate" in (reason or "")
                else (
                    "DOMAIN_MISMATCH"
                    if "violates domain" in (reason or "")
                    else "RANGE_MISMATCH"
                )
            )
            raise SchemaGuardViolation(
                f"SPG SchemaGuard blocked illegal triple ({claim.subject.entity_type}:{claim.subject.name}) "
                f"-[{pred_val}]-> ({claim.object.entity_type}:{claim.object.name}): {reason}",
                predicate=pred_val,
                violation_type=v_type,
            )

    def guard_candidate(self, candidate: Candidate) -> None:
        """Enforce domain/range constraints on a Candidate."""
        self.guard_claim(candidate.claim, candidate.properties)


# -----------------------------------------------------------------------------
# 2. Consistency & Mutual Exclusion Engine
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class TimeWindow:
    """Time window for a business observation or claim."""

    start: datetime | None = None
    end: datetime | None = None

    def overlaps(self, other: "TimeWindow") -> bool:
        """Determine if two time intervals overlap."""
        if self.start is None and self.end is None:
            return True
        if other.start is None and other.end is None:
            return True

        s1 = self.start or datetime.min.replace(tzinfo=timezone.utc)
        e1 = self.end or datetime.max.replace(tzinfo=timezone.utc)
        s2 = other.start or datetime.min.replace(tzinfo=timezone.utc)
        e2 = other.end or datetime.max.replace(tzinfo=timezone.utc)

        return max(s1, s2) <= min(e1, e2)


@dataclass(frozen=True)
class ConflictReport:
    """Report describing whether a conflict or mutual exclusion was detected."""

    has_conflict: bool
    conflict_type: str | None = None
    conflicting_id: str | None = None
    detail: str | None = None


class MutualExclusionEngine:
    """Consistency & Mutual Exclusion Rule Checker.

    Detects positive-negative fact mutual exclusion for the same subject/object
    pair in overlapping time windows, marking conflicting facts as DISPUTED and
    blocking automatic publishing.
    """

    def __init__(self, schema_guard: SchemaGuard | None = None) -> None:
        self.guard = schema_guard or SchemaGuard()

    @staticmethod
    def extract_time_window(
        candidate_or_evidence: Candidate | Publication | Evidence | Sequence[Evidence] | None,
    ) -> TimeWindow:
        """Derive the effective observation/validity time window."""
        if candidate_or_evidence is None:
            return TimeWindow()

        if isinstance(candidate_or_evidence, Publication):
            return TimeWindow(
                start=candidate_or_evidence.published_at,
                end=candidate_or_evidence.valid_until,
            )

        if isinstance(candidate_or_evidence, Candidate):
            props = candidate_or_evidence.properties or {}
            # Explicit window in properties
            if "time_window" in props and isinstance(props["time_window"], tuple):
                tw = props["time_window"]
                return TimeWindow(start=tw[0], end=tw[1])
            # Or derived from evidence
            evidences = candidate_or_evidence.evidence
            if evidences:
                starts = [e.source.observed_at for e in evidences if e.source]
                ends = [e.source.retention_until for e in evidences if e.source]
                if starts and ends:
                    return TimeWindow(start=min(starts), end=max(ends))
            return TimeWindow()

        if isinstance(candidate_or_evidence, Evidence):
            return TimeWindow(
                start=candidate_or_evidence.source.observed_at,
                end=candidate_or_evidence.source.retention_until,
            )

        if isinstance(candidate_or_evidence, (list, tuple)):
            starts = [e.source.observed_at for e in candidate_or_evidence if e.source]
            ends = [e.source.retention_until for e in candidate_or_evidence if e.source]
            if starts and ends:
                return TimeWindow(start=min(starts), end=max(ends))

        return TimeWindow()

    def check_conflict(
        self,
        target: Candidate | Claim,
        existing_items: Sequence[Candidate | Claim | Publication],
    ) -> ConflictReport:
        """Check if target creates a positive/negative mutual exclusion conflict.

        A conflict occurs when:
        1. Same subject and object (or reciprocal subject and object with inverted predicate);
        2. Same predicate (or reciprocal predicate);
        3. Opposing polarity (POSITIVE vs NEGATIVE);
        4. Overlapping time window.
        """
        target_claim = target.claim if isinstance(target, Candidate) else target
        target_window = (
            self.extract_time_window(target)
            if isinstance(target, Candidate)
            else TimeWindow()
        )

        t_sub_id = target_claim.subject.entity_id
        t_obj_id = target_claim.object.entity_id
        t_pred = (
            target_claim.predicate.value
            if isinstance(target_claim.predicate, Predicate)
            else str(target_claim.predicate)
        )
        t_polarity = target_claim.polarity

        schema = self.guard.get_schema(t_pred)
        inv_pred = schema.inverted_predicate if schema else None

        for item in existing_items:
            if isinstance(item, (Candidate, Publication)):
                item_claim = item.claim
                item_id = str(
                    item.candidate_id
                    if isinstance(item, Candidate)
                    else item.publication_id
                )
                item_window = self.extract_time_window(item)
            else:
                item_claim = item
                item_id = "claim"
                item_window = TimeWindow()

            i_sub_id = item_claim.subject.entity_id
            i_obj_id = item_claim.object.entity_id
            i_pred = (
                item_claim.predicate.value
                if isinstance(item_claim.predicate, Predicate)
                else str(item_claim.predicate)
            )
            i_polarity = item_claim.polarity

            # Case 1: Direct same direction (Sub -> Pred -> Obj)
            is_direct_match = (
                t_sub_id == i_sub_id and t_obj_id == i_obj_id and t_pred == i_pred
            )

            # Case 2: Inverted match (Obj -> InvPred -> Sub)
            is_inverted_match = (
                inv_pred is not None
                and t_sub_id == i_obj_id
                and t_obj_id == i_sub_id
                and i_pred == inv_pred
            )

            if is_direct_match or is_inverted_match:
                # Check for polar opposition
                if (
                    (t_polarity == Polarity.POSITIVE and i_polarity == Polarity.NEGATIVE)
                    or (
                        t_polarity == Polarity.NEGATIVE
                        and i_polarity == Polarity.POSITIVE
                    )
                ):
                    # Check time window
                    if target_window.overlaps(item_window):
                        return ConflictReport(
                            has_conflict=True,
                            conflict_type="POLARITY_MUTUAL_EXCLUSION",
                            conflicting_id=item_id,
                            detail=(
                                f"Positive/Negative mutual exclusion conflict between "
                                f"({target_claim.subject.name})-[{t_pred}:{t_polarity.value}]->({target_claim.object.name}) "
                                f"and opposing existing fact {item_id} [{i_pred}:{i_polarity.value}]"
                            ),
                        )

        return ConflictReport(has_conflict=False)

    def evaluate_and_tag(
        self,
        candidate: Candidate,
        existing_items: Sequence[Candidate | Claim | Publication],
    ) -> Candidate:
        """Evaluate candidate and tag as DISPUTED if mutual exclusion detected."""
        conflict = self.check_conflict(candidate, existing_items)
        if conflict.has_conflict:
            return replace(
                candidate,
                state=CandidateState.DISPUTED,
                rejection_reason=f"DISPUTED: {conflict.detail}",
            )
        return candidate


# -----------------------------------------------------------------------------
# 3. Entity Co-occurrence Isolation
# -----------------------------------------------------------------------------

# Predicate keywords/cues in Chinese enterprise texts indicating true assertions
_EXPLICIT_PREDICATE_CUES: dict[str, frozenset[str]] = {
    Predicate.SUPPLIES.value: frozenset(
        {
            "采购",
            "供应",
            "供货",
            "订购",
            "购买",
            "购入",
            "销售给",
            "订购了",
            "供求",
            "交付",
            "协议供货",
            "中标",
            "入围",
        }
    ),
    Predicate.WORKS_ON.value: frozenset(
        {
            "任职",
            "负责",
            "担任",
            "主导",
            "开发",
            "研发",
            "主持",
            "参研",
            "工作于",
            "加入",
            "首席",
            "架构师",
            "经理",
        }
    ),
    Predicate.OWNED_BY.value: frozenset(
        {
            "控股",
            "全资拥有",
            "归属",
            "所属",
            "母公司",
            "旗下",
            "全资子公司",
            "持股",
            "并购",
            "收购",
        }
    ),
    Predicate.PARTY_TO.value: frozenset(
        {
            "签署",
            "签订",
            "缔约",
            "参与",
            "共同发起",
            "联合声明",
            "达成协议",
            "合作协议",
        }
    ),
}


class CoOccurrenceIsolator:
    """Enforces Co-occurrence Isolation principle (Design spec §5.3).

    Multiple entities co-occurring in the same text paragraph without explicit
    verbal syntactic links are strictly degraded to Predicate.CO_OCCURS_WITH,
    and prohibited from being promoted to supplies or ownership relations.
    """

    def __init__(
        self, explicit_cues: Mapping[str, frozenset[str]] | None = None
    ) -> None:
        self.cues = dict(_EXPLICIT_PREDICATE_CUES)
        if explicit_cues:
            self.cues.update(explicit_cues)

    def is_co_occurrence_only(
        self,
        text: str,
        subject_name: str,
        object_name: str,
        predicate: Predicate | str,
    ) -> bool:
        """Determine whether the relation lacks explicit syntactic cues."""
        pred_val = predicate.value if isinstance(predicate, Predicate) else str(predicate)
        if pred_val == Predicate.CO_OCCURS_WITH.value:
            return False

        cues = self.cues.get(pred_val)
        if not cues:
            return False

        s_idx = text.find(subject_name)
        o_idx = text.find(object_name)
        if s_idx < 0 or o_idx < 0:
            return True

        # Check the text window surrounding or between the entities
        left = max(0, min(s_idx, o_idx) - 10)
        right = min(len(text), max(s_idx + len(subject_name), o_idx + len(object_name)) + 10)
        span_text = text[left:right]

        # If none of the explicit cues appear in the span, it is only co-occurrence
        has_cue = any(cue in span_text for cue in cues)
        return not has_cue

    def isolate(self, candidate: Candidate, text: str) -> Candidate:
        """Degrade candidate to Predicate.CO_OCCURS_WITH if syntactic link is missing."""
        if candidate.claim.predicate == Predicate.CO_OCCURS_WITH:
            return candidate

        if self.is_co_occurrence_only(
            text,
            candidate.claim.subject.name,
            candidate.claim.object.name,
            candidate.claim.predicate,
        ):
            degraded_claim = replace(candidate.claim, predicate=Predicate.CO_OCCURS_WITH)
            return replace(candidate, claim=degraded_claim)

        return candidate


# -----------------------------------------------------------------------------
# 4. Entity Resolution & Alias Chain Manager
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class AliasRecord:
    """Record linking an alias name to canonical entity identity."""

    tenant_id: str
    domain: str
    alias_name: str
    canonical_name: str
    entity_type: str
    canonical_id: UUID
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


@dataclass(frozen=True)
class AliasHistoryRecord:
    """Historical record of an entity rename or alias merge."""

    previous_name: str
    new_name: str
    entity_type: str
    changed_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    reason: str = ""


class EntityAliasManager:
    """Manages alias-to-canonical chains, merges, and historical renames."""

    def __init__(self) -> None:
        # (tenant_id, domain) -> {alias_name: AliasRecord}
        self._aliases: dict[tuple[str, str], dict[str, AliasRecord]] = {}
        # (tenant_id, domain) -> list[AliasHistoryRecord]
        self._history: dict[tuple[str, str], list[AliasHistoryRecord]] = {}

    def register_alias(
        self,
        tenant_id: str,
        domain: str,
        alias_name: str,
        canonical_name: str,
        entity_type: str,
        *,
        canonical_id: UUID | None = None,
    ) -> AliasRecord:
        """Register an alias mapping towards a canonical name."""
        if not alias_name or not canonical_name:
            raise KnowledgeError("alias_name and canonical_name must not be empty")

        key = (tenant_id, domain)
        if key not in self._aliases:
            self._aliases[key] = {}

        cid = canonical_id or derive_entity_uuid(
            tenant_id, domain, entity_type, canonical_name
        )
        rec = AliasRecord(
            tenant_id=tenant_id,
            domain=domain,
            alias_name=alias_name,
            canonical_name=canonical_name,
            entity_type=entity_type,
            canonical_id=cid,
        )
        self._aliases[key][alias_name] = rec
        return rec

    def resolve_canonical_name(
        self, tenant_id: str, domain: str, name: str
    ) -> str:
        """Trace alias chain transitively from alias to canonical name with loop prevention."""
        key = (tenant_id, domain)
        mapping = self._aliases.get(key, {})

        curr = name
        visited: set[str] = set()

        while curr in mapping and curr not in visited:
            visited.add(curr)
            curr = mapping[curr].canonical_name

        return curr

    def merge_aliases(
        self,
        tenant_id: str,
        domain: str,
        canonical_name: str,
        aliases: Sequence[str],
        entity_type: str,
    ) -> list[AliasRecord]:
        """Merge a sequence of aliases into a single canonical target."""
        cid = derive_entity_uuid(tenant_id, domain, entity_type, canonical_name)
        records: list[AliasRecord] = []
        for alias in aliases:
            if alias != canonical_name:
                rec = self.register_alias(
                    tenant_id,
                    domain,
                    alias,
                    canonical_name,
                    entity_type,
                    canonical_id=cid,
                )
                records.append(rec)
        return records

    def record_rename(
        self,
        tenant_id: str,
        domain: str,
        old_canonical: str,
        new_canonical: str,
        entity_type: str,
        reason: str = "",
    ) -> None:
        """Record an authoritative entity rename, rewiring alias chains."""
        key = (tenant_id, domain)
        if key not in self._history:
            self._history[key] = []

        now = datetime.now(timezone.utc)
        self._history[key].append(
            AliasHistoryRecord(
                previous_name=old_canonical,
                new_name=new_canonical,
                entity_type=entity_type,
                changed_at=now,
                reason=reason,
            )
        )

        new_id = derive_entity_uuid(tenant_id, domain, entity_type, new_canonical)

        # Wire old canonical name as an alias pointing to new canonical
        self.register_alias(
            tenant_id,
            domain,
            old_canonical,
            new_canonical,
            entity_type,
            canonical_id=new_id,
        )

        # Rewire all existing aliases pointing to old_canonical to point directly to new_canonical
        if key in self._aliases:
            for alias_name, rec in list(self._aliases[key].items()):
                if rec.canonical_name == old_canonical:
                    self._aliases[key][alias_name] = AliasRecord(
                        tenant_id=tenant_id,
                        domain=domain,
                        alias_name=alias_name,
                        canonical_name=new_canonical,
                        entity_type=entity_type,
                        canonical_id=new_id,
                        created_at=rec.created_at,
                    )

    def get_rename_history(
        self, tenant_id: str, domain: str
    ) -> tuple[AliasHistoryRecord, ...]:
        """Retrieve rename history for a tenant domain."""
        return tuple(self._history.get((tenant_id, domain), []))

    def resolve_entity(
        self, tenant_id: str, domain: str, mention_name: str, entity_type: str
    ) -> Entity:
        """Resolve mention to canonical Entity with authoritative UUID5."""
        canon = self.resolve_canonical_name(tenant_id, domain, mention_name)
        cid = derive_entity_uuid(tenant_id, domain, entity_type, canon)
        return Entity(
            entity_id=cid,
            tenant_id=tenant_id,
            domain=domain,
            entity_type=entity_type,
            name=canon,
        )

    def sync_to_storage(
        self,
        conn: psycopg.Connection,
        storage: PostgresKnowledgeStorage,
        tenant_id: str,
        domain: str,
    ) -> int:
        """Persist in-memory alias mappings for a scope to database storage."""
        key = (tenant_id, domain)
        mapping = self._aliases.get(key, {})
        count = 0
        for rec in mapping.values():
            storage.save_entity_alias(
                conn,
                tenant_id=rec.tenant_id,
                domain=rec.domain,
                alias_name=rec.alias_name,
                canonical_name=rec.canonical_name,
                entity_type=rec.entity_type,
                canonical_id=rec.canonical_id,
            )
            count += 1
        return count

    def load_from_storage(
        self,
        conn: psycopg.Connection,
        storage: PostgresKnowledgeStorage,
        tenant_id: str,
        domain: str,
    ) -> int:
        """Load persisted alias mappings from database storage into memory."""
        rows = storage.list_entity_aliases(conn, tenant_id, domain)
        for r in rows:
            cid = r["canonical_id"]
            if isinstance(cid, str):
                cid = UUID(cid)
            self.register_alias(
                tenant_id=r["tenant_id"],
                domain=r["domain"],
                alias_name=r["alias_name"],
                canonical_name=r["canonical_name"],
                entity_type=r["entity_type"],
                canonical_id=cid,
            )
        return len(rows)


class EntityResolver:
    """Unified entity resolution coordinator providing deterministic identity derivation."""

    def __init__(self, alias_manager: EntityAliasManager | None = None) -> None:
        self.alias_manager = alias_manager or EntityAliasManager()

    def resolve(
        self, tenant_id: str, domain: str, name: str, entity_type: str
    ) -> Entity:
        """Resolve a raw or alias mention to its canonical Entity."""
        return self.alias_manager.resolve_entity(tenant_id, domain, name, entity_type)

    def derive_id(
        self, tenant_id: str, domain: str, entity_type: str, canonical_name: str
    ) -> UUID:
        """Derive deterministic UUID5 directly."""
        return derive_entity_uuid(tenant_id, domain, entity_type, canonical_name)
