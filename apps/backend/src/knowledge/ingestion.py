"""Upstream standardized ingestion framework for external enterprise knowledge.

Defines the contract, validation models, and base importer abstractions for
integrating external structured master data, unstructured documents, and trusted tools.

NOTE: This module defines the architectural framework and TODO placeholders.
Concrete connector implementations and database pipeline execution are deferred
to subsequent milestones.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Mapping, Sequence
from uuid import UUID, uuid5, NAMESPACE_DNS

from knowledge.knowledge import (
    Entity,
    KnowledgeError,
    Modality,
    Polarity,
    Predicate,
    Role,
    Source,
    SourceKind,
)


class IngestionValidationSeverity(StrEnum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class IngestionValidationIssue:
    """A single schema, identity, or semantic constraint violation."""

    code: str
    message: str
    field_path: str = ""
    severity: IngestionValidationSeverity = IngestionValidationSeverity.ERROR


@dataclass(frozen=True)
class IngestionValidationReport:
    """Outcome of validating an ingestion batch prior to persistent storage."""

    is_valid: bool
    issues: tuple[IngestionValidationIssue, ...] = field(default_factory=tuple)

    @property
    def error_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == IngestionValidationSeverity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == IngestionValidationSeverity.WARNING)


@dataclass(frozen=True)
class RawEntityItem:
    """Standardized representation of an entity ingested from an upstream source."""

    name: str
    entity_type: str
    external_id: str | None = None
    aliases: tuple[str, ...] = field(default_factory=tuple)
    properties: Mapping[str, Any] = field(default_factory=dict)
    confidence: float = 1.0

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise KnowledgeError("entity name must not be blank")
        if not self.entity_type or not self.entity_type.strip():
            raise KnowledgeError("entity_type must not be blank")
        if not (0.0 <= self.confidence <= 1.0):
            raise KnowledgeError("confidence must be between 0.0 and 1.0")


@dataclass(frozen=True)
class RawRelationItem:
    """Standardized representation of a relation ingested from an upstream source."""

    subject_name_or_id: str
    predicate: str
    object_name_or_id: str
    polarity: Polarity = Polarity.POSITIVE
    modality: Modality = Modality.ASSERTED
    confidence: float = 1.0
    properties: Mapping[str, Any] = field(default_factory=dict)
    evidence_text: str | None = None
    evidence_start: int | None = None
    evidence_end: int | None = None

    def __post_init__(self) -> None:
        if not self.subject_name_or_id or not self.subject_name_or_id.strip():
            raise KnowledgeError("subject must not be blank")
        if not self.predicate or not self.predicate.strip():
            raise KnowledgeError("predicate must not be blank")
        if not self.object_name_or_id or not self.object_name_or_id.strip():
            raise KnowledgeError("object must not be blank")
        if not (0.0 <= self.confidence <= 1.0):
            raise KnowledgeError("confidence must be between 0.0 and 1.0")
        if (self.evidence_start is not None) ^ (self.evidence_end is not None):
            raise KnowledgeError("evidence span requires both start and end or neither")
        if self.evidence_start is not None and self.evidence_end is not None:
            if self.evidence_start < 0 or self.evidence_end <= self.evidence_start:
                raise KnowledgeError("evidence span must be a positive non-empty interval")


@dataclass(frozen=True)
class IngestionSourceMeta:
    """Authoritative metadata describing the origin of an ingestion batch."""

    tenant_id: str
    domain: str
    source_kind: SourceKind
    source_id: str
    version: str
    purpose: str
    acl: frozenset[str]
    observed_at: datetime
    retention_until: datetime
    author: str = "upstream_importer"

    def __post_init__(self) -> None:
        if not all((self.tenant_id, self.domain, self.source_id, self.version, self.purpose)):
            raise KnowledgeError("source metadata must define tenant, domain, source_id, version and purpose")
        if not isinstance(self.source_kind, SourceKind):
            raise KnowledgeError("source_kind must be a valid SourceKind enum")
        if not self.acl or any(not s.strip() for s in self.acl):
            raise KnowledgeError("source ACL must be a non-empty set of subject strings")
        if self.observed_at.tzinfo is None or self.retention_until.tzinfo is None:
            raise KnowledgeError("source timestamps must be timezone-aware")
        if self.retention_until <= self.observed_at:
            raise KnowledgeError("retention_until must be after observed_at")


@dataclass(frozen=True)
class IngestionBatch:
    """A complete payload of entities and relations to be ingested."""

    meta: IngestionSourceMeta
    entities: tuple[RawEntityItem, ...] = field(default_factory=tuple)
    relations: tuple[RawRelationItem, ...] = field(default_factory=tuple)

    @property
    def batch_size(self) -> int:
        return len(self.entities) + len(self.relations)


@dataclass(frozen=True)
class NormalizedKnowledgePayload:
    """Pre-processed entities and candidates ready for the governance repository."""

    source: Source
    entities: tuple[Entity, ...]
    raw_relations: tuple[RawRelationItem, ...]


@dataclass(frozen=True)
class IngestionReceipt:
    """Receipt returned after a batch has been committed or queued."""

    batch_id: UUID
    source_key: tuple[str, str, str, str]  # (tenant, domain, source_id, version)
    entities_count: int
    relations_count: int
    status: str
    receipt_time: datetime


class BaseKnowledgeImporter(ABC):
    """Abstract base class for all upstream enterprise knowledge importers.

    Subclasses implement source-specific ingestion for master data, documents,
    and external tools following the OpenSPG and DeepKE governance requirements.
    """

    def __init__(self, tenant_id: str, domain: str) -> None:
        self.tenant_id = tenant_id
        self.domain = domain

    @abstractmethod
    def validate_batch(self, batch: IngestionBatch) -> IngestionValidationReport:
        """Validate batch structure, types, and domain invariants."""

    @abstractmethod
    def normalize_batch(self, batch: IngestionBatch) -> NormalizedKnowledgePayload:
        """Derive deterministic identities, resolve aliases, and bind sources."""

    def ingest(self, batch: IngestionBatch) -> IngestionReceipt:
        """Execute persistent ingestion into the governance repository.

        TODO: Implement transactional database pipeline:
        1. Validate batch schema, entity uniqueness, and predicate domain/range.
        2. Resolve/derive stable UUID5 identifiers:
           derive_uuid5(tenant_id, domain, entity_type, entity_name)
        3. Register and bind alias mappings (Alias -> Canonical Entity).
        4. Insert or update Source record with strict ACL and retention policies.
        5. Convert RawRelationItem into Candidate rows in PROPOSED state.
        6. Commit in a single transaction and emit Outbox events for audit and AGE graph sync.
        """
        validation = self.validate_batch(batch)
        if not validation.is_valid:
            raise KnowledgeError(
                f"Ingestion batch validation failed with {validation.error_count} errors: "
                f"{[issue.message for issue in validation.issues if issue.severity == IngestionValidationSeverity.ERROR]}"
            )

        # Framework stub: persistence pipeline is deferred
        raise NotImplementedError(
            "TODO: Upstream standardized ingestion persistence pipeline is scheduled for implementation. "
            "Framework contracts and validation rules are defined."
        )


class MasterDataImporter(BaseKnowledgeImporter):
    """Importer for authoritative enterprise master data (e.g. ERP, CRM, MDM).

    - SourceKind: MASTER_DATA
    - Default confidence: 1.0 (Highest trust)
    - Entities typically have explicit external IDs and canonical names.
    """

    def validate_batch(self, batch: IngestionBatch) -> IngestionValidationReport:
        issues: list[IngestionValidationIssue] = []
        if batch.meta.source_kind != SourceKind.MASTER_DATA:
            issues.append(
                IngestionValidationIssue(
                    code="INVALID_SOURCE_KIND",
                    message=f"MasterDataImporter requires MASTER_DATA source_kind, got {batch.meta.source_kind}",
                    field_path="meta.source_kind",
                )
            )

        if not batch.entities:
            issues.append(
                IngestionValidationIssue(
                    code="EMPTY_ENTITIES",
                    message="Master data batch must contain at least one entity",
                    field_path="entities",
                )
            )

        return IngestionValidationReport(
            is_valid=not any(i.severity == IngestionValidationSeverity.ERROR for i in issues),
            issues=tuple(issues),
        )

    def normalize_batch(self, batch: IngestionBatch) -> NormalizedKnowledgePayload:
        # TODO: Implement master data deterministic identity derivation
        raise NotImplementedError("TODO: Master data normalization logic to be implemented.")


class DocumentKnowledgeImporter(BaseKnowledgeImporter):
    """Importer for unstructured documents (e.g. contracts, policies, specifications).

    - SourceKind: DOCUMENT
    - Requires character span tracking and content hash anchoring.
    - Uses DeepKE-inspired multi-stage pipeline for relation extraction.
    """

    def validate_batch(self, batch: IngestionBatch) -> IngestionValidationReport:
        issues: list[IngestionValidationIssue] = []
        if batch.meta.source_kind != SourceKind.DOCUMENT:
            issues.append(
                IngestionValidationIssue(
                    code="INVALID_SOURCE_KIND",
                    message=f"DocumentKnowledgeImporter requires DOCUMENT source_kind, got {batch.meta.source_kind}",
                    field_path="meta.source_kind",
                )
            )

        for idx, rel in enumerate(batch.relations):
            if rel.evidence_text is None or rel.evidence_start is None:
                issues.append(
                    IngestionValidationIssue(
                        code="MISSING_EVIDENCE_SPAN",
                        message=f"Document relation at index {idx} must provide evidence_text and evidence spans",
                        field_path=f"relations[{idx}].evidence",
                    )
                )

        return IngestionValidationReport(
            is_valid=not any(i.severity == IngestionValidationSeverity.ERROR for i in issues),
            issues=tuple(issues),
        )

    def normalize_batch(self, batch: IngestionBatch) -> NormalizedKnowledgePayload:
        # TODO: Implement document evidence anchoring and candidate synthesis
        raise NotImplementedError("TODO: Document normalization logic to be implemented.")


class TrustedToolImporter(BaseKnowledgeImporter):
    """Importer for facts produced by verified enterprise internal tools/APIs.

    - SourceKind: TRUSTED_TOOL
    - High trust with explicit purpose and caller identity tracking.
    """

    def validate_batch(self, batch: IngestionBatch) -> IngestionValidationReport:
        issues: list[IngestionValidationIssue] = []
        if batch.meta.source_kind != SourceKind.TRUSTED_TOOL:
            issues.append(
                IngestionValidationIssue(
                    code="INVALID_SOURCE_KIND",
                    message=f"TrustedToolImporter requires TRUSTED_TOOL source_kind, got {batch.meta.source_kind}",
                    field_path="meta.source_kind",
                )
            )

        return IngestionValidationReport(
            is_valid=not any(i.severity == IngestionValidationSeverity.ERROR for i in issues),
            issues=tuple(issues),
        )

    def normalize_batch(self, batch: IngestionBatch) -> NormalizedKnowledgePayload:
        # TODO: Implement tool output verification and attribute binding
        raise NotImplementedError("TODO: Trusted tool normalization logic to be implemented.")
