"""Minimal extractable observation, serialized only for encrypted knowledge spool.

Default collection and reading authorization are separate. The event contains a
bounded input fragment, exact source coordinates and authenticated governance
metadata; ordinary logs must never serialize it. Missing reliable source identity
cannot establish independent evidence, even when a fragment can be collected.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import Any, Iterable, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_serializer, field_validator, model_validator

from infra.errors import SafetyCode, SafetyError
from knowledge.knowledge import SourceKind
from protocol.identity import UnverifiedSourceContext, validate_request_authorization

__all__ = [
    "EvidenceRef",
    "ObservationEvent",
    "build_observation_event",
    "build_gateway_observation",
    "serialize_event",
    "event_sha256",
]

_SHA256_HEX_LEN = 64


class EvidenceRef(BaseModel):
    """Minimal evidence pointer: content digest + character offset in original source."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    digest: str
    offset: int = Field(ge=0)

    @field_validator("digest")
    @classmethod
    def _sha256_hex(cls, value: str) -> str:
        if len(value) != _SHA256_HEX_LEN or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("digest must be lowercase SHA-256 hex")
        return value


class ObservationMention(BaseModel):
    model_config = ConfigDict(extra='forbid',frozen=True,strict=True)
    name: str = Field(min_length=1,repr=False)
    entity_type: str = Field(min_length=1)
    start: int = Field(ge=0)
    end: int = Field(gt=0)


class ObservationEvent(BaseModel):
    """Minimal governed observation; with bounded encrypted evidence and source access scope."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    tenant: str
    domain: str
    source_id: str
    source_version: str
    source_kind: SourceKind
    evidence_ref: EvidenceRef
    observed_at: datetime
    purpose: str
    retention_policy: str
    acl: frozenset[str] = Field(min_length=1)
    extraction_version: str
    evidence_text: str = Field(min_length=1, max_length=65536, repr=False)
    source_independence_verified: bool = False
    # Current ingress has no original-source proof or ownership decision.
    # Fixed literals prevent request metadata from manufacturing either claim.
    source_provenance: Literal["unverified"] = "unverified"
    ownership_status: Literal["unassigned"] = "unassigned"
    retention_until: datetime
    mentions: tuple[ObservationMention,...] = ()

    @model_validator(mode='after')
    def _evidence_and_retention(self):
        if hashlib.sha256(self.evidence_text.encode('utf-8')).hexdigest() != self.evidence_ref.digest:
            raise ValueError('evidence digest mismatch')
        if self.retention_until.tzinfo is None or self.retention_until <= self.observed_at:
            raise ValueError('invalid retention deadline')
        if any(m.end>len(self.evidence_text) or m.start>=m.end or self.evidence_text[m.start:m.end]!=m.name for m in self.mentions):
            raise ValueError('invalid observed entity coordinates')
        return self

    @field_validator("tenant", "domain", "source_id", "source_version",
                     "purpose", "retention_policy", "extraction_version")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("field must be a non-empty string")
        return value

    @field_validator("observed_at")
    @classmethod
    def _tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        return value

    @field_validator("acl")
    @classmethod
    def _acl_members(cls, value: frozenset[str]) -> frozenset[str]:
        if any(not member.strip() for member in value):
            raise ValueError("acl members must be non-empty strings")
        return value

    @field_serializer("acl")
    def _sorted_acl(self, value: frozenset[str]) -> list[str]:
        return sorted(value)


def _authorized(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def build_observation_event(
    *,
    tenant: str,
    domain: str,
    source_id: str,
    source_version: str,
    source_kind: SourceKind,
    evidence_digest: str,
    evidence_offset: int,
    observed_at: datetime,
    purpose: str,
    retention_policy: str,
    acl: Iterable[str] | None = None,
    extraction_version: str,
    evidence_text: str,
    retention_until: datetime,
    source_independence_verified: bool = False,
    mentions: tuple[ObservationMention,...] = (),
) -> ObservationEvent:
    """Build a minimal observation event from approved material metadata.

    Accepts a bounded fragment with a verified digest and source offset.
    Per Document 11 §4.2, missing client ACL does not reject
    collection; an empty ACL defaults to a domain-governed restricted candidate
    access scope.
    """
    if acl is None:
        members = (f"{domain}:restricted-candidate",)
    else:
        if not isinstance(acl, (frozenset, set, tuple, list)):
            raise SafetyError(SafetyCode.EVENT_INVALID, "acl_shape")
        members = tuple(acl)
        if not members:
            members = (f"{domain}:restricted-candidate",)
        elif any(not _authorized(member) for member in members):
            raise SafetyError(SafetyCode.EVENT_INVALID, "blank_acl_member")

    for label, value in (
        ("tenant", tenant),
        ("domain", domain),
        ("source_id", source_id),
        ("source_version", source_version),
        ("purpose", purpose),
        ("retention_policy", retention_policy),
    ):
        if not _authorized(value):
            raise SafetyError(SafetyCode.EVENT_INVALID, label)
    invalid = False
    try:
        event = ObservationEvent(
            tenant=tenant,
            domain=domain,
            source_id=source_id,
            source_version=source_version,
            source_kind=source_kind,
            evidence_ref=EvidenceRef(digest=evidence_digest, offset=evidence_offset),
            observed_at=observed_at,
            purpose=purpose,
            retention_policy=retention_policy,
            acl=frozenset(members),
            extraction_version=extraction_version,
            evidence_text=evidence_text,
            retention_until=retention_until,
            source_independence_verified=source_independence_verified,
            mentions=mentions,
        )
    except (ValidationError, ValueError):
        invalid = True
    if invalid:
        raise SafetyError(SafetyCode.EVENT_INVALID) from None
    return event


def serialize_event(event: ObservationEvent) -> bytes:
    """Canonical JSON bytes (sorted keys, compact separators, UTF-8).

    These bytes contain sensitive evidence and may only be encrypted into spool;
    they are not suitable for logging or public evidence attachments.
    """
    if not isinstance(event, ObservationEvent):
        raise TypeError("event must be an ObservationEvent")
    payload = event.model_dump(mode="json")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def event_sha256(event: ObservationEvent) -> str:
    """Stable digest of the canonical serialized event (record identity)."""
    return hashlib.sha256(serialize_event(event)).hexdigest()


def build_gateway_observation(
    *,
    tenant: str,
    domain: str,
    request_id: str,
    evidence_digest: str,
    evidence_offset: int = 0,
    observed_at: datetime | None = None,
    source_acl: Iterable[str] | None = None,
    purpose: str = "knowledge-accumulation",
    retention_policy: str = "standard-retention",
    extraction_version: str = "extract-1.0.0",
    evidence_text: str,
    source_kind: SourceKind = SourceKind.USER_ASSERTION,
    source_independence_verified: bool = False,
    retention_until: datetime | None = None,
    source_version: str | None = None,
    mentions: tuple[ObservationMention,...] = (),
    source_context: UnverifiedSourceContext | None = None,
) -> ObservationEvent:
    """Auto-generate an observation event from an incoming gateway request context.

    Per Document 11 §4.2, all gateway inputs are collectible by default. If no
    client ACL is present, a domain-governed restricted-candidate access scope
    is assigned.
    """
    from datetime import timezone
    if observed_at is None:
        observed_at = datetime.now(timezone.utc)
    if source_context is not None:
        if not isinstance(source_context, UnverifiedSourceContext):
            raise SafetyError(SafetyCode.EVENT_INVALID)
        validate_request_authorization(source_context, now=observed_at)
        if (tenant, domain) != (source_context.tenant_id, source_context.domain):
            raise SafetyError(SafetyCode.SCOPE_MISMATCH)
        if source_independence_verified:
            raise SafetyError(SafetyCode.EVENT_INVALID)
        if source_acl is not None and (
                not isinstance(source_acl, (frozenset, set, tuple, list))
                or frozenset(source_acl) != source_context.source_acl):
            raise SafetyError(SafetyCode.ACCESS_DENIED)
        source_acl = source_context.source_acl
    event = build_observation_event(
        tenant=tenant,
        domain=domain,
        source_id=(f"req:{request_id}" if source_independence_verified else f"unverified:{source_kind.value}:{evidence_digest}"),
        source_version=source_version or evidence_digest[:32],
        source_kind=source_kind,
        evidence_digest=evidence_digest,
        evidence_offset=evidence_offset,
        observed_at=observed_at,
        purpose=purpose,
        retention_policy=retention_policy,
        acl=source_acl,
        extraction_version=extraction_version,
        evidence_text=evidence_text,
        retention_until=retention_until or observed_at + timedelta(days=30),
        source_independence_verified=source_independence_verified,
        mentions=mentions,
    )
    if source_independence_verified:
        return event
    # Equal content in different trusted access scopes is not the same source.
    # Replays within a scope remain stable and never establish independence.
    scope_material=json.dumps([event.tenant,event.domain,event.source_kind.value,event.evidence_ref.digest,
                               source_context.source_id if source_context is not None else None,
                               event.purpose,event.retention_policy,sorted(event.acl)],
                              ensure_ascii=False,separators=(',',':')).encode('utf-8')
    return event.model_copy(update={'source_id':f'unverified:{source_kind.value}:'+hashlib.sha256(scope_material).hexdigest()})
