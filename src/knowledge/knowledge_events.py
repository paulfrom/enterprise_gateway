"""K-01 minimal observation events for governed knowledge collection.

Collection is NOT detection: an observation event is generated only for
material whose source, purpose, ACL, and retention are all provable (DESIGN
§7). The event is minimal by construction — source coordinates, a digest +
offset evidence reference, timestamps, governance metadata, and the
extraction version. No full text, excerpts, employee profiles, or payloads
exist on this schema: ``extra="forbid"`` plus the absence of any content
field makes oversharing a schema error, not a policy choice.

The factory :func:`build_observation_event` is the only construction path and
its signature accepts a digest and an offset — never the source text. A
caller holding only the original material cannot hand it to this module
(``TypeError``), which keeps full text out of the event at the signature
level, not just by convention.

Failure split: missing authorization coordinates (empty ACL, blank purpose,
blank retention policy, missing source identity) raise
``COLLECTION_NOT_AUTHORIZED`` — the source must not be collected at all.
Shape violations (bad digest, naive timestamp, wrong types, extra fields)
raise ``EVENT_INVALID``.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_serializer, field_validator

from infra.errors import SafetyCode, SafetyError
from knowledge.knowledge import SourceKind

__all__ = ["EvidenceRef", "ObservationEvent", "build_observation_event",
           "serialize_event", "event_sha256"]

_SHA256_HEX_LEN = 64


class EvidenceRef(BaseModel):
    """Minimal evidence pointer: content digest + character offset. No text."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    digest: str
    offset: int = Field(ge=0)

    @field_validator("digest")
    @classmethod
    def _sha256_hex(cls, value: str) -> str:
        if len(value) != _SHA256_HEX_LEN or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("digest must be lowercase SHA-256 hex")
        return value


class ObservationEvent(BaseModel):
    """Minimal governed observation; metadata only, no full text anywhere."""

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
    acl: Iterable[str],
    extraction_version: str,
) -> ObservationEvent:
    """Build a minimal observation event from APPROVED material metadata.

    Accepts only the evidence digest and offset — the signature has no
    parameter for source text, so passing the full text is a ``TypeError``
    by construction. Authorization invariants (non-empty ACL, purpose,
    retention policy, source identity) fail closed with
    ``COLLECTION_NOT_AUTHORIZED``; schema violations fail with
    ``EVENT_INVALID``.
    """
    if not isinstance(acl, (frozenset, set, tuple, list)):
        raise SafetyError(SafetyCode.EVENT_INVALID, "acl_shape")
    members = tuple(acl)
    if not members or any(not _authorized(member) for member in members):
        raise SafetyError(SafetyCode.COLLECTION_NOT_AUTHORIZED)
    for label, value in (
        ("source_id", source_id),
        ("source_version", source_version),
        ("purpose", purpose),
        ("retention_policy", retention_policy),
    ):
        if not _authorized(value):
            raise SafetyError(SafetyCode.COLLECTION_NOT_AUTHORIZED, label)
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
        )
    except (ValidationError, ValueError):
        invalid = True
    if invalid:
        raise SafetyError(SafetyCode.EVENT_INVALID) from None
    return event


def serialize_event(event: ObservationEvent) -> bytes:
    """Canonical JSON bytes (sorted keys, compact separators, UTF-8).

    The serialized form contains digests and governance metadata only; a byte
    scan over it must never find source text (see K-01 tests' canary check).
    """
    if not isinstance(event, ObservationEvent):
        raise TypeError("event must be an ObservationEvent")
    payload = event.model_dump(mode="json")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def event_sha256(event: ObservationEvent) -> str:
    """Stable digest of the canonical serialized event (record identity)."""
    return hashlib.sha256(serialize_event(event)).hexdigest()
