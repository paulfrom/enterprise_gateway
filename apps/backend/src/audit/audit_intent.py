"""A-01 release-intent ledger: minimal egress metadata, durable commit, permit handle.

Before any egress attempt the gateway must durably commit the minimal release
intent (DESIGN §6): who/what category leaves, under which policy and package
version, for what purpose. The record contains metadata only — never request
bodies, prompts, secrets, or detector findings.

Flow: the caller builds a :class:`ReleaseIntent` (strict pydantic schema,
``extra="forbid"``, no body fields exist), then :func:`commit_release_intent`
serializes canonical JSON and commits it through
:mod:`enterprise_gateway.durable_write` (temp write + fsync + atomic rename +
directory fsync). Only after that persistence boundary is reached is an
immutable :class:`ReleasePermit` returned — "persisted, may attempt send".
Any write/fsync/ENOSPC failure maps to ``AUDIT_WRITE_FAILED`` and no permit
handle is produced; the failure never fabricates the "persisted" state.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from infra.durable_write import DurableWriteError, durable_commit
from infra.errors import SafetyCode, SafetyError

__all__ = ["ReleaseIntent", "ReleasePermit", "commit_release_intent", "serialize_intent"]

_INTENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ReleaseIntent(BaseModel):
    """Minimal release-intent metadata; no body fields exist on this schema."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    intent_id: str
    recorded_at: datetime
    domain: str
    category: str
    policy_version: str
    package_version: str
    purpose: str
    caller_id: str | None = None
    tenant_id: str | None = None
    protocol: str | None = None
    request_model: str | None = None
    upstream_model: str | None = None
    channel_version: str | None = None
    package_hash: str | None = None
    route_id: str | None = None
    model: str | None = None

    @field_validator("intent_id")
    @classmethod
    def _intent_id_safe(cls, value: str) -> str:
        if not _INTENT_ID_RE.fullmatch(value):
            raise ValueError("intent_id must be a safe token")
        return value

    @field_validator("recorded_at")
    @classmethod
    def _tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("recorded_at must be timezone-aware")
        return value

    @field_validator("domain", "category", "policy_version", "package_version", "purpose")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("field must be a non-empty string")
        return value


@dataclass(frozen=True, slots=True)
class ReleasePermit:
    """Immutable proof handle: the intent reached the persistence boundary."""

    intent_id: str
    recorded_at: datetime
    path: Path
    sha256: str


def serialize_intent(intent: ReleaseIntent) -> bytes:
    """Canonical JSON bytes (sorted keys, compact separators, UTF-8)."""
    if not isinstance(intent, ReleaseIntent):
        raise TypeError("intent must be a ReleaseIntent")
    payload = intent.model_dump(mode="json", exclude_none=True)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def commit_release_intent(directory: str | Path, intent: ReleaseIntent) -> ReleasePermit:
    """Durably commit the intent; return a permit only after the fsync boundary.

    Write/fsync/rename failures (including ENOSPC) raise
    ``SafetyError(AUDIT_WRITE_FAILED)`` with no exception chain and produce no
    permit handle. If an intent with the same intent_id already exists, it cannot
    be overwritten and raises ``SafetyError(CONTRACT_VIOLATION)``.
    """
    if not isinstance(intent, ReleaseIntent):
        raise TypeError("intent must be a ReleaseIntent")
    target_path = Path(directory) / f"{intent.intent_id}.intent.json"
    data = serialize_intent(intent)
    if target_path.exists():
        existing_data = target_path.read_bytes()
        if existing_data != data:
            raise SafetyError(
                SafetyCode.CONTRACT_VIOLATION,
                "cannot overwrite existing intent with different payload",
            )
        return ReleasePermit(
            intent_id=intent.intent_id,
            recorded_at=intent.recorded_at,
            path=target_path,
            sha256=hashlib.sha256(data).hexdigest(),
        )
    write_failed = False
    try:
        committed = durable_commit(directory, f"{intent.intent_id}.intent.json", data)
    except DurableWriteError:
        write_failed = True
    if write_failed:
        raise SafetyError(SafetyCode.AUDIT_WRITE_FAILED) from None
    return ReleasePermit(
        intent_id=intent.intent_id,
        recorded_at=intent.recorded_at,
        path=committed.path,
        sha256=hashlib.sha256(data).hexdigest(),
    )
