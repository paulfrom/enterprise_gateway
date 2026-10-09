"""Retention-bucket KEK destruction job: destroy every registered copy, prove irreversibility.

Capability boundary (test/local semantics): this module models the copy
registry of one retention bucket's KEK — primary, backup, cache, recovery and
similar locations, each an independently destroyable and verifiable KEK
store — and the job that destroys every copy when the caller-injected
retention policy says the bucket is due. Real KMS backends, production
volumes, and physical destruction semantics belong to R-05; everything here
is in-memory and must never back a production code path. Retention-period
numbers are never chosen here: the caller supplies the policy object that
decides due-ness.

Destruction flow for one (purpose, bucket) selector:

1. Refuse to run without a retention policy or without a non-empty copy
   registry (the job never claims completion for unscoped work), and refuse
   when the policy says the bucket is not due.
2. For each registered copy, in registration order: prove the copy really
   holds the bucket KEK by decrypting the caller-supplied sealed record
   (a real envelope record wrapped under this bucket's KEK), destroy the
   copy's KEK material, then verify the sealed record now fails to decrypt
   on that copy. A copy already destroyed by an earlier (crashed) run is
   re-verified, not re-destroyed, so re-entering the job is idempotent.
3. Issue a destruction report with per-copy evidence (location, role,
   destruction timestamp, resumed flag, observed verification outcome) only
   after every copy is destroyed and verified. Any destruction failure, or
   any copy that still decrypts afterwards, aborts with a controlled error
   and no report — deletion is never claimed.

Failure-code mapping (all raised as fresh ``SafetyError`` with no
``__context__``/``__cause__`` chain):

- ``CONTRACT_VIOLATION`` — blank purpose/bucket; missing policy or copy
  registry; empty registry; duplicate copy location; sealed record that does
  not match the requested selector; bucket not due per policy; a copy that
  cannot verify the sealed record before destruction.
- ``KMS_UNAVAILABLE`` — a copy store signals its key service failed during
  destruction; post-destruction verification shows a copy still decrypts
  (destruction did not take effect).

``DECRYPTION_FAILED`` is not raised by this module; it is the verification
outcome observed from :func:`enterprise_gateway.envelope_crypto.decrypt_record`
when a destroyed copy can no longer unwrap the sealed record. Key material
never leaves memory and is never written to disk by this module.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Callable

from infra.envelope_crypto import (
    KmsUnavailableError,
    EnvelopeRecord,
    StaticTestKmsProvider,
    decrypt_record,
)
from infra.errors import SafetyCode, SafetyError


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CopyRole(StrEnum):
    """Role of one registered KEK copy within the bucket's copy set."""

    PRIMARY = "primary"
    BACKUP = "backup"
    CACHE = "cache"
    RECOVERY = "recovery"


@dataclass(frozen=True, slots=True)
class KekCopy:
    """One location in the bucket KEK copy registry."""

    location_id: str
    role: CopyRole

    def __post_init__(self) -> None:
        if not isinstance(self.location_id, str):
            raise TypeError("location_id must be a string")
        if not self.location_id.strip():
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "location_id must be non-empty")
        if not isinstance(self.role, CopyRole):
            raise TypeError("role must be a CopyRole")


class LocalKekCopyStore(StaticTestKmsProvider):
    """Test/local in-memory replica of one bucket KEK copy.

    Every copy of the same (purpose, bucket) KEK holds the same synthetic
    KEK bytes (explicitly supplied at construction). Destruction forgets the
    KEK bytes for the selector and refuses further wrapping, so encryption
    under the destroyed bucket fails with ``KMS_UNAVAILABLE``; a later
    unwrap attempt regenerates a fresh random KEK instead of recovering the
    destroyed one, so decryption of records sealed under the true KEK fails
    authentication — which is exactly what the destruction job verifies.
    Destruction is idempotent: destroying an already-destroyed selector
    keeps the original timestamp and reports no error, so a crashed job can
    resume over already-destroyed copies.
    """

    def __init__(self, keks: dict[tuple[str, str], bytes] | None = None) -> None:
        super().__init__(seed_keks=keks)
        self._destroyed: set[tuple[str, str]] = set()
        self._destroyed_at: dict[tuple[str, str], datetime] = {}

    def provision(self, purpose: str, bucket: str, kek: bytes) -> None:
        """Install synthetic KEK bytes for a selector (test/local setup only)."""
        if (purpose, bucket) in self._destroyed:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "selector already destroyed")
        self._set_kek(purpose, bucket, kek)

    def wrap(self, dek: bytes, *, purpose: str, bucket: str) -> bytes:
        if (purpose, bucket) in self._destroyed:
            raise KmsUnavailableError("kek copy destroyed")
        return super().wrap(dek, purpose=purpose, bucket=bucket)

    def destroy(self, purpose: str, bucket: str, *, at: datetime) -> datetime:
        """Destroy this copy's KEK material for the selector.

        Idempotent: returns the original destruction timestamp when the
        selector is already destroyed.
        """
        if not isinstance(purpose, str) or not isinstance(bucket, str):
            raise TypeError("purpose and bucket must be strings")
        if not purpose.strip() or not bucket.strip():
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "purpose and bucket must be non-empty")
        if not isinstance(at, datetime):
            raise TypeError("at must be a datetime")
        selector = (purpose, bucket)
        if selector in self._destroyed:
            return self._destroyed_at[selector]
        self._keks.pop(selector, None)
        self._destroyed.add(selector)
        self._destroyed_at[selector] = at
        return at

    def is_destroyed(self, purpose: str, bucket: str) -> bool:
        return (purpose, bucket) in self._destroyed

    def destruction_time(self, purpose: str, bucket: str) -> datetime | None:
        return self._destroyed_at.get((purpose, bucket))


class KekCopyRegistry:
    """Ordered registry of every copy of one bucket's KEK."""

    def __init__(self) -> None:
        self._entries: list[tuple[KekCopy, LocalKekCopyStore]] = []
        self._locations: set[str] = set()

    def register(self, copy: KekCopy, store: LocalKekCopyStore) -> None:
        if not isinstance(copy, KekCopy):
            raise TypeError("copy must be a KekCopy")
        if not isinstance(store, LocalKekCopyStore):
            raise TypeError("store must be a LocalKekCopyStore")
        if copy.location_id in self._locations:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "duplicate copy location")
        self._locations.add(copy.location_id)
        self._entries.append((copy, store))

    def entries(self) -> tuple[tuple[KekCopy, LocalKekCopyStore], ...]:
        return tuple(self._entries)

    def is_empty(self) -> bool:
        return not self._entries


class RetentionPolicy(ABC):
    """Caller-injected due-ness decision for a retention bucket.

    The retention period and every other parameter live in the caller's
    implementation; this module never supplies or defaults retention numbers.
    """

    @abstractmethod
    def is_due(self, purpose: str, bucket: str, *, now: datetime) -> bool:
        """Return True when the bucket's KEK may be destroyed at ``now``."""


@dataclass(frozen=True, slots=True)
class CopyDestructionEvidence:
    """Per-copy evidence recorded in the destruction report."""

    location_id: str
    role: CopyRole
    destroyed_at: datetime
    resumed: bool
    verification: SafetyCode


@dataclass(frozen=True, slots=True)
class DestructionReport:
    """Issued only when every registered copy is destroyed and verified."""

    purpose: str
    bucket: str
    completed_at: datetime
    copies: tuple[CopyDestructionEvidence, ...]


def _selector_params(purpose: str, bucket: str) -> None:
    if not isinstance(purpose, str) or not isinstance(bucket, str):
        raise TypeError("purpose and bucket must be strings")
    if not purpose.strip() or not bucket.strip():
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "purpose and bucket must be non-empty")


def _copy_fails_decryption(store: LocalKekCopyStore, record: EnvelopeRecord) -> bool:
    """True exactly when the sealed record fails AEAD authentication on this copy."""
    try:
        decrypt_record(store, record)
    except SafetyError as exc:
        return exc.code == SafetyCode.DECRYPTION_FAILED
    return False


def _verify_pre_destruction(store: LocalKekCopyStore, record: EnvelopeRecord) -> None:
    verifies = False
    try:
        decrypt_record(store, record)
        verifies = True
    except SafetyError:
        verifies = False
    if not verifies:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "copy cannot verify sealed record")


def _verify_post_destruction(store: LocalKekCopyStore, record: EnvelopeRecord) -> None:
    if _copy_fails_decryption(store, record):
        return
    raise SafetyError(SafetyCode.KMS_UNAVAILABLE, "kek copy still decrypts after destruction")


def run_kek_destruction_job(
    *,
    purpose: str,
    bucket: str,
    policy: RetentionPolicy | None,
    registry: KekCopyRegistry | None,
    sealed_record: EnvelopeRecord,
    now: Callable[[], datetime] | None = None,
) -> DestructionReport:
    """Destroy every registered copy of the bucket KEK and prove irreversibility.

    Returns a :class:`DestructionReport` only after all copies are destroyed
    and each one was observed failing to decrypt ``sealed_record``. Refuses
    (``CONTRACT_VIOLATION``) without doing any work when the policy or the
    copy registry is missing/empty, when the sealed record does not match the
    requested selector, or when the policy says the bucket is not yet due.
    Any copy that fails to destroy, or still decrypts after destruction,
    aborts the job with ``KMS_UNAVAILABLE`` and no report is issued; an
    aborted job can be re-entered — already-destroyed copies are re-verified
    instead of being destroyed again.
    """
    clock = now if now is not None else _utcnow
    if not callable(clock):
        raise TypeError("now must be callable")
    _selector_params(purpose, bucket)
    if policy is None:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "retention policy required")
    if not isinstance(policy, RetentionPolicy):
        raise TypeError("policy must be a RetentionPolicy")
    if registry is None:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "copy registry required")
    if not isinstance(registry, KekCopyRegistry):
        raise TypeError("registry must be a KekCopyRegistry")
    if registry.is_empty():
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "copy registry is empty")
    if not isinstance(sealed_record, EnvelopeRecord):
        raise TypeError("sealed_record must be an EnvelopeRecord")
    if sealed_record.purpose != purpose or sealed_record.bucket != bucket:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "sealed record does not match selector")

    due = policy.is_due(purpose, bucket, now=clock())
    if not isinstance(due, bool):
        raise TypeError("policy is_due must return bool")
    if not due:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "retention bucket not due")

    evidence: list[CopyDestructionEvidence] = []
    for copy, store in registry.entries():
        if store.is_destroyed(purpose, bucket):
            _verify_post_destruction(store, sealed_record)
            evidence.append(
                CopyDestructionEvidence(
                    location_id=copy.location_id,
                    role=copy.role,
                    destroyed_at=store.destruction_time(purpose, bucket),
                    resumed=True,
                    verification=SafetyCode.DECRYPTION_FAILED,
                )
            )
            continue
        _verify_pre_destruction(store, sealed_record)
        destroy_failed = False
        try:
            destroyed_at = store.destroy(purpose, bucket, at=clock())
        except KmsUnavailableError:
            destroy_failed = True
        if destroy_failed:
            raise SafetyError(SafetyCode.KMS_UNAVAILABLE, "kek copy destruction failed")
        _verify_post_destruction(store, sealed_record)
        evidence.append(
            CopyDestructionEvidence(
                location_id=copy.location_id,
                role=copy.role,
                destroyed_at=destroyed_at,
                resumed=False,
                verification=SafetyCode.DECRYPTION_FAILED,
            )
        )
    return DestructionReport(
        purpose=purpose,
        bucket=bucket,
        completed_at=clock(),
        copies=tuple(evidence),
    )
