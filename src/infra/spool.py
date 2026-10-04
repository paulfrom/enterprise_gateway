"""K-02 encrypted spool: policy-mandated collection lands durably BEFORE use.

When a channel policy mandates knowledge collection (DESIGN §8), the K-01
observation event is envelope-encrypted (A-02: per-record random DEK,
AES-256-GCM, KMS-wrapped DEK keyed by purpose/retention bucket) and committed
through the :mod:`enterprise_gateway.durable_write` primitive. Only after the
persistence boundary is reached does :meth:`SpoolWriter.collect` return a
permit. Write/fsync failures map to ``SPOOL_WRITE_FAILED``; capacity
water-marks (total bytes / file count) map to ``SPOOL_FULL``; both fail with
no permit. Spool bytes on disk must never contain plaintext event fields —
only the serialized envelope (which itself exposes domain/purpose/bucket/
record_id as AAD metadata by design).

Backpressure is explicit, never silent:

- ``CollectionMode.REQUIRED`` — any failure raises; the caller must block.
- ``CollectionMode.OPTIONAL_WITH_GAP_POLICY`` — only legal when the caller
  pre-declares the gap policy. On failure a :class:`GapRecord` is persisted
  (metadata: event digest, reason code, mode, timestamp — no content) and
  returned instead of a permit, so the loss is recorded, auditable, and
  bounded. If even the gap record cannot be persisted, the failure raises
  ``SPOOL_WRITE_FAILED``: silent loss is never an option.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path

from infra.durable_write import DurableWriteError, durable_commit
from infra.envelope_crypto import KmsProvider, encrypt_record, serialize_record
from infra.errors import SafetyCode, SafetyError
from knowledge.knowledge_events import ObservationEvent, event_sha256, serialize_event

__all__ = ["CollectionMode", "GapRecord", "SpoolPermit", "SpoolWriter"]

_SPOOL_PURPOSE_SUFFIX = "knowledge-spool"
_DEFAULT_MAX_TOTAL_BYTES = 1_000_000
_DEFAULT_MAX_FILES = 100


class CollectionMode(StrEnum):
    """Caller-pre-declared collection posture; there is no silent default."""

    REQUIRED = "required"
    OPTIONAL_WITH_GAP_POLICY = "optional_with_gap_policy"


@dataclass(frozen=True, slots=True)
class SpoolPermit:
    """Immutable proof: the encrypted event reached the spool's fsync boundary."""

    record_id: str
    path: Path
    bytes_written: int
    ciphertext_sha256: str


@dataclass(frozen=True, slots=True)
class GapRecord:
    """Explicit, persisted record of an allowed collection gap (metadata only)."""

    event_sha256: str
    reason: SafetyCode
    mode: CollectionMode
    gap_path: Path


def _canonical_gap_record(*, event_digest: str, reason: SafetyCode,
                          mode: CollectionMode, recorded_at: datetime) -> bytes:
    payload = {
        "kind": "gap_record",
        "event_sha256": event_digest,
        "reason": reason.value,
        "mode": mode.value,
        "recorded_at": recorded_at.isoformat(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class SpoolWriter:
    """Durable encrypted spool with parameterized capacity water-marks."""

    def __init__(
        self,
        directory: str | Path,
        kms: KmsProvider,
        *,
        max_total_bytes: int = _DEFAULT_MAX_TOTAL_BYTES,
        max_files: int = _DEFAULT_MAX_FILES,
    ) -> None:
        if not isinstance(kms, KmsProvider):
            raise TypeError("kms must be a KmsProvider")
        if max_total_bytes <= 0 or max_files <= 0:
            raise ValueError("water-marks must be positive")
        self._directory = Path(directory)
        self._kms = kms
        self._max_total_bytes = max_total_bytes
        self._max_files = max_files
        self._directory.mkdir(parents=True, exist_ok=True)

    @property
    def directory(self) -> Path:
        return self._directory

    def _usage(self) -> tuple[int, int]:
        """Count every regular file in the spool directory.

        The water-mark covers gap records, crash-residual ``.tmp`` files, and
        even externally placed files — a conservative single-process
        accounting; concurrent writers need an external lock.
        """
        total = 0
        count = 0
        for entry in self._directory.iterdir():
            if entry.is_file():
                count += 1
                total += entry.stat().st_size
        return total, count

    def _check_watermark(self, directory: Path, incoming: int) -> None:
        """durable_write capacity hook; raises SPOOL_FULL before any file exists."""
        total, count = self._usage()
        if count >= self._max_files or total + incoming > self._max_total_bytes:
            raise SafetyError(SafetyCode.SPOOL_FULL)

    def _spool_name(self, record_id: str) -> str:
        return f"{record_id}.env.json"

    def _collect_required(self, event: ObservationEvent) -> SpoolPermit:
        plaintext = serialize_event(event)
        record_id = f"evt-{hashlib.sha256(plaintext).hexdigest()[:32]}"
        record = encrypt_record(
            self._kms,
            plaintext,
            domain=event.domain,
            bucket=event.retention_policy,
            record_id=record_id,
            purpose=f"{event.purpose}:{_SPOOL_PURPOSE_SUFFIX}",
        )
        data = serialize_record(record)
        write_failed = False
        try:
            committed = durable_commit(
                self._directory, self._spool_name(record_id), data,
                capacity_check=self._check_watermark,
            )
        except DurableWriteError:
            write_failed = True
        if write_failed:
            raise SafetyError(SafetyCode.SPOOL_WRITE_FAILED) from None
        return SpoolPermit(
            record_id=record_id,
            path=committed.path,
            bytes_written=committed.bytes_written,
            ciphertext_sha256=hashlib.sha256(data).hexdigest(),
        )

    def _record_gap(self, event: ObservationEvent, reason: SafetyCode,
                    mode: CollectionMode) -> GapRecord:
        digest = event_sha256(event)
        recorded_at = datetime.now(timezone.utc)
        data = _canonical_gap_record(event_digest=digest, reason=reason,
                                     mode=mode, recorded_at=recorded_at)
        name = f"gap-{digest[:16]}-{os.urandom(4).hex()}.gap.json"
        write_failed = False
        try:
            committed = durable_commit(self._directory, name, data)
        except DurableWriteError:
            write_failed = True
        if write_failed:
            # The policy allows a gap, but only a RECORDED one.
            raise SafetyError(SafetyCode.SPOOL_WRITE_FAILED, "gap_record") from None
        return GapRecord(event_sha256=digest, reason=reason, mode=mode, gap_path=committed.path)

    def collect(self, event: ObservationEvent, *, mode: CollectionMode) -> SpoolPermit | GapRecord:
        """Encrypt + durably spool one event; REQUIRED raises, OPTIONAL may gap.

        ``mode`` must be passed explicitly per call — there is no implicit
        default, so a caller cannot accidentally collect silently.
        """
        if not isinstance(event, ObservationEvent):
            raise TypeError("event must be an ObservationEvent")
        if not isinstance(mode, CollectionMode):
            raise TypeError("mode must be a CollectionMode")
        if mode is CollectionMode.REQUIRED:
            return self._collect_required(event)
        gap_reason: SafetyCode | None = None
        try:
            return self._collect_required(event)
        except SafetyError as exc:
            if exc.code in (SafetyCode.SPOOL_FULL, SafetyCode.SPOOL_WRITE_FAILED,
                            SafetyCode.KMS_UNAVAILABLE):
                gap_reason = exc.code
            else:
                raise
        return self._record_gap(event, gap_reason, mode)
