"""K-03 spool relay: at-least-once delivery with idempotent dedup and post-ack delete.

Relay moves K-02 encrypted spool records into the ledger sink (DESIGN §7:
来源ID+版本+证据位置+规范编码的候选内容幂等去重；历史重发与重试不增加独
立来源数). This module does NOT claim distributed exactly-once: the semantic is
**at-least-once delivery + idempotent contribution**:

1. read stage — every top-level ``*.env.json`` spool file is strict-parsed
   (A-02 :func:`parse_record`) and AEAD-decrypted
   (:func:`decrypt_record`); the plaintext must deserialize as an
   :class:`ObservationEvent`;
2. submit stage — a deterministic :func:`compute_dedup_key` is checked via
   :meth:`LedgerSink.has_contributed`; only a miss calls
   :meth:`LedgerSink.submit`;
3. confirm stage — only after the sink acknowledged (submit returned, or the
   key was already contributed) is the spool file deleted. A crash between
   submit and delete therefore redelivers the record on the next pass; the
   dedup hit then skips the re-submit and only completes the delete, so the
   ledger contribution count never grows (同事件只贡献一次).

Deletion semantics (documented choice): **direct delete**. The file is
removed with :func:`os.remove` only after confirmation; no separate
confirmation queue or tombstone is kept. Rationale: a second durable state
machine would add fsync/ordering complexity without buying anything, because
the ledger-side dedup key already makes redelivery contribution-neutral. The
residual risk (a record submitted but not yet deleted is redelivered) is
explicitly accepted and covered by the crash-injection tests.

Read-stage failures are classified into two classes:

- unrecoverable content errors — tampered/corrupt envelope
  (``INVALID_CIPHERTEXT``, ``DECRYPTION_FAILED``, ``INVALID_WRAPPED_KEY``)
  or plaintext that is not a valid observation event (``EVENT_INVALID``):
  the record can never relay, so it is moved into the ``quarantine/``
  subdirectory of the spool directory (documented isolation — it leaves the
  relay path but stays on disk, auditable, out of the watermark accounting
  of the live spool root) and counted in the relay statistics. Quarantine
  reasons are SafetyCode values only; no business content is ever placed in
  quarantine metadata or exception messages (canary-checked in tests).
- retryable infrastructure errors — a ``KMS_UNAVAILABLE`` decrypt failure
  or an ``OSError`` while reading the spool file (e.g. the file vanished
  after listing): the failure is transient, so the record is NOT quarantined
  and NOT deleted; it stays in the spool, is counted as a
  :class:`RelayFailure`, and the pass raises at the end like any other
  unconfirmed submission.

Unconfirmed or transiently-failed records leave the spool file in place and
are reported at the end of the pass: :meth:`SpoolRelay.relay_once` raises
:class:`SafetyError` with code ``RELAY_SUBMIT_FAILED`` whose ``stats``
attribute carries the full :class:`RelayStats`; a later pass over the
retained file recovers without double contribution once the infrastructure
is healthy again.

The sink is an abstract interface; this batch ships only the in-memory test
sink below. The real PostgreSQL implementation is K-04/K-10.
"""

from __future__ import annotations

import hashlib
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from infra.envelope_crypto import KmsProvider, decrypt_record, parse_record
from infra.errors import SafetyCode, SafetyError
from knowledge.knowledge_events import ObservationEvent, serialize_event
from infra.strict_json import JsonRejectKind, parse_strict_json

__all__ = [
    "InMemoryLedgerSink",
    "LedgerSink",
    "QuarantinedRecord",
    "RelayFailure",
    "RelayStats",
    "SpoolRelay",
    "compute_dedup_key",
]

_SPOOL_RECORD_SUFFIX = ".env.json"
_QUARANTINE_DIRNAME = "quarantine"

# Read-stage SafetyCodes that signal a transient infrastructure outage
# (KMS unavailable), not record damage: the spool file is kept and retried.
_RETRYABLE_READ_CODES = frozenset({SafetyCode.KMS_UNAVAILABLE})

# Canonical key order for the dedup-key pre-image (documented format).
_DEDUP_KEY_FIELDS = (
    "source_id",
    "source_version",
    "evidence_digest",
    "evidence_offset",
    "event_sha256",
)


def _canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def compute_dedup_key(event: ObservationEvent) -> str:
    """Deterministic dedup key: SHA-256 over a canonical JSON pre-image.

    Documented format — the pre-image is canonical JSON (sorted keys, compact
    separators, UTF-8) of exactly these fields::

        {
          "source_id": <event.source_id>,
          "source_version": <event.source_version>,
          "evidence_digest": <event.evidence_ref.digest>,
          "evidence_offset": <event.evidence_ref.offset>,
          "event_sha256": <SHA-256 hex of serialize_event(event)>
        }

    ``event_sha256`` is the digest of the canonical serialized event, i.e. the
    规范编码的事件内容 component; identity of all five components is required
    for two submissions to share a key, so historical redelivery and retries
    of the same event collapse onto one ledger contribution (DESIGN §7).
    """
    if not isinstance(event, ObservationEvent):
        raise TypeError("event must be an ObservationEvent")
    preimage = _canonical_json({
        "source_id": event.source_id,
        "source_version": event.source_version,
        "evidence_digest": event.evidence_ref.digest,
        "evidence_offset": event.evidence_ref.offset,
        "event_sha256": hashlib.sha256(serialize_event(event)).hexdigest(),
    })
    return hashlib.sha256(preimage).hexdigest()


class LedgerSink(ABC):
    """Abstract ledger sink for confirmed observation-event contributions.

    Implementations must make ``submit`` idempotent-safe by key: the relay
    never calls ``submit`` for a key with :meth:`has_contributed` true, but a
    crash after ``submit`` can redeliver the same key. The real PostgreSQL
    sink (unique constraint on the dedup key inside the contribution
    transaction) is K-04/K-10; this batch ships only
    :class:`InMemoryLedgerSink` for local tests.
    """

    @abstractmethod
    def has_contributed(self, dedup_key: str) -> bool:
        """Return True when the dedup key already has a ledger contribution."""

    @abstractmethod
    def submit(self, event: ObservationEvent, dedup_key: str) -> None:
        """Acknowledge one contribution; raise on any failure (no ack)."""


class InMemoryLedgerSink(LedgerSink):
    """Local in-memory test sink — records submission history for assertions.

    Test-only, mirroring ``StaticTestKmsProvider``: it never touches real
    storage and must not back a production path. ``submit`` raises
    ``RuntimeError`` if the key was already contributed, so any relay bug that
    double-submits fails the test loudly instead of silently inflating the
    ledger.
    """

    def __init__(self) -> None:
        self._submissions: dict[str, ObservationEvent] = {}

    def has_contributed(self, dedup_key: str) -> bool:
        return dedup_key in self._submissions

    def submit(self, event: ObservationEvent, dedup_key: str) -> None:
        if dedup_key in self._submissions:
            raise RuntimeError("duplicate contribution for dedup key")
        self._submissions[dedup_key] = event

    @property
    def contribution_count(self) -> int:
        return len(self._submissions)

    def contributed_events(self) -> tuple[ObservationEvent, ...]:
        return tuple(self._submissions.values())


@dataclass(frozen=True, slots=True)
class RelayFailure:
    """One unconfirmed record: the spool file was kept, no ack was reached."""

    spool_name: str
    code: SafetyCode


@dataclass(frozen=True, slots=True)
class QuarantinedRecord:
    """One record isolated to quarantine: never submitted, removed from relay."""

    spool_name: str
    code: SafetyCode
    quarantine_path: Path


@dataclass(frozen=True, slots=True)
class RelayStats:
    """Per-pass relay accounting; failures carry codes only (no content)."""

    submitted: int
    skipped: int
    failed: int
    quarantined: int
    failures: tuple[RelayFailure, ...]
    quarantined_records: tuple[QuarantinedRecord, ...]


# --- patchable confirm hook (crash/failure injection at the confirm stage) ---

def _confirm_remove(path: Path) -> None:
    """Delete a confirmed spool record; patched by tests to inject crashes."""
    os.remove(path)


# -----------------------------------------------------------------------------


def _reject_event_json(_kind: JsonRejectKind):
    raise SafetyError(SafetyCode.EVENT_INVALID)


class SpoolRelay:
    """Relays encrypted spool records into a ledger sink with dedup + ack-delete."""

    def __init__(self, spool_directory: str | Path, kms: KmsProvider,
                 sink: LedgerSink) -> None:
        if not isinstance(kms, KmsProvider):
            raise TypeError("kms must be a KmsProvider")
        if not isinstance(sink, LedgerSink):
            raise TypeError("sink must be a LedgerSink")
        self._directory = Path(spool_directory)
        self._kms = kms
        self._sink = sink

    @property
    def directory(self) -> Path:
        return self._directory

    @property
    def quarantine_directory(self) -> Path:
        return self._directory / _QUARANTINE_DIRNAME

    def _iter_records(self) -> list[Path]:
        if not self._directory.is_dir():
            raise FileNotFoundError(f"spool directory missing: {self._directory}")
        return sorted(
            entry for entry in self._directory.iterdir()
            if entry.is_file() and entry.name.endswith(_SPOOL_RECORD_SUFFIX)
        )

    def _read_event(self, path: Path) -> ObservationEvent:
        """Read stage: strict-parse envelope, decrypt, deserialize the event."""
        record = parse_record(path.read_bytes())
        plaintext = decrypt_record(self._kms, record)
        payload = parse_strict_json(plaintext, reject=_reject_event_json)
        if not isinstance(payload, dict):
            raise SafetyError(SafetyCode.EVENT_INVALID)
        try:
            return ObservationEvent.model_validate_json(plaintext)
        except ValidationError:
            raise SafetyError(SafetyCode.EVENT_INVALID) from None

    def _quarantine(self, path: Path, code: SafetyCode) -> QuarantinedRecord:
        """Isolate an unreadable record: out of the relay path, kept on disk."""
        self.quarantine_directory.mkdir(parents=True, exist_ok=True)
        target = self.quarantine_directory / path.name
        counter = 1
        while target.exists():
            target = self.quarantine_directory / f"{path.stem}-{counter}{path.suffix}"
            counter += 1
        os.replace(path, target)
        return QuarantinedRecord(spool_name=path.name, code=code,
                                 quarantine_path=target)

    def relay_once(self) -> RelayStats:
        """Run one relay pass; returns stats, or raises RELAY_SUBMIT_FAILED.

        Every transient stage-1 failure and every stage-2/stage-3 failure
        keeps its spool file (no confirmation) and is counted; the pass
        always attempts the remaining files. If any failure was recorded, a
        :class:`SafetyError` with code ``RELAY_SUBMIT_FAILED`` is raised at
        the end, with the full :class:`RelayStats` attached as ``exc.stats``
        — a retry over the retained files then recovers through the dedup
        key without double contribution. Quarantined records do not raise:
        they are final.
        """
        submitted = 0
        skipped = 0
        failures: list[RelayFailure] = []
        quarantined: list[QuarantinedRecord] = []
        for path in self._iter_records():
            # Stage 1 — read/decrypt/deserialize. Retryable infrastructure
            # failures (KMS outage, unreadable file) keep the spool file and
            # surface as pass failures; unrecoverable content errors
            # (tampering, bad envelope, non-event payload) are quarantined.
            try:
                event = self._read_event(path)
            except SafetyError as exc:
                if exc.code in _RETRYABLE_READ_CODES:
                    failures.append(RelayFailure(spool_name=path.name,
                                                 code=SafetyCode.RELAY_SUBMIT_FAILED))
                    continue
                try:
                    quarantined.append(self._quarantine(path, exc.code))
                except OSError:
                    # Isolation itself failed (e.g. rename denied): keep the
                    # file in place and report it like an unconfirmed record.
                    failures.append(RelayFailure(spool_name=path.name,
                                                 code=SafetyCode.RELAY_SUBMIT_FAILED))
                continue
            except OSError:
                failures.append(RelayFailure(spool_name=path.name,
                                             code=SafetyCode.RELAY_SUBMIT_FAILED))
                continue
            dedup_key = compute_dedup_key(event)
            # Stage 2 — contribute only on a dedup miss.
            try:
                already = self._sink.has_contributed(dedup_key)
                if not already:
                    self._sink.submit(event, dedup_key)
                    submitted += 1
            except Exception:
                failures.append(RelayFailure(spool_name=path.name,
                                             code=SafetyCode.RELAY_SUBMIT_FAILED))
                continue
            # Stage 3 — confirm by direct delete; failure keeps the file, and
            # the next pass resolves it through has_contributed (skip + delete).
            try:
                _confirm_remove(path)
            except OSError:
                failures.append(RelayFailure(spool_name=path.name,
                                             code=SafetyCode.RELAY_SUBMIT_FAILED))
                continue
            if already:
                skipped += 1
        stats = RelayStats(
            submitted=submitted,
            skipped=skipped,
            failed=len(failures),
            quarantined=len(quarantined),
            failures=tuple(failures),
            quarantined_records=tuple(quarantined),
        )
        if stats.failed:
            exc = SafetyError(SafetyCode.RELAY_SUBMIT_FAILED)
            exc.stats = stats  # type: ignore[attr-defined]
            raise exc
        return stats
