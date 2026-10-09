"""A-06 crash-recovery reconciler: keep unknown results unknown, preserve real ones.

DESIGN §6: exactly-once cannot be built from two independent writes, so the
gateway never fabricates success. After a crash the A-01 intent ledger is
reconciled: an intent whose send outcome was durably recorded keeps its real
result (``SENT`` / ``FAILED``); an intent with no result record is
adjudicated ``RESULT_UNKNOWN`` — never promoted to success, never demoted to
failure. The adjudication itself is durable (``durable_commit``) and
re-entry is idempotent: an intent that already has a reconcile record is
never re-judged, even if new facts (e.g. a late result record) appear later.

Ledger layout (one directory, the A-01 audit ledger):

- ``{intent_id}.intent.json``      — A-01 release intent (audit_intent)
- ``{intent_id}.result.json``      — send outcome recorded after the attempt
- ``{intent_id}.reconcile.json``   — crash-reconciliation adjudication
- ``{intent_id}.intent.quarantined`` — corrupt intent, isolated from the scan

All three active records are canonical JSON (sorted keys, compact separators,
UTF-8) committed through :mod:`enterprise_gateway.durable_write`.

Record formats (fixed):

- result record: ``{"intent_id", "outcome", "recorded_at"}`` where outcome is
  ``"SENT"`` or ``"FAILED"`` (the closed set of real outcomes);
- reconcile record: ``{"intent_id", "adjudication", "outcome",
  "reconciled_at"}`` where adjudication is ``"RESULT_CONFIRMED"`` (outcome
  carries the preserved real result) or ``"RESULT_UNKNOWN"`` (outcome null).

Corruption semantics (chosen and fixed): a corrupt intent document (bad
UTF-8, malformed JSON, duplicate keys, excessive nesting, schema violation,
or filename/payload ``intent_id`` mismatch) is quarantined by an atomic
rename to ``{intent_id}.intent.quarantined`` and the run aborts with
``CONTRACT_VIOLATION`` before any adjudication is written — corrupt intents
are never silently skipped and never adjudicated as unknown. Result records
are refused, not quarantined: a corrupt result document, a result whose
payload ``intent_id`` does not match its file name, or a result for an
intent absent from the ledger raises ``CONTRACT_VIOLATION`` and no
adjudication is written. Any durable-write failure while committing a
reconcile record raises ``AUDIT_WRITE_FAILED``; the entry keeps its prior
state and a re-run continues with the remaining entries.

:func:`record_send_result` is the minimal write side for P-18/R-02 wiring:
after a send attempt completes, record its real outcome durably. It refuses
to overwrite an existing result record — a recorded outcome is an audit fact
and is never rewritten.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import NoReturn

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from infra.durable_write import DurableWriteError, durable_commit
from infra.errors import SafetyCode, SafetyError
from infra.strict_json import JsonRejectKind, parse_strict_json

__all__ = [
    "ReconcileAdjudication",
    "ReconcileRecord",
    "ReconcileSummary",
    "SendOutcome",
    "SendResult",
    "reconcile_after_crash",
    "record_send_result",
    "serialize_reconcile",
    "serialize_result",
]

_INTENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_INTENT_SUFFIX = ".intent.json"
_RESULT_SUFFIX = ".result.json"
_RECONCILE_SUFFIX = ".reconcile.json"
_QUARANTINED_SUFFIX = ".intent.quarantined"


class SendOutcome(StrEnum):
    """Closed set of real send outcomes; nothing else may be recorded."""

    SENT = "SENT"
    FAILED = "FAILED"


class SendResult(BaseModel):
    """Durable send outcome for one committed release intent; metadata only."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    intent_id: str
    outcome: str
    recorded_at: datetime

    @field_validator("intent_id")
    @classmethod
    def _intent_id_safe(cls, value: str) -> str:
        if not _INTENT_ID_RE.fullmatch(value):
            raise ValueError("intent_id must be a safe token")
        return value

    @field_validator("outcome")
    @classmethod
    def _known_outcome(cls, value: str) -> str:
        if value not in {member.value for member in SendOutcome}:
            raise ValueError("outcome must be a registered send outcome")
        return value

    @field_validator("recorded_at")
    @classmethod
    def _tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("recorded_at must be timezone-aware")
        return value


class ReconcileAdjudication(StrEnum):
    """Crash-reconciliation verdict for one intent."""

    RESULT_CONFIRMED = "RESULT_CONFIRMED"
    RESULT_UNKNOWN = "RESULT_UNKNOWN"


class ReconcileRecord(BaseModel):
    """Durable adjudication; exactly one per intent, never rewritten."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    intent_id: str
    adjudication: str
    outcome: str | None
    reconciled_at: datetime

    @field_validator("intent_id")
    @classmethod
    def _intent_id_safe(cls, value: str) -> str:
        if not _INTENT_ID_RE.fullmatch(value):
            raise ValueError("intent_id must be a safe token")
        return value

    @field_validator("adjudication")
    @classmethod
    def _known_adjudication(cls, value: str) -> str:
        if value not in {member.value for member in ReconcileAdjudication}:
            raise ValueError("adjudication must be a registered verdict")
        return value

    @field_validator("reconciled_at")
    @classmethod
    def _tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("reconciled_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _verdict_consistency(self) -> "ReconcileRecord":
        if self.adjudication == ReconcileAdjudication.RESULT_CONFIRMED.value:
            if self.outcome not in {member.value for member in SendOutcome}:
                raise ValueError("confirmed verdict requires a real outcome")
        elif self.outcome is not None:
            raise ValueError("unknown verdict must not carry an outcome")
        return self


@dataclass(frozen=True, slots=True)
class ReconcileSummary:
    """Observability for one reconciliation run; never persisted."""

    scanned_intents: int
    confirmed: int
    marked_unknown: int
    already_adjudicated: int


def serialize_result(result: SendResult) -> bytes:
    """Canonical JSON bytes (sorted keys, compact separators, UTF-8)."""
    if not isinstance(result, SendResult):
        raise TypeError("result must be a SendResult")
    payload = result.model_dump(mode="json")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def serialize_reconcile(record: ReconcileRecord) -> bytes:
    """Canonical JSON bytes (sorted keys, compact separators, UTF-8)."""
    if not isinstance(record, ReconcileRecord):
        raise TypeError("record must be a ReconcileRecord")
    payload = record.model_dump(mode="json")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def record_send_result(directory: str | Path, result: SendResult) -> Path:
    """Durably record the real outcome of one send attempt.

    The caller (P-18/R-02 wiring) invokes this only after the attempt
    completed, passing the outcome it actually observed. An existing result
    record is never overwritten: a recorded outcome is an audit fact, so a
    duplicate registration is refused with ``CONTRACT_VIOLATION``.
    Write/fsync/rename failures (including ENOSPC) raise
    ``SafetyError(AUDIT_WRITE_FAILED)`` with no exception chain.
    """
    if not isinstance(result, SendResult):
        raise TypeError("result must be a SendResult")
    target_dir = Path(directory)
    target = target_dir / f"{result.intent_id}{_RESULT_SUFFIX}"
    if target.exists():
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "result already recorded")
    data = serialize_result(result)
    write_failed = False
    try:
        durable_commit(target_dir, target.name, data)
    except DurableWriteError:
        write_failed = True
    if write_failed:
        raise SafetyError(SafetyCode.AUDIT_WRITE_FAILED) from None
    return target


# --- patchable interop points (failure injection) ----------------------------


def _quarantine(path: Path, target: Path) -> None:
    os.replace(path, target)


# ---------------------------------------------------------------------------


def _reject_corrupt_intent(kind: JsonRejectKind) -> NoReturn:
    raise SafetyError(SafetyCode.CONTRACT_VIOLATION, f"intent document: {kind.value}")


def _reject_corrupt_result(kind: JsonRejectKind) -> NoReturn:
    raise SafetyError(SafetyCode.CONTRACT_VIOLATION, f"result document: {kind.value}")


def _parse_iso(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


_REQUIRED_INTENT_FIELDS = (
    "intent_id",
    "recorded_at",
    "domain",
    "category",
    "policy_version",
    "package_version",
    "purpose",
)
_OPTIONAL_INTENT_FIELDS = (
    "caller_id",
    "tenant_id",
    "protocol",
    "request_model",
    "upstream_model",
    "channel_version",
    "package_hash",
)
_ALL_ALLOWED_INTENT_FIELDS = set(_REQUIRED_INTENT_FIELDS) | set(_OPTIONAL_INTENT_FIELDS)


def _valid_intent_payload(payload: object) -> bool:
    """Structural revalidation of one A-01 intent document."""
    if not isinstance(payload, dict):
        return False
    keys = set(payload)
    if not set(_REQUIRED_INTENT_FIELDS).issubset(keys):
        return False
    if not keys.issubset(_ALL_ALLOWED_INTENT_FIELDS):
        return False
    for key, value in payload.items():
        if value is not None and (not isinstance(value, str) or not value.strip()):
            return False
    if not _INTENT_ID_RE.fullmatch(payload["intent_id"]):
        return False
    recorded_at = _parse_iso(payload["recorded_at"])
    if recorded_at is None or recorded_at.tzinfo is None or recorded_at.utcoffset() is None:
        return False
    return True


def _load_intent(path: Path) -> dict:
    """Parse and revalidate one intent document; quarantine on any defect."""
    corrupt = False
    payload = None
    try:
        payload = parse_strict_json(path.read_bytes(), reject=_reject_corrupt_intent)
    except SafetyError:
        corrupt = True
    if not corrupt and not _valid_intent_payload(payload):
        corrupt = True
    if not corrupt and payload["intent_id"] != path.name[: -len(_INTENT_SUFFIX)]:
        corrupt = True
    if corrupt:
        target = path.with_name(path.name[: -len(_INTENT_SUFFIX)] + _QUARANTINED_SUFFIX)
        quarantine_failed = False
        try:
            _quarantine(path, target)
        except OSError:
            quarantine_failed = True
        if quarantine_failed:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "intent quarantine failed") from None
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "intent document corrupt") from None
    return payload


def _load_result(path: Path) -> SendResult:
    """Parse and validate one result document; refuse (never quarantine)."""
    payload = parse_strict_json(path.read_bytes(), reject=_reject_corrupt_result)
    result = None
    if isinstance(payload, dict) and set(payload) == {"intent_id", "outcome", "recorded_at"}:
        recorded_at = _parse_iso(payload["recorded_at"])
        if recorded_at is not None and isinstance(payload["intent_id"], str) and isinstance(payload["outcome"], str):
            invalid = False
            try:
                result = SendResult(
                    intent_id=payload["intent_id"],
                    outcome=payload["outcome"],
                    recorded_at=recorded_at,
                )
            except ValueError:
                invalid = True
            if invalid:
                result = None
    if result is None:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "result document corrupt") from None
    if result.intent_id != path.name[: -len(_RESULT_SUFFIX)]:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "result intent id mismatch")
    return result


def reconcile_after_crash(directory: str | Path) -> ReconcileSummary:
    """Reconcile the intent ledger after a crash; see module docstring.

    Read-only validation of every intent and result document happens before
    any adjudication is written, so a refused run never half-adjudicates.
    Adjudications are committed one document per intent through
    ``durable_commit``; a write failure raises ``AUDIT_WRITE_FAILED`` and a
    re-run continues with the entries that are not yet adjudicated.
    """
    target_dir = Path(directory)
    if not target_dir.is_dir():
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "ledger directory missing")

    intents: dict[str, dict] = {}
    for path in sorted(p for p in target_dir.iterdir() if p.is_file() and p.name.endswith(_INTENT_SUFFIX)):
        payload = _load_intent(path)
        intents[payload["intent_id"]] = payload

    results: dict[str, SendResult] = {}
    for path in sorted(p for p in target_dir.iterdir() if p.is_file() and p.name.endswith(_RESULT_SUFFIX)):
        result = _load_result(path)
        if result.intent_id not in intents:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "result without matching intent")
        results[result.intent_id] = result

    confirmed = 0
    marked_unknown = 0
    already = 0
    for intent_id in sorted(intents):
        reconcile_path = target_dir / f"{intent_id}{_RECONCILE_SUFFIX}"
        if reconcile_path.exists():
            corrupt = False
            try:
                raw_bytes = reconcile_path.read_bytes()
                if not raw_bytes:
                    corrupt = True
                else:
                    ReconcileRecord.model_validate_json(raw_bytes)
            except Exception:
                corrupt = True
            if corrupt:
                raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "corrupt reconcile record")
            already += 1  # adjudicated earlier; never re-judged
            continue
        result = results.get(intent_id)
        if result is None:
            record = ReconcileRecord(
                intent_id=intent_id,
                adjudication=ReconcileAdjudication.RESULT_UNKNOWN.value,
                outcome=None,
                reconciled_at=datetime.now(timezone.utc),
            )
            marked_unknown += 1
        else:
            record = ReconcileRecord(
                intent_id=intent_id,
                adjudication=ReconcileAdjudication.RESULT_CONFIRMED.value,
                outcome=result.outcome,
                reconciled_at=datetime.now(timezone.utc),
            )
            confirmed += 1
        write_failed = False
        try:
            durable_commit(target_dir, reconcile_path.name, serialize_reconcile(record))
        except DurableWriteError:
            write_failed = True
        if write_failed:
            raise SafetyError(SafetyCode.AUDIT_WRITE_FAILED) from None
    return ReconcileSummary(
        scanned_intents=len(intents),
        confirmed=confirmed,
        marked_unknown=marked_unknown,
        already_adjudicated=already,
    )
