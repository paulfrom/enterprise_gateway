"""B2 admin direct read: single-record plaintext release with paired durable traces.

DESIGN §4.2: the admin review service reads evidence through the trusted
catalog only — it never accepts arbitrary ciphertext or paths. ``list_records``
and ``get_record`` return catalog metadata alone. ``read_plaintext`` walks a
strict order and releases nothing on any refusal path:

1. ``revalidate()`` — the injected session checkpoint (deadline/expiry/revocation).
2. Catalog entry exists, matches the context tenant/domain, and is live
   (status ``available`` and not past ``retention_until``).
3. ``AUDIT_READ_ATTEMPTED`` is durably committed (independent file, fixed
   code, no plaintext/keys); a trace-write failure raises
   ``AUDIT_WRITE_FAILED`` and releases nothing.
4. The current evidence file is re-verified: controlled-root resolution
   (no symlink escape), sha256 against the catalog, envelope parse, and the
   header AAD components (domain/purpose/record_id/format_version) against
   the catalog entry. Any deviation is ``AUDIT_EVIDENCE_CORRUPTED``.
5. ``decrypt_record`` — decryption success alone never releases plaintext.
6. ``revalidate()`` again.
7. The real outcome is durably committed: ``AUDIT_READ_RELEASED`` or
   ``AUDIT_READ_REJECTED:<reason>``. A failed result trace raises
   ``AUDIT_WRITE_FAILED`` and discards the plaintext.
8. Lifecycle and the monotonic ``deadline`` budget are re-checked; time
   spent in KMS or trace writes counts against the budget. On breach the
   plaintext is discarded and ``AUDIT_ACCESS_REJECTED`` is raised.
9. Exactly one plaintext is returned.

Rejections before step 3 (session, unknown record, scope mismatch, expired)
leave no events: nothing was attempted against a validated target. Once the
attempt is durable, every outcome gets its result event; a crash between
attempt and result reads back as ``unknown``, never as success. Events
record actor, session digest, a sha256 of the record handle, scope, and
time — never record ids, plaintext, or key material.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn
from uuid import uuid4

from audit._store import AuditStoreError, LockedDirectory, commit_guarded, read_capped
from audit.catalog import (
    MAX_CATALOG_ENTRY_BYTES,
    MAX_CATALOG_SCAN,
    MAX_EVIDENCE_BYTES,
    _SAFE_TOKEN_RE,
    _is_plain_relative_name,
    CatalogEntry,
    parse_catalog_entry,
)
from infra.durable_write import DurableWriteError
from infra.envelope_crypto import (
    FORMAT_VERSION,
    KmsProvider,
    decrypt_record,
    parse_record,
)
from infra.errors import SafetyCode, SafetyError

__all__ = ["AdminAuditContext", "AdminReviewService"]

EVENT_FORMAT_VERSION = 1
MAX_ACCESS_LOG_BYTES = 64 * 1024 * 1024
MAX_ACCESS_EVENT_BYTES = 64 * 1024
DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100

_EVENT_ATTEMPTED = "AUDIT_READ_ATTEMPTED"
_EVENT_RELEASED = "AUDIT_READ_RELEASED"
_EVENT_REJECTED = "AUDIT_READ_REJECTED"

_REASON_EVIDENCE_CORRUPTED = "evidence_corrupted"
_REASON_AAD_MISMATCH = "aad_mismatch"
_REASON_DECRYPTION_FAILED = "decryption_failed"
_REASON_KMS_UNAVAILABLE = "kms_unavailable"
_REASON_INVALID_WRAPPED_KEY = "invalid_wrapped_key"
_REASON_INVALID_CIPHERTEXT = "invalid_ciphertext"
_REASON_SESSION_EXPIRED = "session_expired"
_REASON_DEADLINE_EXCEEDED = "deadline_exceeded"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True, slots=True)
class AdminAuditContext:
    """One admin read attempt: identity, scope, and a monotonic deadline."""

    actor_id: str
    session_digest: str
    tenant_id: str
    domain: str
    deadline: float

    def __post_init__(self) -> None:
        for name in ("actor_id", "session_digest", "tenant_id", "domain"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip() or len(value) > 256:
                raise ValueError(f"{name} must be a non-empty bounded string")
        if (
            isinstance(self.deadline, bool)
            or not isinstance(self.deadline, (int, float))
            or not math.isfinite(self.deadline)
        ):
            raise ValueError("deadline must be a finite monotonic timestamp")


class AdminReviewService:
    """Single-record admin review over the trusted catalog (DESIGN §4.2)."""

    def __init__(
        self,
        *,
        catalog_directory: Path,
        evidence_root: Path,
        kms,
        revalidate: Callable[[], None],
        review_purpose: str,
        access_log_directory: Path,
    ) -> None:
        if not isinstance(catalog_directory, (str, Path)):
            raise TypeError("catalog_directory must be a str or Path")
        if not isinstance(evidence_root, (str, Path)):
            raise TypeError("evidence_root must be a str or Path")
        if not isinstance(kms, KmsProvider):
            raise TypeError("kms must be a KmsProvider")
        if not callable(revalidate):
            raise TypeError("revalidate must be callable")
        if not isinstance(review_purpose, str) or not review_purpose.strip():
            raise ValueError("review_purpose must be a non-empty string")
        if not isinstance(access_log_directory, (str, Path)):
            raise TypeError("access_log_directory must be a str or Path")
        self._evidence_root = Path(evidence_root).absolute()
        self._kms = kms
        self._revalidate = revalidate
        self._review_purpose = review_purpose
        storage_failed = False
        try:
            self._catalog = LockedDirectory(catalog_directory, create=True)
            self._access_log = LockedDirectory(access_log_directory, create=True)
        except AuditStoreError:
            storage_failed = True
        if storage_failed:
            raise SafetyError(SafetyCode.AUDIT_WRITE_FAILED) from None

    # -- metadata views ------------------------------------------------------

    def list_records(
        self,
        *,
        tenant_id: str,
        domain: str,
        purpose: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        cursor: str | None = None,
    ) -> tuple[list[CatalogEntry], str | None]:
        """One stable page of catalog metadata; no plaintext, no decryption."""
        tenant_id = self._require_scope("tenant_id", tenant_id)
        domain = self._require_scope("domain", domain)
        if purpose is not None and (
            not isinstance(purpose, str) or not purpose.strip() or len(purpose) > 256
        ):
            raise ValueError("purpose must be a non-empty bounded string")
        if type(limit) is not int or isinstance(limit, bool):
            raise TypeError("limit must be an integer")
        if limit < 1:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "limit must be positive")
        limit = min(limit, MAX_PAGE_SIZE)
        if cursor is not None:
            if not isinstance(cursor, str):
                raise TypeError("cursor must be a string or None")
            if not _SAFE_TOKEN_RE.fullmatch(cursor):
                raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "cursor is not a stable token")
        entries: list[CatalogEntry] = []
        with self._catalog.locked():
            scanned = 0
            for path in sorted(self._catalog.path.glob("*.catalog.json")):
                scanned += 1
                if scanned > MAX_CATALOG_SCAN:
                    raise SafetyError(SafetyCode.AUDIT_ACCESS_REJECTED, "catalog scan budget exceeded")
                if path.is_symlink():
                    continue
                raw = read_capped(path, MAX_CATALOG_ENTRY_BYTES)
                if raw is None:
                    continue
                entry = parse_catalog_entry(raw)
                if entry is None or entry.record_id != path.name[: -len(".catalog.json")]:
                    continue  # corrupt or desynced catalog state stays invisible
                if entry.purpose != self._review_purpose:
                    continue
                if entry.tenant_id != tenant_id or entry.domain != domain:
                    continue
                if purpose is not None and entry.purpose != purpose:
                    continue
                entries.append(entry)
        entries.sort(key=lambda item: item.record_id)
        if cursor is not None:
            entries = [entry for entry in entries if entry.record_id > cursor]
        page = entries[:limit]
        next_cursor = page[-1].record_id if len(entries) > limit and page else None
        return page, next_cursor

    def get_record(self, record_id: str, *, tenant_id: str, domain: str) -> CatalogEntry:
        """One catalog entry's metadata, scoped to the caller's tenant/domain."""
        tenant_id = self._require_scope("tenant_id", tenant_id)
        domain = self._require_scope("domain", domain)
        entry = self._load_entry(record_id)
        if (
            entry is None
            or entry.purpose != self._review_purpose
            or entry.tenant_id != tenant_id
            or entry.domain != domain
        ):
            raise SafetyError(SafetyCode.AUDIT_RECORD_NOT_FOUND)
        return entry

    # -- direct read ----------------------------------------------------------

    def read_plaintext(self, record_id: str, *, context: AdminAuditContext) -> bytes:
        """Release exactly one plaintext under the §4.2 order, or refuse."""
        if not isinstance(context, AdminAuditContext):
            raise TypeError("context must be an AdminAuditContext")
        if not isinstance(record_id, str):
            raise TypeError("record_id must be a string")
        # 1. Session checkpoint.
        self._check_session()
        # Early budget guard: a request whose deadline is already spent never
        # touches storage or KMS (the formal check is step 8).
        self._check_deadline(context)
        # 2. Trusted catalog entry, caller scope, live lifecycle.
        entry = self._load_entry(record_id)
        if (
            entry is None
            or entry.purpose != self._review_purpose
            or entry.tenant_id != context.tenant_id
            or entry.domain != context.domain
        ):
            raise SafetyError(SafetyCode.AUDIT_RECORD_NOT_FOUND)
        if entry.status != "available" or not _utcnow() < entry.retention_until:
            raise SafetyError(SafetyCode.AUDIT_RECORD_UNAVAILABLE)
        # 3. Durable attempt trace; failure blocks the read before any decrypt.
        attempt_at = self._log_access(context, record_id, _EVENT_ATTEMPTED)
        # 4. Current file, digest, and header — the catalog is a hint, not proof.
        record = self._verified_record(entry, context, record_id, attempt_at)
        # 5. Decrypt (KMS time counts against the deadline budget).
        try:
            plaintext = decrypt_record(self._kms, record)
        except SafetyError as exc:
            reason = {
                SafetyCode.KMS_UNAVAILABLE: _REASON_KMS_UNAVAILABLE,
                SafetyCode.DECRYPTION_FAILED: _REASON_DECRYPTION_FAILED,
                SafetyCode.INVALID_WRAPPED_KEY: _REASON_INVALID_WRAPPED_KEY,
                SafetyCode.INVALID_CIPHERTEXT: _REASON_INVALID_CIPHERTEXT,
            }.get(exc.code, _REASON_DECRYPTION_FAILED)
            self._reject(context, record_id, attempt_at, reason, exc.code)
        # 6. Session checkpoint again, immediately after decryption.
        try:
            self._check_session()
        except SafetyError:
            self._reject(context, record_id, attempt_at, _REASON_SESSION_EXPIRED,
                         SafetyCode.AUDIT_ACCESS_REJECTED)
        # 7. Durable real outcome; a failed result trace discards the plaintext.
        if self._deadline_blown(context):
            self._reject(context, record_id, attempt_at, _REASON_DEADLINE_EXCEEDED,
                         SafetyCode.AUDIT_ACCESS_REJECTED)
        self._log_access(context, record_id, _EVENT_RELEASED, attempt_at=attempt_at)
        # 8. Lifecycle and monotonic budget, rechecked immediately before release.
        if entry.status != "available" or not _utcnow() < entry.retention_until:
            raise SafetyError(SafetyCode.AUDIT_ACCESS_REJECTED) from None
        if self._deadline_blown(context):
            raise SafetyError(SafetyCode.AUDIT_ACCESS_REJECTED) from None
        return plaintext

    # -- internals ------------------------------------------------------------

    @staticmethod
    def _require_scope(name: str, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string")
        if not value.strip() or len(value) > 256:
            raise ValueError(f"{name} must be a non-empty bounded string")
        return value

    def _check_session(self) -> None:
        try:
            self._revalidate()
        except SafetyError:
            raise
        except Exception:
            raise SafetyError(SafetyCode.AUDIT_ACCESS_REJECTED) from None

    @staticmethod
    def _deadline_blown(context: AdminAuditContext) -> bool:
        return time.monotonic() >= context.deadline

    def _check_deadline(self, context: AdminAuditContext) -> None:
        if self._deadline_blown(context):
            raise SafetyError(SafetyCode.AUDIT_ACCESS_REJECTED) from None

    def _load_entry(self, record_id: str) -> CatalogEntry | None:
        if not isinstance(record_id, str):
            return None
        if not _SAFE_TOKEN_RE.fullmatch(record_id):
            return None
        path = self._catalog.path / f"{record_id}.catalog.json"
        try:
            if not path.is_file():
                return None
        except OSError:
            return None
        raw = read_capped(path, MAX_CATALOG_ENTRY_BYTES)
        if raw is None:
            return None
        entry = parse_catalog_entry(raw)
        if entry is None or entry.record_id != record_id:
            return None
        return entry

    def _verified_record(self, entry: CatalogEntry, context: AdminAuditContext,
                         record_id: str, attempt_at: float):
        name = entry.evidence_path
        resolved = None
        if _is_plain_relative_name(name):
            candidate = self._evidence_root / name
            try:
                if not candidate.is_symlink() and candidate.is_file():
                    maybe = candidate.resolve()
                    if maybe.is_relative_to(self._evidence_root.resolve()):
                        resolved = maybe
            except OSError:
                resolved = None
        if resolved is None:
            self._reject(context, record_id, attempt_at, _REASON_EVIDENCE_CORRUPTED,
                         SafetyCode.AUDIT_EVIDENCE_CORRUPTED)
        data = read_capped(resolved, MAX_EVIDENCE_BYTES)
        if data is None:
            self._reject(context, record_id, attempt_at, _REASON_EVIDENCE_CORRUPTED,
                         SafetyCode.AUDIT_EVIDENCE_CORRUPTED)
        if hashlib.sha256(data).hexdigest() != entry.evidence_sha256:
            self._reject(context, record_id, attempt_at, _REASON_EVIDENCE_CORRUPTED,
                         SafetyCode.AUDIT_EVIDENCE_CORRUPTED)
        try:
            record = parse_record(data)
        except SafetyError:
            self._reject(context, record_id, attempt_at, _REASON_EVIDENCE_CORRUPTED,
                         SafetyCode.AUDIT_EVIDENCE_CORRUPTED)
        if (
            record.format_version != FORMAT_VERSION
            or record.record_id != entry.record_id
            or record.domain != entry.domain
            or record.purpose != entry.purpose
        ):
            self._reject(context, record_id, attempt_at, _REASON_AAD_MISMATCH,
                         SafetyCode.AUDIT_EVIDENCE_CORRUPTED)
        return record

    def _reject(self, context: AdminAuditContext, record_id: str, attempt_at: float,
                reason: str, code: SafetyCode) -> NoReturn:
        """Durable rejected-result trace, then the controlled refusal.

        If the result trace itself cannot be persisted, ``AUDIT_WRITE_FAILED``
        propagates instead: the refusal is real, but nothing is fabricated.
        """
        self._log_access(context, record_id, f"{_EVENT_REJECTED}:{reason}",
                         attempt_at=attempt_at)
        raise SafetyError(code) from None

    def _log_access(self, context: AdminAuditContext, record_id: str, event: str,
                    *, attempt_at: float | None = None) -> float:
        """Durable access event; returns the event timestamp.

        Fixed codes and digests only — never record ids, plaintext, or keys.
        """
        now = time.time()
        body = {
            "format_version": EVENT_FORMAT_VERSION,
            "event": event,
            "actor": context.actor_id,
            "session_digest": context.session_digest,
            "record_sha256": hashlib.sha256(record_id.encode("utf-8")).hexdigest(),
            "tenant_id": context.tenant_id,
            "domain": context.domain,
            "at": now,
        }
        if attempt_at is not None:
            body["attempt_at"] = attempt_at
        data = _json(body)
        if len(data) > MAX_ACCESS_EVENT_BYTES:
            raise SafetyError(SafetyCode.AUDIT_WRITE_FAILED) from None
        write_failed = False
        try:
            with self._access_log.locked():
                commit_guarded(
                    self._access_log.path,
                    f"{uuid4().hex}.json",
                    data,
                    max_bytes=MAX_ACCESS_LOG_BYTES,
                )
        except (OSError, DurableWriteError):
            write_failed = True
        if write_failed:
            raise SafetyError(SafetyCode.AUDIT_WRITE_FAILED) from None
        return now
