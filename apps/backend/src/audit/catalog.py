"""B2 trusted audit catalog: controlled background builder, exact record links.

DESIGN §4.1: a background catalog builder — never on the
:class:`enterprise_gateway.evidence_gate.EvidenceGate.admit` egress path —
scans only the assembler-fixed intent/evidence roots and appends one durable
catalog document per evidence record. A record enters the catalog only
through its persisted, server-preallocated link: the intent document must
carry the exact ``evidence_record_id`` (the same identifier
:class:`enterprise_gateway.evidence_gate.EvidenceSpec` committed), the
evidence file must live inside the controlled evidence root (no symlink
escape), and the envelope header must agree with the link on record_id and
domain. Time-neighbourhood or filename-order guesses are never used.

Retention comes from server-authoritative sources only: the lifecycle fields
persisted in the intent submission when present, otherwise the injected
``lifecycle`` policy callable (``record_id -> (retention_until,
policy_version)``). Client-side values can never mint retention. Legacy
intents without a record_id link, tenant link, or lifecycle basis stay
invisible — the builder neither catalogues them nor counts them as backlog.

Writes are serialized by an OS advisory lock and bounded by an independent
quota (:data:`MAX_CATALOG_BYTES`) so the catalog cannot crowd out mandatory
intent/evidence/spool retention space. A catalog write failure raises
``SafetyError(AUDIT_WRITE_FAILED)``; the builder never fabricates success.

Crash windows fail closed: catalog-without-evidence and
evidence-without-catalog are both refusal states for
:mod:`audit.admin_reader`, which re-verifies the current file, digest, and
header on every read instead of trusting ``status == "available"``.
"""

from __future__ import annotations

import hashlib
from itertools import islice
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from audit._store import AuditStoreError, LockedDirectory, commit_guarded, read_capped
from audit.audit_intent import ReleaseIntent
from infra.durable_write import DurableWriteError
from infra.envelope_crypto import FORMAT_VERSION, parse_record
from infra.errors import SafetyCode, SafetyError
from infra.strict_json import parse_strict_json

__all__ = [
    "CatalogEntry",
    "AuditCatalogBuilder",
    "MAX_CATALOG_BYTES",
    "MAX_CATALOG_ENTRY_BYTES",
    "MAX_CATALOG_SCAN",
    "MAX_EVIDENCE_BYTES",
    "MAX_INTENT_BYTES",
    "parse_catalog_entry",
]

CATALOG_FORMAT_VERSION = 1
MAX_CATALOG_BYTES = 64 * 1024 * 1024
MAX_CATALOG_ENTRY_BYTES = 64 * 1024
MAX_CATALOG_SCAN = 20_000
MAX_INTENT_BYTES = 1024 * 1024
MAX_EVIDENCE_BYTES = 256 * 1024 * 1024

_CATALOG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.catalog\.json$")
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ENTRY_FIELDS = {
    "format_version", "record_id", "tenant_id", "domain", "purpose", "bucket",
    "intent_id", "evidence_path", "evidence_sha256", "bytes_written",
    "created_at", "retention_until", "lifecycle_policy_version", "status",
}
_STATUSES = frozenset({"available", "corrupted", "expired", "purged"})


class _Skip(Exception):
    """Internal: untrusted on-disk state collapses to a skip."""


def _skip(_kind=None):
    raise _Skip()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    """One trusted evidence record as catalogued for admin review.

    ``evidence_path`` is relative to the controlled evidence root.
    ``created_at`` is the authoritative intent time. ``status`` is the
    lifecycle state at catalogue time; the reader re-derives liveness on
    every access and never treats ``available`` as permanently readable.
    """

    tenant_id: str
    record_id: str
    purpose: str
    domain: str
    bucket: str
    intent_id: str
    evidence_path: str
    evidence_sha256: str
    bytes_written: int
    created_at: datetime
    retention_until: datetime
    lifecycle_policy_version: str
    status: str


def _parse_aware(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    if moment.tzinfo is None or moment.utcoffset() is None:
        return None
    return moment


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _is_plain_relative_name(value: object) -> bool:
    return isinstance(value, str) and bool(_SAFE_TOKEN_RE.fullmatch(value))


def parse_catalog_entry(raw: bytes) -> CatalogEntry | None:
    """Strict-parse one catalog document; any deviation means untrusted."""
    if not isinstance(raw, (bytes, str)):
        return None
    try:
        document = parse_strict_json(raw, reject=_skip)
    except _Skip:
        return None
    if not isinstance(document, dict) or set(document) != _ENTRY_FIELDS:
        return None
    if document["format_version"] != CATALOG_FORMAT_VERSION:
        return None
    for name in ("record_id", "tenant_id", "domain", "purpose", "bucket",
                 "intent_id", "lifecycle_policy_version", "status"):
        if not _is_plain_relative_name(document[name]):
            return None
    if document["status"] not in _STATUSES:
        return None
    if not _is_plain_relative_name(document["evidence_path"]):
        return None
    if not _is_sha256(document["evidence_sha256"]):
        return None
    if type(document["bytes_written"]) is not int or document["bytes_written"] < 0:
        return None
    created_at = _parse_aware(document["created_at"])
    retention_until = _parse_aware(document["retention_until"])
    if created_at is None or retention_until is None:
        return None
    return CatalogEntry(
        tenant_id=document["tenant_id"],
        record_id=document["record_id"],
        purpose=document["purpose"],
        domain=document["domain"],
        bucket=document["bucket"],
        intent_id=document["intent_id"],
        evidence_path=document["evidence_path"],
        evidence_sha256=document["evidence_sha256"],
        bytes_written=document["bytes_written"],
        created_at=created_at,
        retention_until=retention_until,
        lifecycle_policy_version=document["lifecycle_policy_version"],
        status=document["status"],
    )


def _entry_document(entry: CatalogEntry) -> bytes:
    return _json({
        "format_version": CATALOG_FORMAT_VERSION,
        "record_id": entry.record_id,
        "tenant_id": entry.tenant_id,
        "domain": entry.domain,
        "purpose": entry.purpose,
        "bucket": entry.bucket,
        "intent_id": entry.intent_id,
        "evidence_path": entry.evidence_path,
        "evidence_sha256": entry.evidence_sha256,
        "bytes_written": entry.bytes_written,
        "created_at": entry.created_at.isoformat(),
        "retention_until": entry.retention_until.isoformat(),
        "lifecycle_policy_version": entry.lifecycle_policy_version,
        "status": entry.status,
    })


def _resolve_inside(root: Path, name: str) -> Path | None:
    """Resolve ``root/name``; ``None`` unless it is a real file inside ``root``."""
    if not _is_plain_relative_name(name):
        return None
    candidate = root / name
    try:
        if candidate.is_symlink() or not candidate.is_file():
            return None
        resolved = candidate.resolve()
        root_resolved = root.resolve()
    except OSError:
        return None
    if not resolved.is_relative_to(root_resolved):
        return None
    return resolved


class AuditCatalogBuilder:
    """Controlled background primitive; the lifecycle loop itself belongs to T4.

    ``build_once()`` processes up to ``batch_limit`` new trusted records per
    call and is idempotent by ``record_id``: restarts rescan freely and never
    duplicate an existing catalog document. ``backlog()`` reports how many
    trusted intent+evidence pairs are not yet catalogued — management-visible
    freshness, never fabricated.
    """

    def __init__(
        self,
        *,
        intent_root: Path,
        evidence_root: Path,
        catalog_directory: Path,
        lifecycle: Callable[[str], tuple[datetime, str]],
        batch_limit: int = 200,
    ) -> None:
        if not isinstance(intent_root, (str, Path)):
            raise TypeError("intent_root must be a str or Path")
        if not isinstance(evidence_root, (str, Path)):
            raise TypeError("evidence_root must be a str or Path")
        if not isinstance(catalog_directory, (str, Path)):
            raise TypeError("catalog_directory must be a str or Path")
        if not callable(lifecycle):
            raise TypeError("lifecycle must be callable")
        if type(batch_limit) is not int or batch_limit < 1:
            raise ValueError("batch_limit must be a positive integer")
        self._intent_root = Path(intent_root).absolute()
        self._evidence_root = Path(evidence_root).absolute()
        self._lifecycle = lifecycle
        self._batch_limit = batch_limit
        catalog_failed = False
        try:
            self._catalog = LockedDirectory(catalog_directory, create=True)
        except AuditStoreError:
            catalog_failed = True
        if catalog_failed:
            raise SafetyError(SafetyCode.AUDIT_WRITE_FAILED) from None

    def build_once(self) -> int:
        """Catalogue up to ``batch_limit`` new trusted records; return that count."""
        committed = 0
        with self._catalog.locked():
            cataloged = self._cataloged_ids()
            for intent_path in self._scan_paths(self._intent_root, "*.intent.json"):
                if committed >= self._batch_limit:
                    break
                entry = self._trusted_entry(intent_path)
                if entry is None or entry.record_id in cataloged:
                    continue
                write_failed = False
                try:
                    commit_guarded(
                        self._catalog.path,
                        f"{entry.record_id}.catalog.json",
                        _entry_document(entry),
                        max_bytes=MAX_CATALOG_BYTES,
                    )
                except (OSError, DurableWriteError):
                    write_failed = True
                if write_failed:
                    raise SafetyError(SafetyCode.AUDIT_WRITE_FAILED) from None
                cataloged.add(entry.record_id)
                committed += 1
        return committed

    def backlog(self) -> int:
        """Trusted intent+evidence pairs not yet in the catalog."""
        pending = 0
        with self._catalog.locked():
            cataloged = self._cataloged_ids()
            for intent_path in self._scan_paths(self._intent_root, "*.intent.json"):
                entry = self._trusted_entry(intent_path)
                if entry is not None and entry.record_id not in cataloged:
                    pending += 1
        return pending

    @staticmethod
    def _scan_paths(root: Path, pattern: str) -> list[Path]:
        """Refuse an incomplete scan instead of reporting false freshness."""
        scan_failed = False
        try:
            paths = list(islice(root.glob(pattern), MAX_CATALOG_SCAN + 1))
        except OSError:
            scan_failed = True
        if scan_failed or len(paths) > MAX_CATALOG_SCAN:
            raise SafetyError(SafetyCode.AUDIT_WRITE_FAILED) from None
        return sorted(paths)

    def _cataloged_ids(self) -> set[str]:
        cataloged: set[str] = set()
        for path in self._scan_paths(self._catalog.path, "*.catalog.json"):
            if not _CATALOG_NAME_RE.fullmatch(path.name) or path.is_symlink():
                continue
            raw = read_capped(path, MAX_CATALOG_ENTRY_BYTES)
            if raw is None:
                continue
            entry = parse_catalog_entry(raw)
            if entry is not None and entry.record_id == path.name[: -len(".catalog.json")]:
                cataloged.add(entry.record_id)
        return cataloged

    def _trusted_entry(self, intent_path: Path) -> CatalogEntry | None:
        """Validate one intent+evidence pair; ``None`` unless fully trusted."""
        raw = read_capped(intent_path, MAX_INTENT_BYTES)
        if raw is None:
            return None
        try:
            intent = ReleaseIntent.model_validate_json(raw)
        except ValueError:
            return None
        if intent.tenant_id is None or intent.evidence_record_id is None:
            return None  # no persisted exact link: legacy records stay invisible
        record_id = intent.evidence_record_id
        evidence_name = f"{record_id}.evidence.json"
        evidence_path = _resolve_inside(self._evidence_root, evidence_name)
        if evidence_path is None:
            return None
        data = read_capped(evidence_path, MAX_EVIDENCE_BYTES)
        if data is None:
            return None
        try:
            record = parse_record(data)
        except SafetyError:
            return None
        if record.format_version != FORMAT_VERSION:
            return None
        if record.record_id != record_id or record.domain != intent.domain:
            return None  # cross-linked or foreign evidence: not this intent's record
        retention_until = intent.evidence_retention_until
        policy_version = intent.evidence_lifecycle_policy_version
        if retention_until is None or policy_version is None:
            lifecycle_retention, lifecycle_policy = self._lifecycle(record_id)
            if (
                not isinstance(lifecycle_retention, datetime)
                or lifecycle_retention.tzinfo is None
                or lifecycle_retention.utcoffset() is None
                or not isinstance(lifecycle_policy, str)
                or not lifecycle_policy.strip()
            ):
                return None  # the policy oracle refused: no fabricated lifecycle
            if retention_until is None:
                retention_until = lifecycle_retention
            if policy_version is None:
                policy_version = lifecycle_policy
        status = "available" if _utcnow() < retention_until else "expired"
        return CatalogEntry(
            tenant_id=intent.tenant_id,
            record_id=record_id,
            purpose=record.purpose,
            domain=intent.domain,
            bucket=record.bucket,
            intent_id=intent.intent_id,
            evidence_path=evidence_name,
            evidence_sha256=hashlib.sha256(data).hexdigest(),
            bytes_written=len(data),
            created_at=intent.recorded_at,
            retention_until=retention_until,
            lifecycle_policy_version=policy_version,
            status=status,
        )
