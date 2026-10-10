"""Durable single-admin state: scrypt material, session digests, login throttles, auth events.

The authoritative record lives on the persistent state volume, not in process
memory: every mutation is serialized through an OS advisory lock (same pattern
as :mod:`infra.file_kms`) and committed with :func:`infra.durable_write.durable_commit`
so concurrent gateway instances observe one consistent state and a crash never
leaves a half-written record. Only password salt + scrypt derived value and
SHA-256 session token digests are stored; plaintext passwords and session
tokens never reach this layer.

Session validity binds the persisted session generation: re-initializing the
admin state (the recovery path, since ``prepare_admin_state`` refuses to
overwrite) rebuilds the generation and thereby invalidates every session —
including ones revoked before a backup was taken.

Failure model: unavailable or corrupt credential/throttle state raises
:class:`AdminStorageUnavailable` and callers must refuse without downgrade;
a forged, tampered, expired or revoked session raises :class:`SessionInvalid`
whose static ``reason`` is safe for audit events, never for client echo.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import secrets
import time
from uuid import uuid4

from infra.durable_write import durable_commit
from infra.strict_json import parse_strict_json

__all__ = [
    "ABSOLUTE_TIMEOUT_SECONDS", "IDLE_TIMEOUT_SECONDS", "MAX_SESSIONS",
    "MAX_THROTTLE_SOURCES", "THROTTLE_MAX_FAILURES", "THROTTLE_WINDOW_SECONDS",
    "AdminCredentials", "AdminStateAlreadyExists", "AdminStateStore",
    "AdminStorageUnavailable", "SessionInvalid", "SessionRecord",
]

IDLE_TIMEOUT_SECONDS = 30 * 60
ABSOLUTE_TIMEOUT_SECONDS = 8 * 60 * 60
THROTTLE_WINDOW_SECONDS = 60
THROTTLE_MAX_FAILURES = 5
MAX_SESSIONS = 64
MAX_THROTTLE_SOURCES = 1024

_FORMAT_VERSION = 1
_ADMIN_FILE = "admin.json"
_THROTTLE_FILE = "throttle.json"
_LOCK_FILE = ".admin.lock"
_MAX_FILE_BYTES = 4096
_ADMIN_FIELDS = {"format_version", "username", "scrypt_n", "scrypt_r", "scrypt_p",
                 "dklen", "salt", "derived_key", "generation", "created_at"}
_SESSION_FIELDS = {"format_version", "digest", "generation", "authenticated_at",
                   "idle_expires_at", "absolute_expires_at", "revoked"}
_EVENTS = {"login", "logout", "session"}
_OUTCOMES = {"success", "refused"}
_CATEGORIES = {"invalid_credentials", "throttled", "unknown", "corrupt", "revoked",
               "idle_expired", "absolute_expired", "generation"}
_MIN_SCRYPT_N = 2 ** 14


class AdminStorageUnavailable(Exception):
    """Controlled storage failure; never carries business content."""

    def __init__(self, detail: str = "admin storage unavailable") -> None:
        super().__init__(detail)


class AdminStateAlreadyExists(Exception):
    """Initialization is one-shot; existing admin state is never overwritten."""

    def __init__(self) -> None:
        super().__init__("admin state already initialized")


class SessionInvalid(Exception):
    """Uniform session refusal; ``reason`` is a static audit category."""

    def __init__(self, reason: str) -> None:
        if reason not in {"malformed", "unknown", "corrupt", "revoked",
                          "idle_expired", "absolute_expired", "generation"}:
            raise ValueError("unregistered session refusal reason")
        self.reason = reason
        super().__init__("admin session refused")


@dataclass(frozen=True, slots=True)
class AdminCredentials:
    username: str
    salt: bytes
    derived_key: bytes
    scrypt_n: int
    scrypt_r: int
    scrypt_p: int
    dklen: int
    generation: str


@dataclass(frozen=True, slots=True)
class SessionRecord:
    digest: str
    generation: str
    authenticated_at: float
    idle_expires_at: float
    absolute_expires_at: float
    revoked: bool


def _unavailable(_kind=None):
    raise AdminStorageUnavailable()


def _json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _is_number(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def _is_hex(value, byte_length: int) -> bool:
    if not isinstance(value, str) or len(value) != byte_length * 2 or value != value.lower():
        return False
    try:
        return len(bytes.fromhex(value)) == byte_length
    except ValueError:
        return False


def _is_digest(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and _is_hex(value, 32)


class AdminStateStore:
    """One controlled admin directory; all mutations serialized by an OS lock."""

    def __init__(self, directory, *, now=time.time, max_sessions: int = MAX_SESSIONS,
                 max_throttle_sources: int = MAX_THROTTLE_SOURCES) -> None:
        if type(max_sessions) is not int or max_sessions < 1:
            raise ValueError("max_sessions must be a positive integer")
        if type(max_throttle_sources) is not int or max_throttle_sources < 1:
            raise ValueError("max_throttle_sources must be a positive integer")
        if not callable(now):
            raise TypeError("now must be a callable returning epoch seconds")
        self._now = now
        self._max_sessions = max_sessions
        self._max_throttle_sources = max_throttle_sources
        try:
            self._directory = Path(directory).absolute()
        except (OSError, TypeError):
            raise AdminStorageUnavailable() from None
        try:
            self._check_directory()
            self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._check_directory()
            if not self._directory.is_dir():
                raise _unavailable()
        except OSError:
            raise _unavailable() from None

    def _check_directory(self) -> None:
        for path in (self._directory, *self._directory.parents):
            if path.is_symlink():
                raise _unavailable()

    @contextmanager
    def _locked(self):
        handle = None
        acquired = False
        try:
            self._check_directory()
            path = self._directory / _LOCK_FILE
            if path.is_symlink():
                raise _unavailable()
            fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            handle = os.fdopen(fd, "r+b", buffering=0)
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                deadline = time.monotonic() + 30
                while True:
                    try:
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise _unavailable() from None
                        time.sleep(0.02)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
            acquired = True
            yield
        except (OSError, ValueError):
            raise _unavailable() from None
        finally:
            if handle is not None:
                if acquired:
                    handle.seek(0)
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                handle.close()

    def _read_file(self, path: Path, reject) -> dict:
        try:
            if path.is_symlink():
                reject()
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(fd, "rb") as stream:
                raw = stream.read(_MAX_FILE_BYTES + 1)
        except OSError:
            reject()
        if len(raw) > _MAX_FILE_BYTES:
            reject()
        document = parse_strict_json(raw, reject=lambda kind: reject())
        if not isinstance(document, dict):
            reject()
        return document

    def _read_admin(self) -> AdminCredentials:
        document = self._read_file(self._directory / _ADMIN_FILE, _unavailable)
        if set(document) != _ADMIN_FIELDS:
            raise _unavailable()
        if (document["format_version"] != _FORMAT_VERSION
                or document["username"] != "admin"
                or type(document["scrypt_n"]) is not int or document["scrypt_n"] < _MIN_SCRYPT_N
                or document["scrypt_n"] & (document["scrypt_n"] - 1)
                or type(document["scrypt_r"]) is not int or document["scrypt_r"] < 1
                or type(document["scrypt_p"]) is not int or document["scrypt_p"] < 1
                or type(document["dklen"]) is not int or document["dklen"] < 16
                or not _is_number(document["created_at"])):
            raise _unavailable()
        salt = document["salt"]
        if (not isinstance(salt, str) or len(salt) < 32 or len(salt) % 2
                or not _is_hex(salt, len(salt) // 2)
                or not _is_hex(document["derived_key"], document["dklen"])):
            raise _unavailable()
        salt = bytes.fromhex(salt)
        if len(salt) < 16:
            raise _unavailable()
        if not _is_hex(document["generation"], 16):
            raise _unavailable()
        return AdminCredentials(username="admin", salt=salt,
                                derived_key=bytes.fromhex(document["derived_key"]),
                                scrypt_n=document["scrypt_n"], scrypt_r=document["scrypt_r"],
                                scrypt_p=document["scrypt_p"], dklen=document["dklen"],
                                generation=document["generation"])

    def _session_path(self, digest: str) -> Path:
        return self._directory / "sessions" / (digest + ".json")

    def _read_session(self, digest: str) -> SessionRecord:
        def corrupt(_kind=None):
            raise SessionInvalid("corrupt")
        path = self._session_path(digest)
        try:
            exists = path.exists()
        except OSError:
            raise _unavailable() from None
        if not exists:
            raise SessionInvalid("unknown")
        document = self._read_file(path, corrupt)
        if set(document) != _SESSION_FIELDS or document["format_version"] != _FORMAT_VERSION:
            corrupt()
        if (document["digest"] != digest or not _is_hex(document["generation"], 16)
                or type(document["revoked"]) is not bool
                or not all(_is_number(document[key]) for key in
                           ("authenticated_at", "idle_expires_at", "absolute_expires_at"))):
            corrupt()
        return SessionRecord(digest=digest, generation=document["generation"],
                             authenticated_at=float(document["authenticated_at"]),
                             idle_expires_at=float(document["idle_expires_at"]),
                             absolute_expires_at=float(document["absolute_expires_at"]),
                             revoked=document["revoked"])

    def _commit_session(self, record: SessionRecord) -> None:
        body = {"format_version": _FORMAT_VERSION, "digest": record.digest,
                "generation": record.generation,
                "authenticated_at": record.authenticated_at,
                "idle_expires_at": record.idle_expires_at,
                "absolute_expires_at": record.absolute_expires_at,
                "revoked": record.revoked}
        sessions = self._directory / "sessions"
        if sessions.is_symlink():
            raise _unavailable()
        sessions.mkdir(mode=0o700, exist_ok=True)
        try:
            durable_commit(sessions, record.digest + ".json", _json(body))
        except OSError:
            raise _unavailable() from None

    def _cleanup_sessions(self, now: float) -> int:
        sessions = self._directory / "sessions"
        if sessions.is_symlink():
            raise _unavailable()
        live = 0
        try:
            entries = list(sessions.glob("*.json")) if sessions.is_dir() else []
        except OSError:
            raise _unavailable() from None
        for path in entries:
            digest = path.name[:-5]
            try:
                record = self._read_session(digest) if _is_digest(digest) else None
            except SessionInvalid:
                record = None
            if record is None:
                continue
            deadline = record.absolute_expires_at
            if now >= deadline or record.revoked:
                try:
                    path.unlink()
                except OSError:
                    raise _unavailable() from None
            else:
                live += 1
        return live

    def initialize(self, *, salt: bytes, derived_key: bytes, scrypt_n: int, scrypt_r: int,
                   scrypt_p: int, dklen: int) -> None:
        """Create the single admin credential once; existing state is never replaced."""
        if (not isinstance(salt, bytes) or len(salt) < 16
                or not isinstance(derived_key, bytes) or len(derived_key) != dklen
                or type(dklen) is not int or dklen < 16
                or type(scrypt_n) is not int or scrypt_n < _MIN_SCRYPT_N
                or scrypt_n & (scrypt_n - 1)
                or type(scrypt_r) is not int or scrypt_r < 1
                or type(scrypt_p) is not int or scrypt_p < 1):
            raise ValueError("invalid scrypt material for admin state")
        with self._locked():
            admin_path = self._directory / _ADMIN_FILE
            if admin_path.exists() or admin_path.is_symlink():
                raise AdminStateAlreadyExists()
            body = {"format_version": _FORMAT_VERSION, "username": "admin",
                    "scrypt_n": scrypt_n, "scrypt_r": scrypt_r, "scrypt_p": scrypt_p,
                    "dklen": dklen, "salt": salt.hex(), "derived_key": derived_key.hex(),
                    "generation": secrets.token_bytes(16).hex(),
                    "created_at": self._now()}
            try:
                durable_commit(self._directory, _ADMIN_FILE, _json(body))
            except OSError:
                raise _unavailable() from None

    def load_credentials(self) -> AdminCredentials:
        with self._locked():
            return self._read_admin()

    def create_session(self, token_digest: str) -> SessionRecord:
        """Persist a new session for a token digest; only the digest is stored."""
        if not _is_digest(token_digest):
            raise ValueError("session token digest must be 32 lowercase hex bytes")
        now = self._now()
        with self._locked():
            credentials = self._read_admin()
            live = self._cleanup_sessions(now)
            if live >= self._max_sessions:
                raise _unavailable()
            record = SessionRecord(digest=token_digest, generation=credentials.generation,
                                   authenticated_at=now, idle_expires_at=now + IDLE_TIMEOUT_SECONDS,
                                   absolute_expires_at=now + ABSOLUTE_TIMEOUT_SECONDS,
                                   revoked=False)
            self._commit_session(record)
            return record

    def validate_session(self, token_digest: str, refresh_idle: bool) -> SessionRecord:
        """Validate a session digest; ``refresh_idle`` durably extends the idle deadline."""
        if not _is_digest(token_digest):
            raise SessionInvalid("malformed")
        if type(refresh_idle) is not bool:
            raise TypeError("refresh_idle must be a bool")
        with self._locked():
            credentials = self._read_admin()
            record = self._read_session(token_digest)
            if record.generation != credentials.generation:
                raise SessionInvalid("generation")
            if record.revoked:
                raise SessionInvalid("revoked")
            now = self._now()
            if now >= record.absolute_expires_at:
                raise SessionInvalid("absolute_expired")
            if now >= record.idle_expires_at:
                raise SessionInvalid("idle_expired")
            if refresh_idle:
                record = SessionRecord(digest=record.digest, generation=record.generation,
                                       authenticated_at=record.authenticated_at,
                                       idle_expires_at=now + IDLE_TIMEOUT_SECONDS,
                                       absolute_expires_at=record.absolute_expires_at,
                                       revoked=False)
                self._commit_session(record)
            return record

    def revoke_session(self, token_digest: str) -> None:
        """Persistently revoke a session; the tombstone is idempotent and durable."""
        if not _is_digest(token_digest):
            raise SessionInvalid("malformed")
        with self._locked():
            record = self._read_session(token_digest)
            if record.revoked:
                return
            self._commit_session(SessionRecord(
                digest=record.digest, generation=record.generation,
                authenticated_at=record.authenticated_at,
                idle_expires_at=record.idle_expires_at,
                absolute_expires_at=record.absolute_expires_at, revoked=True))

    def _read_throttle(self) -> dict:
        path = self._directory / _THROTTLE_FILE
        try:
            if not path.exists():
                return {}
        except OSError:
            raise _unavailable() from None
        document = self._read_file(path, _unavailable)
        if (set(document) != {"format_version", "sources"}
                or document["format_version"] != _FORMAT_VERSION
                or not isinstance(document["sources"], dict)):
            raise _unavailable()
        sources = {}
        for source, failures in document["sources"].items():
            if (not isinstance(source, str) or not source or len(source) > 255
                    or not isinstance(failures, list) or len(failures) > THROTTLE_MAX_FAILURES
                    or not all(_is_number(moment) for moment in failures)):
                raise _unavailable()
            sources[source] = [float(moment) for moment in failures]
        return sources

    def _write_throttle(self, sources: dict) -> None:
        try:
            durable_commit(self._directory, _THROTTLE_FILE,
                           _json({"format_version": _FORMAT_VERSION, "sources": sources}))
        except OSError:
            raise _unavailable() from None

    @staticmethod
    def _validate_source(source) -> str:
        if not isinstance(source, str) or not source or source.strip() != source or len(source) > 255:
            raise ValueError("source address must be a non-empty bounded string")
        return source

    def _pruned_throttle(self, now: float) -> dict:
        cutoff = now - THROTTLE_WINDOW_SECONDS
        return {source: [moment for moment in failures if moment > cutoff]
                for source, failures in self._read_throttle().items()
                if any(moment > cutoff for moment in failures)}

    def login_permitted(self, source: str) -> bool:
        """True while the source has fewer than five recorded failures in the window."""
        source = self._validate_source(source)
        with self._locked():
            sources = self._pruned_throttle(self._now())
            if len(sources.get(source, ())) >= THROTTLE_MAX_FAILURES:
                return False
            if sources != self._read_throttle():
                self._write_throttle(sources)
            return True

    def register_login_failure(self, source: str) -> None:
        self._validate_source(source)
        with self._locked():
            now = self._now()
            sources = self._pruned_throttle(now)
            failures = sources.get(source)
            if failures is None:
                if len(sources) >= self._max_throttle_sources:
                    raise _unavailable()
                failures = sources[source] = []
            if len(failures) >= THROTTLE_MAX_FAILURES:
                return
            failures.append(now)
            self._write_throttle(sources)

    def reset_login_failures(self, source: str) -> None:
        self._validate_source(source)
        with self._locked():
            sources = self._pruned_throttle(self._now())
            if source in sources:
                del sources[source]
                self._write_throttle(sources)

    def record_auth_event(self, *, event: str, outcome: str, source: str,
                          category: str | None = None,
                          session_reference: str | None = None) -> None:
        """Append one durable auth event; never carries passwords, tokens or cookies."""
        if event not in _EVENTS or outcome not in _OUTCOMES:
            raise ValueError("unregistered admin auth event")
        if category is not None and category not in _CATEGORIES:
            raise ValueError("unregistered admin auth event category")
        self._validate_source(source)
        if session_reference is not None and not (isinstance(session_reference, str)
                                                  and len(session_reference) == 16
                                                  and _is_hex(session_reference, 8)):
            raise ValueError("session reference must be a short digest prefix")
        body = {"format_version": _FORMAT_VERSION, "event": event, "outcome": outcome,
                "category": category, "source": source,
                "session_reference": session_reference, "at": self._now()}
        events = self._directory / "events"
        if events.is_symlink():
            raise _unavailable()
        events.mkdir(mode=0o700, exist_ok=True)
        try:
            durable_commit(events, uuid4().hex + ".json", _json(body))
        except OSError:
            raise _unavailable() from None
