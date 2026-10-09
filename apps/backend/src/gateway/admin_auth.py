"""Single-admin password verification, server-side sessions, and FastAPI authorization.

Password verification uses salted scrypt (N=2^17, r=8, p=1, explicit maxmem);
derivation is heavy CPU work, so it always runs off the event loop through
``asyncio.to_thread`` behind a bounded semaphore. Unknown usernames and wrong
passwords take the same derivation path and raise the same
:class:`AdminLoginFailed`, so the comparison path carries no timing or message
difference. Login attempts are throttled per real connection peer (never
client-supplied forwarding headers) by the durable store.

Sessions are 32-byte opaque tokens carried by an HttpOnly cookie; only the
SHA-256 digest is persisted (see :mod:`gateway.admin_storage`). The fixed idle
deadline is 30 minutes (business requests refresh it, session polling does
not) and the fixed absolute deadline is 8 hours, both enforced by the server
clock. When storage fails, every path refuses: there is no key-based or
anonymous downgrade.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import secrets

from fastapi import HTTPException, Request

from gateway.admin_storage import (
    ABSOLUTE_TIMEOUT_SECONDS, IDLE_TIMEOUT_SECONDS, AdminCredentials, AdminStateStore,
    AdminStorageUnavailable, SessionInvalid, SessionRecord,
)

__all__ = [
    "ABSOLUTE_TIMEOUT_SECONDS", "IDLE_TIMEOUT_SECONDS", "ADMIN_USERNAME",
    "SESSION_COOKIE_NAME", "SCRYPT_N", "SCRYPT_R", "SCRYPT_P", "SCRYPT_DKLEN",
    "SALT_BYTES", "TOKEN_BYTES", "AdminAuthService", "AdminContext",
    "AdminLoginFailed", "AdminLoginThrottled", "initialize_admin_state",
]

ADMIN_USERNAME = "admin"
SESSION_COOKIE_NAME = "admin_session"
SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SALT_BYTES = 16
TOKEN_BYTES = 32
MAX_VERIFICATION_CONCURRENCY = 2
# scrypt needs ~128*N*r*p bytes; double it plus slack so OpenSSL never
# refuses the mandated work factors on a supported runtime.
_SCRYPT_MAXMEM = 2 * (128 * SCRYPT_N * SCRYPT_R * SCRYPT_P) + (1 << 20)
_DUMMY_SALT = bytes(SALT_BYTES)
_MAX_USERNAME_BYTES = 64
_MAX_PASSWORD_BYTES = 256
_UNKNOWN_SOURCE = "unknown"


class AdminLoginFailed(Exception):
    """Uniform credential refusal; indistinguishable for unknown user vs bad password."""

    def __init__(self) -> None:
        super().__init__("admin login failed")


class AdminLoginThrottled(Exception):
    """The source exhausted its per-minute failure budget; no verification ran."""

    def __init__(self) -> None:
        super().__init__("admin login throttled")


@dataclass(frozen=True, slots=True)
class AdminContext:
    """Server-constructed admin identity; clients can never mint one."""

    actor_id: str
    scope: str
    session_reference: str
    authenticated_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    _token_digest: str = field(repr=False, compare=False)


def _derive(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                          p=SCRYPT_P, dklen=SCRYPT_DKLEN, maxmem=_SCRYPT_MAXMEM)


def initialize_admin_state(store: AdminStateStore, password: str) -> None:
    """Create the admin credential once; proves the runtime can really derive."""
    if not isinstance(store, AdminStateStore):
        raise TypeError("store must be an AdminStateStore")
    if (not isinstance(password, str) or not password
            or len(password.encode("utf-8")) > _MAX_PASSWORD_BYTES):
        raise ValueError("invalid initial admin password")
    salt = secrets.token_bytes(SALT_BYTES)
    derived = _derive(password, salt)
    store.initialize(salt=salt, derived_key=derived, scrypt_n=SCRYPT_N, scrypt_r=SCRYPT_R,
                     scrypt_p=SCRYPT_P, dklen=SCRYPT_DKLEN)
    credentials = store.load_credentials()
    if not hmac.compare_digest(_derive(password, credentials.salt), credentials.derived_key):
        raise AdminStorageUnavailable()


def _token_digest(token: str) -> str:
    return hashlib.sha256(bytes.fromhex(token)).hexdigest()


def _valid_token_shape(token) -> bool:
    if not isinstance(token, str) or len(token) != TOKEN_BYTES * 2 or token != token.lower():
        return False
    try:
        bytes.fromhex(token)
    except ValueError:
        return False
    return True


class AdminAuthService:
    """Login, session lifecycle and the unified admin dependency for FastAPI routes."""

    def __init__(self, store: AdminStateStore, *, scope: str,
                 max_concurrent_verifications: int = MAX_VERIFICATION_CONCURRENCY) -> None:
        if not isinstance(store, AdminStateStore):
            raise TypeError("store must be an AdminStateStore")
        if (not isinstance(scope, str) or not scope.strip() or scope.strip() != scope
                or len(scope) > 256):
            raise ValueError("scope must be the deployment management scope")
        if type(max_concurrent_verifications) is not int or max_concurrent_verifications < 1:
            raise ValueError("max_concurrent_verifications must be a positive integer")
        self._store = store
        self._scope = scope
        self._verify_semaphore = asyncio.Semaphore(max_concurrent_verifications)

    def _context(self, record: SessionRecord) -> AdminContext:
        return AdminContext(
            actor_id=ADMIN_USERNAME, scope=self._scope,
            session_reference=record.digest[:16],
            authenticated_at=datetime.fromtimestamp(record.authenticated_at, timezone.utc),
            idle_expires_at=datetime.fromtimestamp(record.idle_expires_at, timezone.utc),
            absolute_expires_at=datetime.fromtimestamp(record.absolute_expires_at, timezone.utc),
            _token_digest=record.digest)

    async def _record_event(self, **event) -> None:
        await asyncio.to_thread(self._store.record_auth_event, **event)

    async def login(self, *, username: str, password: str, source: str) -> tuple[str, AdminContext]:
        """Verify credentials, issue a new token, and persist only its digest."""
        for value in (username, password, source):
            if not isinstance(value, str):
                raise TypeError("login fields must be strings")
        if (len(username.encode("utf-8")) > _MAX_USERNAME_BYTES
                or len(password.encode("utf-8")) > _MAX_PASSWORD_BYTES
                or not source or len(source) > 255):
            raise ValueError("login fields exceed bounded lengths")
        if not await asyncio.to_thread(self._store.login_permitted, source):
            await self._record_event(event="login", outcome="refused", source=source,
                                     category="throttled")
            raise AdminLoginThrottled()
        credentials = await asyncio.to_thread(self._store.load_credentials)
        matched = await self._verify(credentials, username, password)
        if not matched:
            await asyncio.to_thread(self._store.register_login_failure, source)
            await self._record_event(event="login", outcome="refused", source=source,
                                     category="invalid_credentials")
            raise AdminLoginFailed()
        await asyncio.to_thread(self._store.reset_login_failures, source)
        token = secrets.token_bytes(TOKEN_BYTES).hex()
        record = await asyncio.to_thread(self._store.create_session, _token_digest(token))
        await self._record_event(event="login", outcome="success", source=source,
                                 session_reference=record.digest[:16])
        return token, self._context(record)

    async def _verify(self, credentials: AdminCredentials, username: str,
                      password: str) -> bool:
        # Unknown usernames derive against a fixed dummy salt so the failure
        # path costs and behaves exactly like a wrong password.
        salt = credentials.salt if username == ADMIN_USERNAME else _DUMMY_SALT
        async with self._verify_semaphore:
            derived = await asyncio.to_thread(_derive, password, salt)
        return (username == ADMIN_USERNAME
                and hmac.compare_digest(derived, credentials.derived_key))

    async def authenticate(self, token: str | None, *, source: str,
                           refresh_idle: bool) -> AdminContext:
        """Validate a presented cookie token; uniform refusal, optional idle refresh."""
        if not isinstance(source, str) or not source:
            raise ValueError("source must be the connection peer address")
        if not _valid_token_shape(token):
            raise SessionInvalid("malformed")
        digest = _token_digest(token)
        try:
            record = await asyncio.to_thread(self._store.validate_session, digest, refresh_idle)
        except SessionInvalid as refused:
            await self._record_event(event="session", outcome="refused", source=source,
                                     category=refused.reason)
            raise
        return self._context(record)

    async def logout(self, context: AdminContext, *, source: str) -> None:
        """Persistently revoke the context's session; invalid sessions are refused."""
        if not isinstance(context, AdminContext):
            raise TypeError("context must be an AdminContext")
        await asyncio.to_thread(self._store.validate_session, context._token_digest, False)
        await asyncio.to_thread(self._store.revoke_session, context._token_digest)
        await self._record_event(event="logout", outcome="success", source=source,
                                 session_reference=context.session_reference)

    async def revalidate(self, context: AdminContext, *, source: str) -> AdminContext:
        """Re-check session and deadlines before synchronized body release; never refreshes."""
        if not isinstance(context, AdminContext):
            raise TypeError("context must be an AdminContext")
        try:
            record = await asyncio.to_thread(self._store.validate_session,
                                             context._token_digest, False)
        except SessionInvalid as refused:
            await self._record_event(event="session", outcome="refused", source=source,
                                     category=refused.reason)
            raise
        return self._context(record)

    def session_dependency(self, *, refresh_idle: bool):
        """FastAPI dependency: cookie token -> AdminContext; 401 invalid, 503 storage down.

        The source address is always the real connection peer; client-supplied
        forwarding or identity headers are never consulted.
        """
        if type(refresh_idle) is not bool:
            raise TypeError("refresh_idle must be a bool")

        async def dependency(request: Request) -> AdminContext:
            client = request.client
            source = client.host if client is not None and client.host else _UNKNOWN_SOURCE
            try:
                return await self.authenticate(request.cookies.get(SESSION_COOKIE_NAME),
                                               source=source, refresh_idle=refresh_idle)
            except SessionInvalid:
                raise HTTPException(status_code=401, detail="ADMIN_SESSION_INVALID") from None
            except AdminStorageUnavailable:
                raise HTTPException(status_code=503, detail="ADMIN_STORAGE_UNAVAILABLE") from None

        return dependency

    def require_admin(self):
        """Dependency variant for business reads/writes: refreshes the idle deadline."""
        return self.session_dependency(refresh_idle=True)

    def require_admin_poll(self):
        """Dependency variant for session polling: never refreshes the idle deadline."""
        return self.session_dependency(refresh_idle=False)
