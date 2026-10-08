"""Trusted identity and unverified BYOK source contracts.

Identity and authorization contexts must originate from trusted transport
or internal authentication providers (e.g. mTLS or internal token verifiers).
Client HTTP headers, user payloads, and self-asserted identity claims are
untrusted and strictly forbidden from creating, altering, or overriding
the protection domain or source ACL.

Supplier credential possession produces a restricted processing source context;
it never creates an enterprise identity or knowledge ownership.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
import hmac
import hashlib
import re

from infra.errors import SafetyCode, SafetyError


FORBIDDEN_CLIENT_IDENTITY_HEADERS: frozenset[str] = frozenset({
    "x-user-id",
    "x-subject-id",
    "x-tenant-id",
    "x-domain",
    "x-protection-domain",
    "x-roles",
    "x-role",
    "x-original-acl",
    "x-acl",
    "x-purpose",
    "x-purposes",
    "x-authenticated-user",
    "x-client-role",
})


def _require_tz(dt: datetime, name: str) -> None:
    if not isinstance(dt, datetime) or dt.tzinfo is None or dt.utcoffset() is None:
        raise SafetyError(SafetyCode.INVALID_IDENTITY, f"{name} must include a timezone")


@dataclass(frozen=True, slots=True, init=False)
class TrustedIdentity:
    """An authenticated, immutable caller identity bound to a protection domain.

    Cannot be constructed from client-provided headers or untrusted query params.
    """

    subject_id: str
    tenant_id: str
    domain: str
    roles: frozenset[str]
    purposes: frozenset[str]
    source_acl: frozenset[str]
    auth_source: str
    authenticated_at: datetime
    expires_at: datetime

    def __init__(
        self,
        subject_id: str,
        tenant_id: str,
        domain: str,
        roles: frozenset[str],
        purposes: frozenset[str],
        source_acl: frozenset[str] | None = None,
        auth_source: str = "",
        authenticated_at: datetime | None = None,
        expires_at: datetime | None = None,
    ) -> None:
        resolved_acl = (
            frozenset({f"{domain}:restricted-candidate"})
            if source_acl is None or not source_acl
            else source_acl
        )
        object.__setattr__(self, "subject_id", subject_id)
        object.__setattr__(self, "tenant_id", tenant_id)
        object.__setattr__(self, "domain", domain)
        object.__setattr__(self, "roles", roles)
        object.__setattr__(self, "purposes", purposes)
        object.__setattr__(self, "source_acl", resolved_acl)
        object.__setattr__(self, "auth_source", auth_source)
        object.__setattr__(self, "authenticated_at", authenticated_at)
        object.__setattr__(self, "expires_at", expires_at)
        self._validate()

    def _validate(self) -> None:
        for field_name, value in [
            ("subject_id", self.subject_id),
            ("tenant_id", self.tenant_id),
            ("domain", self.domain),
            ("auth_source", self.auth_source),
        ]:
            if not isinstance(value, str) or not value.strip():
                raise SafetyError(
                    SafetyCode.INVALID_IDENTITY, f"{field_name} must be a non-empty string"
                )

        for set_name, set_val in [
            ("roles", self.roles),
            ("purposes", self.purposes),
            ("source_acl", self.source_acl),
        ]:
            if not isinstance(set_val, frozenset) or not set_val or any(
                not isinstance(item, str) or not item.strip() for item in set_val
            ):
                raise SafetyError(
                    SafetyCode.INVALID_IDENTITY,
                    f"{set_name} must be a non-empty immutable set of non-empty strings",
                )

        _require_tz(self.authenticated_at, "authenticated_at")
        _require_tz(self.expires_at, "expires_at")

        if self.expires_at <= self.authenticated_at:
            raise SafetyError(
                SafetyCode.INVALID_IDENTITY, "expires_at must be strictly after authenticated_at"
            )

    def is_valid_at(self, now: datetime) -> bool:
        _require_tz(now, "now")
        return self.authenticated_at <= now < self.expires_at


@dataclass(frozen=True, slots=True)
class UnverifiedSourceContext:
    """Server-scoped BYOK request source; not an authenticated enterprise member.

    Correlation identifies credential reuse only. Neither the correlation ID nor
    the processing tenant asserts ownership or grants knowledge-reading rights.
    """

    source_id: str
    tenant_id: str
    domain: str
    received_at: datetime
    expires_at: datetime
    purposes: frozenset[str]
    source_acl: frozenset[str]
    source_provenance: str = "unverified-byok"

    def __post_init__(self) -> None:
        if (not isinstance(self.source_id, str)
                or re.fullmatch(r"byok:[0-9a-f]{64}", self.source_id) is None):
            raise SafetyError(SafetyCode.INVALID_IDENTITY)
        if any(not isinstance(value, str) or not value.strip()
               for value in (self.tenant_id, self.domain)):
            raise SafetyError(SafetyCode.INVALID_IDENTITY)
        if (self.source_provenance != "unverified-byok"
                or self.purposes != frozenset({"model-query"})
                or not isinstance(self.purposes, frozenset)
                or self.source_acl != frozenset({f"{self.domain}:restricted-candidate"})
                or not isinstance(self.source_acl, frozenset)):
            raise SafetyError(SafetyCode.INVALID_IDENTITY)
        _require_tz(self.received_at, "received_at")
        _require_tz(self.expires_at, "expires_at")
        if not timedelta(0) < self.expires_at - self.received_at <= timedelta(minutes=5):
            raise SafetyError(SafetyCode.INVALID_IDENTITY)

    def is_valid_at(self, now: datetime) -> bool:
        _require_tz(now, "now")
        return self.received_at <= now < self.expires_at


def validate_request_authorization(
    identity: TrustedIdentity | UnverifiedSourceContext,
    *,
    now: datetime,
    required_purpose: str = "model-query",
) -> None:
    """Validate request validity and purpose without promoting BYOK to identity."""
    if not isinstance(identity, (TrustedIdentity, UnverifiedSourceContext)):
        raise SafetyError(SafetyCode.INVALID_IDENTITY)
    _require_tz(now, "now")
    issued_at = (identity.authenticated_at if isinstance(identity, TrustedIdentity)
                 else identity.received_at)
    if issued_at > now:
        raise SafetyError(SafetyCode.FUTURE_DATED_AUTH, "identity is future-dated")
    if identity.expires_at <= now:
        raise SafetyError(SafetyCode.AUTH_EXPIRED, "identity has expired")
    if required_purpose not in identity.purposes:
        raise SafetyError(
            SafetyCode.UNAUTHORIZED_PURPOSE,
            f"identity lacks required purpose: {required_purpose}",
        )


def assert_no_client_header_spoofing(headers: Mapping[str, Any]) -> None:
    """Fail closed if client headers attempt to inject or modify identity parameters."""
    if not isinstance(headers, Mapping):
        raise SafetyError(SafetyCode.INVALID_IDENTITY, "headers must be a mapping")
    for key in headers:
        if isinstance(key, str) and key.lower() in FORBIDDEN_CLIENT_IDENTITY_HEADERS:
            raise SafetyError(
                SafetyCode.UNTRUSTED_HEADER_REJECTED,
                f"untrusted header rejected: {key.lower()}",
            )


def resolve_trusted_identity(
    authenticated_context: TrustedIdentity | None,
    headers: Mapping[str, Any] | None = None,
    *,
    now: datetime | None = None,
) -> TrustedIdentity:
    """Enforce trusted authentication context and reject untrusted header claims."""
    if headers is not None:
        assert_no_client_header_spoofing(headers)

    if authenticated_context is None:
        raise SafetyError(SafetyCode.MISSING_IDENTITY)

    if not isinstance(authenticated_context, TrustedIdentity):
        raise SafetyError(SafetyCode.INVALID_IDENTITY)

    if now is not None:
        _require_tz(now, "now")
        if authenticated_context.authenticated_at > now:
            raise SafetyError(SafetyCode.FUTURE_DATED_AUTH)
        if authenticated_context.expires_at <= now:
            raise SafetyError(SafetyCode.AUTH_EXPIRED)

    return authenticated_context


def authorize_scope(
    identity: TrustedIdentity, target_tenant_id: str, target_domain: str
) -> None:
    """Verify that identity protection domain matches target resource scope."""
    if not isinstance(identity, TrustedIdentity):
        raise SafetyError(SafetyCode.INVALID_IDENTITY)
    if (identity.tenant_id, identity.domain) != (target_tenant_id, target_domain):
        raise SafetyError(SafetyCode.SCOPE_MISMATCH)


def authorize_source_acl(identity: TrustedIdentity, source_acl: frozenset[str]) -> None:
    """Verify that identity subject is within the original source ACL."""
    if not isinstance(identity, TrustedIdentity):
        raise SafetyError(SafetyCode.INVALID_IDENTITY)
    if not isinstance(source_acl, frozenset) or identity.subject_id not in source_acl:
        raise SafetyError(SafetyCode.ACCESS_DENIED)


def authorize_purpose(identity: TrustedIdentity, required_purpose: str) -> None:
    """Verify that identity has authorization for the given purpose."""
    if not isinstance(identity, TrustedIdentity):
        raise SafetyError(SafetyCode.INVALID_IDENTITY)
    if not isinstance(required_purpose, str) or required_purpose not in identity.purposes:
        raise SafetyError(SafetyCode.UNAUTHORIZED_PURPOSE)


def authorize_role(identity: TrustedIdentity, required_role: str) -> None:
    """Verify that identity holds the required role."""
    if not isinstance(identity, TrustedIdentity):
        raise SafetyError(SafetyCode.INVALID_IDENTITY)
    if not isinstance(required_role, str) or required_role not in identity.roles:
        raise SafetyError(SafetyCode.MISSING_REQUIRED_ROLE)


class EnterpriseAuthenticator:
    """Trusted internal credentials for enterprise audit review, not BYOK ingress."""

    def __init__(
        self,
        credentials: Mapping[str, TrustedIdentity],
    ) -> None:
        if not isinstance(credentials, Mapping) or any(
                not isinstance(key, str) or not key or not isinstance(value, TrustedIdentity)
                for key, value in credentials.items()):
            raise SafetyError(SafetyCode.INVALID_IDENTITY)
        self._credentials = tuple(credentials.items())

    def authenticate(self, headers: Mapping[str, str]) -> TrustedIdentity:
        token = _request_credential(headers)
        identity = None
        for credential, candidate in self._credentials:
            if hmac.compare_digest(token.encode('utf-8'), credential.encode('utf-8')):
                identity = candidate
                break

        if identity is None:
            raise SafetyError(SafetyCode.INVALID_IDENTITY)
        return identity


def _request_credential(headers: Mapping[str, str]) -> str:
    """Select exactly one canonical request credential; never echo secret data."""
    assert_no_client_header_spoofing(headers)
    credentials = [(name.lower(), value) for name, value in headers.items()
                   if isinstance(name, str) and name.lower() in {"authorization", "x-api-key"}]
    if not credentials:
        raise SafetyError(SafetyCode.MISSING_IDENTITY)
    if len(credentials) != 1:
        raise SafetyError(SafetyCode.INVALID_IDENTITY)
    name, value = credentials[0]
    if not isinstance(value, str):
        raise SafetyError(SafetyCode.INVALID_IDENTITY)
    token = value
    if name == "authorization":
        if not value.startswith("Bearer "):
            raise SafetyError(SafetyCode.INVALID_IDENTITY)
        token = value[7:]
    if not token:
        raise SafetyError(SafetyCode.MISSING_IDENTITY)
    if any(ord(char) < 33 or ord(char) > 126 for char in token):
        raise SafetyError(SafetyCode.INVALID_IDENTITY)
    return token


class ByokAuthenticator:
    """Create restricted processing context from client supplier credentials."""

    def __init__(self, *, domain: str, tenant_id: str, correlation_key: bytes) -> None:
        if any(not isinstance(value, str) or not value.strip() for value in (domain, tenant_id)):
            raise SafetyError(SafetyCode.INVALID_IDENTITY)
        if not isinstance(correlation_key, bytes) or len(correlation_key) < 32:
            raise SafetyError(SafetyCode.INVALID_HMAC_KEY)
        self._domain = domain
        self._tenant_id = tenant_id
        self._correlation_key = correlation_key

    def authenticate(self, headers: Mapping[str, str]) -> UnverifiedSourceContext:
        token = _request_credential(headers)
        # Purpose separation prevents this HMAC from being confused with masking.
        correlation = hmac.new(self._correlation_key, b"byok-source\0" + token.encode("ascii"),
                               hashlib.sha256).hexdigest()
        now = datetime.now(timezone.utc)
        return UnverifiedSourceContext(
            source_id=f"byok:{correlation}", tenant_id=self._tenant_id, domain=self._domain,
            received_at=now, expires_at=now + timedelta(minutes=5),
            purposes=frozenset({"model-query"}),
            source_acl=frozenset({f"{self._domain}:restricted-candidate"}),
        )
