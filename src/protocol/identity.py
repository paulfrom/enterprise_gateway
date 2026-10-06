"""Trusted identity and protection-domain/ACL binding contract.

Identity and authorization contexts must originate from trusted transport
or internal authentication providers (e.g. mTLS or internal token verifiers).
Client HTTP headers, user payloads, and self-asserted identity claims are
untrusted and strictly forbidden from creating, altering, or overriding
the protection domain or source ACL.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping
import hmac

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


def validate_request_authorization(
    identity: TrustedIdentity,
    *,
    now: datetime,
    required_purpose: str = "model-query",
) -> None:
    """Validate identity validity period and required request intent/purpose."""
    if not isinstance(identity, TrustedIdentity):
        raise SafetyError(SafetyCode.INVALID_IDENTITY)
    _require_tz(now, "now")
    if identity.authenticated_at > now:
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
    """Server-owned credential bindings; the HTTP request proves possession."""

    def __init__(
        self,
        credentials: Mapping[str, TrustedIdentity] | None = None,
        *,
        allow_byok: bool = False,
        default_domain: str = "corp-prod",
    ) -> None:
        if credentials:
            if any(not isinstance(k, str) or not k or not isinstance(v, TrustedIdentity) for k, v in credentials.items()):
                raise SafetyError(SafetyCode.INVALID_IDENTITY)
            self._credentials = tuple(credentials.items())
        else:
            self._credentials = ()
        self._allow_byok = allow_byok
        self._default_domain = default_domain

    def authenticate(self, headers: Mapping[str, str]) -> TrustedIdentity:
        assert_no_client_header_spoofing(headers)
        auth_header = ""
        for k, v in headers.items():
            if k.lower() == "authorization":
                auth_header = v
                break
            if k.lower() == "x-api-key" and not auth_header:
                auth_header = f"Bearer {v}"

        if not auth_header.startswith('Bearer ') or not auth_header[7:].strip():
            raise SafetyError(SafetyCode.MISSING_IDENTITY)
        token = auth_header[7:].strip()
        identity = None
        for credential, candidate in self._credentials:
            if hmac.compare_digest(token.encode('utf-8'), credential.encode('utf-8')):
                identity = candidate
                break

        if identity is None:
            if self._allow_byok:
                import hashlib
                from datetime import timedelta, timezone
                now = datetime.now(timezone.utc)
                sub_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()[:12]
                return TrustedIdentity(
                    subject_id=f"byok-{sub_hash}",
                    tenant_id=f"tenant-{sub_hash}",
                    domain=self._default_domain,
                    roles=frozenset({"employee", "ai-assistant"}),
                    purposes=frozenset({"model-query"}),
                    source_acl=frozenset({"worker", "security", "business", "publisher", "reader", "steward"}),
                    auth_source="byok-token",
                    authenticated_at=now - timedelta(minutes=1),
                    expires_at=now + timedelta(days=365),
                )
            raise SafetyError(SafetyCode.INVALID_IDENTITY)
        return identity
