"""Trusted identity and protection-domain/ACL binding contract.

Identity and authorization contexts must originate from trusted transport
or internal authentication providers (e.g. mTLS or internal token verifiers).
Client HTTP headers, user payloads, and self-asserted identity claims are
untrusted and strictly forbidden from creating, altering, or overriding
the protection domain or source ACL.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Mapping

from .knowledge import Role, TrustedActor


class IdentityErrorCode(StrEnum):
    UNTRUSTED_HEADER_REJECTED = "untrusted_header_rejected"
    MISSING_IDENTITY = "missing_identity"
    INVALID_IDENTITY = "invalid_identity"
    SCOPE_MISMATCH = "scope_mismatch"
    ACCESS_DENIED = "access_denied"
    UNAUTHORIZED_PURPOSE = "unauthorized_purpose"
    MISSING_REQUIRED_ROLE = "missing_required_role"
    AUTH_EXPIRED = "auth_expired"
    FUTURE_DATED_AUTH = "future_dated_auth"


class IdentityError(ValueError):
    """Controlled identity failure; message never contains business text or credentials."""

    def __init__(self, code: IdentityErrorCode, detail: str | None = None) -> None:
        self.code = code
        message = f"identity contract violation: {code.value}"
        if detail:
            message = f"{message} ({detail})"
        super().__init__(message)


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
        raise IdentityError(IdentityErrorCode.INVALID_IDENTITY, f"{name} must include a timezone")


@dataclass(frozen=True, slots=True)
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

    def __post_init__(self) -> None:
        for field_name, value in [
            ("subject_id", self.subject_id),
            ("tenant_id", self.tenant_id),
            ("domain", self.domain),
            ("auth_source", self.auth_source),
        ]:
            if not isinstance(value, str) or not value.strip():
                raise IdentityError(
                    IdentityErrorCode.INVALID_IDENTITY, f"{field_name} must be a non-empty string"
                )

        for set_name, set_val in [
            ("roles", self.roles),
            ("purposes", self.purposes),
            ("source_acl", self.source_acl),
        ]:
            if not isinstance(set_val, frozenset) or not set_val or any(
                not isinstance(item, str) or not item.strip() for item in set_val
            ):
                raise IdentityError(
                    IdentityErrorCode.INVALID_IDENTITY,
                    f"{set_name} must be a non-empty immutable set of non-empty strings",
                )

        _require_tz(self.authenticated_at, "authenticated_at")
        _require_tz(self.expires_at, "expires_at")

        if self.expires_at <= self.authenticated_at:
            raise IdentityError(
                IdentityErrorCode.INVALID_IDENTITY, "expires_at must be strictly after authenticated_at"
            )

    def is_valid_at(self, now: datetime) -> bool:
        _require_tz(now, "now")
        return self.authenticated_at <= now < self.expires_at

    def to_trusted_actor(self) -> TrustedActor:
        """Bridge into knowledge domain TrustedActor when appropriate roles are held."""
        actor_roles = set()
        for r in self.roles:
            try:
                actor_roles.add(Role(r))
            except ValueError:
                pass
        return TrustedActor(
            subject_id=self.subject_id,
            tenant_id=self.tenant_id,
            domain=self.domain,
            roles=frozenset(actor_roles),
            purposes=self.purposes,
        )


def assert_no_client_header_spoofing(headers: Mapping[str, Any]) -> None:
    """Fail closed if client headers attempt to inject or modify identity parameters."""
    if not isinstance(headers, Mapping):
        raise IdentityError(IdentityErrorCode.INVALID_IDENTITY, "headers must be a mapping")
    for key in headers:
        if isinstance(key, str) and key.lower() in FORBIDDEN_CLIENT_IDENTITY_HEADERS:
            raise IdentityError(
                IdentityErrorCode.UNTRUSTED_HEADER_REJECTED,
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
        raise IdentityError(IdentityErrorCode.MISSING_IDENTITY)

    if not isinstance(authenticated_context, TrustedIdentity):
        raise IdentityError(IdentityErrorCode.INVALID_IDENTITY)

    if now is not None:
        _require_tz(now, "now")
        if authenticated_context.authenticated_at > now:
            raise IdentityError(IdentityErrorCode.FUTURE_DATED_AUTH)
        if authenticated_context.expires_at <= now:
            raise IdentityError(IdentityErrorCode.AUTH_EXPIRED)

    return authenticated_context


def authorize_scope(
    identity: TrustedIdentity, target_tenant_id: str, target_domain: str
) -> None:
    """Verify that identity protection domain matches target resource scope."""
    if not isinstance(identity, TrustedIdentity):
        raise IdentityError(IdentityErrorCode.INVALID_IDENTITY)
    if (identity.tenant_id, identity.domain) != (target_tenant_id, target_domain):
        raise IdentityError(IdentityErrorCode.SCOPE_MISMATCH)


def authorize_source_acl(identity: TrustedIdentity, source_acl: frozenset[str]) -> None:
    """Verify that identity subject is within the original source ACL."""
    if not isinstance(identity, TrustedIdentity):
        raise IdentityError(IdentityErrorCode.INVALID_IDENTITY)
    if not isinstance(source_acl, frozenset) or identity.subject_id not in source_acl:
        raise IdentityError(IdentityErrorCode.ACCESS_DENIED)


def authorize_purpose(identity: TrustedIdentity, required_purpose: str) -> None:
    """Verify that identity has authorization for the given purpose."""
    if not isinstance(identity, TrustedIdentity):
        raise IdentityError(IdentityErrorCode.INVALID_IDENTITY)
    if not isinstance(required_purpose, str) or required_purpose not in identity.purposes:
        raise IdentityError(IdentityErrorCode.UNAUTHORIZED_PURPOSE)


def authorize_role(identity: TrustedIdentity, required_role: str) -> None:
    """Verify that identity holds the required role."""
    if not isinstance(identity, TrustedIdentity):
        raise IdentityError(IdentityErrorCode.INVALID_IDENTITY)
    if not isinstance(required_role, str) or required_role not in identity.roles:
        raise IdentityError(IdentityErrorCode.MISSING_REQUIRED_ROLE)
