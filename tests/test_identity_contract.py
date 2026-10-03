"""Unit and contract tests for C-02: Trusted identity and domain/ACL binding."""

import json
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
import unittest

from enterprise_gateway.identity import (
    FORBIDDEN_CLIENT_IDENTITY_HEADERS,
    IdentityError,
    IdentityErrorCode,
    TrustedIdentity,
    assert_no_client_header_spoofing,
    authorize_purpose,
    authorize_role,
    authorize_scope,
    authorize_source_acl,
    resolve_trusted_identity,
)
from enterprise_gateway.knowledge import Role, TrustedActor

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "C-02"


class IdentityContractTests(unittest.TestCase):
    def setUp(self) -> None:
        with open(FIXTURES_DIR / "valid_identity.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        self.valid_identity = TrustedIdentity(
            subject_id=data["subject_id"],
            tenant_id=data["tenant_id"],
            domain=data["domain"],
            roles=frozenset(data["roles"]),
            purposes=frozenset(data["purposes"]),
            source_acl=frozenset(data["source_acl"]),
            auth_source=data["auth_source"],
            authenticated_at=datetime.fromisoformat(data["authenticated_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
        )
        self.now = datetime(2026, 10, 3, 10, 30, 0, tzinfo=timezone.utc)

    def test_valid_identity_creation_and_attributes(self) -> None:
        self.assertEqual(self.valid_identity.subject_id, "user-1001")
        self.assertEqual(self.valid_identity.tenant_id, "tenant-alpha")
        self.assertEqual(self.valid_identity.domain, "finance-ops")
        self.assertIn("caller", self.valid_identity.roles)
        self.assertTrue(self.valid_identity.is_valid_at(self.now))

    def test_to_trusted_actor_bridge(self) -> None:
        actor = self.valid_identity.to_trusted_actor()
        self.assertIsInstance(actor, TrustedActor)
        self.assertEqual(actor.subject_id, "user-1001")
        self.assertEqual(actor.tenant_id, "tenant-alpha")
        self.assertEqual(actor.domain, "finance-ops")
        self.assertIn(Role.BUSINESS_REVIEWER, actor.roles)
        self.assertEqual(actor.purposes, self.valid_identity.purposes)

    def test_resolve_trusted_identity_success(self) -> None:
        clean_headers = {"content-type": "application/json", "accept": "application/json"}
        resolved = resolve_trusted_identity(
            self.valid_identity, clean_headers, now=self.now
        )
        self.assertIs(resolved, self.valid_identity)

    def test_missing_identity_context_fails_closed(self) -> None:
        with self.assertRaises(IdentityError) as ctx:
            resolve_trusted_identity(None, headers={})
        self.assertEqual(ctx.exception.code, IdentityErrorCode.MISSING_IDENTITY)

    def test_spoofed_header_user_id_rejected(self) -> None:
        with open(FIXTURES_DIR / "spoofed_header_user_id.json", "r", encoding="utf-8") as f:
            headers = json.load(f)["headers"]
        with self.assertRaises(IdentityError) as ctx:
            resolve_trusted_identity(self.valid_identity, headers=headers)
        self.assertEqual(ctx.exception.code, IdentityErrorCode.UNTRUSTED_HEADER_REJECTED)

    def test_spoofed_header_domain_rejected(self) -> None:
        with open(FIXTURES_DIR / "spoofed_header_domain.json", "r", encoding="utf-8") as f:
            headers = json.load(f)["headers"]
        with self.assertRaises(IdentityError) as ctx:
            resolve_trusted_identity(self.valid_identity, headers=headers)
        self.assertEqual(ctx.exception.code, IdentityErrorCode.UNTRUSTED_HEADER_REJECTED)

    def test_spoofed_header_acl_rejected(self) -> None:
        with open(FIXTURES_DIR / "spoofed_header_acl.json", "r", encoding="utf-8") as f:
            headers = json.load(f)["headers"]
        with self.assertRaises(IdentityError) as ctx:
            resolve_trusted_identity(self.valid_identity, headers=headers)
        self.assertEqual(ctx.exception.code, IdentityErrorCode.UNTRUSTED_HEADER_REJECTED)

    def test_all_forbidden_headers_rejected_case_insensitively(self) -> None:
        for hdr in FORBIDDEN_CLIENT_IDENTITY_HEADERS:
            with self.subTest(header=hdr):
                headers = {hdr.upper(): "spoofed-val"}
                with self.assertRaises(IdentityError) as ctx:
                    assert_no_client_header_spoofing(headers)
                self.assertEqual(ctx.exception.code, IdentityErrorCode.UNTRUSTED_HEADER_REJECTED)

    def test_authorize_scope_positive_and_mismatch(self) -> None:
        authorize_scope(self.valid_identity, "tenant-alpha", "finance-ops")
        
        with self.assertRaises(IdentityError) as ctx1:
            authorize_scope(self.valid_identity, "tenant-beta", "finance-ops")
        self.assertEqual(ctx1.exception.code, IdentityErrorCode.SCOPE_MISMATCH)

        with self.assertRaises(IdentityError) as ctx2:
            authorize_scope(self.valid_identity, "tenant-alpha", "hr-ops")
        self.assertEqual(ctx2.exception.code, IdentityErrorCode.SCOPE_MISMATCH)

    def test_authorize_source_acl_positive_and_access_denied(self) -> None:
        authorize_source_acl(self.valid_identity, frozenset(["user-1001", "other"]))

        with open(FIXTURES_DIR / "acl_forbidden.json", "r", encoding="utf-8") as f:
            forbidden_acl = frozenset(json.load(f)["source_acl"])
        with self.assertRaises(IdentityError) as ctx:
            authorize_source_acl(self.valid_identity, forbidden_acl)
        self.assertEqual(ctx.exception.code, IdentityErrorCode.ACCESS_DENIED)

    def test_authorize_purpose_positive_and_unauthorized(self) -> None:
        authorize_purpose(self.valid_identity, "invoice_processing")

        with open(FIXTURES_DIR / "unauthorized_purpose.json", "r", encoding="utf-8") as f:
            req_purpose = json.load(f)["required_purpose"]
        with self.assertRaises(IdentityError) as ctx:
            authorize_purpose(self.valid_identity, req_purpose)
        self.assertEqual(ctx.exception.code, IdentityErrorCode.UNAUTHORIZED_PURPOSE)

    def test_authorize_role_positive_and_missing(self) -> None:
        authorize_role(self.valid_identity, "caller")
        authorize_role(self.valid_identity, "business_reviewer")

        with self.assertRaises(IdentityError) as ctx:
            authorize_role(self.valid_identity, "security_reviewer")
        self.assertEqual(ctx.exception.code, IdentityErrorCode.MISSING_REQUIRED_ROLE)

    def test_expired_identity_rejected(self) -> None:
        future_now = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
        with self.assertRaises(IdentityError) as ctx:
            resolve_trusted_identity(self.valid_identity, {}, now=future_now)
        self.assertEqual(ctx.exception.code, IdentityErrorCode.AUTH_EXPIRED)

    def test_future_dated_identity_rejected(self) -> None:
        past_now = datetime(2026, 10, 3, 9, 0, 0, tzinfo=timezone.utc)
        with self.assertRaises(IdentityError) as ctx:
            resolve_trusted_identity(self.valid_identity, {}, now=past_now)
        self.assertEqual(ctx.exception.code, IdentityErrorCode.FUTURE_DATED_AUTH)

    def test_invalid_identity_fields_raise_controlled_error(self) -> None:
        base_kwargs = {
            "subject_id": "u1",
            "tenant_id": "t1",
            "domain": "d1",
            "roles": frozenset(["caller"]),
            "purposes": frozenset(["p1"]),
            "source_acl": frozenset(["u1"]),
            "auth_source": "mTLS",
            "authenticated_at": datetime(2026, 10, 3, 10, 0, 0, tzinfo=timezone.utc),
            "expires_at": datetime(2026, 10, 3, 11, 0, 0, tzinfo=timezone.utc),
        }
        # Empty subject_id
        kw = dict(base_kwargs, subject_id="  ")
        with self.assertRaises(IdentityError):
            TrustedIdentity(**kw)

        # Empty roles
        kw = dict(base_kwargs, roles=frozenset())
        with self.assertRaises(IdentityError):
            TrustedIdentity(**kw)

        # Expiry before auth
        kw = dict(base_kwargs, expires_at=datetime(2026, 10, 3, 9, 0, 0, tzinfo=timezone.utc))
        with self.assertRaises(IdentityError):
            TrustedIdentity(**kw)

        # Naive datetime
        kw = dict(base_kwargs, authenticated_at=datetime(2026, 10, 3, 10, 0, 0))
        with self.assertRaises(IdentityError):
            TrustedIdentity(**kw)

    def test_canary_error_message_does_not_echo_secret_values(self) -> None:
        canary = "CANARY_SECRET_AUTH_TOKEN_778899"
        headers = {"x-user-id": canary}
        try:
            resolve_trusted_identity(self.valid_identity, headers=headers)
        except IdentityError as exc:
            msg = str(exc)
            tb = traceback.format_exc()
            self.assertNotIn(canary, msg)
            self.assertNotIn(canary, tb)


if __name__ == "__main__":
    unittest.main()
