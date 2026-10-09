"""BYOK possession creates restricted source context, never enterprise identity."""

from dataclasses import replace
from datetime import timedelta
import unittest

from infra.errors import SafetyCode, SafetyError
from protocol import identity as contract


class ByokSourceTests(unittest.TestCase):
    def authenticator(self, **overrides):
        fields = dict(domain="processing-domain", tenant_id="processing-tenant",
                      correlation_key=b"synthetic-source-key-32-bytes!!!!")
        fields.update(overrides)
        return contract.ByokAuthenticator(**fields)

    def source(self, **headers):
        return self.authenticator().authenticate(headers or {"authorization": "Bearer synthetic-key-a"})

    def test_bearer_is_restricted_source_not_enterprise_identity(self):
        source = self.source()
        self.assertIsInstance(source, contract.UnverifiedSourceContext)
        self.assertNotIsInstance(source, contract.TrustedIdentity)
        self.assertFalse(hasattr(source, "subject_id"))
        self.assertFalse(hasattr(source, "roles"))
        self.assertEqual("unverified-byok", source.source_provenance)
        self.assertEqual(frozenset({"processing-domain:restricted-candidate"}), source.source_acl)
        self.assertEqual(frozenset({"model-query"}), source.purposes)
        self.assertNotIn("synthetic-key-a", repr(source))
        self.assertNotIn("synthetic-key-a", source.source_id)

    def test_x_api_key_and_bearer_have_same_correlation(self):
        bearer = self.source()
        api_key = self.source(**{"X-API-Key": "synthetic-key-a"})
        self.assertEqual(bearer.source_id, api_key.source_id)

    def test_matching_dual_credentials_have_same_restricted_source(self):
        source = self.source(**{"Authorization": "Bearer synthetic-key-a",
                                "X-API-Key": "synthetic-key-a"})
        self.assertEqual(self.source().source_id, source.source_id)
        self.assertEqual(self.source().source_acl, source.source_acl)
        self.assertFalse(hasattr(source, "roles"))

    def test_key_rotation_never_changes_processing_scope_or_grants_ownership(self):
        first = self.source()
        rotated = self.source(**{"authorization": "Bearer synthetic-key-b"})
        self.assertNotEqual(first.source_id, rotated.source_id)
        self.assertEqual((first.tenant_id, first.domain, first.source_acl),
                         (rotated.tenant_id, rotated.domain, rotated.source_acl))
        self.assertFalse(hasattr(rotated, "owner_id"))

    def test_correlation_is_keyed_and_cannot_use_bare_token_hash(self):
        other = self.authenticator(correlation_key=b"other-synthetic-32-byte-key!!!!!!").authenticate(
            {"authorization": "Bearer synthetic-key-a"})
        self.assertNotEqual(self.source().source_id, other.source_id)

    def test_missing_empty_malformed_and_conflicting_credentials_rejected(self):
        for headers in ({}, {"authorization": ""}, {"x-api-key": ""},
                        {"authorization": "Bearer "}, {"authorization": "Basic abc"},
                        {"authorization": "Bearer  key"}, {"authorization": "Bearer key "},
                        {"authorization": "Bearer key\n"}, {"x-api-key": "has whitespace"},
                        {"authorization": "Bearer a", "x-api-key": "b"},
                        {"authorization": "Basic a", "x-api-key": "a"},
                        {"authorization": "Bearer a", "x-api-key": ""},
                        {"authorization": "Bearer ", "x-api-key": "a"},
                        {"authorization": "Bearer has whitespace", "x-api-key": "has whitespace"},
                        {"Authorization": "Bearer a", "authorization": "Bearer a"},
                        {"X-API-Key": "a", "x-api-key": "a"},
                        {"authorization": 123}):
            with self.subTest(headers=headers), self.assertRaises(SafetyError):
                self.authenticator().authenticate(headers)

    def test_all_internal_claim_headers_rejected(self):
        for header in contract.FORBIDDEN_CLIENT_IDENTITY_HEADERS:
            with self.subTest(header=header), self.assertRaises(SafetyError) as caught:
                self.source(**{"authorization": "Bearer synthetic-key-a", header.upper(): "spoof"})
            self.assertEqual(SafetyCode.UNTRUSTED_HEADER_REJECTED, caught.exception.code)

    def test_short_lived_source_only_authorizes_model_query(self):
        source = self.source()
        self.assertLessEqual(source.expires_at - source.received_at, timedelta(minutes=5))
        contract.validate_request_authorization(source, now=source.received_at)
        for now, purpose, code in ((source.received_at - timedelta(seconds=1), "model-query", SafetyCode.FUTURE_DATED_AUTH),
                                   (source.expires_at, "model-query", SafetyCode.AUTH_EXPIRED),
                                   (source.received_at, "knowledge-admin", SafetyCode.UNAUTHORIZED_PURPOSE)):
            with self.subTest(code=code), self.assertRaises(SafetyError) as caught:
                contract.validate_request_authorization(source, now=now, required_purpose=purpose)
            self.assertEqual(code, caught.exception.code)

    def test_unverified_source_cannot_use_enterprise_authorization(self):
        source = self.source()
        for authorize in (lambda: contract.authorize_role(source, "employee"),
                          lambda: contract.authorize_source_acl(source, frozenset({source.source_id})),
                          lambda: contract.resolve_trusted_identity(source),
                          lambda: contract.authorize_scope(source, source.tenant_id, source.domain)):
            with self.assertRaises(SafetyError):
                authorize()

    def test_source_context_cannot_be_changed_to_broad_acl_or_admin_purpose(self):
        source = self.source()
        for update in ({"source_acl": frozenset({"reader", "publisher"})},
                       {"purposes": frozenset({"knowledge-admin"})},
                       {"source_provenance": "trusted"}):
            with self.subTest(update=update), self.assertRaises(SafetyError):
                replace(source, **update)

    def test_server_scope_and_correlation_key_required(self):
        for override in ({"domain": ""}, {"tenant_id": ""}, {"correlation_key": b"short"},
                         {"correlation_key": "plaintext-config"}):
            with self.subTest(override=override), self.assertRaises(SafetyError):
                self.authenticator(**override)

    def test_enterprise_authenticator_has_no_byok_mode(self):
        with self.assertRaises(TypeError):
            contract.EnterpriseAuthenticator(allow_byok=True)


if __name__ == "__main__":
    unittest.main()
