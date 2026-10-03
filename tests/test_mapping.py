"""Executable mapping contracts, not evidence of a working detection gateway."""

import unittest
from unittest.mock import patch

from enterprise_gateway.errors import SafetyError
from enterprise_gateway.mapping import MappingContext
from enterprise_gateway.spans import redact_text


KEY = bytes(range(32))


class MappingTests(unittest.TestCase):
    def context(self, scope="domain-a", version="v1"):
        return MappingContext(scope, version, KEY)

    def assert_blocked(self, code, operation):
        with self.assertRaises(SafetyError) as failure:
            operation()
        self.assertEqual(code, failure.exception.code)

    def test_exact_roundtrip_preserves_distinct_spellings(self):
        originals = ["A", "Ａ", " A ", "é", "é", "甲公司", '含"引号\\及\n换行']
        with self.context() as context:
            tokens = [context.token_for("ORG", value) for value in originals]
            self.assertEqual(len(originals), len(set(tokens)))
            for original, token in zip(originals, tokens):
                self.assertEqual(original, context.restore(token))
            self.assertEqual(tokens[0], context.token_for("ORG", originals[0]))

    def test_scope_type_key_version_and_key_separate_tokens(self):
        with self.context() as first, self.context("domain-b") as second, self.context(version="v2") as third:
            token = first.token_for("ORG", "甲")
            alternatives = [second.token_for("ORG", "甲"), third.token_for("ORG", "甲"), first.token_for("PERSON", "甲")]
            self.assertNotIn(token, alternatives)
            self.assert_blocked("UNKNOWN_TOKEN", lambda: second.restore(token))
        with MappingContext("domain-a", "v1", b"x" * 32) as changed_key:
            self.assertNotEqual(token, changed_key.token_for("ORG", "甲"))

    def test_canonical_framing_prevents_concatenation_ambiguity(self):
        with self.context("ab") as first, self.context("a") as second:
            self.assertNotEqual(first.token_for("ORG", "c"), second.token_for("ORG", "bc"))

    def test_mappings_are_request_local_even_for_the_same_domain(self):
        with self.context() as first, self.context() as second:
            token = first.token_for("ORG", "甲公司")
            self.assertEqual(0, second.entry_count)
            self.assert_blocked("UNKNOWN_TOKEN", lambda: second.restore(token))
            self.assertEqual(token, second.token_for("ORG", "甲公司"))
            self.assertEqual("甲公司", second.restore(token))

    def test_collision_does_not_overwrite_original(self):
        with self.context() as context, patch("enterprise_gateway.mapping.hmac.digest", return_value=b"x" * 32):
            token = context.token_for("ORG", "甲公司")
            self.assert_blocked("TOKEN_COLLISION", lambda: context.token_for("ORG", "乙公司"))
            self.assertEqual("甲公司", context.restore(token))
            self.assertEqual(1, context.entry_count)

    def test_context_clears_references_on_exception_and_cannot_reopen(self):
        context = self.context()
        self.assert_blocked("MAPPING_NOT_ACTIVE", lambda: context.token_for("ORG", "甲公司"))
        with self.assertRaises(RuntimeError):
            with context:
                context.token_for("ORG", "甲公司")
                raise RuntimeError("synthetic interruption")
        self.assertEqual(0, context.entry_count)
        self.assertEqual(b"", context.key)
        self.assert_blocked("MAPPING_NOT_ACTIVE", lambda: context.restore("text"))
        self.assert_blocked("MAPPING_LIFECYCLE", context.__enter__)

    def test_unknown_and_malformed_tokens_fail_without_echoing_content(self):
        with self.context() as context:
            valid = context.token_for("ORG", "甲公司")
            for suffix in (valid[:-1], "<<ENT_broken>>", "<<ENT_", "<<EN"):
                self.assert_blocked("MALFORMED_TOKEN", lambda: context.restore("private-content" + suffix))
            self.assert_blocked("UNKNOWN_TOKEN", lambda: context.restore("<<ENT_v1_" + "0" * 32 + ">>"))
            try:
                context.restore("private-content<<ENT_broken")
            except SafetyError as failure:
                self.assertNotIn("private-content", str(failure))

    def test_natural_token_namespace_is_rejected_even_without_detected_spans(self):
        with self.context() as context:
            token = context.token_for("ORG", "甲公司")
            self.assert_blocked("RESERVED_TOKEN_LITERAL", lambda: redact_text("literal " + token, [], context))
            self.assert_blocked("RESERVED_TOKEN_LITERAL", lambda: context.token_for("ORG", token))

    def test_invalid_unicode_is_controlled(self):
        with self.context() as context:
            self.assert_blocked("INVALID_UNICODE", lambda: context.token_for("ORG", "\ud800"))


if __name__ == "__main__":
    unittest.main()
