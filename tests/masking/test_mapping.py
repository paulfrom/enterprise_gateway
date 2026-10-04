"""Executable mapping contracts, not evidence of a working detection gateway."""

import asyncio
import json
import re
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from infra.errors import SafetyCode, SafetyError
from masking.mapping import MappingContext
from detection.spans import Span, redact_text


KEY = bytes(range(32))
FIXTURES = Path(__file__).parent / "fixtures" / "mapping"
_TOKEN_FORMAT = re.compile(r"<<ENT_[A-Za-z0-9.-]{1,32}_[0-9a-f]{32}>>\Z")


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
        with self.context() as context, patch("masking.mapping.hmac.digest", return_value=b"x" * 32):
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


class StableTokenMatrixTests(unittest.TestCase):
    """Stable token generation tests driven by the synthetic fixture matrix."""

    def setUp(self):
        with open(FIXTURES / "token-matrix.json", "r", encoding="utf-8") as handle:
            self.matrix = json.load(handle)
        self.keys = {name: bytes.fromhex(raw) for name, raw in self.matrix["keys"].items()}

    def context(self, scope="domain-a", version="v1", key=None):
        return MappingContext(scope, version, self.keys["key-a"] if key is None else key)

    def test_same_scope_version_type_and_original_yield_one_stable_token(self):
        case = self.matrix["stability"]
        with self.context(case["scope"], case["key_version"]) as context:
            tokens = {context.token_for(case["entity_type"], case["original"]) for _ in range(case["calls"])}
        self.assertEqual(1, len(tokens))
        (token,) = tokens
        self.assertIsNotNone(_TOKEN_FORMAT.fullmatch(token))

    def test_separation_matrix_yields_distinct_wellformed_tokens(self):
        base = self.matrix["stability"]
        with self.context(base["scope"], base["key_version"]) as context:
            base_token = context.token_for(base["entity_type"], base["original"])
            for case in self.matrix["separation"]:
                with MappingContext(case["scope"], case["key_version"], self.keys[case["key"]]) as other:
                    token = other.token_for(case["entity_type"], case["original"])
                self.assertNotEqual(base_token, token, case["case"])
                self.assertIsNotNone(_TOKEN_FORMAT.fullmatch(token), case["case"])

    def test_variant_spellings_get_distinct_tokens_and_each_restores_exactly(self):
        originals = [entry["original"] for entry in self.matrix["variants"]]
        with self.context("variant-scope") as context:
            tokens = [context.token_for("ORG", original) for original in originals]
            self.assertEqual(len(tokens), len(set(tokens)))
            for original, token in zip(originals, tokens):
                self.assertEqual(original, context.restore(token))

    def test_token_digest_is_128_bit_hex_inside_reserved_frame(self):
        with self.context() as context:
            token = context.token_for("ORG", "合成原值")
        self.assertTrue(token.startswith("<<ENT_v1_"))
        self.assertTrue(token.endswith(">>"))
        digest = token.removeprefix("<<ENT_v1_").removesuffix(">>")
        self.assertEqual(32, len(digest))
        self.assertEqual(16, len(bytes.fromhex(digest)))


class P01RejectionTests(unittest.TestCase):
    """Controlled rejections for illegal generator inputs."""

    def context(self, scope="domain-a", version="v1", key=KEY):
        return MappingContext(scope, version, key)

    def assert_canary_clean(self, failure, canary):
        self.assertNotIn(canary, str(failure.exception))
        self.assertNotIn(canary, repr(failure.exception))
        self.assertIsNone(failure.exception.__cause__)
        self.assertIsNone(failure.exception.__context__)

    def test_invalid_entity_type_rejected(self):
        invalid = ["", "org", "Org", "1ORG", "ORG-", "ORG.", "ORG NAME", "ORG/TYPE", "X" * 33]
        with self.context() as context:
            for entity_type in invalid:
                with self.assertRaises(SafetyError) as failure:
                    context.token_for(entity_type, "合成原值")
                self.assertEqual(SafetyCode.INVALID_ENTITY_TYPE, failure.exception.code, entity_type)

    def test_empty_original_rejected(self):
        with self.context() as context:
            with self.assertRaises(SafetyError) as failure:
                context.token_for("ORG", "")
            self.assertEqual(SafetyCode.EMPTY_ENTITY, failure.exception.code)

    def test_invalid_key_version_rejected_at_construction(self):
        invalid = ["", "v" * 33, "bad version", "v/1", "v_1", "v:1", "<<ENT", 123, None]
        for version in invalid:
            with self.assertRaises(SafetyError) as failure:
                MappingContext("domain-a", version, KEY)
            self.assertEqual(SafetyCode.INVALID_KEY_VERSION, failure.exception.code, version)

    def test_short_or_non_bytes_hmac_key_rejected_at_construction(self):
        invalid = [b"", b"x" * 31, "x" * 32, bytearray(b"x" * 32), None]
        for key in invalid:
            with self.assertRaises(SafetyError) as failure:
                MappingContext("domain-a", "v1", key)
            self.assertEqual(SafetyCode.INVALID_HMAC_KEY, failure.exception.code)

    def test_invalid_scope_rejected_at_construction(self):
        for scope in ["", "   ", 123, None]:
            with self.assertRaises(SafetyError) as failure:
                MappingContext(scope, "v1", KEY)
            self.assertEqual(SafetyCode.INVALID_SCOPE, failure.exception.code)

    def test_synthetic_collision_rejected_without_overwriting_or_leaking(self):
        canary_one = "CNRY-collision-alpha-161"
        canary_two = "CNRY-collision-beta-271"
        with self.context() as context, patch("masking.mapping.hmac.digest", return_value=b"\x5a" * 32):
            token = context.token_for("ORG", canary_one)
            with self.assertRaises(SafetyError) as failure:
                context.token_for("ORG", canary_two)
            self.assertEqual(SafetyCode.TOKEN_COLLISION, failure.exception.code)
            self.assert_canary_clean(failure, canary_two)
            self.assertEqual(canary_one, context.restore(token))
            self.assertEqual(1, context.entry_count)

    def test_synthetic_collision_across_entity_types_rejected(self):
        with self.context() as context, patch("masking.mapping.hmac.digest", return_value=b"\x5a" * 32):
            context.token_for("ORG", "合成同一原值")
            with self.assertRaises(SafetyError) as failure:
                context.token_for("PERSON", "合成同一原值")
            self.assertEqual(SafetyCode.TOKEN_COLLISION, failure.exception.code)
            self.assertEqual(1, context.entry_count)

    def test_repeat_issue_of_same_value_is_idempotent(self):
        with self.context() as context:
            first = context.token_for("ORG", "合成甲公司")
            second = context.token_for("ORG", "合成甲公司")
            self.assertEqual(first, second)
            self.assertEqual(1, context.entry_count)

    def test_token_exposes_no_original_and_single_flip_is_unknown(self):
        canary = "CNRY-token-opacity-577"
        with self.context() as context:
            token = context.token_for("ORG", canary)
            self.assertNotIn(canary, token)
            flipped = token[:-3] + ("0" if token[-3] != "0" else "1") + token[-2:]
            with self.assertRaises(SafetyError) as failure:
                context.restore(flipped)
            self.assertEqual(SafetyCode.UNKNOWN_TOKEN, failure.exception.code)
            self.assert_canary_clean(failure, canary)


class RequestIsolationTests(unittest.TestCase):
    """Request-local mappings, explicit lifecycle, and no shared state tests."""

    def setUp(self):
        with open(FIXTURES / "concurrency.json", "r", encoding="utf-8") as handle:
            self.spec = json.load(handle)

    def context(self, scope="domain-a", version="v1", key=KEY):
        return MappingContext(scope, version, key)

    def test_concurrent_threads_hold_isolated_mappings(self):
        failures: list[BaseException] = []
        per_thread: dict[int, tuple[list[str], int]] = {}
        barrier = threading.Barrier(self.spec["thread_count"])

        def worker(index: int) -> None:
            try:
                scope = f"{self.spec['scope_prefix']}{index}"
                with MappingContext(scope, self.spec["key_version"], KEY) as context:
                    barrier.wait(timeout=30)
                    tokens = [context.token_for(self.spec["entity_type"], value) for value in self.spec["originals"]]
                    per_thread[index] = (tokens, context.entry_count)
                    for value, token in zip(self.spec["originals"], tokens):
                        if context.restore(token) != value:
                            failures.append(AssertionError(f"thread {index} in-context restore mismatch"))
            except BaseException as exc:  # report any thread-side failure to the main thread
                failures.append(exc)

        threads = [threading.Thread(target=worker, args=(index,)) for index in range(self.spec["thread_count"])]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual([], failures)
        self.assertEqual(self.spec["thread_count"], len(per_thread))
        for index, (tokens, count) in per_thread.items():
            self.assertEqual(len(self.spec["originals"]), count, index)
            self.assertEqual(len(tokens), len(set(tokens)), index)
        baseline = per_thread[0][0]
        for index in range(1, self.spec["thread_count"]):
            for left, right in zip(baseline, per_thread[index][0]):
                self.assertNotEqual(left, right)

    def test_new_context_has_no_cross_request_mapping(self):
        scope = f"{self.spec['scope_prefix']}0"
        with MappingContext(scope, self.spec["key_version"], KEY) as first:
            token = first.token_for(self.spec["entity_type"], self.spec["originals"][0])
        with MappingContext(scope, self.spec["key_version"], KEY) as second:
            self.assertEqual(0, second.entry_count)
            with self.assertRaises(SafetyError) as failure:
                second.restore(token)
            self.assertEqual(SafetyCode.UNKNOWN_TOKEN, failure.exception.code)

    def test_base_exception_subclass_exit_still_releases_context(self):
        class SyntheticInterrupt(BaseException):
            pass

        context = self.context()
        with self.assertRaises(SyntheticInterrupt):
            with context:
                context.token_for("ORG", "甲公司")
                raise SyntheticInterrupt()
        self.assertEqual(0, context.entry_count)
        self.assertEqual(b"", context.key)
        with self.assertRaises(SafetyError) as failure:
            context.token_for("ORG", "甲公司")
        self.assertEqual(SafetyCode.MAPPING_NOT_ACTIVE, failure.exception.code)
        with self.assertRaises(SafetyError) as failure:
            context.__enter__()
        self.assertEqual(SafetyCode.MAPPING_LIFECYCLE, failure.exception.code)

    def test_asyncio_cancelled_error_exit_still_releases_context(self):
        context = self.context()
        with self.assertRaises(asyncio.CancelledError):
            with context:
                context.token_for("ORG", "甲公司")
                raise asyncio.CancelledError
        self.assertEqual(0, context.entry_count)
        self.assertEqual(b"", context.key)
        with self.assertRaises(SafetyError) as failure:
            context.restore("text")
        self.assertEqual(SafetyCode.MAPPING_NOT_ACTIVE, failure.exception.code)
        with self.assertRaises(SafetyError) as failure:
            context.__enter__()
        self.assertEqual(SafetyCode.MAPPING_LIFECYCLE, failure.exception.code)

    def test_reentering_active_context_rejected_and_outer_still_closes(self):
        context = self.context()
        with self.assertRaises(SafetyError) as failure:
            with context:
                context.token_for("ORG", "甲公司")
                with context:
                    pass
        self.assertEqual(SafetyCode.MAPPING_LIFECYCLE, failure.exception.code)
        self.assertEqual(0, context.entry_count)
        with self.assertRaises(SafetyError) as failure:
            context.__enter__()
        self.assertEqual(SafetyCode.MAPPING_LIFECYCLE, failure.exception.code)

    def test_closed_context_cannot_be_reused(self):
        context = self.context()
        with context:
            context.token_for("ORG", "甲公司")
        self.assertEqual(0, context.entry_count)
        with self.assertRaises(SafetyError) as failure:
            context.__enter__()
        self.assertEqual(SafetyCode.MAPPING_LIFECYCLE, failure.exception.code)
        with self.assertRaises(SafetyError) as failure:
            context.token_for("ORG", "甲公司")
        self.assertEqual(SafetyCode.MAPPING_NOT_ACTIVE, failure.exception.code)
        with self.assertRaises(SafetyError) as failure:
            context.restore("text")
        self.assertEqual(SafetyCode.MAPPING_NOT_ACTIVE, failure.exception.code)


class ReservedLiteralGuardTests(unittest.TestCase):
    """Reserved token namespace rejection, lookalikes untouched, no escape branch tests."""

    def setUp(self):
        with open(FIXTURES / "reserved-literals.json", "r", encoding="utf-8") as handle:
            self.matrix = json.load(handle)

    def context(self):
        return MappingContext("domain-a", "v1", KEY)

    def test_ordinary_lookalike_literals_are_not_misjudged(self):
        with self.context() as context:
            for literal in self.matrix["accepted"]:
                token = context.token_for("ORG", literal)
                self.assertEqual(literal, context.restore(token), literal)
        with self.context() as context:
            for literal in self.matrix["accepted"]:
                text = f"前缀{literal}后缀合成敏感值"
                spans = [Span(len(f"前缀{literal}后缀"), len(text), "ORG", 3)]
                masked = redact_text(text, spans, context)
                self.assertIn(literal, masked, literal)
                self.assertNotIn("合成敏感值", masked, literal)
                self.assertEqual(text, context.restore(masked), literal)

    def test_reserved_prefix_anywhere_is_rejected(self):
        with self.context() as context:
            for literal in self.matrix["rejected"]:
                with self.assertRaises(SafetyError) as failure:
                    context.token_for("ORG", literal)
                self.assertEqual(SafetyCode.RESERVED_TOKEN_LITERAL, failure.exception.code, literal)

    def test_redact_text_rejects_reserved_prefix_in_text(self):
        nested = "<<ENT_v1_" + "ab" * 16 + ">>"
        with self.context() as context:
            for literal in ("<<ENT", nested):
                with self.assertRaises(SafetyError) as failure:
                    redact_text(f"前文{literal}后文", [], context)
                self.assertEqual(SafetyCode.RESERVED_TOKEN_LITERAL, failure.exception.code, literal)
            token = context.token_for("ORG", "合成甲公司")
            with self.assertRaises(SafetyError) as failure:
                redact_text(f"literal {token}", [], context)
            self.assertEqual(SafetyCode.RESERVED_TOKEN_LITERAL, failure.exception.code)

    def test_no_escape_or_decode_compatibility_for_reserved_prefix(self):
        with self.context() as context:
            backslash_escaped = "\\<<ENT"
            with self.assertRaises(SafetyError) as failure:
                context.token_for("ORG", backslash_escaped)
            self.assertEqual(SafetyCode.RESERVED_TOKEN_LITERAL, failure.exception.code)
            entity_encoded = "%3C%3CENT"
            token = context.token_for("ORG", entity_encoded)
            self.assertEqual(entity_encoded, context.restore(token))

    def test_rejection_messages_carry_no_business_content(self):
        canary = "CNRY-p03-guard-90210"
        with self.assertRaises(SafetyError) as failure:
            MappingContext(canary + "\ud800", "v1", KEY)
        self.assertEqual(SafetyCode.INVALID_UNICODE, failure.exception.code)
        self.assertNotIn(canary, str(failure.exception))
        self.assertNotIn(canary, repr(failure.exception))
        self.assertIsNone(failure.exception.__cause__)
        self.assertIsNone(failure.exception.__context__)
        with self.context() as context:
            with self.assertRaises(SafetyError) as failure:
                context.token_for("ORG", canary + "<<ENT")
            self.assertEqual(SafetyCode.RESERVED_TOKEN_LITERAL, failure.exception.code)
            self.assertNotIn(canary, str(failure.exception))
            self.assertNotIn(canary, repr(failure.exception))
            self.assertIsNone(failure.exception.__cause__)
            self.assertIsNone(failure.exception.__context__)
            with self.assertRaises(SafetyError) as failure:
                redact_text(f"前文{canary}<<ENT后文", [], context)
            self.assertEqual(SafetyCode.RESERVED_TOKEN_LITERAL, failure.exception.code)
            self.assertNotIn(canary, str(failure.exception))


if __name__ == "__main__":
    unittest.main()
