"""Unit and contract tests for editable-field-only request replacer."""

import json
import unittest
from pathlib import Path

from infra.errors import SafetyCode, SafetyError
from gateway.ingress import IngressValidator, ValidatedIngressRequest
from masking.mapping import MappingContext
from policy.policy import load_policy
from protocol.protocols import (
    CLAUDE_MESSAGES_PROTOCOL,
    DEEPSEEK_CHAT_PROTOCOL,
    ClaudeMessagesRequest,
    DeepSeekChatRequest,
    parse_claude_messages,
    parse_deepseek_chat_completion,
)
from masking.replacer import replace_request
from detection.span_resolver import ResolvedSpan
from detection.spans import Span
from protocol.static_exemption import load_exemption_registry

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "replacer"
KEY = bytes(range(32))

EXEMPTION_DATA = {
    "version": "1.0.0",
    "templates": [
        {
            "template_id": "tpl-sys-v1",
            "domain": "test-domain",
            "version": "1.0",
            "text": "You are a helpful assistant.",
            "sha256": "75357d685f238b6afd7738be9786fdafde641eb6ca9a3be7471939715a68a4de",
        }
    ],
}


def _diff_paths(original, replaced, prefix=""):
    if isinstance(original, dict) and isinstance(replaced, dict):
        for key in original:
            yield from _diff_paths(original[key], replaced[key], f"{prefix}.{key}" if prefix else key)
    elif isinstance(original, list) and isinstance(replaced, list):
        assert len(original) == len(replaced)
        for index, (left, right) in enumerate(zip(original, replaced)):
            yield from _diff_paths(left, right, f"{prefix}[{index}]")
    elif original != replaced:
        yield prefix


class ReplacerTests(unittest.TestCase):
    def setUp(self) -> None:
        policy_data = {
            "version": "1.0",
            "rules": [
                {"category": "cat-approved", "label": "approved_external", "scope": "scope-ext"},
            ],
        }
        self.policy = load_policy(policy_data)
        with open(FIXTURES_DIR / "deepseek_request.json", "r", encoding="utf-8") as f:
            self.deepseek_body = f.read()
        with open(FIXTURES_DIR / "claude_request.json", "r", encoding="utf-8") as f:
            self.claude_body = f.read()

    def _validated(self, protocol, raw_body, registry=None):
        return IngressValidator.validate_request(
            raw_body=raw_body,
            protocol=protocol,
            domain="test-domain",
            category="cat-approved",
            policy=self.policy,
            exemption_registry=registry,
        )

    @staticmethod
    def _span(fragment, needle, entity_type, priority=3):
        start = fragment.content.index(needle)
        return Span(start, start + len(needle), entity_type, priority)

    @staticmethod
    def _empty_spans(fragments):
        return {fragment.json_path: () for fragment in fragments}

    def test_deepseek_hits_replaced_only_editable_fields(self) -> None:
        validated = self._validated(DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body)
        fragments = {fragment.json_path: fragment for fragment in validated.fragments}
        user = fragments["messages[1].content"]
        assistant = fragments["messages[2].content"]
        span_map = self._empty_spans(validated.fragments)
        span_map["messages[1].content"] = (
            self._span(user, "13900001111", "PHONE"),
            self._span(user, "02155556666", "PHONE"),
        )
        span_map["messages[2].content"] = (self._span(assistant, "sk-synthetic-000000000000000000000000", "CREDENTIAL"),)

        with MappingContext("scope-ext", "v1", KEY) as context:
            result = replace_request(validated, span_map, context)
            self.assertEqual(3, context.entry_count)
            self.assertEqual(
                user.content, context.restore(result.messages[1].content)
            )
            self.assertEqual(
                assistant.content, context.restore(result.messages[2].content)
            )
            self.assertIn(
                context.token_for("PHONE", "13900001111"), result.messages[1].content
            )

        self.assertIsInstance(result, DeepSeekChatRequest)
        original_dump = validated.parsed_request.model_dump()
        changed = set(_diff_paths(original_dump, result.model_dump()))
        self.assertEqual({"messages[1].content", "messages[2].content"}, changed)

        self.assertEqual("deepseek-flash", result.model)
        self.assertEqual(0.2, result.temperature)
        self.assertEqual(0.9, result.top_p)
        self.assertEqual(["END"], result.stop)
        self.assertEqual("json_object", result.response_format.type)
        self.assertEqual(["system", "user", "assistant"], [m.role for m in result.messages])
        self.assertEqual(original_dump["messages"][0], result.model_dump()["messages"][0])

        serialized = json.dumps(result.model_dump(mode="json"), ensure_ascii=False)
        self.assertNotIn("13900001111", serialized)
        self.assertNotIn("02155556666", serialized)
        self.assertNotIn("sk-synthetic-", serialized)
        self.assertEqual(result, parse_deepseek_chat_completion(serialized))

    def test_claude_hits_replaced_all_editable_positions(self) -> None:
        validated = self._validated(CLAUDE_MESSAGES_PROTOCOL, self.claude_body)
        fragments = {fragment.json_path: fragment for fragment in validated.fragments}
        system = fragments["system"]
        user = fragments["messages[0].content"]
        block = fragments["messages[1].content[0].text"]
        span_map = self._empty_spans(validated.fragments)
        span_map["system"] = (self._span(system, "T-2026-0001", "CASE_ID"),)
        span_map["messages[0].content"] = (self._span(user, "13800002222", "PHONE"),)
        span_map["messages[1].content[0].text"] = (
            self._span(block, "HT-2026-SYNTH-0007", "CONTRACT_ID"),
        )

        with MappingContext("scope-ext", "v1", KEY) as context:
            result = replace_request(validated, span_map, context)
            self.assertEqual(3, context.entry_count)
            self.assertEqual(system.content, context.restore(result.system))
            self.assertEqual(user.content, context.restore(result.messages[0].content))
            self.assertEqual(
                block.content, context.restore(result.messages[1].content[0].text)
            )

        self.assertIsInstance(result, ClaudeMessagesRequest)
        changed = set(
            _diff_paths(validated.parsed_request.model_dump(), result.model_dump())
        )
        self.assertEqual(
            {"system", "messages[0].content", "messages[1].content[0].text"}, changed
        )

        self.assertEqual("claude-sonnet-5-5", result.model)
        self.assertEqual(512, result.max_tokens)
        self.assertEqual(["STOP"], result.stop_sequences)
        self.assertEqual(0.1, result.temperature)
        self.assertEqual(0.95, result.top_p)
        self.assertEqual(40, result.top_k)
        self.assertEqual("user", result.messages[0].role)
        self.assertEqual("text", result.messages[1].content[0].type)

        serialized = json.dumps(result.model_dump(mode="json"), ensure_ascii=False)
        self.assertNotIn("13800002222", serialized)
        self.assertNotIn("HT-2026-SYNTH-0007", serialized)
        self.assertEqual(result, parse_claude_messages(serialized))

    def test_request_without_hits_is_byte_identical(self) -> None:
        validated = self._validated(DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body)
        with MappingContext("scope-ext", "v1", KEY) as context:
            result = replace_request(validated, self._empty_spans(validated.fragments), context)
            self.assertEqual(0, context.entry_count)
        self.assertEqual(validated.parsed_request.model_dump(), result.model_dump())

    def test_exempt_fragment_passes_through_without_detection(self) -> None:
        registry = load_exemption_registry(EXEMPTION_DATA)
        validated = self._validated(DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body, registry)
        exempt = {f.json_path: f for f in validated.fragments if not f.requires_detection}
        self.assertEqual({"messages[0].content"}, set(exempt))
        with MappingContext("scope-ext", "v1", KEY) as context:
            result = replace_request(validated, self._empty_spans(validated.fragments), context)
            self.assertEqual(0, context.entry_count)
        self.assertEqual(validated.parsed_request.model_dump(), result.model_dump())

    def test_hit_in_exempt_fragment_blocked(self) -> None:
        registry = load_exemption_registry(EXEMPTION_DATA)
        validated = self._validated(DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body, registry)
        span_map = self._empty_spans(validated.fragments)
        span_map["messages[0].content"] = (Span(0, 3, "ORG"),)
        with MappingContext("scope-ext", "v1", KEY) as context:
            with self.assertRaises(SafetyError) as failure:
                replace_request(validated, span_map, context)
            self.assertEqual(SafetyCode.UNSAFE_REPLACEMENT, failure.exception.code)
            self.assertNotIn("helpful assistant", str(failure.exception))
            self.assertIsNone(failure.exception.__cause__)
            self.assertIsNone(failure.exception.__context__)
            self.assertEqual(0, context.entry_count)

    def test_hit_in_model_field_blocks_request(self) -> None:
        validated = self._validated(DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body)
        span_map = self._empty_spans(validated.fragments)
        span_map["model"] = (Span(0, 5, "MODEL"),)
        with MappingContext("scope-ext", "v1", KEY) as context:
            with self.assertRaises(SafetyError) as failure:
                replace_request(validated, span_map, context)
            self.assertEqual(SafetyCode.UNSAFE_REPLACEMENT, failure.exception.code)
            self.assertNotIn("deepseek-flash", str(failure.exception))
            self.assertIsNone(failure.exception.__context__)
            self.assertEqual(0, context.entry_count)

    def test_hit_in_numeric_parameter_blocks(self) -> None:
        cases = [
            (DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body, "temperature"),
            (DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body, "top_p"),
            (CLAUDE_MESSAGES_PROTOCOL, self.claude_body, "max_tokens"),
            (CLAUDE_MESSAGES_PROTOCOL, self.claude_body, "top_k"),
        ]
        for protocol, body, path in cases:
            with self.subTest(protocol=protocol, path=path):
                validated = self._validated(protocol, body)
                span_map = self._empty_spans(validated.fragments)
                span_map[path] = (Span(0, 1, "NUMBER"),)
                with MappingContext("scope-ext", "v1", KEY) as context:
                    with self.assertRaises(SafetyError) as failure:
                        replace_request(validated, span_map, context)
                    self.assertEqual(SafetyCode.UNSAFE_REPLACEMENT, failure.exception.code)

    def test_hit_in_string_typed_protocol_parameter_blocks(self) -> None:
        for protocol, body, path in [
            (DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body, "stop"),
            (CLAUDE_MESSAGES_PROTOCOL, self.claude_body, "stop_sequences"),
        ]:
            with self.subTest(protocol=protocol, path=path):
                validated = self._validated(protocol, body)
                span_map = self._empty_spans(validated.fragments)
                span_map[path] = (Span(0, 3, "STOPWORD"),)
                with MappingContext("scope-ext", "v1", KEY) as context:
                    with self.assertRaises(SafetyError) as failure:
                        replace_request(validated, span_map, context)
                    self.assertEqual(SafetyCode.UNSAFE_REPLACEMENT, failure.exception.code)

    def test_hit_in_role_field_blocks(self) -> None:
        validated = self._validated(DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body)
        span_map = self._empty_spans(validated.fragments)
        span_map["messages[0].role"] = (Span(0, 4, "ROLE"),)
        with MappingContext("scope-ext", "v1", KEY) as context:
            with self.assertRaises(SafetyError) as failure:
                replace_request(validated, span_map, context)
            self.assertEqual(SafetyCode.UNSAFE_REPLACEMENT, failure.exception.code)

    def test_deepseek_block_style_path_blocked(self) -> None:
        validated = self._validated(DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body)
        span_map = self._empty_spans(validated.fragments)
        span_map["messages[0].content[0].text"] = (Span(0, 3, "ORG"),)
        with MappingContext("scope-ext", "v1", KEY) as context:
            with self.assertRaises(SafetyError) as failure:
                replace_request(validated, span_map, context)
            self.assertEqual(SafetyCode.UNSAFE_REPLACEMENT, failure.exception.code)

    def test_unknown_and_out_of_range_paths_blocked(self) -> None:
        cases = [
            (DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body, "foobar"),
            (DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body, "messages[9].content"),
            (DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body, "messages[0].content.text"),
            (DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body, "system"),
            (CLAUDE_MESSAGES_PROTOCOL, self.claude_body, "foobar"),
            (CLAUDE_MESSAGES_PROTOCOL, self.claude_body, "messages[9].content"),
            (CLAUDE_MESSAGES_PROTOCOL, self.claude_body, "messages[1].content"),
            (CLAUDE_MESSAGES_PROTOCOL, self.claude_body, "messages[0].content[0].text"),
        ]
        for protocol, body, path in cases:
            with self.subTest(protocol=protocol, path=path):
                validated = self._validated(protocol, body)
                span_map = self._empty_spans(validated.fragments)
                span_map[path] = (Span(0, 1, "ORG"),)
                with MappingContext("scope-ext", "v1", KEY) as context:
                    with self.assertRaises(SafetyError) as failure:
                        replace_request(validated, span_map, context)
                    self.assertEqual(SafetyCode.UNSAFE_REPLACEMENT, failure.exception.code)

    def test_out_of_bounds_span_rejected(self) -> None:
        validated = self._validated(DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body)
        fragments = {fragment.json_path: fragment for fragment in validated.fragments}
        user = fragments["messages[1].content"]
        span_map = self._empty_spans(validated.fragments)
        span_map["messages[1].content"] = (Span(0, len(user.content) + 1, "PHONE"),)
        with MappingContext("scope-ext", "v1", KEY) as context:
            with self.assertRaises(SafetyError) as failure:
                replace_request(validated, span_map, context)
            self.assertEqual(SafetyCode.INVALID_SPAN, failure.exception.code)
            self.assertNotIn("13900001111", str(failure.exception))
            self.assertEqual(0, context.entry_count)

    def test_invalid_span_items_and_result_shapes_rejected(self) -> None:
        validated = self._validated(DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body)
        with MappingContext("scope-ext", "v1", KEY) as context:
            for bad_items, expected in [
                ((0, 5, "PHONE"), SafetyCode.INVALID_SPAN),
                ((Span(0, 5, "phone"),), SafetyCode.INVALID_SPAN),
                ("not-a-span-set", SafetyCode.INVALID_DETECTOR_RESULTS),
                (None, SafetyCode.INVALID_DETECTOR_RESULTS),
            ]:
                with self.subTest(bad_items=bad_items):
                    span_map = self._empty_spans(validated.fragments)
                    span_map["messages[1].content"] = bad_items
                    with self.assertRaises(SafetyError) as failure:
                        replace_request(validated, span_map, context)
                    self.assertEqual(expected, failure.exception.code)
            with self.assertRaises(SafetyError) as failure:
                replace_request(validated, [("messages[0].content", ())], context)
            self.assertEqual(SafetyCode.INVALID_DETECTOR_RESULTS, failure.exception.code)

    def test_secret_span_blocks_before_mapping(self) -> None:
        validated = self._validated(DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body)
        span_map = self._empty_spans(validated.fragments)
        span_map["messages[1].content"] = (Span(0, 11, "SECRET", 0),)
        with MappingContext("scope-ext", "v1", KEY) as context:
            with self.assertRaises(SafetyError) as failure:
                replace_request(validated, span_map, context)
            self.assertEqual(SafetyCode.SECRET_DETECTED, failure.exception.code)
            self.assertEqual(0, context.entry_count)

    def test_missing_spans_for_required_fragment_rejected(self) -> None:
        validated = self._validated(DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body)
        span_map = {
            fragment.json_path: ()
            for fragment in validated.fragments
            if fragment.json_path != "messages[1].content"
        }
        with MappingContext("scope-ext", "v1", KEY) as context:
            with self.assertRaises(SafetyError) as failure:
                replace_request(validated, span_map, context)
            self.assertEqual(SafetyCode.DETECTION_INCOMPLETE, failure.exception.code)

    def test_reserved_token_literal_in_text_rejected(self) -> None:
        raw_body = json.dumps(
            {
                "model": "deepseek-flash",
                "messages": [{"role": "user", "content": "普通前缀<<ENT注入，电话 13900009999"}],
            },
            ensure_ascii=False,
        )
        validated = self._validated(DEEPSEEK_CHAT_PROTOCOL, raw_body)
        fragment = validated.fragments[0]
        start = fragment.content.index("13900009999")
        span_map = {fragment.json_path: (Span(start, start + 11, "PHONE"),)}
        with MappingContext("scope-ext", "v1", KEY) as context:
            with self.assertRaises(SafetyError) as failure:
                replace_request(validated, span_map, context)
            self.assertEqual(SafetyCode.RESERVED_TOKEN_LITERAL, failure.exception.code)
            self.assertNotIn("13900009999", str(failure.exception))
            self.assertEqual(0, context.entry_count)

    def test_lookalike_literals_untouched_and_roundtrip(self) -> None:
        raw_body = json.dumps(
            {
                "model": "deepseek-flash",
                "messages": [
                    {"role": "user", "content": "参考<<ent-lower 与 <ENT-UPPER，电话 13900003333"}
                ],
            },
            ensure_ascii=False,
        )
        validated = self._validated(DEEPSEEK_CHAT_PROTOCOL, raw_body)
        fragment = validated.fragments[0]
        start = fragment.content.index("13900003333")
        span_map = {fragment.json_path: (Span(start, start + 11, "PHONE"),)}
        with MappingContext("scope-ext", "v1", KEY) as context:
            result = replace_request(validated, span_map, context)
            self.assertIn("<<ent-lower", result.messages[0].content)
            self.assertIn("<ENT-UPPER", result.messages[0].content)
            self.assertNotIn("13900003333", result.messages[0].content)
            self.assertEqual(fragment.content, context.restore(result.messages[0].content))

    def test_resolved_span_inputs_accepted(self) -> None:
        validated = self._validated(CLAUDE_MESSAGES_PROTOCOL, self.claude_body)
        fragments = {fragment.json_path: fragment for fragment in validated.fragments}
        user = fragments["messages[0].content"]
        start = user.content.index("13800002222")
        span_map = self._empty_spans(validated.fragments)
        span_map["messages[0].content"] = (
            ResolvedSpan(start, start + 11, "PHONE", 3, ("rule:phone", "ner")),
        )
        with MappingContext("scope-ext", "v1", KEY) as context:
            result = replace_request(validated, span_map, context)
            self.assertEqual(1, context.entry_count)
            self.assertEqual(user.content, context.restore(result.messages[0].content))

    def test_inactive_mapping_context_rejected(self) -> None:
        validated = self._validated(DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body)
        fragments = {fragment.json_path: fragment for fragment in validated.fragments}
        user = fragments["messages[1].content"]
        span_map = self._empty_spans(validated.fragments)
        span_map["messages[1].content"] = (self._span(user, "13900001111", "PHONE"),)
        context = MappingContext("scope-ext", "v1", KEY)
        context.__enter__()
        context.__exit__(None, None, None)
        with self.assertRaises(SafetyError) as failure:
            replace_request(validated, span_map, context)
        self.assertEqual(SafetyCode.MAPPING_NOT_ACTIVE, failure.exception.code)

    def test_wrong_input_types_rejected(self) -> None:
        validated = self._validated(DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body)
        with MappingContext("scope-ext", "v1", KEY) as context:
            with self.assertRaises(TypeError):
                replace_request("not-a-request", {}, context)
            with self.assertRaises(TypeError):
                replace_request(validated, {}, "not-a-context")

    def test_protocol_model_mismatch_rejected(self) -> None:
        validated = self._validated(DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body)
        mismatched = ValidatedIngressRequest(
            protocol=CLAUDE_MESSAGES_PROTOCOL,
            model=validated.model,
            category=validated.category,
            domain=validated.domain,
            parsed_request=validated.parsed_request,
            fragments=validated.fragments,
        )
        with MappingContext("scope-ext", "v1", KEY) as context:
            with self.assertRaises(SafetyError) as failure:
                replace_request(mismatched, {}, context)
            self.assertEqual(SafetyCode.CONTRACT_VIOLATION, failure.exception.code)

    def test_unsupported_protocol_rejected(self) -> None:
        validated = self._validated(DEEPSEEK_CHAT_PROTOCOL, self.deepseek_body)
        unsupported = ValidatedIngressRequest(
            protocol="grpc-backend-v1",
            model=validated.model,
            category=validated.category,
            domain=validated.domain,
            parsed_request=validated.parsed_request,
            fragments=validated.fragments,
        )
        with MappingContext("scope-ext", "v1", KEY) as context:
            with self.assertRaises(SafetyError) as failure:
                replace_request(unsupported, {}, context)
            self.assertEqual(SafetyCode.UNSAFE_REPLACEMENT, failure.exception.code)

    def test_stop_and_stop_sequences_redaction(self) -> None:
        # DeepSeek stop string
        body_ds = json.dumps({
            "model": "deepseek-flash",
            "messages": [{"role": "user", "content": "hello"}],
            "stop": "STOP_CANARY_1",
        })
        val_ds = IngressValidator.validate_request(
            body_ds, DEEPSEEK_CHAT_PROTOCOL, "scope-ext", "cat-approved", self.policy
        )
        self.assertEqual(val_ds.fragments[1].json_path, "stop")
        with MappingContext("scope-ext", "v1", KEY) as context:
            redacted = replace_request(
                val_ds,
                {"messages[0].content": (), "stop": (Span(0, 13, "ORG", 1),)},
                context,
            )
            self.assertTrue(redacted.stop.startswith("<<ENT_v1_"))

        # Claude stop_sequences list
        body_cl = json.dumps({
            "model": "claude-sonnet-5-5",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": "hello"}],
            "stop_sequences": ["STOP_CANARY_A", "STOP_CANARY_B"],
        })
        val_cl = IngressValidator.validate_request(
            body_cl, CLAUDE_MESSAGES_PROTOCOL, "scope-ext", "cat-approved", self.policy
        )
        self.assertEqual(val_cl.fragments[1].json_path, "stop_sequences[0]")
        self.assertEqual(val_cl.fragments[2].json_path, "stop_sequences[1]")
        with MappingContext("scope-ext", "v1", KEY) as context:
            redacted_cl = replace_request(
                val_cl,
                {
                    "messages[0].content": (),
                    "stop_sequences[0]": (Span(0, 13, "ORG", 1),),
                    "stop_sequences[1]": (),
                },
                context,
            )
            self.assertTrue(redacted_cl.stop_sequences[0].startswith("<<ENT_v1_"))
            self.assertEqual(redacted_cl.stop_sequences[1], "STOP_CANARY_B")


if __name__ == "__main__":
    unittest.main()
