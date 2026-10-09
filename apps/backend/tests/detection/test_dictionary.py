"""Unit and contract tests for D-06 (dictionary compilation) and D-07 (longest-match detector)."""

from __future__ import annotations

import json
import traceback
import unittest
from pathlib import Path

from detection.dictionary import (
    CompiledDictionary,
    DictionaryDocument,
    analyze_dictionary,
    compile_dictionary,
    compute_dictionary_hash,
)
from infra.errors import SafetyCode, SafetyError
from detection.spans import Span

D06_DIR = Path(__file__).parent / "fixtures" / "dictionary"
D07_DIR = Path(__file__).parent / "fixtures" / "dictionary" / "matching"

CANARY_CONFLICT = "CNRY-D06-conflict-entry-77331"
CANARY_TAMPER = "CNRY-D06-tamper-entry-99110"
CANARY_NOTE = "CNRY-D07-fixture-2b2b2b"


def _load_fixture(name: str) -> str:
    return (D06_DIR / name).read_text(encoding="utf-8")


def _load_json(name: str) -> dict:
    return json.loads(_load_fixture(name))


class DictionaryCompilationTests(unittest.TestCase):
    """企业词典编译测试：严格校验 + 本地编译 + 版本可追溯。"""

    def setUp(self) -> None:
        self.compiled = compile_dictionary(_load_fixture("valid_dictionary_v1.json"))

    def test_valid_dictionary_compiles(self) -> None:
        self.assertIsInstance(self.compiled, CompiledDictionary)
        self.assertEqual(self.compiled.dictionary_id, "ent-dict-synthetic-v1")
        self.assertEqual(self.compiled.version, "1.0.0")
        self.assertEqual(self.compiled.domain, "synthetic-demo")
        self.assertEqual(len(self.compiled.entries), 6)

    def test_compiled_product_traces_source_version_and_sha256(self) -> None:
        declared = _load_json("valid_dictionary_v1.json")
        self.assertEqual(self.compiled.version, declared["version"])
        self.assertEqual(self.compiled.sha256, declared["sha256"])
        v2 = compile_dictionary(_load_fixture("valid_dictionary_v2.json"))
        self.assertEqual(v2.version, "1.1.0")
        self.assertNotEqual(v2.sha256, self.compiled.sha256)
        self.assertGreater(len(v2.entries), len(self.compiled.entries))

    def test_declared_sha256_matches_recomputed_content_hash(self) -> None:
        declared = _load_json("valid_dictionary_v1.json")
        entries = tuple(
            type(self.compiled.entries[0])(text=e["text"], entity_type=e["entity_type"])
            for e in declared["entries"]
        )
        expected = compute_dictionary_hash(
            declared["dictionary_id"], declared["version"], declared["domain"], entries
        )
        self.assertEqual(self.compiled.sha256, expected)

    def test_compile_accepts_trusted_mapping(self) -> None:
        compiled = compile_dictionary(_load_json("valid_dictionary_v1.json"))
        self.assertEqual(compiled.version, "1.0.0")
        self.assertEqual(compiled.sha256, self.compiled.sha256)

    def test_rejects_malformed_json(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            compile_dictionary('{"dictionary_id": "truncated')
        self.assertIs(ctx.exception.code, SafetyCode.DICTIONARY_INVALID)

    def test_rejects_invalid_utf8(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            compile_dictionary(b"\xff\xfe\x00broken")
        self.assertIs(ctx.exception.code, SafetyCode.DICTIONARY_INVALID)

    def test_rejects_duplicate_json_key(self) -> None:
        source = _load_fixture("valid_dictionary_v1.json")
        doubled = source.replace(
            '"version": "1.0.0"', '"version": "1.0.0", "version": "2.0.0"', 1
        )
        self.assertNotEqual(doubled, source)
        with self.assertRaises(SafetyError) as ctx:
            compile_dictionary(doubled)
        self.assertIs(ctx.exception.code, SafetyCode.DICTIONARY_INVALID)

    def test_rejects_missing_field(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            compile_dictionary(_load_fixture("bad_missing_field.json"))
        self.assertIs(ctx.exception.code, SafetyCode.DICTIONARY_INVALID)

    def test_rejects_wrong_field_type(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            compile_dictionary(_load_fixture("bad_wrong_type.json"))
        self.assertIs(ctx.exception.code, SafetyCode.DICTIONARY_INVALID)

    def test_rejects_extra_field(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            compile_dictionary(_load_fixture("bad_extra_field.json"))
        self.assertIs(ctx.exception.code, SafetyCode.DICTIONARY_INVALID)

    def test_rejects_non_object_document(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            compile_dictionary('["not", "an", "object"]')
        self.assertIs(ctx.exception.code, SafetyCode.DICTIONARY_INVALID)

    def test_rejects_duplicate_entry(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            compile_dictionary(_load_fixture("bad_duplicate_entry.json"))
        self.assertIs(ctx.exception.code, SafetyCode.DICTIONARY_INVALID)

    def test_rejects_empty_entry_text(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            compile_dictionary(_load_fixture("bad_empty_text.json"))
        self.assertIs(ctx.exception.code, SafetyCode.DICTIONARY_INVALID)

    def test_rejects_whitespace_only_entry_text(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            compile_dictionary(_load_fixture("bad_whitespace_text.json"))
        self.assertIs(ctx.exception.code, SafetyCode.DICTIONARY_INVALID)

    def test_rejects_unknown_entity_type_format(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            compile_dictionary(_load_fixture("bad_entity_type_format.json"))
        self.assertIs(ctx.exception.code, SafetyCode.DICTIONARY_INVALID)

    def test_rejects_invalid_sha256_format(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            compile_dictionary(_load_fixture("bad_sha256_format.json"))
        self.assertIs(ctx.exception.code, SafetyCode.DICTIONARY_INVALID)

    def test_rejects_empty_entries(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            compile_dictionary(_load_fixture("bad_empty_entries.json"))
        self.assertIs(ctx.exception.code, SafetyCode.DICTIONARY_INVALID)

    def test_rejects_hash_mismatch_tampered_content(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            compile_dictionary(_load_fixture("bad_hash_mismatch.json"))
        self.assertIs(ctx.exception.code, SafetyCode.DICTIONARY_INVALID)

    def test_rejects_conflicting_entity_type_for_same_text(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            compile_dictionary(_load_fixture("conflict_dictionary.json"))
        self.assertIs(ctx.exception.code, SafetyCode.DICTIONARY_CONFLICT)

    def test_rejection_messages_never_echo_document_content(self) -> None:
        canary_sources = [
            ("conflict_dictionary.json", CANARY_CONFLICT),
            ("bad_hash_mismatch.json", CANARY_TAMPER),
        ]
        for fixture, canary in canary_sources:
            with self.assertRaises(SafetyError) as ctx:
                compile_dictionary(_load_fixture(fixture))
            self.assertNotIn(canary, str(ctx.exception))
            self.assertNotIn(canary, repr(ctx.exception))
            self.assertNotIn(canary, traceback.format_exc())
        with self.assertRaises(SafetyError) as ctx:
            compile_dictionary(_load_fixture("bad_entity_type_format.json"))
        self.assertNotIn("org-name", str(ctx.exception))
        self.assertNotIn("星链重工集团", str(ctx.exception))

    def test_automaton_rebuilt_locally_on_every_compile(self) -> None:
        again = compile_dictionary(_load_fixture("valid_dictionary_v1.json"))
        self.assertIsNot(self.compiled._automaton, again._automaton)
        doc = CompiledDictionary.__doc__ or ""
        self.assertIn("本地", doc)
        self.assertIn("不持久化", doc)
        self.assertIn("跨平台", doc)

    def test_rejects_untrusted_source_type(self) -> None:
        with self.assertRaises(TypeError):
            compile_dictionary(12345)  # type: ignore[arg-type]


class LongestMatchDetectionTests(unittest.TestCase):
    """最长匹配与偏移测试：最长匹配、code point 偏移、单字段输入单位、版本可追溯。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.compiled = compile_dictionary(_load_fixture("valid_dictionary_v1.json"))
        cls.cases = json.loads((D07_DIR / "cases.json").read_text(encoding="utf-8"))

    def _spans(self, text: str) -> tuple[Span, ...]:
        return analyze_dictionary(text, self.compiled).spans

    def test_alias_nesting_matches_longest(self) -> None:
        text = self.cases["alias_nesting_text"]
        spans = self._spans(text)
        self.assertEqual(len(spans), 1)
        span = spans[0]
        self.assertEqual((span.start, span.end), (2, 7))
        self.assertEqual(text[span.start : span.end], "ABC公司")
        self.assertEqual(span.entity_type, "ORG")
        self.assertEqual(span.priority, 3)

    def test_chinese_entity_exact_code_point_offsets(self) -> None:
        text = self.cases["chinese_offsets_text"]
        # 含两个增补平面字符（各 1 个 code point、UTF-8 各 4 字节）：
        # code point 坐标系下 "星链重工集团" 为 [6,12)；字节坐标系下会偏移。
        self.assertEqual(len(text), 16)
        spans = self._spans(text)
        self.assertEqual(len(spans), 1)
        span = spans[0]
        self.assertEqual((span.start, span.end), (6, 12))
        self.assertEqual(text[span.start : span.end], "星链重工集团")
        prefix_bytes = len(text[:6].encode("utf-8"))
        self.assertNotEqual(span.start, prefix_bytes)

    def test_nested_chinese_alias_matches_longest(self) -> None:
        spans = self._spans("星链重工集团发布公告")
        self.assertEqual(len(spans), 1)
        self.assertEqual((spans[0].start, spans[0].end), (0, 6))
        self.assertEqual(spans[0].entity_type, "ORG")

    def test_repeated_entity_all_occurrences_match(self) -> None:
        text = self.cases["repeated_text"]
        spans = self._spans(text)
        self.assertEqual(len(spans), 3)
        self.assertEqual(
            [(s.start, s.end, s.entity_type) for s in spans],
            [(0, 6, "ORG"), (7, 13, "ORG"), (16, 22, "ORG")],
        )
        self.assertEqual(text[0:6], text[16:22])

    def test_multiple_entity_types_in_one_text(self) -> None:
        spans = self._spans("临湖新材料实验室与云杉数据科技联合共建")
        self.assertEqual(
            [(s.start, s.end, s.entity_type) for s in spans],
            [(0, 8, "LOCATION"), (9, 15, "ORG")],
        )

    def test_non_entity_text_yields_no_spans(self) -> None:
        result = analyze_dictionary(self.cases["non_entity_text"], self.compiled)
        self.assertEqual(result.spans, ())

    def test_empty_text_yields_no_spans(self) -> None:
        result = analyze_dictionary("", self.compiled)
        self.assertEqual(result.spans, ())

    def test_cross_field_halves_never_merge(self) -> None:
        # 实体 "星链重工集团" 被拆进两个字段：检测以单字段文本为单位，
        # 本模块不替调用方跨字段拼接——右半字段单独检测不命中，
        # 左半字段只命中其自身内容 "星链重工"；只有调用方显式拼接成
        # 单个字段文本时才出现完整实体 "星链重工集团" 的最长命中。
        left = analyze_dictionary(self.cases["cross_field_left"], self.compiled)
        right = analyze_dictionary(self.cases["cross_field_right"], self.compiled)
        self.assertEqual(
            [(s.start, s.end, s.entity_type) for s in left.spans],
            [(0, 4, "ORG")],
        )
        self.assertEqual(right.spans, ())
        joined = analyze_dictionary(
            self.cases["cross_field_left"] + self.cases["cross_field_right"],
            self.compiled,
        )
        self.assertEqual(len(joined.spans), 1)
        self.assertEqual((joined.spans[0].start, joined.spans[0].end), (0, 6))

    def test_detection_carries_dictionary_version(self) -> None:
        text = self.cases["alias_nesting_text"]
        v1 = analyze_dictionary(text, self.compiled)
        self.assertEqual(v1.dictionary_version, "1.0.0")
        v2 = compile_dictionary(_load_fixture("valid_dictionary_v2.json"))
        v2_result = analyze_dictionary(text, v2)
        self.assertEqual(v2_result.dictionary_version, "1.1.0")
        self.assertEqual(
            [(s.start, s.end) for s in v1.spans],
            [(s.start, s.end) for s in v2_result.spans],
        )

    def test_detection_spans_merge_compatible_with_spans_module(self) -> None:
        # 词典输出即 spans.Span 契约：可被 merge_spans 直接消费。
        from detection.spans import merge_spans

        text = self.cases["repeated_text"]
        spans = self._spans(text)
        merged = merge_spans(spans, text_length=len(text))
        self.assertEqual(len(merged), 3)

    def test_rejects_non_str_text(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            analyze_dictionary(12345, self.compiled)  # type: ignore[arg-type]
        self.assertIs(ctx.exception.code, SafetyCode.INVALID_TEXT)

    def test_rejects_wrong_compiled_product(self) -> None:
        with self.assertRaises(TypeError):
            analyze_dictionary("text", object())  # type: ignore[arg-type]

    def test_fixture_note_canary_present_but_never_matched_as_entity(self) -> None:
        self.assertIn(CANARY_NOTE, self.cases["note"])
        result = analyze_dictionary(self.cases["note"], self.compiled)
        self.assertEqual(result.spans, ())
        for text in self.cases.values():
            if isinstance(text, str):
                for span in self._spans(text):
                    self.assertNotIn("CNRY", text[span.start : span.end])


if __name__ == "__main__":
    unittest.main()
