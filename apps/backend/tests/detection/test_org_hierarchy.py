"""Tests for fine-grained hierarchical organization candidate extraction (方案 B)."""

import unittest

from detection.org_hierarchy import extract_hierarchy_org_candidates
from detection.span_resolver import DetectionCandidate, resolve_spans
from detection.spans import redact_text
from masking.mapping import MappingContext


class OrgHierarchyTests(unittest.TestCase):
    def test_extract_three_level_hierarchy(self) -> None:
        text = "四川虹信软件股份有限公司/企业业务中心/数字化供应链事业部"
        # Seed candidate simulating NER detecting the root company
        seed = [
            DetectionCandidate(
                start=0,
                end=len("四川虹信软件股份有限公司"),
                entity_type="ORG",
                priority=3,
                source="ner",
            )
        ]
        derived = extract_hierarchy_org_candidates(text, seed)
        self.assertEqual(len(derived), 2)
        self.assertEqual(text[derived[0].start : derived[0].end], "企业业务中心")
        self.assertEqual(derived[0].entity_type, "ORG")
        self.assertEqual(derived[0].source, "rule:org_hierarchy")

        self.assertEqual(text[derived[1].start : derived[1].end], "数字化供应链事业部")
        self.assertEqual(derived[1].entity_type, "ORG")
        self.assertEqual(derived[1].source, "rule:org_hierarchy")

        # Verify resolve_spans and masking roundtrip
        all_candidates = seed + list(derived)
        resolved = resolve_spans(all_candidates, text_length=len(text))
        self.assertEqual(len(resolved), 3)

        from detection.spans import Span
        spans = [Span(r.start, r.end, r.entity_type, r.priority) for r in resolved]
        with MappingContext(scope="test") as ctx:
            masked = redact_text(text, spans, ctx)
            self.assertEqual(masked, "<ORG_001>/<ORG_002>/<ORG_003>")

    def test_delimiters_variants(self) -> None:
        variants = [
            ("四川虹信软件股份有限公司 - 企业业务中心 - 数字化供应链事业部", "-"),
            ("四川虹信软件股份有限公司 > 企业业务中心 > 数字化供应链事业部", ">"),
            ("四川虹信软件股份有限公司\\企业业务中心\\数字化供应链事业部", "\\"),
            ("四川虹信软件股份有限公司 / 企业业务中心 / 数字化供应链事业部", "/"),
        ]
        for text, delim in variants:
            with self.subTest(delim=delim):
                seed = [
                    DetectionCandidate(
                        start=0,
                        end=len("四川虹信软件股份有限公司"),
                        entity_type="ORG",
                        priority=3,
                        source="ner",
                    )
                ]
                derived = extract_hierarchy_org_candidates(text, seed)
                self.assertEqual(len(derived), 2)
                self.assertEqual(text[derived[0].start : derived[0].end], "企业业务中心")
                self.assertEqual(text[derived[1].start : derived[1].end], "数字化供应链事业部")

    def test_department_with_parens(self) -> None:
        text = "四川虹信软件股份有限公司/研发中心（成都分部）/前端组"
        seed = [
            DetectionCandidate(
                start=0,
                end=len("四川虹信软件股份有限公司"),
                entity_type="ORG",
                priority=3,
                source="ner",
            )
        ]
        derived = extract_hierarchy_org_candidates(text, seed)
        self.assertEqual(len(derived), 2)
        self.assertEqual(text[derived[0].start : derived[0].end], "研发中心（成都分部）")
        self.assertEqual(text[derived[1].start : derived[1].end], "前端组")

    def test_stops_at_sentence_punctuation(self) -> None:
        text = "四川虹信软件股份有限公司/研发中心。请大家注意安排！"
        seed = [
            DetectionCandidate(
                start=0,
                end=len("四川虹信软件股份有限公司"),
                entity_type="ORG",
                priority=3,
                source="ner",
            )
        ]
        derived = extract_hierarchy_org_candidates(text, seed)
        self.assertEqual(len(derived), 1)
        self.assertEqual(text[derived[0].start : derived[0].end], "研发中心")

    def test_no_false_positive_on_non_org(self) -> None:
        # A PER entity followed by a slash should not trigger hierarchy extraction
        text = "张三/企业业务中心"
        seed = [
            DetectionCandidate(
                start=0,
                end=2,
                entity_type="PER",
                priority=3,
                source="ner",
            )
        ]
        derived = extract_hierarchy_org_candidates(text, seed)
        self.assertEqual(derived, ())

    def test_empty_input(self) -> None:
        self.assertEqual(extract_hierarchy_org_candidates("", []), ())
        self.assertEqual(extract_hierarchy_org_candidates("测试文本", []), ())
