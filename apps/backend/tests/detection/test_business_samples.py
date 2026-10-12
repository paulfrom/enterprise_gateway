"""合成业务评测语料：严格结构、人工金标范围和现有规则语义校验。"""

import json
import unittest
from pathlib import Path

from detection.recognizers import analyze_text


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "ner" / "business-samples.json"
PRODUCTION_TOKENIZER = (
    Path(__file__).resolve().parents[2]
    / "models"
    / "bert4ner-base-chinese-onnx"
    / "tokenizer.json"
)
NER_TYPES = {"PER", "ORG", "LOC"}
RULE_TYPES = {
    "PHONE_NUMBER",
    "CN_ID_NUMBER",
    "CN_USCC",
    "MONEY_AMOUNT",
    "ACCOUNT_NUMBER",
    "CONTRACT_NUMBER",
    "SECRET",
}


class BusinessSampleFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        cls.samples = cls.corpus["samples"]

    def test_strict_schema_and_code_point_spans(self) -> None:
        corpus = self.corpus
        self.assertEqual(
            set(corpus),
            {"schema_version", "synthetic_only", "span_convention", "dictionary_entries", "samples"},
        )
        self.assertEqual(type(corpus["schema_version"]), int)
        self.assertEqual(corpus["schema_version"], 1)
        self.assertIs(corpus["synthetic_only"], True)
        self.assertEqual(corpus["span_convention"], "unicode-codepoint-half-open")
        self.assertIsInstance(corpus["dictionary_entries"], list)
        self.assertIsInstance(self.samples, list)
        identifiers = set()
        for sample in self.samples:
            with self.subTest(sample=sample["id"]):
                self.assertEqual(
                    set(sample), {"id", "scenario", "tags", "fragments", "expect_secret_block"}
                )
                self.assertIsInstance(sample["id"], str)
                self.assertTrue(sample["id"].strip())
                self.assertNotIn(sample["id"], identifiers)
                identifiers.add(sample["id"])
                self.assertIsInstance(sample["scenario"], str)
                self.assertTrue(sample["scenario"].strip())
                self.assertIsInstance(sample["tags"], list)
                self.assertTrue(sample["tags"])
                self.assertEqual(len(sample["tags"]), len(set(sample["tags"])))
                for tag in sample["tags"]:
                    self.assertIsInstance(tag, str)
                    self.assertTrue(tag.strip())
                self.assertEqual(type(sample["expect_secret_block"]), bool)
                self.assertIsInstance(sample["fragments"], list)
                self.assertTrue(sample["fragments"])
                for fragment in sample["fragments"]:
                    self.assertEqual(set(fragment), {"text", "entities"})
                    text = fragment["text"]
                    self.assertIsInstance(text, str)
                    self.assertTrue(text.strip())
                    text.encode("utf-8", errors="strict")
                    self.assertIsInstance(fragment["entities"], list)
                    seen = set()
                    for entity in fragment["entities"]:
                        self.assertEqual(set(entity), {"type", "start", "end"})
                        self.assertIn(entity["type"], NER_TYPES | RULE_TYPES)
                        self.assertEqual(type(entity["start"]), int)
                        self.assertEqual(type(entity["end"]), int)
                        self.assertLessEqual(0, entity["start"])
                        self.assertLess(entity["start"], entity["end"])
                        self.assertLessEqual(entity["end"], len(text))
                        self.assertTrue(text[entity["start"] : entity["end"]].strip())
                        signature = (entity["type"], entity["start"], entity["end"])
                        self.assertNotIn(signature, seen)
                        seen.add(signature)

    def test_all_authored_names_are_fully_annotated(self) -> None:
        """校验每处虚构实体，包括长文本中间及重复出现处，避免漏标。"""
        entries = self.corpus["dictionary_entries"]
        lexicon = {}
        for entry in entries:
            self.assertEqual(set(entry), {"text", "entity_type"})
            self.assertIsInstance(entry["text"], str)
            self.assertTrue(entry["text"].strip())
            self.assertIn(entry["entity_type"], NER_TYPES)
            self.assertNotIn(entry["text"], lexicon)
            lexicon[entry["text"]] = entry["entity_type"]
        used_surfaces = set()
        for sample in self.samples:
            for index, fragment in enumerate(sample["fragments"]):
                with self.subTest(sample=sample["id"], fragment=index):
                    text = fragment["text"]
                    gold = {
                        (entity["type"], entity["start"], entity["end"])
                        for entity in fragment["entities"]
                        if entity["type"] in NER_TYPES
                    }
                    expected = set()
                    for surface, entity_type in lexicon.items():
                        start = text.find(surface)
                        while start >= 0:
                            expected.add((entity_type, start, start + len(surface)))
                            used_surfaces.add(surface)
                            start = text.find(surface, start + 1)
                    self.assertEqual(gold, expected)
        self.assertEqual(used_surfaces, set(lexicon))

    def test_rule_gold_matches_current_default_recognizers(self) -> None:
        """规则金标须真实可检出，负例和其他文本不得遗漏规则命中。"""
        for sample in self.samples:
            for index, fragment in enumerate(sample["fragments"]):
                with self.subTest(sample=sample["id"], fragment=index):
                    expected = {
                        (entity["type"], entity["start"], entity["end"])
                        for entity in fragment["entities"]
                        if entity["type"] in RULE_TYPES
                    }
                    actual = {
                        (span.entity_type, span.start, span.end)
                        for span in analyze_text(fragment["text"])
                    }
                    self.assertEqual(actual, expected)

    def test_unicode_offsets_use_code_points(self) -> None:
        sample = next(sample for sample in self.samples if sample["id"] == "customer-unicode-offsets")
        fragment = sample["fragments"][0]
        person = next(entity for entity in fragment["entities"] if entity["type"] == "PER")
        self.assertEqual(person, {"type": "PER", "start": 12, "end": 15})
        self.assertEqual(fragment["text"][person["start"] : person["end"]], "林澈澄")
        self.assertGreater(len(fragment["text"][:person["start"]].encode("utf-8")), person["start"])

    def test_coverage_and_whole_request_secret_expectations(self) -> None:
        self.assertGreaterEqual(len(self.samples), 30)
        self.assertEqual(
            {sample["scenario"] for sample in self.samples},
            {"customer_service", "contract", "finance", "human_resources", "rule_format", "secret", "low_risk"},
        )
        gold_types = {
            entity["type"]
            for sample in self.samples
            for fragment in sample["fragments"]
            for entity in fragment["entities"]
        }
        self.assertEqual(gold_types, NER_TYPES | RULE_TYPES)
        self.assertGreaterEqual(sum(len(sample["fragments"]) > 1 for sample in self.samples), 4)
        negatives = [sample for sample in self.samples if "negative" in sample["tags"]]
        self.assertGreaterEqual(len(negatives), 5)
        for sample in negatives:
            self.assertTrue(all(not fragment["entities"] for fragment in sample["fragments"]))
            self.assertFalse(sample["expect_secret_block"])
        long_samples = [sample for sample in self.samples if "long" in sample["tags"]]
        self.assertGreaterEqual(len(long_samples), 3)
        self.assertGreaterEqual(max(len(sample["fragments"][0]["text"]) for sample in long_samples), 8192)
        for sample in self.samples:
            has_secret = any(
                entity["type"] == "SECRET"
                for fragment in sample["fragments"]
                for entity in fragment["entities"]
            )
            self.assertEqual(sample["expect_secret_block"], has_secret)

    @unittest.skipUnless(PRODUCTION_TOKENIZER.is_file(), "本机生产 tokenizer 未安装")
    def test_long_entity_crossings_with_production_tokenizer(self) -> None:
        """真实 tokenizer 校验 126 内容 token、32 步长的窗口跨界实体。"""
        from tokenizers import Tokenizer

        tokenizer = Tokenizer.from_file(str(PRODUCTION_TOKENIZER))
        for sample in self.samples:
            if "cross-window-entity" not in sample["tags"]:
                continue
            with self.subTest(sample=sample["id"]):
                fragment = sample["fragments"][0]
                encoding = tokenizer.encode(fragment["text"], add_special_tokens=False)
                crossings = []
                for entity in fragment["entities"]:
                    indices = [
                        index for index, (start, end) in enumerate(encoding.offsets)
                        if start < entity["end"] and end > entity["start"]
                    ]
                    self.assertTrue(indices)
                    first, end = indices[0], indices[-1] + 1
                    crossings.extend(
                        boundary for boundary in range(126, len(encoding.ids), 32)
                        if first < boundary < end
                    )
                self.assertTrue(crossings)
                self.assertEqual(fragment["entities"][-1]["end"], len(fragment["text"]))


if __name__ == "__main__":
    unittest.main()
