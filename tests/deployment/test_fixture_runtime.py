"""The synthetic classifier has a finite allowlist and a real refusal branch."""
import json
import unittest

from tests.deployment.fixture_runtime import APPROVED_TEXT, LOCAL_TEXT, UNKNOWN_TEXT, classify


class DeploymentClassifierTests(unittest.TestCase):
    def test_exact_fixture_content_controls_classification(self):
        for text, category in ((APPROVED_TEXT, "STANDARD"), (LOCAL_TEXT, "LOCAL_ONLY"),
                               (UNKNOWN_TEXT, "UNKNOWN"), ("arbitrary content", "UNKNOWN")):
            with self.subTest(category=category):
                raw = json.dumps({"messages": [{"content": text}], "category": "STANDARD"}).encode()
                self.assertEqual(category, classify(raw))

    def test_malformed_or_extended_content_cannot_be_approved(self):
        for content in (None, [], [{"type": "text", "text": APPROVED_TEXT}, {"type": "text", "text": "extra"}]):
            self.assertEqual("UNKNOWN", classify(json.dumps({"messages": [{"content": content}]}).encode()))
        self.assertEqual("UNKNOWN", classify(b"invalid"))
