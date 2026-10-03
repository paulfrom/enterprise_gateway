"""Unit and contract tests for P-04: Ingress validation barrier."""

import json
from pathlib import Path
import unittest

from enterprise_gateway.ingress import (
    BusinessTextFragment,
    IngressErrorCode,
    IngressValidationError,
    IngressValidator,
    ValidatedIngressRequest,
)
from enterprise_gateway.policy import load_policy
from enterprise_gateway.protocols import CLAUDE_MESSAGES_PROTOCOL, DEEPSEEK_CHAT_PROTOCOL
from enterprise_gateway.static_exemption import load_exemption_registry

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class IngressValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        policy_data = {
            "version": "1.0",
            "rules": [
                {"category": "cat-approved", "label": "approved_external", "scope": "scope-ext"},
                {"category": "cat-secret", "label": "secret", "scope": "scope-loc"},
                {"category": "cat-local", "label": "local_only", "scope": "scope-loc"},
            ],
        }
        self.policy = load_policy(policy_data)

        exemption_data = {
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
        self.exemption_registry = load_exemption_registry(exemption_data)

    def test_deepseek_valid_request_admission(self) -> None:
        with open(FIXTURES_DIR / "P-04" / "deepseek_valid_request.json", "r", encoding="utf-8") as f:
            raw_body = f.read()

        validated = IngressValidator.validate_request(
            raw_body=raw_body,
            protocol=DEEPSEEK_CHAT_PROTOCOL,
            domain="test-domain",
            category="cat-approved",
            policy=self.policy,
            exemption_registry=self.exemption_registry,
        )

        self.assertEqual(validated.protocol, DEEPSEEK_CHAT_PROTOCOL)
        self.assertEqual(validated.model, "deepseek-flash")
        self.assertEqual(len(validated.fragments), 2)

        # Fragment 0 matches tpl-sys-v1 -> exempt!
        self.assertEqual(validated.fragments[0].content, "You are a helpful assistant.")
        self.assertFalse(validated.fragments[0].requires_detection)
        self.assertEqual(validated.fragments[0].matched_template_id, "tpl-sys-v1")

        # Fragment 1 is user content -> requires detection!
        self.assertEqual(validated.fragments[1].content, "Hello DeepSeek!")
        self.assertTrue(validated.fragments[1].requires_detection)
        self.assertIsNone(validated.fragments[1].matched_template_id)

    def test_claude_valid_request_admission(self) -> None:
        with open(FIXTURES_DIR / "P-04" / "claude_valid_request.json", "r", encoding="utf-8") as f:
            raw_body = f.read()

        validated = IngressValidator.validate_request(
            raw_body=raw_body,
            protocol=CLAUDE_MESSAGES_PROTOCOL,
            domain="test-domain",
            category="cat-approved",
            policy=self.policy,
        )
        self.assertEqual(validated.protocol, CLAUDE_MESSAGES_PROTOCOL)
        self.assertEqual(validated.model, "claude-sonnet-5-5")
        self.assertEqual(len(validated.fragments), 1)
        self.assertTrue(validated.fragments[0].requires_detection)

    def test_unapproved_category_fails_closed(self) -> None:
        with open(FIXTURES_DIR / "P-04" / "deepseek_valid_request.json", "r", encoding="utf-8") as f:
            raw_body = f.read()

        # Category 'cat-secret' is rejected before protocol parse
        with self.assertRaises(IngressValidationError) as ctx:
            IngressValidator.validate_request(
                raw_body=raw_body,
                protocol=DEEPSEEK_CHAT_PROTOCOL,
                domain="test-domain",
                category="cat-secret",
                policy=self.policy,
            )
        self.assertEqual(ctx.exception.code, IngressErrorCode.POLICY_REJECTED)

    def test_stream_rejected_at_ingress(self) -> None:
        with open(FIXTURES_DIR / "P-04" / "deepseek_stream_rejected.json", "r", encoding="utf-8") as f:
            raw_body = f.read()

        with self.assertRaises(IngressValidationError) as ctx:
            IngressValidator.validate_request(
                raw_body=raw_body,
                protocol=DEEPSEEK_CHAT_PROTOCOL,
                domain="test-domain",
                category="cat-approved",
                policy=self.policy,
            )
        self.assertEqual(ctx.exception.code, IngressErrorCode.PROTOCOL_VIOLATION)

    def test_tools_rejected_at_ingress(self) -> None:
        with open(FIXTURES_DIR / "P-04" / "claude_tools_rejected.json", "r", encoding="utf-8") as f:
            raw_body = f.read()

        with self.assertRaises(IngressValidationError) as ctx:
            IngressValidator.validate_request(
                raw_body=raw_body,
                protocol=CLAUDE_MESSAGES_PROTOCOL,
                domain="test-domain",
                category="cat-approved",
                policy=self.policy,
            )
        self.assertEqual(ctx.exception.code, IngressErrorCode.PROTOCOL_VIOLATION)

    def test_unsupported_protocol_rejected(self) -> None:
        with self.assertRaises(IngressValidationError) as ctx:
            IngressValidator.validate_request(
                raw_body="{}",
                protocol="unsupported-protocol-v9",
                domain="test-domain",
                category="cat-approved",
                policy=self.policy,
            )
        self.assertEqual(ctx.exception.code, IngressErrorCode.UNSUPPORTED_PROTOCOL)


if __name__ == "__main__":
    unittest.main()
