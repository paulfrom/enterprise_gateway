"""Unit and contract tests for C-04: Exact static content exemption."""

import json
from pathlib import Path
import unittest

from enterprise_gateway.static_exemption import (
    ExemptionDecision,
    ExemptionError,
    ExemptionErrorCode,
    ExemptionStatus,
    StaticExemptionRegistry,
    evaluate_and_detect,
    inspect_static_exemption,
    load_exemption_registry,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "C-04"


class StaticExemptionTests(unittest.TestCase):
    def setUp(self) -> None:
        with open(FIXTURES_DIR / "registry.json", "r", encoding="utf-8") as f:
            self.registry_raw = f.read()
        self.registry = load_exemption_registry(self.registry_raw)

    def test_registry_loading_success(self) -> None:
        self.assertEqual(self.registry.version, "1.0.0")
        self.assertEqual(len(self.registry.templates), 2)
        tpl = self.registry.find_template("finance-ops", "tpl-finance-sys-prompt-v1")
        self.assertIsNotNone(tpl)
        self.assertEqual(tpl.domain, "finance-ops")

    def test_registry_invalid_digest_rejected(self) -> None:
        bad_data = {
            "version": "1.0.0",
            "templates": [
                {
                    "template_id": "tpl-1",
                    "domain": "d1",
                    "version": "1.0",
                    "text": "Hello world",
                    "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
                }
            ]
        }
        with self.assertRaises(ExemptionError) as ctx:
            load_exemption_registry(bad_data)
        self.assertEqual(ctx.exception.code, ExemptionErrorCode.INVALID_TEMPLATE)

    def test_registry_duplicate_template_ids_rejected(self) -> None:
        tpl_text = "Standard text"
        sha = "838e121526de009fbab4a44b1c8f3521b44ecad9c81a298ea38a0f96d66e7fb6"
        bad_data = {
            "version": "1.0.0",
            "templates": [
                {"template_id": "tpl-dup", "domain": "d1", "version": "1.0", "text": tpl_text, "sha256": sha},
                {"template_id": "tpl-dup", "domain": "d1", "version": "1.0", "text": tpl_text, "sha256": sha},
            ]
        }
        with self.assertRaises(ExemptionError) as ctx:
            load_exemption_registry(bad_data)
        self.assertEqual(ctx.exception.code, ExemptionErrorCode.INVALID_TEMPLATE)

    def test_registry_duplicate_json_keys_rejected(self) -> None:
        raw_json = '{"version": "1.0", "version": "2.0", "templates": []}'
        with self.assertRaises(ExemptionError) as ctx:
            load_exemption_registry(raw_json)
        self.assertEqual(ctx.exception.code, ExemptionErrorCode.INVALID_REGISTRY)

    def test_exact_match_exemption_positive(self) -> None:
        with open(FIXTURES_DIR / "exact_match.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        detector_calls: list[str] = []

        def spy_detector(text: str) -> dict[str, str]:
            detector_calls.append(text)
            return {"status": "detected"}

        decision, result = evaluate_and_detect(
            text=data["text"],
            domain=data["domain"],
            registry=self.registry,
            detector_callable=spy_detector,
            declared_template_id=data["template_id"],
        )

        self.assertEqual(decision.status, ExemptionStatus.EXEMPT)
        self.assertEqual(decision.matched_template_id, data["template_id"])
        self.assertIsNone(result)
        # Detector MUST NOT be called on exact exemption
        self.assertEqual(len(detector_calls), 0)

    def test_exact_match_without_declared_template_id_positive(self) -> None:
        with open(FIXTURES_DIR / "exact_match.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        decision = inspect_static_exemption(
            text=data["text"],
            domain=data["domain"],
            registry=self.registry,
            declared_template_id=None,
        )
        self.assertEqual(decision.status, ExemptionStatus.EXEMPT)
        self.assertEqual(decision.matched_template_id, data["template_id"])

    def test_single_char_modification_fails_exemption(self) -> None:
        with open(FIXTURES_DIR / "single_char_modified.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        detector_calls: list[str] = []

        def spy_detector(text: str) -> str:
            detector_calls.append(text)
            return "scanned"

        decision, result = evaluate_and_detect(
            text=data["text"],
            domain=data["domain"],
            registry=self.registry,
            detector_callable=spy_detector,
            declared_template_id=data["template_id"],
        )

        self.assertEqual(decision.status, ExemptionStatus.NOT_EXEMPT)
        self.assertIsNone(decision.matched_template_id)
        self.assertEqual(result, "scanned")
        # Detector MUST be called when even 1 character differs
        self.assertEqual(len(detector_calls), 1)

    def test_whitespace_modification_fails_exemption(self) -> None:
        with open(FIXTURES_DIR / "whitespace_modified.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        detector_calls: list[str] = []
        decision, _ = evaluate_and_detect(
            text=data["text"],
            domain=data["domain"],
            registry=self.registry,
            detector_callable=lambda t: detector_calls.append(t),
            declared_template_id=data["template_id"],
        )
        self.assertEqual(decision.status, ExemptionStatus.NOT_EXEMPT)
        self.assertEqual(len(detector_calls), 1)

    def test_variable_injection_fails_exemption(self) -> None:
        with open(FIXTURES_DIR / "variable_injected.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        detector_calls: list[str] = []
        decision, _ = evaluate_and_detect(
            text=data["text"],
            domain=data["domain"],
            registry=self.registry,
            detector_callable=lambda t: detector_calls.append(t),
            declared_template_id=data["template_id"],
        )
        self.assertEqual(decision.status, ExemptionStatus.NOT_EXEMPT)
        self.assertEqual(len(detector_calls), 1)

    def test_inseparable_combination_fails_exemption(self) -> None:
        with open(FIXTURES_DIR / "inseparable_combination.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        detector_calls: list[str] = []
        decision, _ = evaluate_and_detect(
            text=data["text"],
            domain=data["domain"],
            registry=self.registry,
            detector_callable=lambda t: detector_calls.append(t),
            declared_template_id=data["template_id"],
        )
        self.assertEqual(decision.status, ExemptionStatus.NOT_EXEMPT)
        self.assertEqual(len(detector_calls), 1)

    def test_cross_domain_fails_exemption(self) -> None:
        with open(FIXTURES_DIR / "cross_domain.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        decision = inspect_static_exemption(
            text=data["text"],
            domain=data["domain"],
            registry=self.registry,
            declared_template_id=data["template_id"],
        )
        self.assertEqual(decision.status, ExemptionStatus.NOT_EXEMPT)

    def test_unregistered_template_id_fails_exemption(self) -> None:
        decision = inspect_static_exemption(
            text="Any text",
            domain="finance-ops",
            registry=self.registry,
            declared_template_id="non-existent-template-id",
        )
        self.assertEqual(decision.status, ExemptionStatus.NOT_EXEMPT)

    def test_nonstandard_json_constant_rejected(self) -> None:
        raw_json = '{"version": "1.0", "templates": NaN}'
        with self.assertRaises(ExemptionError) as ctx:
            load_exemption_registry(raw_json)
        self.assertEqual(ctx.exception.code, ExemptionErrorCode.REGISTRY_PARSE_FAILED)


if __name__ == "__main__":
    unittest.main()
