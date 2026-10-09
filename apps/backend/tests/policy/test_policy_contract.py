"""Executable egress-policy contract tests; synthetic fixtures and spies only, no network."""

import traceback
import unittest
from pathlib import Path
from unittest import mock

from policy.egress import (
    DataClassification,
    DetectorStatus,
    EgressPolicy,
    REQUIRED_DETECTORS,
    authorize_egress,
)
from infra.errors import SafetyCode, SafetyError
from policy.policy import (
    CLASSIFICATION_BY_LABEL,
    CategoryLabel,
    ClassificationPolicy,
    authorize_with_policy,
    load_policy,
    resolve_egress_policy,
)

FIXTURES = Path(__file__).parent / "fixtures"
CANARY = "CNRY-policy-note-789"


def fixture_text(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


def complete_results():
    return {detector: DetectorStatus.PASSED for detector in REQUIRED_DETECTORS}


def run_pipeline(policy, category, detector_results):
    """Run the policy pipeline behind synthetic spies.

    The eligibility spy wraps the real egress contract (synthetic observation,
    not network evidence); ``outbound`` counts would-be sends after success.
    Returns (eligibility_spy, error_or_None, outbound_attempts).
    """
    outbound = 0
    with mock.patch(
        "policy.policy.authorize_egress", wraps=authorize_egress
    ) as eligibility:
        error = None
        try:
            authorize_with_policy(policy, category, detector_results)
        except SafetyError as exc:
            error = exc
        else:
            outbound = 1
    return eligibility, error, outbound


class StrictParsingTests(unittest.TestCase):
    def test_valid_approved_document_parses(self):
        policy = load_policy(fixture_text("valid-approved.json"))
        self.assertIsInstance(policy, ClassificationPolicy)
        rule = policy.rules[0]
        self.assertIs(rule.label, CategoryLabel.APPROVED_EXTERNAL)
        self.assertEqual(rule.category, "customer_faq")
        self.assertEqual(rule.scope, "support-external")

    def test_trusted_mapping_object_parses(self):
        policy = load_policy(
            {
                "version": "2026-10.synthetic",
                "rules": [
                    {
                        "category": "customer_faq",
                        "label": "approved_external",
                        "scope": "support-external",
                    }
                ],
            }
        )
        self.assertIsInstance(policy, ClassificationPolicy)

    def test_rejecting_fixtures_raise_policy_error(self):
        expected_codes = {
            "unknown-label.json": SafetyCode.POLICY_VALIDATION_FAILED,
            "missing-version.json": SafetyCode.POLICY_VALIDATION_FAILED,
            "wrong-type-scope.json": SafetyCode.POLICY_VALIDATION_FAILED,
            "empty-scope.json": SafetyCode.POLICY_VALIDATION_FAILED,
            "unknown-field.json": SafetyCode.POLICY_VALIDATION_FAILED,
            "duplicate-key.json": SafetyCode.DUPLICATE_POLICY_KEY,
            "duplicate-category.json": SafetyCode.POLICY_VALIDATION_FAILED,
        }
        for name, code in expected_codes.items():
            with self.subTest(fixture=name):
                with self.assertRaises(SafetyError) as ctx:
                    load_policy(fixture_text(name))
                self.assertIs(ctx.exception.code, code)

    def test_no_string_or_bool_coercion(self):
        rule = {"category": "customer_faq", "label": "approved_external", "scope": "support-external"}
        for version in (20261003, True):
            with self.subTest(version=version):
                with self.assertRaises(SafetyError):
                    load_policy({"version": version, "rules": [rule]})
        for scope in (True, ["support-external"]):
            with self.subTest(scope=scope):
                with self.assertRaises(SafetyError):
                    load_policy({"version": "2026-10.synthetic", "rules": [dict(rule, scope=scope)]})

    def test_non_object_or_malformed_json_rejected(self):
        for text in ('["customer_faq"]', '"approved_external"', "123", '{"version": "truncated'):
            with self.subTest(text=text):
                with self.assertRaises(SafetyError):
                    load_policy(text)

    def test_policy_error_does_not_echo_business_text(self):
        try:
            load_policy(fixture_text("unknown-field.json"))
        except SafetyError as exc:
            self.assertNotIn(CANARY, str(exc))
            self.assertIsNone(exc.__cause__)
            self.assertIsNone(exc.__context__)
            formatted = traceback.format_exc()
        else:
            self.fail("SafetyError not raised")
        self.assertNotIn(CANARY, formatted)
        self.assertNotIn("ValidationError", formatted)

    def test_nonstandard_json_constants_rejected(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(constant=constant):
                try:
                    load_policy('{"version": %s, "rules": []}' % constant)
                except SafetyError as exc:
                    self.assertIsNone(exc.__cause__)
                    self.assertIsNone(exc.__context__)
                else:
                    self.fail("SafetyError not raised")

    def test_excessively_nested_document_rejected(self):
        document = '{"wrap":' * 1500 + "1" + "}" * 1500
        try:
            load_policy(document)
        except SafetyError as exc:
            self.assertIsNone(exc.__cause__)
            self.assertIsNone(exc.__context__)
        else:
            self.fail("SafetyError not raised")

    def test_secret_and_local_only_fixture_documents_parse(self):
        for name in ("label-secret.json", "label-local-only.json", "matrix.json"):
            with self.subTest(fixture=name):
                self.assertIsInstance(load_policy(fixture_text(name)), ClassificationPolicy)


class TrustedSourceBoundaryTests(unittest.TestCase):
    def test_request_shaped_object_is_not_a_policy_source(self):
        class FakeClientRequest:
            """Mimics a client request self-declaring approval via body and headers."""

            headers = {"X-Data-Classification": "approved_external", "X-Scope": "support-external"}

            def json(self):
                return {
                    "version": "2026-10.synthetic",
                    "rules": [
                        {
                            "category": "customer_faq",
                            "label": "approved_external",
                            "scope": "support-external",
                        }
                    ],
                }

        request = FakeClientRequest()
        with self.assertRaises(TypeError):
            load_policy(request)
        with self.assertRaises(TypeError):
            resolve_egress_policy(request, "customer_faq")
        with self.assertRaises(TypeError):
            authorize_with_policy(request, "customer_faq", complete_results())

    def test_trusted_mapping_flows_through_pipeline(self):
        policy = load_policy(
            {
                "version": "2026-10.synthetic",
                "rules": [
                    {
                        "category": "customer_faq",
                        "label": "approved_external",
                        "scope": "support-external",
                    }
                ],
            }
        )
        eligibility, error, outbound = run_pipeline(policy, "customer_faq", complete_results())
        self.assertIsNone(error)
        self.assertEqual(eligibility.call_count, 1)
        self.assertEqual(outbound, 1)


class ClassificationMatrixTests(unittest.TestCase):
    def setUp(self):
        self.matrix = load_policy(fixture_text("matrix.json"))

    def test_labels_reuse_egress_classification(self):
        self.assertIs(CLASSIFICATION_BY_LABEL[CategoryLabel.SECRET], DataClassification.LOCAL_ONLY)
        self.assertIs(CLASSIFICATION_BY_LABEL[CategoryLabel.LOCAL_ONLY], DataClassification.LOCAL_ONLY)
        self.assertIs(
            CLASSIFICATION_BY_LABEL[CategoryLabel.APPROVED_EXTERNAL],
            DataClassification.APPROVED_EXTERNAL,
        )

    def test_approved_category_reaches_eligibility_and_egress(self):
        for category in ("customer_faq", "product_manual"):
            with self.subTest(category=category):
                eligibility, error, outbound = run_pipeline(
                    self.matrix, category, complete_results()
                )
                self.assertIsNone(error)
                self.assertEqual(eligibility.call_count, 1)
                self.assertEqual(outbound, 1)
                policy_arg = eligibility.call_args.args[0]
                self.assertIsInstance(policy_arg, EgressPolicy)
                self.assertIs(policy_arg.classification, DataClassification.APPROVED_EXTERNAL)
                self.assertEqual(policy_arg.scope, "support-external")

    def test_secret_label_rejected_before_eligibility(self):
        policy = load_policy(fixture_text("label-secret.json"))
        eligibility, error, outbound = run_pipeline(policy, "salary_record", complete_results())
        self.assertIsInstance(error, SafetyError)
        self.assertIs(error.code, SafetyCode.CATEGORY_NOT_APPROVED)
        self.assertEqual(eligibility.call_count, 0)
        self.assertEqual(outbound, 0)

    def test_local_only_label_rejected_before_eligibility(self):
        policy = load_policy(fixture_text("label-local-only.json"))
        eligibility, error, outbound = run_pipeline(policy, "internal_memo", complete_results())
        self.assertIsInstance(error, SafetyError)
        self.assertIs(error.code, SafetyCode.CATEGORY_NOT_APPROVED)
        self.assertEqual(eligibility.call_count, 0)
        self.assertEqual(outbound, 0)

    def test_secret_and_local_only_labels_stay_distinct_in_matrix(self):
        labels = {rule.category: rule.label for rule in self.matrix.rules}
        self.assertIs(labels["salary_record"], CategoryLabel.SECRET)
        self.assertIs(labels["internal_memo"], CategoryLabel.LOCAL_ONLY)

    def test_unknown_category_rejected(self):
        eligibility, error, outbound = run_pipeline(self.matrix, "ghost_category", complete_results())
        self.assertIsInstance(error, SafetyError)
        self.assertIs(error.code, SafetyCode.UNKNOWN_CATEGORY)
        self.assertEqual(eligibility.call_count, 0)
        self.assertEqual(outbound, 0)

    def test_missing_category_rejected(self):
        for category in ("", "   ", None):
            with self.subTest(category=category):
                eligibility, error, outbound = run_pipeline(self.matrix, category, complete_results())
                self.assertIsInstance(error, SafetyError)
                self.assertIs(error.code, SafetyCode.MISSING_CATEGORY)
                self.assertEqual(eligibility.call_count, 0)
                self.assertEqual(outbound, 0)


class EgressCombinationTests(unittest.TestCase):
    def setUp(self):
        self.matrix = load_policy(fixture_text("matrix.json"))

    def test_approved_with_missing_detector_still_blocked(self):
        results = complete_results()
        del results[next(iter(REQUIRED_DETECTORS))]
        eligibility, error, outbound = run_pipeline(self.matrix, "customer_faq", results)
        self.assertIsInstance(error, SafetyError)
        self.assertIs(error.code, SafetyCode.DETECTION_INCOMPLETE)
        self.assertEqual(eligibility.call_count, 1)
        self.assertEqual(outbound, 0)

    def test_approved_with_failed_or_timed_out_detector_still_blocked(self):
        detector = next(iter(REQUIRED_DETECTORS))
        for status in (DetectorStatus.FAILED, DetectorStatus.TIMEOUT):
            with self.subTest(status=status):
                results = dict(complete_results(), **{detector: status})
                eligibility, error, outbound = run_pipeline(self.matrix, "customer_faq", results)
                self.assertIsInstance(error, SafetyError)
                self.assertIs(error.code, SafetyCode.DETECTION_FAILED)
                self.assertEqual(eligibility.call_count, 1)
                self.assertEqual(outbound, 0)

    def test_approved_with_unknown_detector_still_blocked(self):
        eligibility, error, outbound = run_pipeline(
            self.matrix, "customer_faq", dict(complete_results(), extra=DetectorStatus.PASSED)
        )
        self.assertIsInstance(error, SafetyError)
        self.assertIs(error.code, SafetyCode.UNKNOWN_DETECTOR)
        self.assertEqual(eligibility.call_count, 1)
        self.assertEqual(outbound, 0)


if __name__ == "__main__":
    unittest.main()
