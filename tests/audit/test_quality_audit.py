"""Unit and contract tests for quality audit and threshold contracts."""

import json
from pathlib import Path
import unittest

from infra.errors import SafetyCode, SafetyError
from audit.quality_audit import (
    ApprovedThresholds,
    DatasetSample,
    DatasetSplitAudit,
    QualityEvaluator,
    QualityStatus,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "quality"

_HEX_64 = "a" * 64
_HEX_64_B = "b" * 64


def make_sample(sample_id: str, digest: str, labels: list[str]) -> DatasetSample:
    return DatasetSample(
        sample_id=sample_id,
        domain="finance-ops",
        source="synthetic",
        text_digest=digest,
        labels=labels,
    )


class QualityAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        with open(FIXTURES_DIR / "approved_thresholds.json", "r", encoding="utf-8") as f:
            th_data = json.load(f)
            self.thresholds = ApprovedThresholds.model_validate(th_data)

    def test_clean_splits_pass_audit(self) -> None:
        with open(FIXTURES_DIR / "split_clean.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            train = [DatasetSample.model_validate(x) for x in data["train"]]
            dev = [DatasetSample.model_validate(x) for x in data["dev"]]
            test = [DatasetSample.model_validate(x) for x in data["test"]]

        DatasetSplitAudit.audit_splits(train, dev, test)

    def test_contaminated_id_fails_audit(self) -> None:
        with open(FIXTURES_DIR / "split_contaminated_id.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            train = [DatasetSample.model_validate(x) for x in data["train"]]
            dev = [DatasetSample.model_validate(x) for x in data["dev"]]
            test = [DatasetSample.model_validate(x) for x in data["test"]]

        with self.assertRaises(SafetyError) as ctx:
            DatasetSplitAudit.audit_splits(train, dev, test)
        self.assertIs(ctx.exception.code, SafetyCode.DATASET_CONTAMINATION)

    def test_contaminated_content_fails_audit(self) -> None:
        with open(FIXTURES_DIR / "split_contaminated_content.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            train = [DatasetSample.model_validate(x) for x in data["train"]]
            dev = [DatasetSample.model_validate(x) for x in data["dev"]]
            test = [DatasetSample.model_validate(x) for x in data["test"]]

        with self.assertRaises(SafetyError) as ctx:
            DatasetSplitAudit.audit_splits(train, dev, test)
        self.assertIs(ctx.exception.code, SafetyCode.DATASET_CONTAMINATION)

    def test_train_dev_shared_id_fails_audit(self) -> None:
        train = [make_sample("s1", _HEX_64, ["PHONE"])]
        dev = [make_sample("s1", _HEX_64_B, ["PHONE"])]
        test = [make_sample("s2", "c" * 64, ["PHONE"])]

        with self.assertRaises(SafetyError) as ctx:
            DatasetSplitAudit.audit_splits(train, dev, test)
        self.assertIs(ctx.exception.code, SafetyCode.DATASET_CONTAMINATION)

    def test_train_dev_shared_digest_fails_audit(self) -> None:
        # Same content re-keyed under a different sample ID must still be caught.
        train = [make_sample("s1", _HEX_64, ["PHONE"])]
        dev = [make_sample("s2", _HEX_64, ["PHONE"])]
        test = [make_sample("s3", _HEX_64_B, ["PHONE"])]

        with self.assertRaises(SafetyError) as ctx:
            DatasetSplitAudit.audit_splits(train, dev, test)
        self.assertIs(ctx.exception.code, SafetyCode.DATASET_CONTAMINATION)

    def test_sample_text_digest_must_be_lowercase_sha256_hex(self) -> None:
        for bad_digest in ("A" * 64, "g" * 64, "a" * 63, "a" * 65, "", "not-hex"):
            with self.subTest(digest=bad_digest):
                with self.assertRaises(Exception):
                    make_sample("s1", bad_digest, ["PHONE"])

    def test_evaluator_unapproved_thresholds_status(self) -> None:
        ground_truths = {"s1": ["PHONE"], "s2": ["PHONE"]}
        predictions = {"s1": ["PHONE"], "s2": ["PHONE"]}

        report = QualityEvaluator.evaluate(ground_truths, predictions, thresholds=None)
        self.assertIs(report.status, QualityStatus.UNAPPROVED_THRESHOLDS)
        self.assertEqual(report.to_dict()["status"], "UNAPPROVED_THRESHOLDS")
        self.assertEqual(report.sample_count, 2)
        self.assertEqual(report.zero_failure_one_sided_upper_bound, 1.5)  # 3/2

    def test_evaluator_hard_failure_on_secret_leakage(self) -> None:
        # Sample s1 has SECRET, but prediction missed it!
        ground_truths = {
            "s1": ["SECRET"],
            "s2": ["PHONE"],
            "s3": ["PHONE"]
        }
        predictions = {
            "s1": [],  # SECRET MISSED!
            "s2": ["PHONE"],
            "s3": ["PHONE"]
        }

        report = QualityEvaluator.evaluate(ground_truths, predictions, thresholds=self.thresholds)
        self.assertIs(report.status, QualityStatus.HARD_FAILURE_SECRET_LEAKED)
        self.assertTrue(any("SECRET leakage" in r for r in report.failure_reasons))

    def test_evaluator_secret_hard_failure_is_case_and_whitespace_insensitive(self) -> None:
        for secret_label in ("Secret", " secret  ", "SECRET"):
            with self.subTest(secret_label=secret_label):
                ground_truths = {"s1": [secret_label], "s2": ["PHONE"]}
                predictions = {"s1": [], "s2": ["PHONE"]}  # secret missed!

                report = QualityEvaluator.evaluate(
                    ground_truths, predictions, thresholds=self.thresholds
                )
                self.assertIs(report.status, QualityStatus.HARD_FAILURE_SECRET_LEAKED)

    def test_evaluator_secret_hard_failure_aggregates_all_secret_categories(self) -> None:
        ground_truths = {"s1": ["SECRET"], "s2": ["Secret"]}
        predictions = {"s1": [], "s2": []}

        report = QualityEvaluator.evaluate(ground_truths, predictions, thresholds=self.thresholds)
        self.assertIs(report.status, QualityStatus.HARD_FAILURE_SECRET_LEAKED)
        self.assertTrue(any("2 secret items" in r for r in report.failure_reasons))

    def test_evaluator_passes_when_all_thresholds_met(self) -> None:
        ground_truths = {
            "s1": ["SECRET"],
            "s2": ["PHONE"],
            "s3": ["PHONE"],
            "s4": ["SECRET"]
        }
        predictions = {
            "s1": ["SECRET"],
            "s2": ["PHONE"],
            "s3": ["PHONE"],
            "s4": ["SECRET"]
        }

        report = QualityEvaluator.evaluate(ground_truths, predictions, thresholds=self.thresholds)
        self.assertIs(report.status, QualityStatus.PASS)
        self.assertEqual(len(report.failure_reasons), 0)
        self.assertEqual(report.category_metrics["SECRET"]["leakage_rate"], 0.0)
        self.assertEqual(report.zero_failure_one_sided_upper_bound, 0.75)  # 3/4

    def test_evaluator_fails_when_regular_threshold_not_met(self) -> None:
        # PHONE precision fails threshold (many false positives)
        ground_truths = {
            "s1": ["PHONE"],
            "s2": []
        }
        predictions = {
            "s1": ["PHONE"],
            "s2": ["PHONE"]  # False positive -> precision 0.5 < 0.90
        }

        report = QualityEvaluator.evaluate(ground_truths, predictions, thresholds=self.thresholds)
        self.assertIs(report.status, QualityStatus.FAIL_THRESHOLDS)
        self.assertTrue(any("PHONE precision" in r for r in report.failure_reasons))

    def test_evaluator_fails_when_threshold_category_has_no_samples(self) -> None:
        ground_truths = {"s1": ["PHONE"], "s2": ["PHONE"]}
        predictions = {"s1": ["PHONE"], "s2": ["PHONE"]}
        # thresholds fixture declares SECRET, but no evaluation sample carries it.
        report = QualityEvaluator.evaluate(ground_truths, predictions, thresholds=self.thresholds)
        self.assertIs(report.status, QualityStatus.FAIL_THRESHOLDS)
        self.assertTrue(any("SECRET has no evaluation samples" in r for r in report.failure_reasons))

    def test_empty_samples_rejected(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            QualityEvaluator.evaluate({}, {})
        self.assertIs(ctx.exception.code, SafetyCode.INVALID_SAMPLE)


if __name__ == "__main__":
    unittest.main()
