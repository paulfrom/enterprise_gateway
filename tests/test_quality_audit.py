"""Unit and contract tests for C-06: Quality audit and threshold contracts."""

import json
from pathlib import Path
import unittest

from enterprise_gateway.quality_audit import (
    ApprovedThresholds,
    CategoryThreshold,
    DatasetSample,
    DatasetSplitAudit,
    QualityAuditError,
    QualityErrorCode,
    QualityEvaluationReport,
    QualityEvaluator,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "C-06"


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

        with self.assertRaises(QualityAuditError) as ctx:
            DatasetSplitAudit.audit_splits(train, dev, test)
        self.assertEqual(ctx.exception.code, QualityErrorCode.DATASET_CONTAMINATION)

    def test_contaminated_content_fails_audit(self) -> None:
        with open(FIXTURES_DIR / "split_contaminated_content.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            train = [DatasetSample.model_validate(x) for x in data["train"]]
            dev = [DatasetSample.model_validate(x) for x in data["dev"]]
            test = [DatasetSample.model_validate(x) for x in data["test"]]

        with self.assertRaises(QualityAuditError) as ctx:
            DatasetSplitAudit.audit_splits(train, dev, test)
        self.assertEqual(ctx.exception.code, QualityErrorCode.DATASET_CONTAMINATION)

    def test_evaluator_unapproved_thresholds_status(self) -> None:
        ground_truths = {"s1": ["PHONE"], "s2": ["PHONE"]}
        predictions = {"s1": ["PHONE"], "s2": ["PHONE"]}

        report = QualityEvaluator.evaluate(ground_truths, predictions, thresholds=None)
        self.assertEqual(report.status, "UNAPPROVED_THRESHOLDS")
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
        self.assertEqual(report.status, "HARD_FAILURE_SECRET_LEAKED")
        self.assertTrue(any("SECRET leakage" in r for r in report.failure_reasons))

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
        self.assertEqual(report.status, "PASS")
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
        self.assertEqual(report.status, "FAIL_THRESHOLDS")
        self.assertTrue(any("PHONE precision" in r for r in report.failure_reasons))

    def test_empty_samples_rejected(self) -> None:
        with self.assertRaises(QualityAuditError) as ctx:
            QualityEvaluator.evaluate({}, {})
        self.assertEqual(ctx.exception.code, QualityErrorCode.INVALID_SAMPLE)


if __name__ == "__main__":
    unittest.main()
