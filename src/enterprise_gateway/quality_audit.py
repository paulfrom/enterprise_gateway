"""Quality criteria, dataset split auditing, and evaluation threshold contracts.

Implements strict dataset partition auditing (zero contamination between train,
dev, and test splits), evaluation metrics with 3/n zero-failure confidence
bounds, and hard fail-closed enforcement for secret leakage.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class QualityErrorCode(StrEnum):
    DATASET_CONTAMINATION = "dataset_contamination"
    INVALID_SAMPLE = "invalid_sample"
    UNAPPROVED_THRESHOLDS = "unapproved_thresholds"
    SECRET_LEAKAGE_HARD_FAILURE = "secret_leakage_hard_failure"
    THRESHOLD_NOT_MET = "threshold_not_met"


class QualityAuditError(ValueError):
    """Controlled quality audit contract violation."""

    def __init__(self, code: QualityErrorCode, detail: str | None = None) -> None:
        self.code = code
        msg = f"quality audit violation: {code.value}"
        if detail:
            msg = f"{msg} ({detail})"
        super().__init__(msg)


class DatasetSample(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    sample_id: str
    domain: str
    source: str
    text_digest: str
    labels: list[str]

    @field_validator("sample_id", "domain", "source", "text_digest")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("sample fields must not be blank")
        return value


class DatasetSplitAudit:
    """Enforces mathematical disjointness between train, dev, and test sets."""

    @staticmethod
    def audit_splits(
        train_samples: Sequence[DatasetSample],
        dev_samples: Sequence[DatasetSample],
        test_samples: Sequence[DatasetSample],
    ) -> None:
        train_ids = {s.sample_id for s in train_samples}
        dev_ids = {s.sample_id for s in dev_samples}
        test_ids = {s.sample_id for s in test_samples}

        # Check ID overlap
        overlap_test_train = test_ids & train_ids
        if overlap_test_train:
            raise QualityAuditError(
                QualityErrorCode.DATASET_CONTAMINATION,
                f"test set contaminated with {len(overlap_test_train)} train IDs",
            )

        overlap_test_dev = test_ids & dev_ids
        if overlap_test_dev:
            raise QualityAuditError(
                QualityErrorCode.DATASET_CONTAMINATION,
                f"test set contaminated with {len(overlap_test_dev)} dev IDs",
            )

        overlap_train_dev = train_ids & dev_ids
        if overlap_train_dev:
            raise QualityAuditError(
                QualityErrorCode.DATASET_CONTAMINATION,
                f"dev set contaminated with {len(overlap_train_dev)} train IDs",
            )

        # Check text digest overlap (prevent re-keyed identical samples)
        train_digests = {s.text_digest for s in train_samples}
        dev_digests = {s.text_digest for s in dev_samples}
        test_digests = {s.text_digest for s in test_samples}

        digest_overlap = test_digests & (train_digests | dev_digests)
        if digest_overlap:
            raise QualityAuditError(
                QualityErrorCode.DATASET_CONTAMINATION,
                f"identical content found across evaluation splits: {len(digest_overlap)} duplicates",
            )


class CategoryThreshold(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    category: str
    min_precision: float = Field(ge=0.0, le=1.0)
    min_recall: float = Field(ge=0.0, le=1.0)
    min_f1: float = Field(ge=0.0, le=1.0)
    max_leakage_rate: float = Field(ge=0.0, le=1.0)


class ApprovedThresholds(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    threshold_version: str
    approved_by: str
    approved_at: str
    category_thresholds: dict[str, CategoryThreshold]
    require_zero_secret_leakage: bool = True

    @field_validator("threshold_version", "approved_by", "approved_at")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("threshold metadata must not be blank")
        return value


@dataclass(frozen=True, slots=True)
class QualityEvaluationReport:
    sample_count: int
    category_metrics: dict[str, dict[str, float]]
    zero_failure_one_sided_upper_bound: float
    status: str
    failure_reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_count": self.sample_count,
            "category_metrics": self.category_metrics,
            "zero_failure_one_sided_upper_bound": self.zero_failure_one_sided_upper_bound,
            "status": self.status,
            "failure_reasons": list(self.failure_reasons),
        }


class QualityEvaluator:
    """Computes evaluation metrics and enforces threshold and zero-leakage contracts."""

    @staticmethod
    def evaluate(
        ground_truths: Mapping[str, Sequence[str]],
        predictions: Mapping[str, Sequence[str]],
        thresholds: ApprovedThresholds | None = None,
    ) -> QualityEvaluationReport:
        sample_keys = sorted(set(ground_truths.keys()) | set(predictions.keys()))
        n = len(sample_keys)
        if n == 0:
            raise QualityAuditError(QualityErrorCode.INVALID_SAMPLE, "no evaluation samples provided")

        all_categories = set()
        for labels in ground_truths.values():
            all_categories.update(labels)
        for labels in predictions.values():
            all_categories.update(labels)

        category_stats: dict[str, dict[str, int]] = {
            cat: {"tp": 0, "fp": 0, "fn": 0} for cat in all_categories
        }

        for k in sample_keys:
            gt_set = set(ground_truths.get(k, []))
            pred_set = set(predictions.get(k, []))
            for cat in all_categories:
                in_gt = cat in gt_set
                in_pred = cat in pred_set
                if in_gt and in_pred:
                    category_stats[cat]["tp"] += 1
                elif not in_gt and in_pred:
                    category_stats[cat]["fp"] += 1
                elif in_gt and not in_pred:
                    category_stats[cat]["fn"] += 1

        category_metrics: dict[str, dict[str, float]] = {}
        for cat, stats in category_stats.items():
            tp = stats["tp"]
            fp = stats["fp"]
            fn = stats["fn"]
            precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if fn == 0 else 0.0)
            recall = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if fp == 0 else 0.0)
            f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
            leakage_rate = fn / (tp + fn) if (tp + fn) > 0 else 0.0
            category_metrics[cat] = {
                "tp": float(tp),
                "fp": float(fp),
                "fn": float(fn),
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "leakage_rate": round(leakage_rate, 4),
            }

        # 3/n Rule: 95% single-sided upper bound for zero observed failures
        zero_failure_upper_bound = round(3.0 / n, 4)

        failures: list[str] = []
        # Hard Rule: Secret leakage is NEVER acceptable regardless of other recalls
        secret_metrics = category_metrics.get("SECRET") or category_metrics.get("secret")
        if secret_metrics and secret_metrics["fn"] > 0:
            failures.append(
                f"SECRET leakage detected: {int(secret_metrics['fn'])} secret items escaped detection"
            )

        if thresholds is None:
            return QualityEvaluationReport(
                sample_count=n,
                category_metrics=category_metrics,
                zero_failure_one_sided_upper_bound=zero_failure_upper_bound,
                status="UNAPPROVED_THRESHOLDS",
                failure_reasons=tuple(failures or ["thresholds_not_approved_by_business_owner"]),
            )

        if failures:
            return QualityEvaluationReport(
                sample_count=n,
                category_metrics=category_metrics,
                zero_failure_one_sided_upper_bound=zero_failure_upper_bound,
                status="HARD_FAILURE_SECRET_LEAKED",
                failure_reasons=tuple(failures),
            )

        # Check category thresholds
        for cat_name, th in thresholds.category_thresholds.items():
            metrics = category_metrics.get(cat_name)
            if not metrics:
                continue
            if metrics["precision"] < th.min_precision:
                failures.append(f"{cat_name} precision {metrics['precision']} < min {th.min_precision}")
            if metrics["recall"] < th.min_recall:
                failures.append(f"{cat_name} recall {metrics['recall']} < min {th.min_recall}")
            if metrics["f1"] < th.min_f1:
                failures.append(f"{cat_name} f1 {metrics['f1']} < min {th.min_f1}")
            if metrics["leakage_rate"] > th.max_leakage_rate:
                failures.append(f"{cat_name} leakage {metrics['leakage_rate']} > max {th.max_leakage_rate}")

        status = "FAIL_THRESHOLDS" if failures else "PASS"
        return QualityEvaluationReport(
            sample_count=n,
            category_metrics=category_metrics,
            zero_failure_one_sided_upper_bound=zero_failure_upper_bound,
            status=status,
            failure_reasons=tuple(failures),
        )
