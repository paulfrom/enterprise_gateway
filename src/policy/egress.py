"""Egress authorization contract; this module is not a detector or proxy.

Callers must obtain classification and detector results from trusted components.
The supplied status values do not, by themselves, prove that detection occurred.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from infra.errors import SafetyCode, SafetyError


class DataClassification(str, Enum):
    UNCLASSIFIED = "unclassified"
    LOCAL_ONLY = "local_only"
    APPROVED_EXTERNAL = "approved_external"


class DetectorStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    TIMEOUT = "timeout"


REQUIRED_DETECTORS = frozenset({"rules", "dictionary", "ner"})


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    scope: str
    classification: DataClassification = DataClassification.UNCLASSIFIED


def authorize_egress(
    policy: EgressPolicy, detector_results: Mapping[str, DetectorStatus]
) -> None:
    """Check the external-egress contract, without performing detection or I/O."""
    if not isinstance(policy.scope, str) or not policy.scope.strip():
        raise SafetyError(SafetyCode.INVALID_SCOPE)
    if not isinstance(policy.classification, DataClassification):
        raise SafetyError(SafetyCode.INVALID_CLASSIFICATION)
    if policy.classification is DataClassification.UNCLASSIFIED:
        raise SafetyError(SafetyCode.UNCLASSIFIED_DATA)
    if policy.classification is DataClassification.LOCAL_ONLY:
        raise SafetyError(SafetyCode.LOCAL_ONLY_DATA)
    if not isinstance(detector_results, Mapping):
        raise SafetyError(SafetyCode.INVALID_DETECTOR_RESULTS)
    if not REQUIRED_DETECTORS.issubset(detector_results):
        raise SafetyError(SafetyCode.DETECTION_INCOMPLETE)
    if set(detector_results) != REQUIRED_DETECTORS:
        raise SafetyError(SafetyCode.UNKNOWN_DETECTOR)
    if any(status is not DetectorStatus.PASSED for status in detector_results.values()):
        raise SafetyError(SafetyCode.DETECTION_FAILED)
