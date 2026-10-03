"""Executable egress-authorization contracts; not detection or network evidence."""

import unittest

from enterprise_gateway.egress import (
    DataClassification,
    DetectorStatus,
    EgressPolicy,
    REQUIRED_DETECTORS,
    authorize_egress,
)
from enterprise_gateway.errors import SafetyError


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.complete = {detector: DetectorStatus.PASSED for detector in REQUIRED_DETECTORS}

    def test_local_only_and_unclassified_never_authorize_external_egress(self):
        for classification in (DataClassification.LOCAL_ONLY, DataClassification.UNCLASSIFIED):
            with self.assertRaises(SafetyError):
                authorize_egress(EgressPolicy("domain", classification), self.complete)

    def test_missing_failed_or_timed_out_component_blocks(self):
        policy = EgressPolicy("domain", DataClassification.APPROVED_EXTERNAL)
        for detector in REQUIRED_DETECTORS:
            missing = dict(self.complete)
            del missing[detector]
            with self.assertRaisesRegex(SafetyError, "DETECTION_INCOMPLETE"):
                authorize_egress(policy, missing)
            for status in (DetectorStatus.FAILED, DetectorStatus.TIMEOUT, "passed"):
                failed = dict(self.complete, **{detector: status})
                with self.assertRaisesRegex(SafetyError, "DETECTION_FAILED"):
                    authorize_egress(policy, failed)

    def test_only_explicit_approval_with_complete_results_passes_contract(self):
        authorize_egress(EgressPolicy("domain", DataClassification.APPROVED_EXTERNAL), self.complete)
        with self.assertRaisesRegex(SafetyError, "INVALID_CLASSIFICATION"):
            authorize_egress(EgressPolicy("domain", "approved_external"), self.complete)
        with self.assertRaisesRegex(SafetyError, "UNKNOWN_DETECTOR"):
            authorize_egress(EgressPolicy("domain", DataClassification.APPROVED_EXTERNAL), dict(self.complete, extra=DetectorStatus.PASSED))


if __name__ == "__main__":
    unittest.main()
