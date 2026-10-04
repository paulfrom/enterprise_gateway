"""Tests for A-08 audit watermark guard (audit_watermark.py)."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from audit.audit_watermark import (
    AuditWatermarkGuard,
    WatermarkAssessment,
    WatermarkLevel,
    WatermarkPolicy,
    verify_audit_watermark,
)
from infra.durable_write import DurableWriteError
from infra.errors import SafetyCode, SafetyError


class AuditWatermarkGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.audit_path = Path(self.temp_dir.name)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_healthy_volume_permits_egress(self) -> None:
        # 1000 MB total, 500 MB used (50%), 500 MB free
        probe = lambda p: (1000 * 1024 * 1024, 500 * 1024 * 1024, 500 * 1024 * 1024)
        policy = WatermarkPolicy(blocking_ratio=0.90, warning_ratio=0.80, min_available_bytes=10 * 1024 * 1024)

        guard = AuditWatermarkGuard(self.audit_path, policy, probe=probe)
        assessment = guard.check_egress_permitted()

        self.assertIsInstance(assessment, WatermarkAssessment)
        self.assertEqual(WatermarkLevel.HEALTHY, assessment.level)
        self.assertEqual(0.5, assessment.used_ratio)
        self.assertEqual(500 * 1024 * 1024, assessment.available_bytes)

    def test_warning_volume_permits_egress(self) -> None:
        # 1000 MB total, 850 MB used (85%), 150 MB free
        probe = lambda p: (1000 * 1024 * 1024, 850 * 1024 * 1024, 150 * 1024 * 1024)
        policy = WatermarkPolicy(blocking_ratio=0.90, warning_ratio=0.80, min_available_bytes=10 * 1024 * 1024)

        guard = AuditWatermarkGuard(self.audit_path, policy, probe=probe)
        assessment = guard.check_egress_permitted()

        self.assertEqual(WatermarkLevel.WARNING, assessment.level)
        self.assertAlmostEqual(0.85, assessment.used_ratio)

    def test_exact_blocking_ratio_boundary_blocked(self) -> None:
        # 1000 MB total, 900 MB used (exactly 90.0%), 100 MB free
        probe = lambda p: (1000 * 1024 * 1024, 900 * 1024 * 1024, 100 * 1024 * 1024)
        policy = WatermarkPolicy(blocking_ratio=0.90, warning_ratio=0.80, min_available_bytes=10 * 1024 * 1024)

        guard = AuditWatermarkGuard(self.audit_path, policy, probe=probe)
        with self.assertRaises(SafetyError) as exc_info:
            guard.check_egress_permitted()
        self.assertEqual(SafetyCode.AUDIT_WATERMARK_BLOCKED, exc_info.exception.code)
        self.assertIsNone(exc_info.exception.__cause__)
        self.assertIsNone(exc_info.exception.__context__)

        # assess() returns the measurement evidence without raising
        assessment = guard.assess()
        self.assertEqual(WatermarkLevel.BLOCKED, assessment.level)

    def test_above_blocking_ratio_blocked(self) -> None:
        # 1000 MB total, 950 MB used (95%), 50 MB free
        probe = lambda p: (1000 * 1024 * 1024, 950 * 1024 * 1024, 50 * 1024 * 1024)
        policy = WatermarkPolicy(blocking_ratio=0.90, warning_ratio=0.80, min_available_bytes=10 * 1024 * 1024)

        with self.assertRaises(SafetyError) as exc_info:
            verify_audit_watermark(self.audit_path, policy, probe=probe)
        self.assertEqual(SafetyCode.AUDIT_WATERMARK_BLOCKED, exc_info.exception.code)

    def test_insufficient_available_bytes_blocked(self) -> None:
        # 1000 MB total, 200 MB used (20%), but only 5 MB free (< 10 MB min)
        probe = lambda p: (1000 * 1024 * 1024, 200 * 1024 * 1024, 5 * 1024 * 1024)
        policy = WatermarkPolicy(blocking_ratio=0.90, warning_ratio=0.80, min_available_bytes=10 * 1024 * 1024)

        guard = AuditWatermarkGuard(self.audit_path, policy, probe=probe)
        with self.assertRaises(SafetyError) as exc_info:
            guard.check_egress_permitted()
        self.assertEqual(SafetyCode.AUDIT_WATERMARK_BLOCKED, exc_info.exception.code)

    def test_probe_oserror_fails_closed(self) -> None:
        def failing_probe(p: Path) -> tuple[int, int, int]:
            raise OSError("I/O error reading filesystem statistics")

        policy = WatermarkPolicy()
        guard = AuditWatermarkGuard(self.audit_path, policy, probe=failing_probe)
        with self.assertRaises(SafetyError) as exc_info:
            guard.check_egress_permitted()
        self.assertEqual(SafetyCode.AUDIT_WATERMARK_BLOCKED, exc_info.exception.code)
        self.assertNotIn("I/O error", str(exc_info.exception))
        self.assertIsNone(exc_info.exception.__cause__)
        self.assertIsNone(exc_info.exception.__context__)

    def test_probe_permission_error_fails_closed(self) -> None:
        def failing_probe(p: Path) -> tuple[int, int, int]:
            raise PermissionError("Access denied")

        policy = WatermarkPolicy()
        guard = AuditWatermarkGuard(self.audit_path, policy, probe=failing_probe)
        with self.assertRaises(SafetyError) as exc_info:
            guard.check_egress_permitted()
        self.assertEqual(SafetyCode.AUDIT_WATERMARK_BLOCKED, exc_info.exception.code)

    def test_invalid_policy_values_rejected(self) -> None:
        with self.assertRaises(SafetyError):
            WatermarkPolicy(blocking_ratio=1.5)
        with self.assertRaises(SafetyError):
            WatermarkPolicy(blocking_ratio=-0.1)
        with self.assertRaises(SafetyError):
            WatermarkPolicy(warning_ratio=0.95, blocking_ratio=0.90)  # warning > blocking
        with self.assertRaises(SafetyError):
            WatermarkPolicy(min_available_bytes=-10)

    def test_invalid_probe_values_fail_closed(self) -> None:
        # Total bytes is 0
        probe_zero = lambda p: (0, 0, 0)
        policy = WatermarkPolicy()
        guard = AuditWatermarkGuard(self.audit_path, policy, probe=probe_zero)
        with self.assertRaises(SafetyError) as exc_info:
            guard.check_egress_permitted()
        self.assertEqual(SafetyCode.AUDIT_WATERMARK_BLOCKED, exc_info.exception.code)

    def test_default_probe_real_tempdir(self) -> None:
        policy = WatermarkPolicy(blocking_ratio=0.9999, warning_ratio=0.999, min_available_bytes=1024)
        guard = AuditWatermarkGuard(self.audit_path, policy)
        assessment = guard.check_egress_permitted()

        self.assertIsInstance(assessment, WatermarkAssessment)
        self.assertGreater(assessment.total_bytes, 0)
        self.assertGreater(assessment.available_bytes, 0)
        self.assertEqual(str(self.audit_path), assessment.path)

    def test_enospc_semantic_distinction_from_watermark(self) -> None:
        """Watermark check passes, but actual write failure raises AUDIT_WRITE_FAILED (A-01).

        This confirms that ENOSPC / disk-full write errors are distinct from
        AUDIT_WATERMARK_BLOCKED capacity pre-flight rejections.
        """
        probe = lambda p: (1000 * 1024 * 1024, 500 * 1024 * 1024, 500 * 1024 * 1024)
        policy = WatermarkPolicy()
        guard = AuditWatermarkGuard(self.audit_path, policy, probe=probe)

        # 1. Pre-flight check passes: healthy
        assessment = guard.check_egress_permitted()
        self.assertEqual(WatermarkLevel.HEALTHY, assessment.level)

        # 2. Later real write encounters ENOSPC in durable write layer
        def simulate_enospc_durable_write() -> None:
            raise SafetyError(SafetyCode.AUDIT_WRITE_FAILED, "ENOSPC")

        with self.assertRaises(SafetyError) as exc_info:
            simulate_enospc_durable_write()
        self.assertEqual(SafetyCode.AUDIT_WRITE_FAILED, exc_info.exception.code)


if __name__ == "__main__":
    unittest.main()
