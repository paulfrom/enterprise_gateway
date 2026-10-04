"""A-08 audit watermark guard.

Guards audit/evidence storage by verifying disk volume capacity prior to
granting outbound egress permits. When capacity hits or exceeds the injected
blocking watermark, or when disk probing fails, egress is blocked fail-closed
with ``AUDIT_WATERMARK_BLOCKED``.

Capacity boundaries and policies are injected by the caller. This guard
operates as a pre-flight capacity check; real I/O write failures (e.g. ENOSPC
during durable fsync) are preserved as ``AUDIT_WRITE_FAILED`` (A-01) or
``EVIDENCE_GATE_FAILED`` (A-03).
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
import shutil

from infra.errors import SafetyCode, SafetyError

__all__ = [
    "AuditWatermarkGuard",
    "DiskUsageProbe",
    "WatermarkAssessment",
    "WatermarkLevel",
    "WatermarkPolicy",
    "verify_audit_watermark",
]

DiskUsageProbe = Callable[[Path], tuple[int, int, int]]


class WatermarkLevel(StrEnum):
    HEALTHY = "HEALTHY"
    WARNING = "WARNING"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True, slots=True)
class WatermarkPolicy:
    """Policy thresholds injected by the caller.

    - ``blocking_ratio``: usage ratio at or above which egress is blocked (>= blocking_ratio).
    - ``warning_ratio``: usage ratio at or above which a warning is flagged (>= warning_ratio).
    - ``min_available_bytes``: minimum free bytes required; if free < min_available_bytes, blocked.
    """

    blocking_ratio: float = 0.90
    warning_ratio: float = 0.80
    min_available_bytes: int = 10 * 1024 * 1024  # 10 MiB default safe minimum

    def __post_init__(self) -> None:
        if (
            not isinstance(self.blocking_ratio, (int, float))
            or isinstance(self.blocking_ratio, bool)
            or not math.isfinite(self.blocking_ratio)
            or not (0.0 < self.blocking_ratio <= 1.0)
        ):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "invalid blocking_ratio")
        if (
            not isinstance(self.warning_ratio, (int, float))
            or isinstance(self.warning_ratio, bool)
            or not math.isfinite(self.warning_ratio)
            or not (0.0 <= self.warning_ratio <= self.blocking_ratio)
        ):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "invalid warning_ratio")
        if (
            not isinstance(self.min_available_bytes, int)
            or isinstance(self.min_available_bytes, bool)
            or self.min_available_bytes < 0
        ):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "invalid min_available_bytes")


@dataclass(frozen=True, slots=True)
class WatermarkAssessment:
    """Measurement evidence produced by the watermark probe."""

    level: WatermarkLevel
    total_bytes: int
    used_bytes: int
    available_bytes: int
    used_ratio: float
    path: str


def _default_probe(path: Path) -> tuple[int, int, int]:
    usage = shutil.disk_usage(path)
    return (usage.total, usage.used, usage.free)


class AuditWatermarkGuard:
    """Pre-flight capacity guard for audit and evidence volumes."""

    def __init__(
        self,
        audit_dir: Path | str,
        policy: WatermarkPolicy,
        probe: DiskUsageProbe | None = None,
    ) -> None:
        if not isinstance(policy, WatermarkPolicy):
            raise TypeError("policy must be a WatermarkPolicy")
        self._audit_dir = Path(audit_dir)
        self._policy = policy
        self._probe = probe if probe is not None else _default_probe

    @property
    def audit_dir(self) -> Path:
        return self._audit_dir

    @property
    def policy(self) -> WatermarkPolicy:
        return self._policy

    def assess(self) -> WatermarkAssessment:
        """Probe the volume and return an assessment without raising on BLOCKED."""
        probe_failed = False
        try:
            total, used, free = self._probe(self._audit_dir)
        except Exception:
            probe_failed = True

        if probe_failed:
            raise SafetyError(SafetyCode.AUDIT_WATERMARK_BLOCKED, "probe failure")

        if total <= 0 or used < 0 or free < 0:
            raise SafetyError(SafetyCode.AUDIT_WATERMARK_BLOCKED, "invalid volume measurements")

        used_ratio = used / total

        # Strict boundary decision:
        # 1. Available bytes strictly less than minimum required -> BLOCKED
        # 2. Used ratio greater than or equal to blocking threshold -> BLOCKED
        # 3. Used ratio greater than or equal to warning threshold -> WARNING
        # 4. Otherwise -> HEALTHY
        if free < self._policy.min_available_bytes or used_ratio >= self._policy.blocking_ratio:
            level = WatermarkLevel.BLOCKED
        elif used_ratio >= self._policy.warning_ratio:
            level = WatermarkLevel.WARNING
        else:
            level = WatermarkLevel.HEALTHY

        return WatermarkAssessment(
            level=level,
            total_bytes=total,
            used_bytes=used,
            available_bytes=free,
            used_ratio=used_ratio,
            path=str(self._audit_dir),
        )

    def check_egress_permitted(self) -> WatermarkAssessment:
        """Pre-flight check before issuing an egress permit.

        Raises ``SafetyError(AUDIT_WATERMARK_BLOCKED)`` when watermark is BLOCKED
        or probe fails; returns ``WatermarkAssessment`` when permitted (HEALTHY or WARNING).
        """
        assessment = self.assess()
        if assessment.level == WatermarkLevel.BLOCKED:
            raise SafetyError(SafetyCode.AUDIT_WATERMARK_BLOCKED, "watermark limit exceeded")
        return assessment


def verify_audit_watermark(
    audit_dir: Path | str,
    policy: WatermarkPolicy,
    probe: DiskUsageProbe | None = None,
) -> WatermarkAssessment:
    """Convenience helper to verify volume capacity for an egress permit."""
    guard = AuditWatermarkGuard(audit_dir=audit_dir, policy=policy, probe=probe)
    return guard.check_egress_permitted()
