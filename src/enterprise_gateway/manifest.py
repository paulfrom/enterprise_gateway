"""Package manifest and request-level version pinning contract.

Ensures that every request binds to a complete, single, immutable manifest hash.
Corrupted or tampered packages fail closed and cannot be activated.
In-flight requests remain pinned to their original package version even across
blue-green switches or configuration updates.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ManifestErrorCode(StrEnum):
    INVALID_MANIFEST = "invalid_manifest"
    CORRUPTED_PACKAGE = "corrupted_package"
    VERSION_MISMATCH = "version_mismatch"
    UNAUTHORIZED_SWITCH = "unauthorized_switch"


class ManifestError(ValueError):
    """Controlled package manifest contract violation."""

    def __init__(self, code: ManifestErrorCode, detail: str | None = None) -> None:
        self.code = code
        msg = f"manifest contract violation: {code.value}"
        if detail:
            msg = f"{msg} ({detail})"
        super().__init__(msg)


def _compute_package_hash(manifest_id: str, version: str, components: Mapping[str, ComponentEntry]) -> str:
    """Deterministically compute root package hash from sorted component identities."""
    hasher = hashlib.sha256()
    hasher.update(manifest_id.encode("utf-8"))
    hasher.update(b":")
    hasher.update(version.encode("utf-8"))
    for comp_name in sorted(components.keys()):
        comp = components[comp_name]
        hasher.update(b":")
        hasher.update(comp.name.encode("utf-8"))
        hasher.update(b"=")
        hasher.update(comp.version.encode("utf-8"))
        hasher.update(b"=")
        hasher.update(comp.sha256.lower().encode("utf-8"))
    return hasher.hexdigest()


class ComponentEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    name: str
    version: str
    sha256: str

    @field_validator("name", "version", "sha256")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("component fields must not be blank")
        return value


class PackageManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    manifest_id: str
    version: str
    created_at: str
    components: dict[str, ComponentEntry]
    package_hash: str

    @model_validator(mode="after")
    def _verify_package_hash(self) -> PackageManifest:
        expected = _compute_package_hash(self.manifest_id, self.version, self.components)
        if self.package_hash.lower() != expected.lower():
            raise ValueError("package_hash does not match component specification")
        return self

    def verify_payloads(self, payloads: Mapping[str, str | bytes]) -> None:
        """Verify that actual in-memory or on-disk payloads match declared hashes."""
        for comp_name, comp in self.components.items():
            if comp_name not in payloads:
                raise ManifestError(
                    ManifestErrorCode.CORRUPTED_PACKAGE, f"missing required component: {comp_name}"
                )
            raw = payloads[comp_name]
            raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
            actual_digest = hashlib.sha256(raw_bytes).hexdigest()
            if actual_digest != comp.sha256.lower():
                raise ManifestError(
                    ManifestErrorCode.CORRUPTED_PACKAGE,
                    f"digest mismatch for component: {comp_name}",
                )


@dataclass(frozen=True, slots=True)
class RequestVersionHandle:
    """An immutable per-request handle pinning a single package hash."""

    request_id: str
    package_hash: str
    version: str
    manifest: PackageManifest
    bound_at: datetime

    def assert_consistent_hash(self, current_hash: str) -> None:
        """Verify that operations within the same request do not mix package hashes."""
        if current_hash != self.package_hash:
            raise ManifestError(ManifestErrorCode.VERSION_MISMATCH)


class VersionManager:
    """Manages active package versions and provides immutable request handles."""

    def __init__(self, initial_manifest: PackageManifest, initial_payloads: Mapping[str, str | bytes]) -> None:
        initial_manifest.verify_payloads(initial_payloads)
        self._active_manifest = initial_manifest
        self._payloads = dict(initial_payloads)

    @property
    def active_manifest(self) -> PackageManifest:
        return self._active_manifest

    @property
    def active_package_hash(self) -> str:
        return self._active_manifest.package_hash

    def bind_request(self, request_id: str, *, now: datetime | None = None) -> RequestVersionHandle:
        """Pin the current active package version for a new incoming request."""
        if not isinstance(request_id, str) or not request_id.strip():
            raise ManifestError(ManifestErrorCode.INVALID_MANIFEST, "invalid request_id")
        timestamp = now or datetime.now(timezone.utc)
        return RequestVersionHandle(
            request_id=request_id,
            package_hash=self._active_manifest.package_hash,
            version=self._active_manifest.version,
            manifest=self._active_manifest,
            bound_at=timestamp,
        )

    def switch_version(self, new_manifest: PackageManifest, new_payloads: Mapping[str, str | bytes]) -> None:
        """Switch active package version only after full integrity verification passes."""
        if not isinstance(new_manifest, PackageManifest):
            raise ManifestError(ManifestErrorCode.INVALID_MANIFEST, "invalid manifest object")
        # Fail closed: must verify before applying. Corrupted package leaves active version unchanged.
        new_manifest.verify_payloads(new_payloads)
        self._active_manifest = new_manifest
        self._payloads = dict(new_payloads)


def build_manifest(
    manifest_id: str,
    version: str,
    components: Mapping[str, tuple[str, str | bytes]],
    created_at: str | None = None,
) -> tuple[PackageManifest, dict[str, str | bytes]]:
    """Helper to assemble a valid PackageManifest and payload dictionary."""
    comp_entries = {}
    payload_dict = {}
    for name, (comp_ver, raw) in components.items():
        raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
        digest = hashlib.sha256(raw_bytes).hexdigest()
        comp_entries[name] = ComponentEntry(name=name, version=comp_ver, sha256=digest)
        payload_dict[name] = raw

    created = created_at or "2026-10-03T10:00:00Z"
    pkg_hash = _compute_package_hash(manifest_id, version, comp_entries)
    manifest = PackageManifest(
        manifest_id=manifest_id,
        version=version,
        created_at=created,
        components=comp_entries,
        package_hash=pkg_hash,
    )
    return manifest, payload_dict
