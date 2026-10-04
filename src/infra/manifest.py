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
from typing import Any, Mapping, NoReturn

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator, model_validator

from infra.errors import SafetyCode, SafetyError
from infra.strict_json import JsonRejectKind, parse_strict_json

REQUIRED_COMPONENTS = frozenset({'policy', 'rules', 'dictionary', 'ner', 'mapping', 'protocol', 'audit', 'route'})


def _compute_package_hash(manifest_id: str, version: str, components: Mapping[str, ComponentEntry]) -> str:
    """Deterministically compute the root hash over a canonical JSON structure.

    Hashing a normalized structure (instead of delimiter-joined strings)
    eliminates concatenation ambiguity: distinct component name/version
    pairings always produce distinct digests.
    """
    canonical = json.dumps(
        {
            "manifest_id": manifest_id,
            "version": version,
            "components": {
                name: {"version": comp.version, "sha256": comp.sha256.lower()}
                for name, comp in sorted(components.items())
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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


class ImmutableDict(dict):
    """Deeply immutable mapping to prevent tampering with manifest components."""

    def __copy__(self) -> ImmutableDict:
        return self

    def __deepcopy__(self, memo: Any) -> ImmutableDict:
        return self

    def __setitem__(self, key: Any, value: Any) -> NoReturn:
        raise TypeError("ImmutableDict cannot be modified")

    def __delitem__(self, key: Any) -> NoReturn:
        raise TypeError("ImmutableDict cannot be modified")

    def clear(self) -> NoReturn:
        raise TypeError("ImmutableDict cannot be modified")

    def pop(self, *args: Any, **kwargs: Any) -> NoReturn:
        raise TypeError("ImmutableDict cannot be modified")

    def popitem(self) -> NoReturn:
        raise TypeError("ImmutableDict cannot be modified")

    def update(self, *args: Any, **kwargs: Any) -> NoReturn:
        raise TypeError("ImmutableDict cannot be modified")

    def setdefault(self, *args: Any, **kwargs: Any) -> NoReturn:
        raise TypeError("ImmutableDict cannot be modified")


class PackageManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    manifest_id: str
    version: str
    created_at: str
    components: dict[str, ComponentEntry]
    package_hash: str

    @field_validator("components", mode="after")
    @classmethod
    def _freeze_components(cls, value: Mapping[str, ComponentEntry]) -> ImmutableDict:
        return ImmutableDict(value)

    @model_validator(mode="after")
    def _verify_package_hash(self) -> PackageManifest:
        if set(self.components) != REQUIRED_COMPONENTS:
            raise ValueError('complete protection package required')
        if any(name != component.name for name,component in self.components.items()):
            raise ValueError('component name mismatch')
        expected = _compute_package_hash(self.manifest_id, self.version, self.components)
        if self.package_hash.lower() != expected.lower():
            raise ValueError("package_hash does not match component specification")
        return self

    def verify_payloads(self, payloads: Mapping[str, str | bytes]) -> None:
        """Verify that actual in-memory or on-disk payloads match declared hashes."""
        for comp_name, comp in self.components.items():
            if comp_name not in payloads:
                raise SafetyError(
                    SafetyCode.CORRUPTED_PACKAGE, f"missing required component: {comp_name}"
                )

            raw = payloads[comp_name]
            raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
            actual_digest = hashlib.sha256(raw_bytes).hexdigest()
            if actual_digest != comp.sha256.lower():
                raise SafetyError(
                    SafetyCode.CORRUPTED_PACKAGE,
                    f"digest mismatch for component: {comp_name}",
                )

    def require_complete(self) -> None:
        if set(self.components) != REQUIRED_COMPONENTS:
            raise SafetyError(SafetyCode.INVALID_MANIFEST, 'incomplete protection package')


def _reject_json(kind: JsonRejectKind) -> NoReturn:
    raise SafetyError(SafetyCode.INVALID_MANIFEST)


def load_manifest(source: str | bytes | Mapping[str, Any]) -> PackageManifest:
    """Strictly load a trusted package manifest document.

    Parser and validator exceptions carry submitted input values, so rejections
    are raised as fresh SafetyError objects after handling ends: no __context__
    or __cause__ chain, and messages never contain str(exc) or document text.
    """
    if isinstance(source, Mapping):
        payload: Any = source
    elif isinstance(source, (str, bytes)):
        payload = parse_strict_json(source, reject=_reject_json)
    else:
        raise TypeError(
            "manifest source must be trusted JSON text or a mapping built by trusted code"
        )
    if not isinstance(payload, dict):
        raise SafetyError(SafetyCode.INVALID_MANIFEST, "manifest must be a JSON object")
    validation_failed = False
    try:
        manifest = PackageManifest.model_validate(payload)
    except ValidationError:
        validation_failed = True
    if validation_failed:
        raise SafetyError(SafetyCode.CORRUPTED_PACKAGE, "manifest failed strict integrity validation")
    return manifest


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
            raise SafetyError(SafetyCode.VERSION_MISMATCH)
        expected = _compute_package_hash(
            self.manifest.manifest_id, self.manifest.version, self.manifest.components
        )
        if expected.lower() != self.package_hash.lower():
            raise SafetyError(SafetyCode.CORRUPTED_PACKAGE)


def _require_tz(dt: datetime, name: str) -> None:
    if not isinstance(dt, datetime) or dt.tzinfo is None or dt.utcoffset() is None:
        raise SafetyError(SafetyCode.INVALID_MANIFEST, f"{name} must include a timezone")


class VersionManager:
    """Manages active package versions and provides immutable request handles."""

    def __init__(self, initial_manifest: PackageManifest, initial_payloads: Mapping[str, str | bytes]) -> None:
        if not isinstance(initial_manifest, PackageManifest):
            raise SafetyError(SafetyCode.INVALID_MANIFEST, "initial manifest object is required")
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
            raise SafetyError(SafetyCode.INVALID_MANIFEST, "invalid request_id")
        if now is None:
            timestamp = datetime.now(timezone.utc)
        else:
            _require_tz(now, "now")
            timestamp = now
        manifest_copy = self._active_manifest.model_copy(deep=True)
        return RequestVersionHandle(
            request_id=request_id,
            package_hash=self._active_manifest.package_hash,
            version=self._active_manifest.version,
            manifest=manifest_copy,
            bound_at=timestamp,
        )

    def switch_version(self, new_manifest: PackageManifest, new_payloads: Mapping[str, str | bytes]) -> None:
        """Switch active package version only after full integrity verification passes."""
        if not isinstance(new_manifest, PackageManifest):
            raise SafetyError(SafetyCode.INVALID_MANIFEST, "invalid manifest object")
        # Fail closed: must verify before applying. Corrupted package leaves active version unchanged.
        new_manifest.verify_payloads(new_payloads)
        self._active_manifest = new_manifest
        self._payloads = dict(new_payloads)
