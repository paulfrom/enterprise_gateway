"""Test fixture helpers for assembling valid C-05 package manifests.

Build helpers live in the test suite (not the production contract module) so
the production manifest surface exposes only strict loading and verification.
"""

from __future__ import annotations

import hashlib
from typing import Mapping

from infra.manifest import (
    ComponentEntry,
    PackageManifest,
    _compute_package_hash,
)


def build_manifest(
    manifest_id: str,
    version: str,
    components: Mapping[str, tuple[str, str | bytes]],
    created_at: str,
) -> tuple[PackageManifest, dict[str, str | bytes]]:
    """Assemble a valid PackageManifest and payload dictionary for tests."""
    comp_entries = {}
    payload_dict = {}
    for name, (comp_ver, raw) in components.items():
        raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
        digest = hashlib.sha256(raw_bytes).hexdigest()
        comp_entries[name] = ComponentEntry(name=name, version=comp_ver, sha256=digest)
        payload_dict[name] = raw

    pkg_hash = _compute_package_hash(manifest_id, version, comp_entries)
    manifest = PackageManifest(
        manifest_id=manifest_id,
        version=version,
        created_at=created_at,
        components=comp_entries,
        package_hash=pkg_hash,
    )
    return manifest, payload_dict
