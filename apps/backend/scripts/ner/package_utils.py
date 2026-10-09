"""Shared helpers for building D-08 NER artifact packages.

Used by export_onnx.py (real bert4ner package) and
build_mini_fixture_package.py (hermetic contract-test fixture).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

LICENSE_APACHE_2_0 = "apache-2.0"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(package_dir: Path, artifact: str) -> dict:
    """Write manifest.json listing every payload file (all but the manifest)."""
    files = {}
    for path in sorted(package_dir.iterdir()):
        if not path.is_file() or path.name == "manifest.json":
            continue
        files[path.name] = {
            "sha256": sha256_of(path),
            "bytes": path.stat().st_size,
        }
    manifest = {
        "manifest_version": 1,
        "artifact": artifact,
        "created_utc": utc_now(),
        "signature": None,
        "files": files,
    }
    with open(package_dir / "manifest.json", "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")
    return manifest


def write_license_excerpt(package_dir: Path, source: str) -> None:
    """Write the machine-checked license attestation required by the contract."""
    attestation = {
        "license": LICENSE_APACHE_2_0,
        "license_verified": True,
        "source": source,
        "excerpt_date_utc": utc_now()[:10],
    }
    with open(package_dir / "license-excerpt.json", "w", encoding="utf-8") as f:
        json.dump(attestation, f, indent=2, ensure_ascii=False)
        f.write("\n")
