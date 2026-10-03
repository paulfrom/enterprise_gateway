"""Unit and contract tests for C-05: Package manifest and request-level version pinning."""

import json
from pathlib import Path
import unittest

from enterprise_gateway.manifest import (
    ComponentEntry,
    ManifestError,
    ManifestErrorCode,
    PackageManifest,
    RequestVersionHandle,
    VersionManager,
    build_manifest,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "C-05"


class VersionManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        with open(FIXTURES_DIR / "valid_manifest_v1.json", "r", encoding="utf-8") as f:
            v1_data = json.load(f)
            self.m1 = PackageManifest.model_validate(v1_data["manifest"])
            self.p1 = v1_data["payloads"]

        with open(FIXTURES_DIR / "valid_manifest_v2.json", "r", encoding="utf-8") as f:
            v2_data = json.load(f)
            self.m2 = PackageManifest.model_validate(v2_data["manifest"])
            self.p2 = v2_data["payloads"]

        self.manager = VersionManager(self.m1, self.p1)

    def test_manifest_creation_and_integrity(self) -> None:
        self.assertEqual(self.m1.manifest_id, "pkg-prod-v1")
        self.assertEqual(self.m1.version, "1.0.0")
        self.assertIn("policy", self.m1.components)
        self.m1.verify_payloads(self.p1)

    def test_manifest_hash_tampering_rejected_by_validator(self) -> None:
        bad_dict = self.m1.model_dump()
        bad_dict["package_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
        with self.assertRaises(Exception):
            PackageManifest.model_validate(bad_dict)

    def test_request_version_pinning_in_flight(self) -> None:
        # Step 1: Request 1 binds to V1
        handle_req1 = self.manager.bind_request("req-001")
        self.assertEqual(handle_req1.package_hash, self.m1.package_hash)
        self.assertEqual(handle_req1.version, "1.0.0")

        # Step 2: Global version manager switches to V2 (Blue-Green switch)
        self.manager.switch_version(self.m2, self.p2)
        self.assertEqual(self.manager.active_package_hash, self.m2.package_hash)

        # Step 3: Request 2 binds to V2
        handle_req2 = self.manager.bind_request("req-002")
        self.assertEqual(handle_req2.package_hash, self.m2.package_hash)
        self.assertEqual(handle_req2.version, "2.0.0")

        # Step 4: Crucial invariant - in-flight Request 1 REMAINS pinned to V1
        self.assertEqual(handle_req1.package_hash, self.m1.package_hash)
        self.assertNotEqual(handle_req1.package_hash, handle_req2.package_hash)

    def test_consistent_hash_assertion_enforced(self) -> None:
        handle = self.manager.bind_request("req-test")
        handle.assert_consistent_hash(self.m1.package_hash)

        with self.assertRaises(ManifestError) as ctx:
            handle.assert_consistent_hash("other-tampered-hash")
        self.assertEqual(ctx.exception.code, ManifestErrorCode.VERSION_MISMATCH)

    def test_corrupted_payload_fails_switch_and_preserves_active(self) -> None:
        with open(FIXTURES_DIR / "corrupted_tampered.json", "r", encoding="utf-8") as f:
            tampered_data = json.load(f)
            tampered_m = PackageManifest.model_validate(tampered_data["manifest"])
            tampered_p = tampered_data["payloads"]

        # Attempt to switch to corrupted package
        with self.assertRaises(ManifestError) as ctx:
            self.manager.switch_version(tampered_m, tampered_p)
        self.assertEqual(ctx.exception.code, ManifestErrorCode.CORRUPTED_PACKAGE)

        # Active version MUST remain unaffected V1
        self.assertEqual(self.manager.active_package_hash, self.m1.package_hash)

    def test_missing_component_payload_fails_closed(self) -> None:
        incomplete_payloads = dict(self.p1)
        del incomplete_payloads["policy"]

        with self.assertRaises(ManifestError) as ctx:
            self.m1.verify_payloads(incomplete_payloads)
        self.assertEqual(ctx.exception.code, ManifestErrorCode.CORRUPTED_PACKAGE)

    def test_build_manifest_helper(self) -> None:
        manifest, payloads = build_manifest(
            "pkg-test", "0.9.0",
            {"rule1": ("1.0", "content-1"), "rule2": ("1.1", "content-2")}
        )
        self.assertIsInstance(manifest, PackageManifest)
        manifest.verify_payloads(payloads)


if __name__ == "__main__":
    unittest.main()
