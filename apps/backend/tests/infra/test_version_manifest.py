"""Unit and contract tests for package manifest and request-level version pinning."""

import json
import traceback
from datetime import datetime, timezone
from pathlib import Path
import unittest

from infra.errors import SafetyCode, SafetyError
from infra.manifest import (
    PackageManifest,
    VersionManager,
    load_manifest,
)
from tests.infra.manifest_fixtures import build_manifest

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "manifest"
CANARY = "CNRY-manifest-marker-424242"


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

    def test_load_manifest_accepts_trusted_json_text(self) -> None:
        with open(FIXTURES_DIR / "valid_manifest_v1.json", "r", encoding="utf-8") as f:
            manifest = load_manifest(json.dumps(json.load(f)["manifest"]))
        self.assertIsInstance(manifest, PackageManifest)
        self.assertEqual(manifest.manifest_id, "pkg-prod-v1")

    def test_load_manifest_rejects_malformed_json(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            load_manifest('{"manifest_id": "truncated')
        self.assertIs(ctx.exception.code, SafetyCode.INVALID_MANIFEST)
        self.assertIsNone(ctx.exception.__cause__)
        self.assertIsNone(ctx.exception.__context__)

    def test_load_manifest_rejects_non_object_document(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            load_manifest('["not-a-manifest"]')
        self.assertIs(ctx.exception.code, SafetyCode.INVALID_MANIFEST)

    def test_manifest_hash_tampering_rejected_by_strict_loader(self) -> None:
        bad_dict = self.m1.model_dump()
        bad_dict["package_hash"] = "0" * 64
        with self.assertRaises(SafetyError) as ctx:
            load_manifest(bad_dict)
        self.assertIs(ctx.exception.code, SafetyCode.CORRUPTED_PACKAGE)
        self.assertIsNone(ctx.exception.__cause__)
        self.assertIsNone(ctx.exception.__context__)

    def test_load_manifest_error_does_not_echo_submitted_content(self) -> None:
        bad_dict = self.m1.model_dump()
        bad_dict["created_at"] = CANARY
        bad_dict["package_hash"] = "0" * 64
        try:
            load_manifest(json.dumps(bad_dict))
        except SafetyError as exc:
            self.assertNotIn(CANARY, str(exc))
            self.assertNotIn(CANARY, repr(exc))
            self.assertIsNone(exc.__cause__)
            self.assertIsNone(exc.__context__)
            self.assertNotIn(CANARY, traceback.format_exc())
        else:
            self.fail("SafetyError not raised")

    def test_incomplete_component_set_is_rejected(self):
        body=self.m1.model_dump()
        del body['components']['route']
        with self.assertRaises(SafetyError): load_manifest(body)

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

        with self.assertRaises(SafetyError) as ctx:
            handle.assert_consistent_hash("other-tampered-hash")
        self.assertIs(ctx.exception.code, SafetyCode.VERSION_MISMATCH)

    def test_corrupted_payload_fails_switch_and_preserves_active(self) -> None:
        with open(FIXTURES_DIR / "corrupted_tampered.json", "r", encoding="utf-8") as f:
            tampered_data = json.load(f)
            tampered_m = PackageManifest.model_validate(tampered_data["manifest"])
            tampered_p = tampered_data["payloads"]

        # Attempt to switch to corrupted package
        with self.assertRaises(SafetyError) as ctx:
            self.manager.switch_version(tampered_m, tampered_p)
        self.assertIs(ctx.exception.code, SafetyCode.CORRUPTED_PACKAGE)

        # Active version MUST remain unaffected V1
        self.assertEqual(self.manager.active_package_hash, self.m1.package_hash)

    def test_missing_component_payload_fails_closed(self) -> None:
        incomplete_payloads = dict(self.p1)
        del incomplete_payloads["policy"]

        with self.assertRaises(SafetyError) as ctx:
            self.m1.verify_payloads(incomplete_payloads)
        self.assertIs(ctx.exception.code, SafetyCode.CORRUPTED_PACKAGE)

    def test_version_manager_rejects_non_manifest_object(self) -> None:
        with self.assertRaises(SafetyError) as ctx:
            VersionManager(object(), {})
        self.assertIs(ctx.exception.code, SafetyCode.INVALID_MANIFEST)

        with self.assertRaises(SafetyError) as ctx:
            self.manager.switch_version(object(), {})
        self.assertIs(ctx.exception.code, SafetyCode.INVALID_MANIFEST)

    def test_bind_request_rejects_naive_datetime(self) -> None:
        naive = datetime(2026, 10, 3, 10, 0, 0)
        with self.assertRaises(SafetyError) as ctx:
            self.manager.bind_request("req-tz", now=naive)
        self.assertIs(ctx.exception.code, SafetyCode.INVALID_MANIFEST)

        aware = datetime(2026, 10, 3, 10, 0, 0, tzinfo=timezone.utc)
        handle = self.manager.bind_request("req-tz-ok", now=aware)
        self.assertEqual(handle.bound_at, aware)

    def test_build_manifest_helper(self) -> None:
        manifest, payloads = build_manifest(
            "pkg-test", "0.9.0",
            {name: ("1.0", "synthetic-"+name) for name in ("policy","rules","dictionary","ner","mapping","protocol","audit","route")},
            created_at="2026-10-03T10:00:00Z",
        )
        self.assertIsInstance(manifest, PackageManifest)
    def test_components_deep_immutability(self) -> None:
        manifest, payloads = build_manifest(
            "pkg-freeze", "1.0.0",
            {name: ("1.0", "synthetic-"+name) for name in ("policy","rules","dictionary","ner","mapping","protocol","audit","route")},
            created_at="2026-10-04T00:00:00Z",
        )
        with self.assertRaises(TypeError):
            manifest.components.clear()
        with self.assertRaises(TypeError):
            manifest.components["new_comp"] = None  # type: ignore

        manager = VersionManager(manifest, payloads)
        handle = manager.bind_request("req-freeze")
        with self.assertRaises(TypeError):
            handle.manifest.components.clear()
        # Verify consistent hash check succeeds on intact manifest
        handle.assert_consistent_hash(manager.active_package_hash)


if __name__ == "__main__":
    unittest.main()
