"""Tests for the admin OpenAPI export tool (scripts/export_admin_openapi.py)."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts.export_admin_openapi import (
    ADMIN_PATH_PREFIX,
    REPO_ROOT,
    generate_admin_openapi,
    main,
    serialize_openapi,
)

EXPECTED_ADMIN_ROUTES = {
    "/api/admin/login",
    "/api/admin/session",
    "/api/admin/logout",
    "/api/admin/sources",
    "/api/admin/sources/{source_id}",
    "/api/admin/candidates",
    "/api/admin/candidates/{candidate_id}",
    "/api/admin/publications",
    "/api/admin/publications/{publication_id}",
    "/api/admin/observations",
    "/api/admin/observations/{observation_id}",
    "/api/admin/sources/{source_id}/governance",
    "/api/admin/sources/{source_id}/withdraw",
    "/api/admin/candidates/{candidate_id}/publish",
    "/api/admin/candidates/{candidate_id}/reject",
    "/api/admin/candidates/{candidate_id}/revise",
    "/api/admin/publications/{publication_id}/revoke",
    "/api/admin/audit/records",
    "/api/admin/audit/records/{record_id}",
    "/api/admin/audit/events",
    "/api/admin/requests",
    "/api/admin/requests/{request_id}",
}

FORBIDDEN_ROUTE_PREFIXES = (
    "/login",
    "/admin",
    "/healthz",
    "/readyz",
    "/v1/",
)


class ExportAdminOpenApiTests(unittest.TestCase):
    def test_generate_admin_openapi_structure(self):
        schema = generate_admin_openapi()
        self.assertIn("openapi", schema)
        self.assertEqual(schema["openapi"], "3.1.0")
        self.assertIn("info", schema)
        self.assertEqual(schema["info"]["title"], "Enterprise Privacy Gateway Admin API")
        self.assertEqual(schema["info"]["version"], "1.0.0")

        paths = schema.get("paths", {})
        self.assertEqual(set(paths.keys()), EXPECTED_ADMIN_ROUTES)

        for path in paths:
            self.assertTrue(
                path.startswith(ADMIN_PATH_PREFIX),
                f"Path {path} does not start with {ADMIN_PATH_PREFIX}",
            )
            for forbidden in FORBIDDEN_ROUTE_PREFIXES:
                self.assertFalse(
                    path == forbidden or (forbidden.endswith("/") and path.startswith(forbidden)),
                    f"Forbidden prefix {forbidden} found in path {path}",
                )

    def test_components_schemas(self):
        schema = generate_admin_openapi()
        components = schema.get("components", {})
        self.assertIn("schemas", components)
        schemas = components["schemas"]

        expected_schemas = {
            "Basis",
            "Governance",
            "Publish",
            "Revise",
            "Withdraw",
            "ValidationError",
            "HTTPValidationError",
        }
        for name in expected_schemas:
            self.assertIn(name, schemas, f"Missing expected schema: {name}")

    def test_stable_unique_operation_ids(self):
        schema = generate_admin_openapi()
        paths = schema.get("paths", {})
        operation_ids = []

        for path, methods in paths.items():
            for method, op in methods.items():
                if isinstance(op, dict):
                    op_id = op.get("operationId")
                    self.assertTrue(
                        bool(op_id),
                        f"Missing operationId for {method.upper()} {path}",
                    )
                    operation_ids.append(op_id)

        self.assertEqual(
            len(operation_ids),
            len(set(operation_ids)),
            "operationId values must be unique across all operations",
        )

    def test_determinism_and_reproducibility(self):
        content1 = serialize_openapi(generate_admin_openapi())
        content2 = serialize_openapi(generate_admin_openapi())
        self.assertEqual(content1, content2)

    def test_no_leak_of_machine_paths(self):
        content = serialize_openapi(generate_admin_openapi())
        self.assertNotIn("/home/", content)
        self.assertNotIn("/tmp/", content)
        self.assertNotIn("/var/", content)

    def test_cli_export_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sub" / "admin.openapi.json"
            exit_code = main(["--output", str(target)])
            self.assertEqual(exit_code, 0)
            self.assertTrue(target.is_file())

            written = target.read_text(encoding="utf-8")
            expected = serialize_openapi(generate_admin_openapi())
            self.assertEqual(written, expected)

    def test_cli_check_success_when_matching(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "admin.openapi.json"
            target.write_text(serialize_openapi(generate_admin_openapi()), encoding="utf-8")

            exit_code = main(["--check", "--output", str(target)])
            self.assertEqual(exit_code, 0)

    def test_cli_check_failure_when_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "nonexistent.json"
            exit_code = main(["--check", "--output", str(target)])
            self.assertEqual(exit_code, 1)

    def test_cli_check_failure_when_drift_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "admin.openapi.json"
            drifted_content = '{"drift": true}\n'
            target.write_text(drifted_content, encoding="utf-8")

            exit_code = main(["--check", "--output", str(target)])
            self.assertEqual(exit_code, 1)
            # Must not overwrite on check
            self.assertEqual(target.read_text(encoding="utf-8"), drifted_content)

    def test_repo_contract_file_matches(self):
        repo_contract = REPO_ROOT / "contracts" / "admin.openapi.json"
        self.assertTrue(repo_contract.is_file(), f"Repo contract missing: {repo_contract}")
        exit_code = main(["--check", "--output", str(repo_contract)])
        self.assertEqual(
            exit_code,
            0,
            f"Repository contract at {repo_contract} is drifted or out-of-sync!",
        )


if __name__ == "__main__":
    unittest.main()
