"""Unit and contract tests for upstream error sanitizer."""

import json
from pathlib import Path
import unittest

from gateway.error_sanitizer import ErrorSanitizer, SanitizedErrorResponse

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "error_sanitizer"


class ErrorSanitizerTests(unittest.TestCase):
    def test_sanitize_429_preserves_status_and_retry_after(self) -> None:
        with open(FIXTURES_DIR / "upstream_429_retry_after.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        sanitized = ErrorSanitizer.sanitize(
            upstream_status=data["status"],
            upstream_headers=data["headers"],
            upstream_raw_body=data["raw_body"],
        )

        self.assertEqual(sanitized.status_code, 429)
        self.assertEqual(sanitized.headers.get("retry-after"), "30")
        self.assertNotIn("x-upstream-trace", sanitized.headers)
        self.assertEqual(sanitized.body["error"]["code"], "UPSTREAM_RATE_LIMITED")

        # Crucial canary check: raw token in upstream body MUST NOT appear in sanitized output
        raw_str = sanitized.to_json()
        self.assertNotIn("sk-upstream-secret-key-999", raw_str)

    def test_sanitize_500_purges_sensitive_ip_and_credentials(self) -> None:
        with open(FIXTURES_DIR / "upstream_500_with_sensitive_leak.json", "r", encoding="utf-8") as f:
            data = json.load(f)

        sanitized = ErrorSanitizer.sanitize(
            upstream_status=data["status"],
            upstream_headers=data["headers"],
            upstream_raw_body=data["raw_body"],
        )

        self.assertEqual(sanitized.status_code, 500)
        self.assertEqual(sanitized.body["error"]["code"], "UPSTREAM_INTERNAL_ERROR")
        self.assertEqual(len(sanitized.headers), 0)

        # Crucial canary check: IP and password in raw body MUST NOT appear
        raw_str = sanitized.to_json()
        self.assertNotIn("10.240.12.3", raw_str)
        self.assertNotIn("secret123", raw_str)
        self.assertNotIn("root", raw_str)

    def test_sanitize_unexpected_status_defaults_to_502(self) -> None:
        sanitized = ErrorSanitizer.sanitize(
            upstream_status=200,  # 200 passed as error is invalid!
            upstream_headers={},
            upstream_raw_body="invalid",
        )
        self.assertEqual(sanitized.status_code, 502)
        self.assertEqual(sanitized.body["error"]["code"], "UPSTREAM_BAD_GATEWAY")


if __name__ == "__main__":
    unittest.main()
