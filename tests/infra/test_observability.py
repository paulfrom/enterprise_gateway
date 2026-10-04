"""Observability whitelist tests, including output-contract consistency check."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from gateway.error_sanitizer import ErrorSanitizer, SanitizedErrorResponse
from infra.errors import SafetyCode, SafetyError
from infra.observability import ALLOWED_FIELDS, scan_record, scan_sanitized_error

FIXTURES = Path(__file__).parent / "fixtures" / "observability"
CANARY = "CNRY-A07"


def fixture_records():
    return json.loads((FIXTURES / "observation_records.json").read_text(encoding="utf-8"))


def assert_violation(testcase, ctx, field_part):
    exc = ctx.exception
    testcase.assertIsInstance(exc, SafetyError)
    testcase.assertEqual(exc.code, SafetyCode.OBSERVABILITY_VIOLATION)
    testcase.assertIn(field_part, str(exc))
    testcase.assertNotIn(CANARY, str(exc))  # detail is static field names only


class WhitelistAcceptTests(unittest.TestCase):
    def test_safe_baseline_record_passes(self):
        entries = scan_record(fixture_records()["safe_baseline"])
        self.assertTrue(entries)  # real validation result, not a stub pass

    def test_accepts_controlled_p13_style_fields(self):
        record = {
            "timestamp": "2026-10-03T13:02:11+00:00",
            "level": "error",
            "event_code": "egress.upstream_failed",
            "status_code": 429,
            "error_code": "UPSTREAM_RATE_LIMITED",
            "message": "上游模型服务触发限流，请稍后重试。",
            "retry_after": "30",
            "count": 2,
        }
        self.assertEqual(len(scan_record(record)), len(record))

    def test_non_mapping_rejected(self):
        with self.assertRaises(TypeError):
            scan_record(["not", "a", "mapping"])  # type: ignore[arg-type]


class PlantedLeakTests(unittest.TestCase):
    """Positive control: planted canary body/credential records MUST be caught."""

    def test_planted_body_leak_caught(self):
        with self.assertRaises(SafetyError) as ctx:
            scan_record(fixture_records()["planted_body_leak"])
        assert_violation(self, ctx, "value:message")

    def test_planted_nested_payload_caught(self):
        with self.assertRaises(SafetyError) as ctx:
            scan_record(fixture_records()["planted_nested_payload"])
        assert_violation(self, ctx, "value:message")

    def test_planted_credential_caught(self):
        with self.assertRaises(SafetyError) as ctx:
            scan_record(fixture_records()["planted_credential_leak"])
        assert_violation(self, ctx, "value:message")

    def test_whitelist_extra_field_caught(self):
        with self.assertRaises(SafetyError) as ctx:
            scan_record(fixture_records()["whitelist_extras"])
        assert_violation(self, ctx, "field:unknown")

    def test_unknown_field_name_is_never_echoed(self):
        # An offending field name is caller input: a body canary smuggled in
        # the key must not leak into the public error message.
        with self.assertRaises(SafetyError) as ctx:
            scan_record({f"payload-{CANARY}-leak-via-key": 1})
        self.assertEqual(ctx.exception.code, SafetyCode.OBSERVABILITY_VIOLATION)
        self.assertNotIn(CANARY, str(ctx.exception))
        self.assertNotIn(CANARY, repr(ctx.exception))

    def test_secret_tripwires_inside_allowed_fields(self):
        cases = [
            "-----begin rsa private key-----\nMIIB",
            "token=AK-abcdef123456",
            "password: hunter2",
            "authorization bearer abcdef1234567890",
        ]
        for text in cases:
            with self.subTest(text=text):
                with self.assertRaises(SafetyError) as ctx:
                    scan_record({"timestamp": 1, "event_code": "x", "message": text})
                self.assertEqual(ctx.exception.code, SafetyCode.OBSERVABILITY_VIOLATION)


class ShapeConstraintTests(unittest.TestCase):
    def test_container_values_rejected_even_on_allowed_names(self):
        with self.assertRaises(SafetyError) as ctx:
            scan_record({"timestamp": 1, "message": {"nested": "dict"}})
        assert_violation(self, ctx, "value:message")

    def test_control_characters_rejected(self):
        with self.assertRaises(SafetyError) as ctx:
            scan_record({"timestamp": 1, "message": "line1\nline2 body"})
        assert_violation(self, ctx, "value:message")

    def test_bad_enums_numbers_and_tokens_rejected(self):
        bad_records = [
            ({"level": "infoo"}, "value:level"),
            ({"status_code": 90}, "value:status_code"),
            ({"count": -1}, "value:count"),
            ({"event_code": "not a token!"}, "value:event_code"),
            ({"timestamp": "not-a-time"}, "value:timestamp"),
            ({"timestamp": True}, "value:timestamp"),
        ]
        for record, part in bad_records:
            with self.subTest(record=record):
                with self.assertRaises(SafetyError) as ctx:
                    scan_record(record)
                assert_violation(self, ctx, part)

    def test_scanner_is_not_an_always_pass_stub(self):
        # Structural proof: perturbing a safe record always flips the verdict.
        safe = dict(fixture_records()["safe_baseline"])
        scan_record(safe)
        for key in list(safe):
            tampered = dict(safe)
            tampered[key] = {"canary": CANARY}
            with self.assertRaises(SafetyError):
                scan_record(tampered)
        with self.assertRaises(SafetyError):
            scan_record({**safe, "canary_field": CANARY})
        self.assertNotIn("canary_field", ALLOWED_FIELDS)


class P13ConsistencyTests(unittest.TestCase):
    def test_p13_sanitized_output_stays_inside_whitelist(self):
        raw = json.dumps({"error": "raw upstream blew up with CNRY-A07-p13-raw-body 私钥泄漏"}).encode()
        response = ErrorSanitizer.sanitize(500, {"Retry-After": "30", "X-Internal": "no"}, raw)
        entries = scan_sanitized_error(response)
        as_dict = dict(entries)
        self.assertEqual(as_dict["status_code"], 500)
        self.assertEqual(as_dict["retry_after"], "30")
        self.assertNotIn("x_internal", as_dict)
        rendered = json.dumps(as_dict, ensure_ascii=False)
        self.assertNotIn(CANARY, rendered)

    def test_hypothetical_p13_drift_with_content_is_caught(self):
        # If a future P-13 change ever puts content into the message, the
        # whitelist scanner must catch it (no silent whitelist drift).
        # A realistic drift: the upstream body gets dumped into the message,
        # blowing past the short-static-text cap.
        drifted = SanitizedErrorResponse(
            status_code=502,
            headers={},
            body={"error": {"code": "UPSTREAM_FAILURE",
                            "message": f"failure dumping body {CANARY}-drift " + "正文" * 200}},
        )
        with self.assertRaises(SafetyError) as ctx:
            scan_sanitized_error(drifted)
        self.assertEqual(ctx.exception.code, SafetyCode.OBSERVABILITY_VIOLATION)


if __name__ == "__main__":
    unittest.main()
