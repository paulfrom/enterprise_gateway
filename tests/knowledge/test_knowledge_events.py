"""Knowledge observation event tests: schema validation, authorization partition, zero full-text leakage."""

import hashlib
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from infra.errors import SafetyCode, SafetyError
from knowledge.knowledge import SourceKind
from knowledge.knowledge_events import (
    EvidenceRef,
    ObservationEvent,
    build_observation_event,
    serialize_event,
)

FIXTURES = Path(__file__).parent / "fixtures"
OBSERVED_AT = datetime(2026, 10, 3, 13, 2, 11, tzinfo=timezone.utc)

EXCERPT = (FIXTURES / "source_excerpt.txt").read_text(encoding="utf-8")
DIGEST = hashlib.sha256(EXCERPT.encode("utf-8")).hexdigest()
CANARY_TEXT = "integration-lead@example.invalid"  # synthetic marker inside the source text


def build(**overrides):
    fields = {
        "tenant": "tenant-acme",
        "domain": "scope-procurement",
        "source_id": "src-contract-alpha",
        "source_version": "v3",
        "source_kind": SourceKind.DOCUMENT,
        "evidence_digest": DIGEST,
        "evidence_offset": 42,
        "observed_at": OBSERVED_AT,
        "purpose": "supplier-relationship-management",
        "retention_policy": "bucket-180d",
        "acl": frozenset({"steward-01", "reviewer-07"}),
        "extraction_version": "extract-1.4.0",
    }
    fields.update(overrides)
    return build_observation_event(**fields)


class EventBuildTests(unittest.TestCase):
    def test_minimal_event_builds_and_serializes(self):
        event = build()
        self.assertIsInstance(event, ObservationEvent)
        self.assertIsInstance(event.acl, frozenset)
        payload = json.loads(serialize_event(event).decode("utf-8"))
        self.assertEqual(payload["tenant"], "tenant-acme")
        self.assertEqual(payload["source_kind"], "document")
        self.assertEqual(payload["evidence_ref"], {"digest": DIGEST, "offset": 42})
        self.assertEqual(payload["acl"], ["reviewer-07", "steward-01"])  # canonical sorted

    def test_factory_signature_never_accepts_full_text(self):
        # The only construction path has no content parameter: passing the
        # source text is a signature-level TypeError, not a policy decision.
        with self.assertRaises(TypeError):
            build(content=EXCERPT)  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            build(text="员工诉求全文")  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            build(body=EXCERPT)  # type: ignore[call-arg]

    def test_serialized_bytes_contain_no_source_text(self):
        event = build()
        raw = serialize_event(event)
        self.assertNotIn(CANARY_TEXT.encode("utf-8"), raw)
        self.assertNotIn("合同草案".encode("utf-8"), raw)
        self.assertNotIn(EXCERPT.encode("utf-8"), raw)
        self.assertIn(DIGEST.encode("ascii"), raw)  # digest reference IS present

    def test_schema_has_no_content_field_and_forbids_extras(self):
        content_fields = {"content", "text", "body", "fulltext", "excerpt", "payload"}
        self.assertFalse(content_fields & set(ObservationEvent.model_fields))
        with self.assertRaises(ValidationError):
            ObservationEvent(**build().model_dump(), excerpt="员工诉求全文")  # type: ignore[arg-type]


class AuthorizationFailureTests(unittest.TestCase):
    """Missing governance coordinates or blank values fail closed with EVENT_INVALID."""

    def test_empty_acl_defaults_to_restricted_candidate(self):
        event = build(acl=frozenset())
        self.assertEqual(event.acl, frozenset({"scope-procurement:restricted-candidate"}))

    def test_blank_acl_member_rejected(self):
        with self.assertRaises(SafetyError) as ctx:
            build(acl=frozenset({"steward-01", " "}))
        self.assertEqual(ctx.exception.code, SafetyCode.EVENT_INVALID)

    def test_blank_purpose_rejected(self):
        with self.assertRaises(SafetyError) as ctx:
            build(purpose="  ")
        self.assertEqual(ctx.exception.code, SafetyCode.EVENT_INVALID)

    def test_blank_retention_policy_rejected(self):
        with self.assertRaises(SafetyError) as ctx:
            build(retention_policy="")
        self.assertEqual(ctx.exception.code, SafetyCode.EVENT_INVALID)

    def test_missing_source_identity_rejected(self):
        for override in ({"source_id": ""}, {"source_version": ""}, {"source_version": "  "}):
            with self.subTest(override=override):
                with self.assertRaises(SafetyError) as ctx:
                    build(**override)
                self.assertEqual(ctx.exception.code, SafetyCode.EVENT_INVALID)

    def test_build_gateway_observation(self):
        from knowledge.knowledge_events import build_gateway_observation
        event = build_gateway_observation(
            tenant="corp-tenant",
            domain="corp.test",
            request_id="req-12345",
            evidence_digest=DIGEST,
        )
        self.assertEqual(event.domain, "corp.test")
        self.assertEqual(event.source_id, "req:req-12345")
        self.assertEqual(event.acl, frozenset({"corp.test:restricted-candidate"}))


class SchemaFailureTests(unittest.TestCase):
    """Shape violations fail with EVENT_INVALID."""

    def test_bad_evidence_digest_rejected(self):
        for bad in ("zz" * 32, "AB" * 32, DIGEST[:63], ""):
            with self.subTest(digest=bad[:12]):
                with self.assertRaises(SafetyError) as ctx:
                    build(evidence_digest=bad)
                self.assertEqual(ctx.exception.code, SafetyCode.EVENT_INVALID)

    def test_negative_offset_rejected(self):
        with self.assertRaises(SafetyError) as ctx:
            build(evidence_offset=-1)
        self.assertEqual(ctx.exception.code, SafetyCode.EVENT_INVALID)

    def test_naive_observed_at_rejected(self):
        with self.assertRaises(SafetyError) as ctx:
            build(observed_at=datetime(2026, 10, 3, 13, 2, 11))
        self.assertEqual(ctx.exception.code, SafetyCode.EVENT_INVALID)

    def test_untyped_source_kind_rejected(self):
        with self.assertRaises(SafetyError) as ctx:
            build(source_kind="document")  # type: ignore[arg-type]
        self.assertEqual(ctx.exception.code, SafetyCode.EVENT_INVALID)

    def test_unshaped_acl_rejected(self):
        with self.assertRaises(SafetyError) as ctx:
            build(acl="steward-01")  # type: ignore[arg-type]
        self.assertEqual(ctx.exception.code, SafetyCode.EVENT_INVALID)

    def test_evidence_ref_direct_schema_validation(self):
        with self.assertRaises(ValidationError):
            EvidenceRef(digest="not-hex", offset=0)
        with self.assertRaises(ValidationError):
            EvidenceRef(digest=DIGEST, offset=-5)

    def test_controlled_error_carries_no_business_text(self):
        try:
            build(acl=frozenset())
        except SafetyError as exc:
            self.assertIsNone(exc.__cause__)
            self.assertIsNone(exc.__context__)
            self.assertNotIn("steward", str(exc))
            self.assertNotIn("tenant-acme", str(exc))


if __name__ == "__main__":
    unittest.main()
