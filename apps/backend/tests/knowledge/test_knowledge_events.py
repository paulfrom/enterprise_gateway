"""Knowledge observation event tests: schema validation, authorization partition, zero full-text leakage."""

import hashlib
import json
import unittest
from datetime import datetime, timezone, timedelta
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
        "evidence_text": EXCERPT,
        "retention_until": OBSERVED_AT + timedelta(days=30),
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

    def test_unassigned_ownership_does_not_prevent_collection(self):
        event = build()
        payload = json.loads(serialize_event(event))
        self.assertEqual("unassigned", payload["ownership_status"])
        self.assertEqual("unverified", payload["source_provenance"])
        self.assertNotIn("owner_id", payload)
        self.assertEqual(frozenset({"steward-01", "reviewer-07"}), event.acl)

    def test_owner_and_trusted_provenance_cannot_be_self_declared(self):
        fields = build().model_dump()
        for changes in ({"owner_id": "someone"}, {"ownership_status": "assigned"},
                        {"source_provenance": "trusted"}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                ObservationEvent(**(fields | changes))

    def test_factory_signature_never_accepts_full_text(self):
        # The only construction path has no content parameter: passing the
        # source text is a signature-level TypeError, not a policy decision.
        with self.assertRaises(TypeError):
            build(content=EXCERPT)  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            build(text="员工诉求全文")  # type: ignore[call-arg]
        with self.assertRaises(TypeError):
            build(body=EXCERPT)  # type: ignore[call-arg]

    def test_evidence_is_in_memory_serialization_for_encrypted_spool(self):
        event = build()
        raw = serialize_event(event)
        self.assertIn(CANARY_TEXT.encode("utf-8"), raw)
        self.assertIn("合同草案".encode("utf-8"), raw)
        self.assertEqual(EXCERPT, json.loads(raw)["evidence_text"])
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
            evidence_text=EXCERPT,
        )
        self.assertEqual(event.domain, "corp.test")
        self.assertTrue(event.source_id.startswith("unverified:user_assertion:"))
        self.assertEqual(event.acl, frozenset({"corp.test:restricted-candidate"}))

    def test_byok_source_collects_unassigned_restricted_observation(self):
        from knowledge.knowledge_events import build_gateway_observation
        from knowledge.worker import extract_event_candidates
        from protocol.identity import ByokAuthenticator
        context = ByokAuthenticator(domain="processing", tenant_id="tenant",
                                    correlation_key=b"synthetic-correlation-key-32-bytes").authenticate(
                                        {"authorization": "Bearer synthetic-key"})
        text = "甲公司向乙公司采购设备"
        event = build_gateway_observation(tenant=context.tenant_id, domain=context.domain,
            request_id="request", evidence_digest=hashlib.sha256(text.encode()).hexdigest(),
            evidence_text=text, observed_at=context.received_at, source_context=context)
        self.assertEqual("unassigned", event.ownership_status)
        self.assertEqual("unverified", event.source_provenance)
        self.assertFalse(event.source_independence_verified)
        self.assertEqual(frozenset({"processing:restricted-candidate"}), event.acl)
        source, candidates = extract_event_candidates(event)
        self.assertFalse(source.independence_verified)
        self.assertTrue(candidates)
        self.assertTrue(all(candidate.independent_source_count == 0 for candidate in candidates))
        self.assertNotIn("synthetic-key", serialize_event(event).decode())

    def test_byok_source_cannot_expand_acl_scope_or_evidence_independence(self):
        from knowledge.knowledge_events import build_gateway_observation
        from protocol.identity import ByokAuthenticator
        context = ByokAuthenticator(domain="processing", tenant_id="tenant",
                                    correlation_key=b"synthetic-correlation-key-32-bytes").authenticate(
                                        {"x-api-key": "synthetic-key"})
        fields = dict(tenant=context.tenant_id, domain=context.domain, request_id="request",
            evidence_digest=DIGEST, evidence_text=EXCERPT, observed_at=context.received_at,
            source_context=context)
        for change in ({"tenant": "another-tenant"}, {"domain": "another-domain"},
                       {"source_acl": frozenset({"reader"})},
                       {"source_independence_verified": True}):
            with self.subTest(change=change), self.assertRaises(SafetyError):
                build_gateway_observation(**(fields | change))

    def test_byok_key_rotation_never_assigns_ownership(self):
        from knowledge.knowledge_events import build_gateway_observation
        from protocol.identity import ByokAuthenticator
        authenticator = ByokAuthenticator(domain="processing", tenant_id="tenant",
                                         correlation_key=b"synthetic-correlation-key-32-bytes")
        events = []
        for token in ("synthetic-key-1", "synthetic-key-2"):
            context = authenticator.authenticate({"authorization": "Bearer " + token})
            events.append(build_gateway_observation(tenant=context.tenant_id, domain=context.domain,
                request_id="request", evidence_digest=DIGEST, evidence_text=EXCERPT,
                observed_at=context.received_at, source_context=context))
        first, rotated = events
        self.assertNotEqual(first.source_id, rotated.source_id)
        self.assertEqual((first.tenant, first.domain, first.ownership_status, first.acl),
                         (rotated.tenant, rotated.domain, rotated.ownership_status, rotated.acl))


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
