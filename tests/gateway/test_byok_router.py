"""Synthetic BYOK sources and three fixed-provider HTTP routes."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import httpx
from starlette.testclient import TestClient

from audit.audit_watermark import AuditWatermarkGuard, WatermarkPolicy
from audit.evidence_gate import EvidenceGate
from detection.dictionary import DictionaryEntry, compile_dictionary, compute_dictionary_hash
from detection.detection_orchestrator import DetectionOrchestrator
from detection.recognizers import default_recognizers
from gateway.app import create_app
from gateway.provider_router import ProviderConfig, ProviderRouter, create_provider_pipeline
from infra.envelope_crypto import StaticTestKmsProvider
from infra.errors import SafetyCode, SafetyError
from infra.spool import SpoolWriter
from policy.policy import CategoryLabel, CategoryRule, ClassificationPolicy
from protocol.admission import AdmissionLimiter
from protocol.identity import ByokAuthenticator, UnverifiedSourceContext
from protocol.protocols import CLAUDE_MESSAGES_PROTOCOL, DEEPSEEK_CHAT_PROTOCOL

HMAC_KEY = b"synthetic-source-correlation-key-32bytes!"


def authenticator():
    return ByokAuthenticator(domain="corp-prod", tenant_id="restricted-ingress", correlation_key=HMAC_KEY)


class TestByokAuthentication(unittest.TestCase):
    def test_byok_creates_unverified_restricted_source(self):
        source = authenticator().authenticate({"Authorization": "Bearer synthetic-user-key"})
        self.assertIsInstance(source, UnverifiedSourceContext)
        self.assertTrue(source.source_id.startswith("byok:"))
        self.assertEqual(source.source_provenance, "unverified-byok")
        self.assertEqual(source.source_acl, frozenset({"corp-prod:restricted-candidate"}))
        self.assertFalse(hasattr(source, "roles"))
        self.assertFalse(hasattr(source, "subject_id"))
        self.assertNotIn("synthetic-user-key", repr(source))

    def test_x_api_key_correlates_same_source_without_granting_ownership(self):
        auth = authenticator()
        bearer = auth.authenticate({"Authorization": "Bearer synthetic-user-key"})
        native = auth.authenticate({"x-api-key": "synthetic-user-key"})
        self.assertEqual(bearer.source_id, native.source_id)
        self.assertEqual(native.domain, "corp-prod")
        self.assertEqual(native.purposes, frozenset({"model-query"}))

    def test_missing_conflicting_or_forged_credentials_rejected(self):
        for headers in ({}, {"Authorization": "Basic synthetic-key"},
                        {"Authorization": "Bearer key", "x-api-key": "other"},
                        {"Authorization": "Bearer key", "x-subject-id": "employee"}):
            with self.subTest(headers=headers), self.assertRaises(SafetyError):
                authenticator().authenticate(headers)


class TestMultiProviderRouting(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.intents, self.evidence, self.spool_dir = (root / name for name in ("intents", "evidence", "spool"))
        for path in (self.intents, self.evidence, self.spool_dir):
            path.mkdir()
        self.received = []

        def upstream(request):
            payload = json.loads(request.content)
            self.received.append((request, payload))
            if request.url.path == "/v1/messages":
                reply = {"id": "msg_test", "type": "message", "role": "assistant",
                         "model": payload["model"], "content": [{"type": "text", "text": "mock reply"}],
                         "stop_reason": "end_turn", "stop_sequence": None,
                         "usage": {"input_tokens": 5, "output_tokens": 5}}
            else:
                reply = {"id": "chatcmpl-test", "object": "chat.completion", "created": 1,
                         "model": payload["model"], "choices": [{"index": 0,
                         "message": {"role": "assistant", "content": "mock reply"}, "finish_reason": "stop"}],
                         "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10}}
            return httpx.Response(200, json=reply)

        entries = (DictionaryEntry(text="甲公司", entity_type="ORG"),)
        dictionary = compile_dictionary({"dictionary_id": "test-dict", "version": "v1", "domain": "corp-prod",
            "entries": [entry.model_dump() for entry in entries],
            "sha256": compute_dictionary_hash("test-dict", "v1", "corp-prod", entries)})
        detector = DetectionOrchestrator(recognizers=default_recognizers(), dictionary=dictionary,
            ner_package_dir=Path(__file__).resolve().parents[2] / "models" / "bert4ner-base-chinese-onnx")
        kms = StaticTestKmsProvider()
        policy = ClassificationPolicy(version="synthetic-policy-v1", rules=(CategoryRule(
            category="STANDARD", label=CategoryLabel.APPROVED_EXTERNAL, scope="corp-prod"),))
        pipelines = {}
        for channel, model, protocol, path, header in (
            ("deepseek", "deepseek-chat", DEEPSEEK_CHAT_PROTOCOL, "/v1/chat/completions", "authorization"),
            ("openai", "gpt-test", DEEPSEEK_CHAT_PROTOCOL, "/v1/chat/completions", "authorization"),
            ("claude", "claude-test", CLAUDE_MESSAGES_PROTOCOL, "/v1/messages", "x-api-key"),
        ):
            pipeline = create_provider_pipeline(ProviderConfig(channel_id=channel, protocol=protocol,
                url=f"https://{channel}.supplier.example{path}", models=(model,), credential_header=header),
                domain="corp-prod", policy=policy, detector=detector,
                admission_limiter=AdmissionLimiter(max_body_bytes=1048576),
                watermark_guard=AuditWatermarkGuard(self.intents, WatermarkPolicy(0.9, 0.8, 1024)),
                evidence_gate=EvidenceGate(self.intents, evidence_directory=self.evidence, kms=kms),
                spool_writer=SpoolWriter(self.spool_dir, kms), evidence_bucket="synthetic-retention",
                transport=httpx.MockTransport(upstream), resolver=lambda host: ("127.0.0.1",))
            pipelines[model] = pipeline
            self.addCleanup(pipeline.egress_client.close)
        # This category approval exists solely in the controlled synthetic fixture.
        self.client = TestClient(create_app(router=ProviderRouter(pipelines),
            authenticator=authenticator(), classifier=lambda raw: "STANDARD", hmac_key=HMAC_KEY,
            client_profile='strict'))
        self.addCleanup(self.client.close)

    def post(self, model, headers, path="/v1/chat/completions"):
        payload = {"model": model, "messages": [{"role": "user", "content": "hello"}]}
        if path == "/v1/messages":
            payload["max_tokens"] = 32
        return self.client.post(path, headers=headers, json=payload)

    def test_deepseek_openai_and_claude_are_bound_and_use_current_key(self):
        cases = (("deepseek-chat", "deepseek", "authorization", "Bearer synthetic-ds", "/v1/chat/completions"),
                 ("gpt-test", "openai", "authorization", "Bearer synthetic-openai", "/v1/chat/completions"),
                 ("claude-test", "claude", "x-api-key", "synthetic-claude", "/v1/messages"))
        for model, channel, header, key, path in cases:
            with self.subTest(model=model):
                response = self.post(model, {header: key}, path)
                self.assertEqual(response.status_code, 200, response.text)
                request, payload = self.received[-1]
                self.assertEqual(str(request.url), f"https://{channel}.supplier.example{path}")
                self.assertEqual(request.headers[header], key)
                self.assertEqual(payload["model"], model)
                if header == "x-api-key":
                    self.assertEqual(request.headers["anthropic-version"], "2023-06-01")
                    self.assertNotIn("authorization", request.headers)
                else:
                    self.assertNotIn("x-api-key", request.headers)
                self.assertNotIn("x-subject-id", request.headers)
        self.assertEqual(len(self.received), 3)
        self.assertEqual(len(list(self.evidence.glob("*.json"))), 3)

    def test_missing_double_malformed_key_and_unadmitted_model_never_send(self):
        for headers in ({}, {"Authorization": "Bearer synthetic", "x-api-key": "other"},
                        {"Authorization": "Basic synthetic"}, {"Authorization": "Bearer "},
                        {"x-api-key": ""}):
            with self.subTest(headers=headers):
                response = self.post("deepseek-chat", headers)
                self.assertEqual(response.status_code, 401, response.text)
        response = self.post("unadmitted-model", {"Authorization": "Bearer synthetic"})
        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(self.received, [])

    def test_protocol_confusion_and_internal_identity_claim_never_send(self):
        response = self.post("claude-test", {"Authorization": "Bearer synthetic"})
        self.assertEqual(response.status_code, 400, response.text)
        response = self.post("deepseek-chat", {"Authorization": "Bearer synthetic", "x-subject-id": "employee"})
        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(self.received, [])


if __name__ == "__main__":
    unittest.main()
