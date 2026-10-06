"""Contract test for BYOK authentication and multi-provider routing."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

import httpx
from starlette.testclient import TestClient

from audit.audit_watermark import AuditWatermarkGuard, WatermarkPolicy
from audit.evidence_gate import EvidenceGate
from detection.detection_orchestrator import DetectionOrchestrator
from detection.recognizers import default_recognizers
from gateway.app import create_app
from gateway.provider_router import ProviderConfig, ProviderRouter, create_provider_pipeline
from infra.envelope_crypto import StaticTestKmsProvider
from infra.errors import SafetyCode, SafetyError
from infra.spool import SpoolWriter
from policy.policy import CategoryLabel, CategoryRule, ClassificationPolicy
from protocol.admission import AdmissionLimiter
from protocol.identity import EnterpriseAuthenticator, TrustedIdentity
from protocol.protocols import CLAUDE_MESSAGES_PROTOCOL, DEEPSEEK_CHAT_PROTOCOL


class TestByokAuthentication(unittest.TestCase):
    def test_byok_authenticator_derives_identity(self):
        auth = EnterpriseAuthenticator(allow_byok=True, default_domain="corp-prod")
        identity = auth.authenticate({"Authorization": "Bearer sk-user-custom-key-12345"})
        self.assertTrue(identity.subject_id.startswith("byok-"))
        self.assertEqual(identity.domain, "corp-prod")
        self.assertIn("model-query", identity.purposes)

    def test_byok_authenticator_supports_x_api_key(self):
        auth = EnterpriseAuthenticator(allow_byok=True, default_domain="corp-prod")
        identity = auth.authenticate({"x-api-key": "sk-ant-custom-key-99999"})
        self.assertTrue(identity.subject_id.startswith("byok-"))
        self.assertEqual(identity.domain, "corp-prod")

    def test_byok_disabled_rejects_unknown_token(self):
        auth = EnterpriseAuthenticator(allow_byok=False)
        with self.assertRaises(SafetyError) as ctx:
            auth.authenticate({"Authorization": "Bearer sk-unknown-key"})
        self.assertEqual(ctx.exception.code, SafetyCode.INVALID_IDENTITY)


class TestMultiProviderRouting(unittest.TestCase):
    def test_router_dispatch_and_byok_header_passthrough(self):
        # 1. Spy transport to capture outbound upstream headers
        received_upstreams = []

        def mock_upstream(request: httpx.Request) -> httpx.Response:
            received_upstreams.append({
                "url": str(request.url),
                "auth": request.headers.get("Authorization"),
                "x_api_key": request.headers.get("x-api-key"),
                "content": json.loads(request.content.decode("utf-8")),
            })
            model_name = json.loads(request.content.decode("utf-8")).get("model", "deepseek-chat")
            reply = {
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "created": 1234567,
                "model": model_name,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "mock reply"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10},
            }
            return httpx.Response(200, json=reply)

        transport = httpx.MockTransport(mock_upstream)

        # 2. Shared assets
        from detection.dictionary import DictionaryEntry, compile_dictionary, compute_dictionary_hash
        entries = (DictionaryEntry(text="甲公司", entity_type="ORG"),)
        dictionary = compile_dictionary({
            "dictionary_id": "test-dict",
            "version": "v1",
            "domain": "corp-prod",
            "entries": [e.model_dump() for e in entries],
            "sha256": compute_dictionary_hash("test-dict", "v1", "corp-prod", entries),
        })
        ner_package = Path(__file__).resolve().parents[2] / "models" / "bert4ner-base-chinese-onnx"

        detector = DetectionOrchestrator(
            recognizers=default_recognizers(),
            dictionary=dictionary,
            ner_package_dir=ner_package,
        )

        kms = StaticTestKmsProvider()
        policy = ClassificationPolicy(
            version="v1",
            rules=(CategoryRule(category="STANDARD", label=CategoryLabel.APPROVED_EXTERNAL, scope="corp-prod"),),
        )
        limiter = AdmissionLimiter(max_body_bytes=1048576)
        watermark = AuditWatermarkGuard(
            Path("."),
            WatermarkPolicy(0.9, 0.8, 1024),
            probe=lambda p: (1000 * 1024 * 1024, 100 * 1024 * 1024, 900 * 1024 * 1024),
        )
        evidence = EvidenceGate(Path("."), evidence_directory=Path("."), kms=kms)
        spool = SpoolWriter(Path("."), kms)

        # Build DeepSeek Pipeline
        p_ds = create_provider_pipeline(
            ProviderConfig(
                channel_id="chan-deepseek",
                protocol=DEEPSEEK_CHAT_PROTOCOL,
                url="https://api.deepseek.com/v1/chat/completions",
                models=("deepseek-chat",),
                credential=None,  # BYOK
            ),
            domain="corp-prod",
            policy=policy,
            detector=detector,
            admission_limiter=limiter,
            watermark_guard=watermark,
            evidence_gate=evidence,
            spool_writer=spool,
        )
        p_ds.egress_client._client._transport = transport

        # Build OpenAI Pipeline
        p_oa = create_provider_pipeline(
            ProviderConfig(
                channel_id="chan-openai",
                protocol=DEEPSEEK_CHAT_PROTOCOL,
                url="https://api.openai.com/v1/chat/completions",
                models=("gpt-4o",),
                credential=None,  # BYOK
            ),
            domain="corp-prod",
            policy=policy,
            detector=detector,
            admission_limiter=limiter,
            watermark_guard=watermark,
            evidence_gate=evidence,
            spool_writer=spool,
        )
        p_oa.egress_client._client._transport = transport

        router = ProviderRouter({
            "deepseek-chat": p_ds,
            "gpt-4o": p_oa,
        })

        app = create_app(
            router=router,
            allow_byok=True,
            hmac_key=b"enterprise-local-hmac-key-32bytes-secret!",
        )
        client = TestClient(app)

        # 3. Call with DeepSeek model and custom key
        resp1 = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer sk-user-ds-key-111"},
            json={"model": "deepseek-chat", "messages": [{"role": "user", "content": "hello"}]},
        )
        self.assertEqual(resp1.status_code, 200, f"resp1 failed with: {resp1.text}")
        self.assertEqual(received_upstreams[-1]["url"], "https://api.deepseek.com/v1/chat/completions")
        self.assertEqual(received_upstreams[-1]["auth"], "Bearer sk-user-ds-key-111")

        # 4. Call with GPT-4o model and different key
        resp2 = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer sk-user-openai-key-222"},
            json={"model": "gpt-4o", "messages": [{"role": "user", "content": "hello gpt"}]},
        )
        self.assertEqual(resp2.status_code, 200, f"resp2 failed with: {resp2.text}")
        self.assertEqual(received_upstreams[-1]["url"], "https://api.openai.com/v1/chat/completions")
        self.assertEqual(received_upstreams[-1]["auth"], "Bearer sk-user-openai-key-222")

        # 5. Call with unadmitted model -> rejected
        resp3 = client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer sk-any-key"},
            json={"model": "unsupported-model-x", "messages": [{"role": "user", "content": "test"}]},
        )
        self.assertEqual(resp3.status_code, 400)


if __name__ == "__main__":
    unittest.main()
