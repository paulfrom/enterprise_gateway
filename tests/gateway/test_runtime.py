from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx
from starlette.testclient import TestClient

from audit.audit_watermark import WatermarkPolicy
from detection.dictionary import DictionaryEntry, compile_dictionary, compute_dictionary_hash
from gateway.runtime import create_runtime_app, load_custom_provider
from infra.envelope_crypto import KmsUnavailableError, StaticTestKmsProvider, decrypt_record, parse_record
from infra.errors import SafetyError
from knowledge.knowledge_events import ObservationEvent
from policy.policy import CategoryLabel, CategoryRule, ClassificationPolicy
from protocol.identity import TrustedIdentity


NER_PACKAGE = Path(__file__).resolve().parents[2] / "models" / "bert4ner-base-chinese-onnx"


class FixedProviderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "models.json"
        self.entry = {"id": "deepseek-flash", "name": "deepseek-flash", "vendor": "Custom",
                      "url": "https://supplier.example/v1/chat/completions",
                      "apiKey": "supplier-test-secret", "useCustomProtocol": False,
                      "supportsToolCall": True, "supportsImages": True, "supportsReasoning": True}

    def write(self, payload):
        self.path.write_text(json.dumps(payload), encoding="utf-8")

    def test_exact_fixed_provider_secret_hidden(self):
        self.write([self.entry])
        provider = load_custom_provider(self.path)
        self.assertEqual("deepseek-flash", provider.model_id)
        self.assertEqual(("supplier.example", 443), (provider.host, provider.port))
        self.assertNotIn(self.entry["apiKey"], repr(provider))

    def test_invalid_or_ambiguous_supplier_file_rejected_without_secret(self):
        payloads = [[], [self.entry, self.entry], self.entry]
        for changes in ({"url": "http://supplier.example/v1/chat/completions"},
                        {"url": "https://supplier.example/v1/messages"},
                        {"url": "https://user:secret@supplier.example/v1/chat/completions"},
                        {"url": "https://supplier.example/v1/chat/completions?key=secret"},
                        {"url": "https://supplier.example/v1/chat/completions#fragment"},
                        {"url": "https://supplier.example:0/v1/chat/completions"},
                        {"url": "https://supplier.example:65536/v1/chat/completions"},
                        {"useCustomProtocol": True}, {"vendor": "Unspecified"},
                        {"apiKey": ""}, {"id": ""}, {"supportsImages": "true"},
                        {"base_url": "https://other.example"}):
            payloads.append([{**self.entry, **changes}])
        for payload in payloads:
            with self.subTest(payload_index=payloads.index(payload)):
                self.write(payload)
                with self.assertRaises(SafetyError) as caught:
                    load_custom_provider(self.path)
                self.assertNotIn(self.entry["apiKey"], str(caught.exception))

    def test_duplicate_and_oversized_config_rejected(self):
        for raw in (b'[{"id":"a","id":"b"}]', b" " * 65537, b"[NaN]", b"\xff"):
            self.path.write_bytes(raw)
            with self.assertRaises(SafetyError):
                load_custom_provider(self.path)


class RuntimeAssemblyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.provider_file = self.root / "models.json"
        self.provider_file.write_text(json.dumps([{
            "id": "deepseek-flash", "vendor": "Custom",
            "url": "https://supplier.example/v1/chat/completions",
            "apiKey": "supplier-test-secret", "useCustomProtocol": False,
        }]), encoding="utf-8")
        now = datetime.now(timezone.utc)
        self.identity = TrustedIdentity("synthetic-agent", "synthetic-tenant", "runtime-test",
                                        frozenset({"employee"}), frozenset({"model-query"}),
                                        auth_source="synthetic-acceptance", authenticated_at=now-timedelta(minutes=1),
                                        expires_at=now+timedelta(hours=1))
        entries = tuple(DictionaryEntry(text=text, entity_type=kind) for text, kind in
                        (("甲公司", "ORG"), ("乙公司", "ORG"), ("张三", "PER")))
        self.dictionary = compile_dictionary({"dictionary_id": "runtime-dict", "version": "v1",
            "domain": self.identity.domain, "entries": [e.model_dump() for e in entries],
            "sha256": compute_dictionary_hash("runtime-dict", "v1", self.identity.domain, entries)})
        self.kms = StaticTestKmsProvider()
        self.calls = []
        self.transport = httpx.MockTransport(self.upstream)
        self.policy = ClassificationPolicy(version="runtime-test-v1", rules=(
            CategoryRule(category="STANDARD", label=CategoryLabel.APPROVED_EXTERNAL, scope=self.identity.domain),))

    def upstream(self, request):
        self.calls.append(request)
        self.assertEqual("Bearer supplier-test-secret", request.headers["authorization"])
        self.assertNotIn("enterprise-test-token", str(request.headers))
        for truth in ("甲公司", "乙公司", "张三", "13800138000"):
            self.assertNotIn(truth, request.content.decode())
        payload = json.loads(request.content)
        return httpx.Response(200, json={"id": "chatcmpl-runtime", "object": "chat.completion",
            "created": 1, "model": "deepseek-flash", "choices": [{"index": 0,
                "message": {"role": "assistant", "content": payload["messages"][-1]["content"]},
                "finish_reason": "stop"}], "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

    def app(self, **changes):
        args = dict(provider_config_path=self.provider_file, identity=self.identity,
            enterprise_token="enterprise-test-token", hmac_key=b"h"*32, kms=self.kms,
            dictionary=self.dictionary, ner_package_dir=NER_PACKAGE, state_directory=self.root/"state",
            policy=self.policy, watermark_policy=WatermarkPolicy(), transport=self.transport,
            evidence_bucket="synthetic-runtime-acceptance",
            ner_timeout=120.0,
            resolver=lambda _host: ("127.0.0.1",))
        args.update(changes)
        return create_runtime_app(**args)

    def test_real_protection_encrypted_spool_complete_version_and_cleanup(self):
        app = self.app()
        prompt = "甲公司向乙公司采购设备。联系人张三的电话是13800138000。"
        with patch.object(app.state.pipeline.detector, "close", wraps=app.state.pipeline.detector.close) as close_detector:
            with patch.object(app.state.pipeline.egress_client, "close", wraps=app.state.pipeline.egress_client.close) as close_egress:
                with TestClient(app) as client:
                    response = client.post("/v1/chat/completions", headers={"Authorization": "Bearer enterprise-test-token"},
                                           json={"model": "deepseek-flash", "messages": [{"role": "user", "content": prompt}]})
                    self.assertEqual(200, response.status_code, response.text)
                    self.assertEqual(prompt, response.json()["choices"][0]["message"]["content"])
                    self.assertEqual(1, len(self.calls))
                    self.assertEqual(503, client.get("/readyz").status_code)
                    app.state.pipeline.version_handle.manifest.require_complete()
                    files = list(app.state.runtime_spool_directory.glob("*.env.json"))
                    self.assertEqual(1, len(files))
                    self.assertNotIn(prompt.encode(), files[0].read_bytes())
                    event = ObservationEvent.model_validate_json(decrypt_record(self.kms, parse_record(files[0].read_bytes())))
                    self.assertEqual(prompt, event.evidence_text)
                    evidence_files = list((self.root/"state"/"evidence").glob("*.evidence.json"))
                    self.assertEqual(1, len(evidence_files))
                    self.assertNotIn(prompt.encode(), evidence_files[0].read_bytes())
                    self.assertTrue(decrypt_record(self.kms, parse_record(evidence_files[0].read_bytes())))
                close_detector.assert_called_once()
                close_egress.assert_called_once()

    def test_unknown_model_url_fields_images_thinking_and_credentials_rejected_zero_calls(self):
        app = self.app()
        config = json.loads(self.provider_file.read_text())
        config[0]["id"] = "changed-after-assembly"
        config[0]["url"] = "https://new-supplier.example/v1/chat/completions"
        self.provider_file.write_text(json.dumps(config), encoding="utf-8")
        self.assertEqual("deepseek-flash", app.state.runtime_model_id)
        self.assertEqual("supplier.example", app.state.pipeline.egress_client.binding.host)
        valid = {"model": "deepseek-flash", "messages": [{"role": "user", "content": "hello"}]}
        attempts = [({**valid, "model": "unadmitted"}, "enterprise-test-token"),
                    ({**valid, "base_url": "https://other.example"}, "enterprise-test-token"),
                    ({**valid, "apiKey": "caller-supplier-secret"}, "enterprise-test-token"),
                    ({**valid, "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "https://image.example"}}]}]}, "enterprise-test-token"),
                    ({**valid, "thinking": {"type": "enabled"}}, "enterprise-test-token"),
                    (valid, "supplier-test-secret")]
        with TestClient(app) as client:
            for body, token in attempts:
                response = client.post("/v1/chat/completions", headers={"Authorization": "Bearer "+token}, json=body)
                self.assertGreaterEqual(response.status_code, 400)
            self.assertEqual(0, len(self.calls))
            self.assertEqual([], list(app.state.runtime_spool_directory.glob("*.env.json")))

    def test_actual_disk_capacity_policy_blocks_egress(self):
        app = self.app(watermark_policy=WatermarkPolicy(min_available_bytes=2**63))
        with TestClient(app) as client:
            response = client.post("/v1/chat/completions", headers={"Authorization": "Bearer enterprise-test-token"},
                json={"model": "deepseek-flash", "messages": [{"role": "user", "content": "hello"}]})
            self.assertGreaterEqual(response.status_code, 400)
            self.assertEqual("AUDIT_WATERMARK_BLOCKED", response.json()["error"]["code"])
            self.assertEqual(0, len(self.calls))

    def test_missing_kms_ner_short_hmac_or_reused_supplier_key_rejected(self):
        for changes in ({"kms": None}, {"ner_package_dir": self.root/"missing-ner"},
                        {"hmac_key": b"short"}, {"enterprise_token": "supplier-test-secret"},
                        {"evidence_bucket": ""}):
            with self.assertRaises(SafetyError):
                self.app(**changes)

    def test_evidence_encryption_failure_blocks_before_supplier(self):
        app = self.app()
        with patch.object(self.kms, "wrap", side_effect=KmsUnavailableError("synthetic KMS unavailable")):
            with TestClient(app) as client:
                response = client.post("/v1/chat/completions", headers={"Authorization": "Bearer enterprise-test-token"},
                    json={"model": "deepseek-flash", "messages": [{"role": "user", "content": "hello"}]})
                self.assertGreaterEqual(response.status_code, 400)
                self.assertEqual("KMS_UNAVAILABLE", response.json()["error"]["code"])
                self.assertEqual(0, len(self.calls))


if __name__ == "__main__":
    unittest.main()
