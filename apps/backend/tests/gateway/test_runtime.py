"""Actual standalone factory: real detector/keys/disk, synthetic supplier only."""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import httpx
from starlette.testclient import TestClient

from audit.audit_watermark import WatermarkPolicy
from detection.dictionary import DictionaryEntry, compile_dictionary, compute_dictionary_hash
from gateway.runtime import create_runtime_app
from infra.envelope_crypto import KmsUnavailableError, decrypt_record, parse_record
from infra.errors import SafetyError
from infra.file_kms import FileKmsProvider
from knowledge.knowledge_events import ObservationEvent
from policy.policy import CategoryLabel, CategoryRule, ClassificationPolicy

NER_PACKAGE = Path(__file__).resolve().parents[2] / "models" / "bert4ner-base-chinese-onnx"


class RuntimeAssemblyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.domain = "runtime-test"
        self.provider_file = self.root / "providers.json"
        self.provider_file.write_text(json.dumps({"providers": [
            {"channel_id": "chat", "protocol": "deepseek-chat-completions",
             "url": "https://chat.example/v1/chat/completions", "models": ["chat-fixture"]},
            {"channel_id": "messages", "protocol": "claude-messages", "credential_header": "x-api-key",
             "url": "https://messages.example/v1/messages", "models": ["claude-fixture"]},
        ]}), encoding="utf-8")
        entries = tuple(DictionaryEntry(text=text, entity_type=kind) for text, kind in
                        (("甲公司", "ORG"), ("乙公司", "ORG"), ("张三", "PER")))
        self.dictionary_data = {"dictionary_id": "runtime-dict", "version": "v1",
            "domain": self.domain, "entries": [entry.model_dump() for entry in entries],
            "sha256": compute_dictionary_hash("runtime-dict", "v1", self.domain, entries)}
        self.dictionary = compile_dictionary(self.dictionary_data)
        self.kms = FileKmsProvider(self.root / "state" / "keys", b"m" * 32)
        self.kms.provision(purpose="model-query", bucket="synthetic-evidence")
        self.kms.provision(purpose="knowledge-accumulation:knowledge-spool", bucket="standard-retention")
        self.calls = []
        self.transport = httpx.MockTransport(self.upstream)
        self.policy = ClassificationPolicy(version="synthetic-policy-v1", rules=(
            CategoryRule(category="STANDARD", label=CategoryLabel.APPROVED_EXTERNAL, scope=self.domain),
            CategoryRule(category="SECRET", label=CategoryLabel.SECRET, scope=self.domain),))
        dictionary_file, policy_file = self.root / "dictionary.json", self.root / "policy.json"
        dictionary_file.write_text(json.dumps(self.dictionary_data), encoding="utf-8")
        policy_file.write_text(self.policy.model_dump_json(), encoding="utf-8")
        self.operator_env = {"GATEWAY_PROCESSING_DOMAIN": self.domain, "GATEWAY_PROCESSING_TENANT": "processing-tenant",
            "GATEWAY_STATE_DIR": str(self.root/"state"), "GATEWAY_EVIDENCE_BUCKET": "synthetic-evidence",
            "GATEWAY_HMAC_KEY": (b"h"*32).hex(), "GATEWAY_SOURCE_CORRELATION_KEY": (b"c"*32).hex(),
            "GATEWAY_KMS_MASTER_KEY": (b"m"*32).hex(), "GATEWAY_DICTIONARY_FILE": str(dictionary_file),
            "GATEWAY_POLICY_FILE": str(policy_file), "GATEWAY_NER_PACKAGE_DIR": str(NER_PACKAGE)}

    def upstream(self, request):
        self.calls.append(request)
        if request.url.path == "/v1/messages":
            self.assertEqual("synthetic-key", request.headers["x-api-key"])
            self.assertEqual("2023-06-01", request.headers["anthropic-version"])
            self.assertNotIn("authorization", request.headers)
        else:
            self.assertEqual("Bearer synthetic-key", request.headers["authorization"])
            self.assertNotIn("x-api-key", request.headers)
        for truth in ("甲公司", "乙公司", "张三", "13800138000"):
            self.assertNotIn(truth, request.content.decode())
        payload = json.loads(request.content)
        content = payload["messages"][-1]["content"]
        if request.url.path == "/v1/messages":
            return httpx.Response(200, json={"id": "msg-runtime", "type": "message", "role": "assistant",
                "model": payload["model"], "content": content if isinstance(content, list) else [{"type": "text", "text": content}],
                "stop_reason": "end_turn", "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1}})
        return httpx.Response(200, json={"id": "chatcmpl-runtime", "object": "chat.completion",
            "created": 1, "model": payload["model"], "choices": [{"index": 0,
                "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

    def app(self, **changes):
        args = dict(provider_config_path=self.provider_file, domain=self.domain, tenant_id="processing-tenant",
            correlation_key=b"c"*32, hmac_key=b"h"*32, kms=self.kms,
            dictionary=self.dictionary, ner_package_dir=NER_PACKAGE, state_directory=self.root/"state",
            policy=self.policy, watermark_policy=WatermarkPolicy(), transport=self.transport,
            evidence_bucket="synthetic-evidence", classifier=lambda _raw: "STANDARD",
            ner_timeout=120.0, resolver=lambda _host: ("127.0.0.1",))
        args.update(changes)
        return create_runtime_app(**args)

    def post(self, client, prompt="hello", **changes):
        body = {"model": "chat-fixture", "messages": [{"role": "user", "content": prompt}]}
        body.update(changes)
        return client.post("/v1/chat/completions", headers={"Authorization": "Bearer synthetic-key"}, json=body)

    def test_real_protection_two_protocols_encrypted_storage_and_lifecycle(self):
        app = self.app()
        prompt = "甲公司向乙公司采购设备。联系人张三的电话是13800138000。"
        with ExitStack() as stack:
            detector = app.state.runtime_pipelines[0].detector
            close_detector = stack.enter_context(patch.object(detector, "close", wraps=detector.close))
            close_clients = [stack.enter_context(patch.object(pipeline.egress_client, "close",
                              wraps=pipeline.egress_client.close)) for pipeline in app.state.runtime_pipelines]
            with TestClient(app) as client:
                self.assertEqual(200, client.get("/readyz").status_code)
                response = self.post(client, prompt)
                self.assertEqual(200, response.status_code, response.text)
                self.assertEqual(prompt, response.json()["choices"][0]["message"]["content"])
                response = client.post("/v1/messages", headers={"x-api-key": "synthetic-key"},
                    json={"model": "claude-fixture", "max_tokens": 128,
                          "messages": [{"role": "user", "content": [{"type": "text", "text": prompt}]}]})
                self.assertEqual(200, response.status_code, response.text)
                self.assertEqual(prompt, response.json()["content"][0]["text"])
                self.assertEqual(2, len(self.calls))
                for pipeline in app.state.runtime_pipelines:
                    pipeline.version_handle.manifest.require_complete()
                spool = list(app.state.runtime_spool_directory.glob("*.env.json"))
                self.assertEqual(2, len(spool))
                for file in spool:
                    self.assertNotIn(prompt.encode(), file.read_bytes())
                    event = ObservationEvent.model_validate_json(decrypt_record(self.kms, parse_record(file.read_bytes())))
                    self.assertEqual(prompt, event.evidence_text)
                    self.assertEqual(frozenset({self.domain + ":restricted-candidate"}), event.acl)
                    self.assertEqual("unassigned", event.ownership_status)
                    self.assertEqual("unverified", event.source_provenance)
                    self.assertFalse(event.source_independence_verified)
                evidence = list(app.state.runtime_evidence_directory.glob("*.evidence.json"))
                self.assertEqual(2, len(evidence))
                for file in evidence:
                    self.assertNotIn(prompt.encode(), file.read_bytes())
                    self.assertTrue(decrypt_record(self.kms, parse_record(file.read_bytes())))
            close_detector.assert_called_once()
            for close in close_clients:
                close.assert_called_once()
            self.assertTrue(app.state.runtime_closed)

    def test_unknown_fields_pass_through_but_do_not_override_route_or_credentials(self):
        app = self.app()
        with TestClient(app) as client:
            self.assertGreaterEqual(self.post(client, model="unadmitted").status_code, 400)
            response = client.post("/v1/chat/completions", json={"model": "chat-fixture", "messages": []})
            self.assertGreaterEqual(response.status_code, 400)
            self.assertEqual(0, len(self.calls))
            for changes in ({"base_url": "https://other.example"},
                            {"apiKey": "payload-secret"}, {"thinking": {"type": "enabled"}}):
                self.assertEqual(self.post(client, **changes).status_code, 200)
                request = self.calls[-1]
                self.assertEqual(request.url.host, app.state.runtime_pipelines[0].egress_client.binding.host)
                self.assertEqual(request.headers['authorization'], 'Bearer synthetic-key')
                payload = json.loads(request.content)
                for name, value in changes.items():
                    self.assertEqual(payload[name], value)

    def test_classifier_missing_secret_and_unknown_categories_never_egress(self):
        for classifier in (None, lambda _raw: "SECRET", lambda _raw: "unknown"):
            with self.subTest(classifier=classifier):
                app = self.app(classifier=classifier)
                before = set(app.state.runtime_spool_directory.glob("*.env.json"))
                with TestClient(app) as client:
                    if classifier is None:
                        self.assertEqual(503, client.get("/readyz").status_code)
                    self.assertGreaterEqual(self.post(client).status_code, 400)
                    after = set(app.state.runtime_spool_directory.glob("*.env.json"))
                    if classifier is None:
                        self.assertEqual(before, after)
                    else:
                        self.assertEqual(1, len(after - before))
                        file = (after - before).pop()
                        self.assertNotIn(b"hello", file.read_bytes())
                        event = ObservationEvent.model_validate_json(
                            decrypt_record(self.kms, parse_record(file.read_bytes())))
                        self.assertEqual("hello", event.evidence_text)
                        self.assertEqual("unassigned", event.ownership_status)
                        self.assertEqual(frozenset({self.domain + ":restricted-candidate"}), event.acl)
                self.assertEqual(0, len(self.calls))

    def test_actual_disk_capacity_policy_blocks_readiness_and_egress(self):
        app = self.app(watermark_policy=WatermarkPolicy(min_available_bytes=2**63))
        with TestClient(app) as client:
            self.assertEqual(503, client.get("/readyz").status_code)
            self.assertGreaterEqual(self.post(client).status_code, 400)
            self.assertEqual(0, len(self.calls))

    def test_missing_kms_ner_short_keys_or_evidence_bucket_rejected(self):
        for changes in ({"kms": None}, {"ner_package_dir": self.root/"missing-ner"},
                        {"hmac_key": b"short"}, {"correlation_key": b"short"},
                        {"evidence_bucket": ""}, {"classifier": "STANDARD"}):
            with self.subTest(changes=changes), self.assertRaises(SafetyError):
                self.app(**changes)

    def test_kms_outage_blocks_readiness_and_supplier(self):
        app = self.app()
        with patch.object(self.kms, "wrap", side_effect=KmsUnavailableError("synthetic failure")):
            with TestClient(app) as client:
                self.assertEqual(503, client.get("/readyz").status_code)
                self.assertGreaterEqual(self.post(client).status_code, 400)
                self.assertEqual(0, len(self.calls))

    def test_closed_detector_refuses_readiness_and_forwarding(self):
        app = self.app()
        with TestClient(app) as client:
            app.state.runtime_pipelines[0].detector.close()
            self.assertEqual(503, client.get("/readyz").status_code)
            self.assertEqual(503, self.post(client).status_code)
            self.assertEqual(0, len(self.calls))

    def test_closed_underlying_egress_refuses_readiness_and_forwarding(self):
        app = self.app()
        with TestClient(app) as client:
            app.state.runtime_pipelines[0].egress_client._client.close()
            self.assertEqual(503, client.get("/readyz").status_code)
            self.assertEqual(503, self.post(client).status_code)
            self.assertEqual(0, len(self.calls))

    def test_operator_launcher_uses_same_factory_and_requires_no_fake_defaults(self):
        import start_gateway
        with patch.dict(os.environ, self.operator_env, clear=True):
            # DNS must remain controlled for synthetic supplier hosts.
            with patch("infra.egress_client.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]):
                app = start_gateway.build_app(providers_config_path=self.provider_file)
            screen = app.state.runtime_pipelines[0].detector._risk_screener
            self.assertTrue(screen.config.enabled)
            self.assertEqual(screen.config.threshold, 0.35)
            self.assertEqual(screen.config.budget_ms, 2)
            with TestClient(app) as client:
                self.assertEqual(200, client.get("/healthz").status_code)
                self.assertEqual(503, client.get("/readyz").status_code)
                self.assertEqual(503, self.post(client).status_code)
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(SafetyError):
            start_gateway.build_app(providers_config_path=self.provider_file)

    def test_launcher_secret_file_and_ambiguous_sources(self):
        import start_gateway
        secret = self.root / "hmac.hex"
        secret.write_text((b"h"*32).hex()+"\n", encoding="ascii")
        with patch.dict(os.environ, {"GATEWAY_HMAC_KEY_FILE": str(secret)}, clear=True):
            self.assertEqual(b"h"*32, start_gateway._load_secret("GATEWAY_HMAC_KEY"))
        with patch.dict(os.environ, {"GATEWAY_HMAC_KEY_FILE": str(secret), "GATEWAY_HMAC_KEY": (b"h"*32).hex()}, clear=True):
            with self.assertRaises(SafetyError):
                start_gateway._load_secret("GATEWAY_HMAC_KEY")

    def test_explicit_provision_refuses_to_rebuild_keys_after_record_loss(self):
        import start_gateway
        from infra.envelope_crypto import encrypt_record, serialize_record
        record = encrypt_record(self.kms, b"synthetic evidence", domain=self.domain,
                                bucket="synthetic-evidence", record_id="record-1", purpose="model-query")
        evidence = self.root / "state" / "evidence"
        evidence.mkdir()
        (evidence / "record-1.evidence.json").write_bytes(serialize_record(record))
        for key in (self.root / "state" / "keys").glob("*.key.json"):
            key.unlink()
        env = {"GATEWAY_STATE_DIR": str(self.root / "state"),
               "GATEWAY_EVIDENCE_BUCKET": "synthetic-evidence", "GATEWAY_KMS_MASTER_KEY": (b"m"*32).hex()}
        with patch.dict(os.environ, env, clear=True), self.assertRaises(KmsUnavailableError):
            start_gateway.provision_keys()
        with patch.dict(os.environ, self.operator_env, clear=True), self.assertRaises(KmsUnavailableError):
            start_gateway.build_app(providers_config_path=self.provider_file)
        self.assertEqual([], list((self.root / "state" / "keys").glob("*.key.json")))

    def test_explicit_provision_initializes_only_controlled_empty_state(self):
        import start_gateway
        state = self.root / "fresh-state"
        env = {"GATEWAY_STATE_DIR": str(state), "GATEWAY_EVIDENCE_BUCKET": "synthetic-evidence",
               "GATEWAY_KMS_MASTER_KEY": (b"m"*32).hex()}
        with patch.dict(os.environ, env, clear=True):
            start_gateway.provision_keys()
            files = {path.name: path.read_bytes() for path in (state / "keys").glob("*.key.json")}
            start_gateway.provision_keys()
            self.assertEqual(files, {path.name: path.read_bytes() for path in (state / "keys").glob("*.key.json")})
        self.assertEqual(2, len(files))


if __name__ == "__main__":
    unittest.main()
