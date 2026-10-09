"""Strict server-side route configuration: synthetic inputs only."""
import json
import tempfile
import unittest
from pathlib import Path

from gateway.provider_router import ProviderConfig
from infra.errors import SafetyError
from protocol.protocols import DEEPSEEK_CHAT_PROTOCOL, CLAUDE_MESSAGES_PROTOCOL


def provider(**changes):
    values = dict(channel_id="channel", protocol=DEEPSEEK_CHAT_PROTOCOL,
                  url="https://supplier.example/v1/chat/completions",
                  models=("model",), credential_header="authorization", timeout_seconds=30)
    values.update(changes)
    return ProviderConfig(**values)


class ProviderConfigTests(unittest.TestCase):
    def test_http_and_https_allowed_for_both_protocols_on_nonloopback_hosts(self):
        for protocol, path, header in (
            (DEEPSEEK_CHAT_PROTOCOL, "/v1/chat/completions", "authorization"),
            (CLAUDE_MESSAGES_PROTOCOL, "/v1/messages", "x-api-key"),
        ):
            for scheme in ("http", "https"):
                for host in ("supplier.example", "203.0.113.1", "10.0.0.1",
                             "192.168.0.1", "[fd00::1]"):
                    url = f"{scheme}://{host}{path}"
                    with self.subTest(protocol=protocol, url=url):
                        self.assertEqual(url, provider(protocol=protocol, url=url,
                                                      credential_header=header).url)

    def test_validated_exact_models_and_paths(self):
        self.assertEqual(provider().models, ("model",))
        self.assertEqual(provider(protocol=CLAUDE_MESSAGES_PROTOCOL,
                                  url="https://supplier.example/v1/messages",
                                  credential_header="x-api-key").protocol, CLAUDE_MESSAGES_PROTOCOL)

    def test_invalid_fields_are_rejected(self):
        for field, value in (
            ("channel_id", ""), ("channel_id", " padded "), ("channel_id", 1),
            ("protocol", "responses"), ("protocol", []),
            ("url", "https://user:secret@supplier.example/v1/chat/completions"),
            ("url", "https://supplier.example:0/v1/chat/completions"),
            ("url", "https://supplier.example:/v1/chat/completions"),
            ("url", "https://supplier.example/v1/chat/completions?q=x"),
            ("url", "https://supplier.example/v1/chat/completions#x"),
            ("url", "https://supplier.example/v1/chat/completions?"),
            ("url", "https://supplier.example/v1/chat/completions#"),
            ("url", "https://supplier.example/v1/messages"),
            ("url", "https://supplier.example/v1/chat/completions/"),
            ("url", "https://supplier.example/v1/%63hat/completions"),
            ("url", "https://supplier.example/v1/chat/completions\n"),
            ("url", "ftp://supplier.example/v1/chat/completions"),
            ("url", "https:///v1/chat/completions"), ("url", 1),
            ("models", ()), ("models", ("",)), ("models", (" padded ",)),
            ("models", ("model", "model")), ("models", "model"),
            ("models", ("model", 2)), ("models", ["model"]),
            ("credential_header", "x-api-key"), ("credential_header", "Authorization"),
            ("timeout_seconds", True), ("timeout_seconds", "30"),
            ("timeout_seconds", 0), ("timeout_seconds", float("nan")),
            ("timeout_seconds", float("inf")),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(SafetyError):
                    provider(**{field: value})

    def test_server_credential_parameter_does_not_exist(self):
        with self.assertRaises(TypeError):
            provider(credential="synthetic-server-key")


class ProviderLoaderTests(unittest.TestCase):
    def load(self, text):
        from gateway.provider_router import load_provider_configs
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "providers.json"
            path.write_text(text, encoding="utf-8")
            return load_provider_configs(path)

    def test_loader_returns_validated_tuple(self):
        value = self.load('{"providers":[{"channel_id":"c","protocol":"deepseek-chat-completions",'
                          '"url":"http://127.0.0.1:1234/v1/chat/completions","models":["m"]}]}')
        self.assertIsInstance(value, tuple)
        self.assertEqual(value[0].models, ("m",))

    def test_strict_json_schema_and_duplicates(self):
        route = dict(channel_id="c", protocol=DEEPSEEK_CHAT_PROTOCOL,
                     url="https://supplier.example/v1/chat/completions", models=["m"])
        bad = ["{}", "[]", '{"providers":[]}', '{"providers":null}',
               '{"providers":[],"providers":[]}', '{"providers":[],"extra":1}',
               json.dumps({"providers": [route, route]}),
               json.dumps({"providers": [route, {**route, "models": ["different"]}]}),
               json.dumps({"providers": [route, {**route, "channel_id": "other"}]}),
               json.dumps({"providers": [{**route, "credential": "synthetic-secret"}]}),
               json.dumps({"providers": [{**route, "timeout_seconds": float("nan")}]}),
               json.dumps({"providers": [{**route, "extra": 1}]}),
               json.dumps({"providers": [{**route, "models": "m"}]}),
               json.dumps({"providers": [{**route, "models": ["m", "m"]}]}),
               json.dumps({"providers": [{k: v for k, v in route.items() if k != "url"}]}),
               json.dumps({"providers": [route]}).replace('"channel_id": "c"',
                          '"channel_id": "c", "channel_id": "c"')]
        for text in bad:
            with self.subTest(text=text):
                with self.assertRaises(SafetyError) as caught:
                    self.load(text)
                self.assertNotIn("synthetic-secret", str(caught.exception))


class ProviderPipelineFactoryTests(unittest.TestCase):
    def arguments(self):
        return dict(domain="restricted", policy=object(), detector=object(),
                    admission_limiter=object(), watermark_guard=object(),
                    evidence_gate=None, spool_writer=object(), resolver=lambda _: ("127.0.0.1",))

    def test_audit_bucket_is_required(self):
        from gateway.provider_router import create_provider_pipeline
        with self.assertRaises(TypeError):
            create_provider_pipeline(provider(), **self.arguments())
        for bucket in (None, "", " padded ", 1):
            with self.subTest(bucket=bucket), self.assertRaises(SafetyError):
                create_provider_pipeline(provider(), evidence_bucket=bucket, **self.arguments())

    def test_missing_or_fake_audit_gate_is_rejected_before_resolution(self):
        from gateway.provider_router import create_provider_pipeline
        from unittest.mock import Mock
        resolver = Mock(side_effect=AssertionError("must not resolve"))
        for gate in (None, object()):
            arguments = {**self.arguments(), "evidence_gate": gate, "resolver": resolver}
            with self.subTest(gate=gate), self.assertRaises(SafetyError):
                create_provider_pipeline(provider(), evidence_bucket="evidence", **arguments)
        resolver.assert_not_called()

    def test_failed_pipeline_assembly_closes_new_egress(self):
        from audit.evidence_gate import EvidenceGate
        from infra.envelope_crypto import StaticTestKmsProvider
        from gateway.provider_router import create_provider_pipeline
        from unittest.mock import Mock, patch
        with tempfile.TemporaryDirectory() as tmp:
            gate = EvidenceGate(Path(tmp), evidence_directory=Path(tmp), kms=StaticTestKmsProvider())
            arguments = {**self.arguments(), "evidence_gate": gate}
            egress = Mock()
            with patch("gateway.provider_router.BoundEgressClient", return_value=egress), \
                 patch("gateway.provider_router.ProtectedPipeline", side_effect=RuntimeError("assembly failed")):
                with self.assertRaises(RuntimeError):
                    create_provider_pipeline(provider(), evidence_bucket="evidence", **arguments)
            egress.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
