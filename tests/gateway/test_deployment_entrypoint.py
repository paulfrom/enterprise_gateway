"""Operator-only classification imports and native TLS launcher behavior."""
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from starlette.testclient import TestClient

import start_gateway
from policy.policy import CategoryLabel, CategoryRule, ClassificationPolicy
from tests.gateway import test_runtime as runtime_fixtures


class DeploymentEntrypointTests(unittest.TestCase):
    def setUp(self):
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        self.module = types.ModuleType("synthetic_operator_classifier")
        self.module.classify = lambda _raw: "STANDARD"
        self.module.not_callable = "operator-sensitive-value"
        self.module.wrong_signature = lambda _raw, _extra: "STANDARD"
        async def async_classifier(_raw):
            return "STANDARD"
        self.module.async_classifier = async_classifier
        self.addCleanup(patch.stopall)
        patch.dict(sys.modules, {self.module.__name__: self.module}).start()

    def run_main(self, args=(), env=None, app=None):
        with patch.dict(os.environ, env or {}, clear=True), \
             patch.object(sys, "argv", ["start_gateway.py", *args]), \
             patch.object(start_gateway, "build_app", return_value=app) as build, \
             patch.object(start_gateway.uvicorn, "run") as run, \
             redirect_stdout(self.stdout), redirect_stderr(self.stderr):
            result = start_gateway.main()
        return result, build, run

    def test_operator_classifier_environment_passes_callable_without_invoking_it(self):
        with patch.object(self.module, "classify", wraps=self.module.classify) as classifier:
            result, build, run = self.run_main(env={"GATEWAY_CLASSIFIER": self.module.__name__ + ":classify"})
            self.assertEqual(0, result)
            self.assertIs(classifier, build.call_args.kwargs["classifier"])
            classifier.assert_not_called()
            run.assert_called_once()

    def test_operator_classifier_cli_passes_callable(self):
        result, build, _ = self.run_main(["--classifier", self.module.__name__ + ":classify"])
        self.assertEqual(0, result)
        self.assertIs(self.module.classify, build.call_args.kwargs["classifier"])

    def test_unconfigured_classifier_has_no_approval_default(self):
        result, build, _ = self.run_main()
        self.assertEqual(0, result)
        self.assertIsNone(build.call_args.kwargs["classifier"])

    def test_nonloopback_listener_without_tls_uses_http(self):
        for host in ("0.0.0.0", "10.0.0.1", "::"):
            with self.subTest(host=host):
                result, _, run = self.run_main(["--host", host])
                self.assertEqual(0, result)
                run.assert_called_once()
                self.assertEqual(host, run.call_args.kwargs["host"])
                self.assertIsNone(run.call_args.kwargs["ssl_certfile"])
                self.assertIsNone(run.call_args.kwargs["ssl_keyfile"])

    def test_empty_optional_environment_settings_mean_unconfigured(self):
        result, build, run = self.run_main(env={"GATEWAY_CLASSIFIER": "", "GATEWAY_SSL_CERTFILE": "",
                                               "GATEWAY_SSL_KEYFILE": ""})
        self.assertEqual(0, result)
        self.assertIsNone(build.call_args.kwargs["classifier"])
        self.assertIsNone(run.call_args.kwargs["ssl_certfile"])
        self.assertIsNone(run.call_args.kwargs["ssl_keyfile"])

    def test_explicit_empty_classifier_or_tls_cli_argument_refuses(self):
        for args in (["--classifier", ""], ["--ssl-certfile", "", "--ssl-keyfile", ""]):
            with self.subTest(args=args):
                result, build, run = self.run_main(args)
                self.assertEqual(2, result)
                build.assert_not_called()
                run.assert_not_called()

    def test_invalid_classifier_configuration_refuses_without_config_or_traceback(self):
        for reference in (" ", "operator-sensitive-module", "missing_sensitive_module:classify",
                          self.module.__name__ + ":missing_sensitive_attribute",
                          self.module.__name__ + ":not_callable", self.module.__name__ + ":wrong_signature",
                          self.module.__name__ + ":async_classifier"):
            with self.subTest(reference=reference):
                self.stderr.seek(0)
                self.stderr.truncate()
                result, build, run = self.run_main(env={"GATEWAY_CLASSIFIER": reference})
                self.assertEqual(2, result)
                build.assert_not_called()
                run.assert_not_called()
                self.assertNotIn("Traceback", self.stderr.getvalue())
                self.assertNotIn("operator-sensitive", self.stderr.getvalue())
                self.assertNotIn("missing_sensitive", self.stderr.getvalue())

    def test_classifier_import_exception_does_not_disclose_exception(self):
        with patch.object(start_gateway, "import_module", side_effect=RuntimeError("operator-sensitive-secret")):
            result, build, run = self.run_main(env={"GATEWAY_CLASSIFIER": self.module.__name__ + ":classify"})
        self.assertEqual(2, result)
        build.assert_not_called()
        run.assert_not_called()
        self.assertNotIn("operator-sensitive-secret", self.stderr.getvalue())
        self.assertNotIn("Traceback", self.stderr.getvalue())

    def test_incomplete_or_invalid_tls_configuration_refuses_before_assembly(self):
        for env in ({"GATEWAY_SSL_CERTFILE": "operator-sensitive-cert.pem"},
                    {"GATEWAY_SSL_KEYFILE": "operator-sensitive-key.pem"},
                    {"GATEWAY_SSL_CERTFILE": " ", "GATEWAY_SSL_KEYFILE": " "},
                    {"GATEWAY_SSL_CERTFILE": "missing-cert.pem", "GATEWAY_SSL_KEYFILE": "missing-key.pem"}):
            with self.subTest(env=env):
                result, build, run = self.run_main(env=env)
                self.assertEqual(2, result)
                build.assert_not_called()
                run.assert_not_called()
                self.assertNotIn("operator-sensitive", self.stderr.getvalue())
                self.assertNotIn("Traceback", self.stderr.getvalue())

    def test_valid_tls_pair_uses_native_uvicorn_options(self):
        with tempfile.TemporaryDirectory() as directory:
            certfile, keyfile = Path(directory) / "cert.pem", Path(directory) / "key.pem"
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                    .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                    .not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
            certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
            result, _, run = self.run_main(["--ssl-certfile", str(certfile), "--ssl-keyfile", str(keyfile)])
            self.assertEqual(0, result)
            self.assertEqual(str(certfile), run.call_args.kwargs["ssl_certfile"])
            self.assertEqual(str(keyfile), run.call_args.kwargs["ssl_keyfile"])
            self.assertFalse(run.call_args.kwargs["access_log"])
            # The uvicorn default and preflight both use native TLS server mode.
            import inspect
            import ssl
            self.assertEqual(ssl.PROTOCOL_TLS_SERVER,
                             inspect.signature(start_gateway.uvicorn.run).parameters["ssl_version"].default)
            self.assertGreaterEqual(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).minimum_version,
                                    ssl.TLSVersion.TLSv1_2)

    def test_encrypted_mismatched_or_malformed_tls_key_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            certfile, keyfile = Path(directory) / "cert.pem", Path(directory) / "key.pem"
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                    .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
                    .not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
            certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            for content in (b"operator-sensitive-malformed-key",
                            other.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()),
                            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.BestAvailableEncryption(b"operator-sensitive-passphrase"))):
                keyfile.write_bytes(content)
                result, build, run = self.run_main(env={"GATEWAY_SSL_CERTFILE": str(certfile),
                                                       "GATEWAY_SSL_KEYFILE": str(keyfile)})
                self.assertEqual(2, result)
                build.assert_not_called()
                run.assert_not_called()
                self.assertNotIn("operator-sensitive", self.stderr.getvalue())
                self.assertNotIn("Traceback", self.stderr.getvalue())

    def test_invalid_port_environment_refuses_without_value_or_traceback(self):
        for port in ("operator-sensitive-port", "0", "65536"):
            with self.subTest(port=port), self.assertRaises(SystemExit) as failure:
                self.run_main(env={"GATEWAY_PORT": port})
            self.assertEqual(2, failure.exception.code)
            self.assertNotIn("operator-sensitive", self.stderr.getvalue())
            self.assertNotIn("Traceback", self.stderr.getvalue())

    def test_missing_operator_assets_refuse_without_traceback(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(sys, "argv", ["start_gateway.py"]), \
             patch.object(start_gateway.uvicorn, "run") as run, redirect_stderr(self.stderr):
            self.assertEqual(2, start_gateway.main())
        run.assert_not_called()
        self.assertNotIn("Traceback", self.stderr.getvalue())

    def test_cli_loaded_classifier_approved_local_only_unknown_and_missing(self):
        fixture = runtime_fixtures.RuntimeAssemblyTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.policy = ClassificationPolicy(version="synthetic-deployment-policy", rules=(
            CategoryRule(category="STANDARD", label=CategoryLabel.APPROVED_EXTERNAL, scope=fixture.domain),
            CategoryRule(category="LOCAL", label=CategoryLabel.LOCAL_ONLY, scope=fixture.domain),))
        Path(fixture.operator_env["GATEWAY_POLICY_FILE"]).write_text(fixture.policy.model_dump_json(), encoding="utf-8")
        real_factory = start_gateway.create_runtime_app
        def controlled_factory(**kwargs):
            return real_factory(**kwargs, transport=fixture.transport, resolver=lambda _host: ("127.0.0.1",),
                                ner_timeout=120.0)
        for category in ("STANDARD", "LOCAL", "UNKNOWN", None):
            with self.subTest(category=category):
                env = dict(fixture.operator_env)
                if category is not None:
                    self.module.classify = lambda _raw, result=category: result
                    env["GATEWAY_CLASSIFIER"] = self.module.__name__ + ":classify"
                else:
                    env.update(GATEWAY_CLASSIFIER="", GATEWAY_SSL_CERTFILE="", GATEWAY_SSL_KEYFILE="")
                captured = []
                with patch.dict(os.environ, env, clear=True), \
                     patch.object(sys, "argv", ["start_gateway.py", "--config", str(fixture.provider_file)]), \
                     patch.object(start_gateway, "create_runtime_app", side_effect=controlled_factory), \
                     patch.object(start_gateway.uvicorn, "run", side_effect=lambda app, **_kwargs: captured.append(app)), \
                     redirect_stdout(self.stdout), redirect_stderr(self.stderr):
                    self.assertEqual(0, start_gateway.main())
                calls_before = len(fixture.calls)
                with TestClient(captured[0]) as client:
                    self.assertEqual(200, client.get("/healthz").status_code)
                    self.assertEqual(503 if category is None else 200, client.get("/readyz").status_code)
                    response = fixture.post(client)
                    self.assertEqual(200 if category == "STANDARD" else 503 if category is None else 403,
                                     response.status_code, response.text)
                self.assertEqual(1 if category == "STANDARD" else 0, len(fixture.calls) - calls_before)


if __name__ == "__main__":
    unittest.main()
