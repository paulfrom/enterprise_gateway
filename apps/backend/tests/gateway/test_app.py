import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from httpx import ASGITransport, AsyncClient
from pydantic import BaseModel, ConfigDict, ValidationError

from gateway.app import create_app
from infra.config import ReviewSettings, load_settings


class ContractProbe(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    content: str


class ReviewAppTests(unittest.IsolatedAsyncioTestCase):
    async def test_alive_is_not_production_ready(self):
        async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://review") as client:
            self.assertEqual((await client.get("/healthz")).status_code, 200)
            response = await client.get("/readyz")
            self.assertEqual(response.status_code, 503)
            self.assertFalse(response.json()["ready"])

    async def test_channel_refusal_does_not_echo_or_connect(self):
        canary = "CNRY-企业合成秘密-123"
        async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://review") as client:
            with patch("socket.socket.connect") as connect:
                for path in ("/v1/chat/completions", "/v1/messages"):
                    response = await client.post(path, json={"messages": [{"content": canary}]},
                                                 headers={"Authorization": "Bearer CNRY-credential-123"})
                    self.assertEqual(response.status_code, 503)
                    self.assertNotIn(canary, response.text)
                    self.assertNotIn("CNRY-credential-123", response.text)
                connect.assert_not_called()

    async def test_unknown_route_does_not_echo(self):
        async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://review") as client:
            response = await client.post("/CNRY-secret", content="CNRY-secret")
            self.assertEqual(response.status_code, 404)
            self.assertNotIn("CNRY-secret", response.text)

    async def test_validation_error_does_not_echo_submitted_content(self):
        app = create_app()

        @app.post("/contract-probe")
        async def probe(_body: ContractProbe) -> dict[str, bool]:
            return {"ok": True}

        canary = "CNRY-校验合成秘密-456"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://review") as client:
            for payload in ({"content": [canary]}, {"content": "ok", "undeclared": canary}):
                response = await client.post("/contract-probe", json=payload)
                self.assertEqual(response.status_code, 422)
                self.assertNotIn(canary, response.text)
            malformed = await client.post("/contract-probe", content='{"content": "truncated')
            self.assertEqual(malformed.status_code, 422)

    async def test_ingress_log_redacts_credentials_and_body(self):
        credential = "CNRY-ingress-credential-789"
        secret_body = "CNRY-ingress-body-秘密-789"
        async with AsyncClient(transport=ASGITransport(app=create_app()), base_url="http://review") as client:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                response = await client.post(
                    "/v1/chat/completions?key=CNRY-query-credential-789",
                    content=secret_body,
                    headers={"Authorization": f"Bearer {credential}", "X-Api-Key": credential},
                )
            output = buffer.getvalue()
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(credential, output)
        self.assertNotIn(secret_body, output)
        self.assertNotIn("CNRY-query-credential-789", output)
        self.assertIn("POST", output)
        self.assertIn("/v1/chat/completions", output)
        self.assertIn("<redacted>", output)
        self.assertIn(hashlib.sha256(secret_body.encode("utf-8")).hexdigest()[:16], output)

    def test_configuration_cannot_enable_unbuilt_features(self):
        for payload in ({"external_egress": True}, {"real_knowledge_capture": True},
                        {"profile": "production"}, {"fallback_url": "https://example.com"}):
            with self.assertRaises(ValidationError):
                ReviewSettings.model_validate(payload)

    def test_duplicate_configuration_keys_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text('{"external_egress":false,"external_egress":false}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_settings(path)
            path.write_text(json.dumps(ReviewSettings().model_dump()), encoding="utf-8")
            self.assertFalse(load_settings(path).external_egress)

    async def test_mounted_pipeline_roundtrip_and_safety_error(self):
        from unittest.mock import MagicMock
        from datetime import datetime, timezone
        from infra.errors import SafetyCode, SafetyError
        from protocol.identity import ByokAuthenticator
        from gateway.provider_router import ProviderRouter

        mock_pipeline = MagicMock()
        mock_pipeline.domain = "corp.test"
        mock_pipeline.path = "/v1/chat/completions"
        mock_pipeline.request_timeout = 60.0
        mock_pipeline.body_limit = 65536

        # Mock success result
        mock_response = MagicMock()
        mock_response.model_dump.return_value = {
            "id": "chatcmpl-test",
            "choices": [{"message": {"role": "assistant", "content": "hello"}}]
        }
        mock_result = MagicMock()
        mock_result.response = mock_response
        mock_result.upstream_stream = None
        mock_pipeline.process_request.return_value = mock_result

        app = create_app(
            router=ProviderRouter({'deepseek-flash': mock_pipeline}),
            authenticator=ByokAuthenticator(domain='corp.test', tenant_id='test', correlation_key=b'c'*32),
            classifier=lambda _: 'STANDARD',
            hmac_key=b"0123456789abcdef0123456789abcdef",
        )

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://review") as client:
            # Positive 200
            res = await client.post("/v1/chat/completions", headers={"authorization":"Bearer valid-token"}, json={"model": "deepseek-flash", "messages": [{"role": "user", "content": "hi"}]})
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.json()["id"], "chatcmpl-test")

            # Missing identity returns 401 when no identity is available
            app_no_id = create_app(router=ProviderRouter({'deepseek-flash': mock_pipeline}), classifier=lambda _: 'STANDARD')
            async with AsyncClient(transport=ASGITransport(app=app_no_id), base_url="http://review") as client_no_id:
                res_no_id = await client_no_id.post("/v1/chat/completions", json={"model": "deepseek-flash", "messages": [{"role": "user", "content": "hi"}]})
                self.assertEqual(res_no_id.status_code, 401)

            # Safety error mapping (e.g. SECRET_DETECTED -> 403)
            mock_pipeline.process_request.side_effect = SafetyError(SafetyCode.SECRET_DETECTED, "secret")
            res_sec = await client.post("/v1/chat/completions", headers={"authorization":"Bearer valid-token"}, json={"model": "deepseek-flash", "messages": [{"role": "user", "content": "sk-123"}]})
            self.assertEqual(res_sec.status_code, 403)
            self.assertEqual(res_sec.json()["error"]["code"], "SECRET_DETECTED")


if __name__ == "__main__":
    unittest.main()

