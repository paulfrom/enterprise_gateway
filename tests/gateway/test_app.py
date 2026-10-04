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


if __name__ == "__main__":
    unittest.main()

