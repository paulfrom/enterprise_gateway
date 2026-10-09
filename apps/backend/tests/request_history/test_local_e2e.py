"""Real local controls and isolated PostgreSQL; supplier responses are synthetic.

This module deliberately composes the existing RuntimeAssemblyTests fixture
instead of inheriting its test suite. No real supplier or business text is used.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from types import SimpleNamespace
import unittest
from uuid import UUID, uuid4

import httpx
import psycopg
from starlette.testclient import TestClient

from request_history import PostgresHistoryStore
from request_history.models import PURPOSE
from tests.gateway import test_runtime
from tests.request_history.pg_support import configuration

SYNTHETIC_PROMPT = "甲公司向乙公司采购设备。联系人张三的电话是13800138000。"
HTML_PROBE = '<img src=x onerror="window.__history_html_executed=true"><script>window.__history_html_executed=true</script>'
SUPPLIER_HEADERS = {"Authorization": "Bearer synthetic-key"}


@contextmanager
def synthetic_history_runtime():
    """Fresh scope, real detector/FileKMS/PG, real admin state and a finite echo supplier."""
    fixture = test_runtime.RuntimeAssemblyTests(methodName="runTest")
    app = None
    try:
        fixture.setUp()
        config = configuration()
        audit_directory = fixture.root / "history-read-audit"
        audit_directory.mkdir()
        bucket = "synthetic-one-day-history"
        fixture.kms.provision(purpose=PURPOSE, bucket=bucket)
        tenant_id = "synthetic-history-" + uuid4().hex
        store = PostgresHistoryStore(
            config["app_dsn"], fixture.kms, tenant_id=tenant_id,
            domain=fixture.domain, retention_days=1, bucket=bucket,
            audit_directory=audit_directory,
        )
        from gateway.admin_auth import AdminAuthService, initialize_admin_state
        from gateway.admin_storage import AdminStateStore
        from scripts.prepare_admin_state import INITIAL_ADMIN_PASSWORD
        admin_store = AdminStateStore(fixture.root / "state" / "admin")
        initialize_admin_state(admin_store, INITIAL_ADMIN_PASSWORD)
        admin_service = AdminAuthService(admin_store, scope=f"{tenant_id}/{fixture.domain}")
        upstream_bodies = []

        def supplier(request):
            response = fixture.upstream(request)
            incoming = json.loads(request.content)
            if incoming.get("stream"):
                from tests.protocol.test_stream_events import chat, choice, claude
                if request.url.path == "/v1/messages":
                    message = response.json()
                    text = "".join(block["text"] for block in message["content"] if block["type"] == "text")
                    message.update(content=[], stop_reason=None,
                                   usage={"input_tokens": 1, "output_tokens": 0})
                    wire_body = (
                        claude("message_start", message=message)
                        + claude("content_block_start", index=0, content_block={"type": "text", "text": ""})
                        + claude("content_block_delta", index=0, delta={"type": "text_delta", "text": text})
                        + claude("content_block_stop", index=0)
                        + claude("message_delta", delta={"stop_reason": "end_turn", "stop_sequence": None},
                                 usage={"output_tokens": 1})
                        + claude("message_stop")
                    )
                else:
                    text = response.json()["choices"][0]["message"]["content"]
                    wire_body = (chat([choice(delta={"role": "assistant", "content": text})], model=incoming["model"])
                                 + chat([choice(finish="stop")], model=incoming["model"])
                                 + b"data: [DONE]\n\n")
                response = httpx.Response(200, content=wire_body,
                                          headers={"content-type": "text/event-stream"})
            if b"HTML_RENDER_PROBE" in request.content:
                payload = response.json()
                if request.url.path == "/v1/messages":
                    payload["content"].append({"type": "text", "text": HTML_PROBE})
                else:
                    payload["choices"][0]["message"]["content"] += "\n" + HTML_PROBE
                response = httpx.Response(200, json=payload)
            upstream_bodies.append(response.content)
            return response

        fixture.transport = httpx.MockTransport(supplier)
        app = fixture.app(
            tenant_id=tenant_id, history_store=store, admin_service=admin_service,
            ner_timeout=60.0,
            classifier=lambda body: "SECRET" if b"BLOCKED_PREVIEW" in body else "STANDARD",
        )
        yield SimpleNamespace(app=app, fixture=fixture, store=store,
                              admin_service=admin_service, config=config,
                              upstream_bodies=upstream_bodies)
    finally:
        # TestClient/uvicorn ordinarily owns shutdown. Also close an assembly
        # whose seed/setup failed before either lifespan was entered.
        if app is not None and not app.state.runtime_closed:
            pipelines = app.state.runtime_pipelines
            try:
                if pipelines:
                    pipelines[0].detector.close()
            finally:
                for pipeline in pipelines:
                    pipeline.egress_client.close()
                app.state.runtime_closed = True
        fixture.doCleanups()


def admin_login(client):
    """Real login through the HTTP route; the cookie jar carries the session."""
    from scripts.prepare_admin_state import INITIAL_ADMIN_PASSWORD
    response = client.post("/api/admin/login", headers={"Origin": "http://testserver"},
                           json={"username": "admin", "password": INITIAL_ADMIN_PASSWORD})
    if response.status_code != 200:
        raise RuntimeError("Synthetic admin login failed")
    return response.json()["csrf_token"]


def synthetic_requests(*, preview: bool = False):
    values = [
        ("/v1/chat/completions", SUPPLIER_HEADERS,
         {"model": "chat-fixture", "messages": [{"role": "user", "content": SYNTHETIC_PROMPT}]}),
        ("/v1/messages", {"x-api-key": "synthetic-key"},
         {"model": "claude-fixture", "max_tokens": 128,
          "messages": [{"role": "user", "content": [{"type": "text", "text": SYNTHETIC_PROMPT}]}]}),
    ]
    if preview:
        values.extend([
            ("/v1/chat/completions", SUPPLIER_HEADERS,
             {"model": "chat-fixture", "messages": [{"role": "user", "content": "HTML_RENDER_PROBE：" + SYNTHETIC_PROMPT}]}),
            ("/v1/chat/completions", SUPPLIER_HEADERS,
             {"model": "chat-fixture", "messages": [{"role": "user", "content": "BLOCKED_PREVIEW：" + SYNTHETIC_PROMPT}]}),
        ])
    return values


class HistoryRuntimePostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.environ.get("GATEWAY_HISTORY_PG_CONFIG"):
            raise unittest.SkipTest("Explicit isolated history PostgreSQL configuration required")
        configuration()

    def test_two_protocols_record_actual_four_stages_encrypted_in_pg(self):
        with synthetic_history_runtime() as runtime, TestClient(runtime.app) as client:
            self.assertEqual(200, client.get("/readyz").status_code)
            admin_login(client)
            ids = []
            for index, (path, headers, payload) in enumerate(synthetic_requests()):
                with self.subTest(protocol=path):
                    response = client.post(path, headers=headers, json=payload)
                    self.assertEqual(200, response.status_code, "Synthetic protected request failed")
                    identifier = response.headers["x-request-id"]
                    self.assertEqual(identifier, str(UUID(identifier)))
                    ids.append(identifier)
                    detail_response = client.get("/api/admin/requests/" + identifier)
                    self.assertEqual(200, detail_response.status_code)
                    detail = detail_response.json()
                    self.assertEqual("completed", detail["status"])
                    stages = {stage["stage"]: stage for stage in detail["stages"]}
                    self.assertEqual({"input", "redacted", "upstream", "restored"}, set(stages))
                    self.assertTrue(all(stage["state"] == "complete" for stage in stages.values()))
                    self.assertEqual(payload, json.loads(stages["input"]["body"]))
                    self.assertEqual(json.loads(runtime.fixture.calls[index].content), json.loads(stages["redacted"]["body"]))
                    self.assertEqual(runtime.upstream_bodies[index].decode(), stages["upstream"]["body"])
                    self.assertEqual(response.content.decode(), stages["restored"]["body"])
                    for truth in ("甲公司", "乙公司", "张三", "13800138000"):
                        self.assertNotIn(truth, stages["redacted"]["body"])
                        self.assertNotIn(truth, stages["upstream"]["body"])
                        self.assertIn(truth, stages["restored"]["body"])
                    self.assertNotIn("synthetic-key", json.dumps(detail))
                    self.assertEqual("no-store", detail_response.headers["cache-control"])
            self.assertEqual(2, len(runtime.fixture.calls))
            with psycopg.connect(runtime.config["admin_dsn"], connect_timeout=10) as connection:
                envelopes = connection.execute(
                    "SELECT envelope FROM request_stage_contents WHERE request_id=ANY(%s::uuid[])", (ids,),
                ).fetchall()
            self.assertEqual(8, len(envelopes))
            self.assertTrue(all(SYNTHETIC_PROMPT.encode() not in bytes(row[0]) for row in envelopes))
            self.assertTrue(all(b"13800138000" not in bytes(row[0]) for row in envelopes))

    def test_admin_session_pagination_metadata_filters_and_console_pages(self):
        with synthetic_history_runtime() as runtime, TestClient(runtime.app) as client:
            for path, headers, payload in synthetic_requests():
                self.assertEqual(200, client.post(path, headers=headers, json=payload).status_code)
            for headers in ({}, SUPPLIER_HEADERS, {"Authorization": "Bearer " + "0" * 64}):
                self.assertEqual(401, client.get("/api/admin/requests", headers=headers).status_code)
            for path in ("/history", "/api/requests", "/api/requests/" + str(uuid4())):
                self.assertEqual(404, client.get(path).status_code)
            self.assertEqual(302, client.get("/admin", follow_redirects=False).status_code)
            login_page = client.get("/login")
            self.assertEqual(200, login_page.status_code)
            self.assertIn("script-src 'self'", login_page.headers["content-security-policy"])
            admin_login(client)
            self.assertEqual(200, client.get("/admin").status_code)
            self.assertEqual(200, client.get("/admin/requests").status_code)
            first = client.get("/api/admin/requests?limit=1").json()
            self.assertEqual(1, len(first["items"]))
            self.assertIsNotNone(first["next_cursor"])
            second = client.get("/api/admin/requests",
                                params={"limit": 1, "cursor": first["next_cursor"]}).json()
            self.assertEqual(1, len(second["items"]))
            self.assertNotEqual(first["items"][0]["request_id"], second["items"][0]["request_id"])
            self.assertIsNone(second["next_cursor"])
            filtered = client.get("/api/admin/requests?model=claude-fixture&status=completed").json()
            self.assertEqual(1, len(filtered["items"]))
            self.assertEqual("claude-fixture", filtered["items"][0]["model"])
            by_protocol = client.get("/api/admin/requests?protocol=claude-messages").json()
            self.assertEqual(["claude-fixture"], [item["model"] for item in by_protocol["items"]])
            # Body content is never a filter input.
            self.assertEqual([], client.get("/api/admin/requests?model=13800138000").json()["items"])
            self.assertEqual(2, len(runtime.fixture.calls), "History browsing must not call supplier")

    def test_two_protocols_real_sse_wire_history_through_pg_and_api(self):
        with synthetic_history_runtime() as runtime, TestClient(runtime.app) as client:
            admin_login(client)
            for index, (path, headers, payload) in enumerate(synthetic_requests()):
                with self.subTest(protocol=path):
                    payload = dict(payload, stream=True)
                    response = client.post(path, headers=headers, json=payload)
                    self.assertEqual(200, response.status_code)
                    self.assertIn("text/event-stream", response.headers["content-type"])
                    identifier = response.headers["x-request-id"]
                    detail_response = client.get("/api/admin/requests/" + identifier)
                    self.assertEqual(200, detail_response.status_code)
                    detail = detail_response.json()
                    self.assertEqual("completed", detail["status"])
                    stages = {stage["stage"]: stage for stage in detail["stages"]}
                    self.assertTrue(all(stage["state"] == "complete" for stage in stages.values()))
                    self.assertEqual(payload, json.loads(stages["input"]["body"]))
                    self.assertEqual(runtime.fixture.calls[index].content.decode(), stages["redacted"]["body"])
                    self.assertEqual("text/event-stream", stages["upstream"]["media_type"])
                    self.assertEqual("text/event-stream", stages["restored"]["media_type"])
                    self.assertEqual(runtime.upstream_bodies[index].decode(), stages["upstream"]["body"])
                    self.assertEqual(response.content.decode(), stages["restored"]["body"])
                    self.assertNotIn("event: error", response.text)
                    for truth in ("甲公司", "乙公司", "张三", "13800138000"):
                        self.assertNotIn(truth, stages["redacted"]["body"])
                        self.assertNotIn(truth, stages["upstream"]["body"])
                        self.assertIn(truth, stages["restored"]["body"])
                    self.assertNotIn("synthetic-key", json.dumps(detail))
            self.assertEqual(2, len(runtime.fixture.calls))

    def test_synthetic_html_stays_in_body_and_blocked_request_has_no_model_result(self):
        with synthetic_history_runtime() as runtime, TestClient(runtime.app) as client:
            admin_login(client)
            probes = synthetic_requests(preview=True)[2:]
            path, headers, payload = probes[0]
            response = client.post(path, headers=headers, json=payload)
            self.assertEqual(200, response.status_code)
            detail = client.get("/api/admin/requests/" + response.headers["x-request-id"]).json()
            self.assertIn(HTML_PROBE, json.loads(detail["stages"][3]["body"])["choices"][0]["message"]["content"])
            path, headers, payload = probes[1]
            blocked = client.post(path, headers=headers, json=payload)
            self.assertGreaterEqual(blocked.status_code, 400)
            self.assertEqual(1, len(runtime.fixture.calls))
            detail = client.get("/api/admin/requests/" + blocked.headers["x-request-id"]).json()
            self.assertEqual("blocked", detail["status"])
            stages = {stage["stage"]: stage for stage in detail["stages"]}
            self.assertEqual("not_produced", stages["redacted"]["state"])
            self.assertEqual("not_produced", stages["upstream"]["state"])
            self.assertIsNone(stages["upstream"]["body"])
            # The gateway did produce a refusal response; it is recorded exactly.
            self.assertEqual(blocked.content.decode(), stages["restored"]["body"])


if __name__ == "__main__":
    unittest.main()
