"""Management faults and bounded load preserve the real protected model path."""
from __future__ import annotations

import asyncio
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

import httpx
import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

from audit.audit_intent import ReleaseIntent, commit_release_intent
from infra.durable_write import DurableWriteError, durable_commit
from infra.envelope_crypto import encrypt_record, serialize_record
from knowledge.governance import KnowledgeGovernanceService
from knowledge.storage import PostgresKnowledgeStorage
from tests.integration.test_admin_governance import synthetic_governance_runtime
from scripts.prepare_admin_state import INITIAL_ADMIN_PASSWORD


TENANT_TEXT = "甲公司向乙公司提供服务，张三电话13800138000。"
PROTOCOLS = (("/v1/chat/completions", "chat-fixture"), ("/v1/messages", "claude-fixture"))
LOAD_RECORD_COUNT = 80
LOAD_CONCURRENCY = 3
MODEL_SAMPLES = 2
HEARTBEAT_INTERVAL_SECONDS = 0.01
MAX_ADDED_MODEL_LATENCY_SECONDS = 2.0
MAX_ADDED_EVENT_LOOP_LAG_SECONDS = 0.5


async def login(client):
    response = await client.post("/api/admin/login", json={"username": "admin", "password": INITIAL_ADMIN_PASSWORD},
                                 headers={"origin": "http://gateway"})
    if response.status_code != 200:
        raise AssertionError(response.text)
    return {"origin": "http://gateway", "x-admin-csrf": response.json()["csrf_token"]}


def model_body(model, stream):
    body = {"model": model, "messages": [{"role": "user", "content": TENANT_TEXT}], "stream": stream}
    if model == "claude-fixture":
        body["max_tokens"] = 100
    return body


def response_strings(response):
    """Decode JSON/SSE values so wire escaping cannot hide failed restoration."""
    values = []
    def collect(value):
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, dict):
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)
    if response.headers.get("content-type", "").startswith("text/event-stream"):
        for line in response.text.splitlines():
            if line.startswith("data: ") and line != "data: [DONE]":
                collect(json.loads(line[6:]))
    else:
        collect(response.json())
    return "".join(values)


def seed_load_records(runtime):
    """Server-generated encrypted records exercise actual scans, KMS and writes."""
    state = runtime.fixture.root / "state"
    now = datetime.now(timezone.utc)
    for index in range(LOAD_RECORD_COUNT):
        record_id = "load-" + uuid4().hex
        intent = ReleaseIntent(intent_id="intent-" + record_id, recorded_at=now,
            domain=runtime.domain, category="STANDARD", policy_version="synthetic-policy-v1",
            package_version="synthetic-load-v1", purpose="egress-audit", tenant_id=runtime.tenant,
            evidence_record_id=record_id, evidence_retention_until=now + timedelta(days=30),
            evidence_lifecycle_policy_version="model-query-retention-30d-v1")
        commit_release_intent(state / "intents", intent)
        record = encrypt_record(runtime.kms, ("synthetic audit load " + str(index)).encode(),
            domain=runtime.domain, purpose="model-query", bucket="synthetic-evidence", record_id=record_id)
        durable_commit(state / "evidence", record_id + ".evidence.json", serialize_record(record))


class AdminGovernanceFaultIsolationTests(unittest.TestCase):
    def assert_model_result(self, response):
        self.assertEqual(response.status_code, 200, response.text)
        text = response_strings(response)
        for original in ("甲公司", "乙公司", "张三", "13800138000"):
            self.assertIn(original, text)
        self.assertNotIn("<<ENT", text)

    async def protected_protocol_matrix(self, client, runtime):
        before = len(runtime.fixture.calls)
        for path, model in PROTOCOLS:
            for stream in (False, True):
                with self.subTest(model=model, stream=stream):
                    response = await client.post(path, json=model_body(model, stream),
                        headers={"authorization": "Bearer synthetic-key"})
                    self.assert_model_result(response)
        calls = runtime.fixture.calls[before:]
        self.assertEqual(4, len(calls))
        for call in calls:
            for original in ("甲公司", "乙公司", "张三", "13800138000"):
                self.assertNotIn(original, call.content.decode())

    def test_admin_csrf_secret_is_redacted_from_ingress_logging(self):
        with synthetic_governance_runtime() as runtime:
            captured = io.StringIO()
            async def exercise():
                async with runtime.app.router.lifespan_context(runtime.app):
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=runtime.app), base_url="http://gateway") as client:
                        headers = await login(client)
                        with redirect_stdout(captured):
                            response = await client.get("/api/admin/sources", headers=headers)
                        self.assertEqual(response.status_code, 200, response.text)
                        self.assertNotIn(headers["x-admin-csrf"], captured.getvalue())
                        self.assertIn("x-admin-csrf: <redacted>", captured.getvalue())
            asyncio.run(exercise())

    def test_admin_pg_outage_preserves_both_protocols_json_and_sse_and_audit(self):
        with synthetic_governance_runtime() as runtime:
            async def exercise():
                async with runtime.app.router.lifespan_context(runtime.app):
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=runtime.app), base_url="http://gateway") as client:
                        headers = await login(client)
                        healthy = await client.get("/api/admin/sources", headers=headers)
                        self.assertEqual(healthy.status_code, 200, healthy.text)
                        # A real failed connect on the dedicated admin DSN leaves worker/model resources intact.
                        with patch.object(runtime.storage, "admin_dsn", "host=127.0.0.1 port=1 dbname=synthetic_unavailable connect_timeout=1"):
                            for path, model in PROTOCOLS:
                                for stream in (False, True):
                                    with self.subTest(model=model, stream=stream):
                                        response = await client.post(path, json=model_body(model, stream),
                                            headers={"authorization": "Bearer synthetic-key"})
                                        self.assert_model_result(response)
                            refused = await client.get("/api/admin/sources", headers=headers)
                            self.assertEqual(refused.status_code, 503, refused.text)
                            self.assertEqual(refused.json(), {"error": {"code": "KNOWLEDGE_ADMIN_UNAVAILABLE"}})
                            await asyncio.to_thread(runtime.builder.build_once)
                            records = await client.get("/api/admin/audit/records", headers=headers)
                            self.assertEqual(records.status_code, 200, records.text)
                            self.assertTrue(records.json()["items"])
                            record_id = records.json()["items"][0]["record_id"]
                            detail = await client.get("/api/admin/audit/records/" + record_id, headers=headers)
                            self.assertEqual(detail.status_code, 200, detail.text)
                            self.assertIn("甲公司", detail.json()["plaintext"])
                        self.assertEqual(len(runtime.fixture.calls), 4)
            asyncio.run(exercise())


    def test_catalog_write_failure_backlog_and_rescan_recover_original_evidence(self):
        from infra.envelope_crypto import parse_record
        from infra.errors import SafetyError
        with synthetic_governance_runtime() as runtime:
            async def exercise():
                async with runtime.app.router.lifespan_context(runtime.app):
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=runtime.app), base_url="http://gateway") as client:
                        headers = await login(client)
                        with patch("audit.catalog.commit_guarded", side_effect=DurableWriteError("synthetic catalog volume unavailable")):
                            await self.protected_protocol_matrix(client, runtime)
                            with self.assertRaises(SafetyError):
                                await asyncio.to_thread(runtime.builder.build_once)
                            self.assertGreaterEqual(runtime.builder.backlog(), 4)
                            originals = {parse_record(path.read_bytes()).record_id: (path, path.read_bytes())
                                for path in runtime.app.state.runtime_evidence_directory.glob('*.evidence.json')}
                            self.assertEqual(4, len(originals))
                            self.assertTrue(all(path.exists() for path, _body in originals.values()))
                            # Metadata lag cannot suppress mandatory encrypted retention.
                            self.assertEqual(4, len(list((runtime.fixture.root/'state'/'intents').glob('*.json'))))
                        await asyncio.to_thread(runtime.builder.build_once)
                        self.assertEqual(0, runtime.builder.backlog())
                        records = await client.get('/api/admin/audit/records', headers=headers)
                        self.assertEqual(200, records.status_code, records.text)
                        self.assertEqual(set(originals), {row['record_id'] for row in records.json()['items']})
                        for record_id, (path, body) in originals.items():
                            self.assertEqual(body, path.read_bytes())
                            detail = await client.get('/api/admin/audit/records/'+record_id, headers=headers)
                            self.assertEqual(200, detail.status_code, detail.text)
                            self.assertIn('甲公司', detail.json()['plaintext'])
            asyncio.run(exercise())

    def test_management_queue_saturation_preserves_protected_protocol_matrix(self):
        # Stall only this test's management calls, leaving the shared PG tables
        # and other services available while actual HTTP admission is exercised.
        from contextlib import contextmanager
        import threading
        with synthetic_governance_runtime() as runtime:
            entered = threading.Barrier(5)
            release = threading.Event()
            original = runtime.storage.admin_transaction

            @contextmanager
            def stalled_transaction(**scope):
                entered.wait(timeout=15)
                if not release.wait(60):
                    raise RuntimeError('Synthetic management release timed out')
                with original(**scope) as conn:
                    yield conn

            async def exercise():
                async with runtime.app.router.lifespan_context(runtime.app):
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=runtime.app), base_url='http://gateway') as client:
                        headers = await login(client)
                        with patch.object(runtime.storage, 'admin_transaction', side_effect=stalled_transaction):
                            pending = [asyncio.create_task(client.get('/api/admin/sources',headers=headers)) for _ in range(4)]
                            try:
                                await asyncio.to_thread(entered.wait, 15)
                                overflow = await client.get('/api/admin/sources',headers=headers)
                                self.assertEqual(503,overflow.status_code,overflow.text)
                                self.assertEqual({'error':{'code':'KNOWLEDGE_ADMIN_UNAVAILABLE'}},overflow.json())
                                await self.protected_protocol_matrix(client,runtime)
                            finally:
                                release.set()
                                results = await asyncio.gather(*pending)
                            self.assertTrue(all(response.status_code == 200 for response in results))
                        recovered = await client.get('/api/admin/sources',headers=headers)
                        self.assertEqual(200,recovered.status_code,recovered.text)
            asyncio.run(exercise())

    def test_stopped_real_consumer_leaves_publication_pending_and_model_path_available(self):
        from hashlib import sha256
        from infra.envelope_crypto import decrypt_record, parse_record
        from knowledge.governance import AdminActionContext
        from knowledge.knowledge import Role, TrustedActor
        from knowledge.knowledge_events import ObservationEvent
        from knowledge.worker import KnowledgeWorker, PostgresKnowledgeSink
        with synthetic_governance_runtime() as runtime:
            async def exercise():
                async with runtime.app.router.lifespan_context(runtime.app):
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=runtime.app),base_url='http://gateway') as client:
                        await login(client)
                        body=model_body('chat-fixture',False)
                        body['messages']=[{'role':'user','content':'甲公司向乙公司采购设备。'}]
                        self.assertEqual(200,(await client.post(PROTOCOLS[0][0],json=body,headers={'authorization':'Bearer synthetic-key'})).status_code)
                        event=ObservationEvent.model_validate_json(decrypt_record(runtime.kms,parse_record(next(runtime.app.state.runtime_spool_directory.glob('*.env.json')).read_bytes())))
                        processor=TrustedActor('worker',runtime.tenant,runtime.domain,frozenset({Role.KNOWLEDGE_PROCESSOR}),frozenset({event.purpose}))
                        worker=KnowledgeWorker(runtime.app.state.runtime_spool_directory,runtime.kms,
                            PostgresKnowledgeSink(runtime.storage,processor,runtime.kms,processing_acl=(runtime.domain+':restricted-candidate',)))
                        self.assertEqual(1,(await asyncio.to_thread(worker.run_once)).submitted)
                        until=datetime.now(timezone.utc)+timedelta(hours=1)
                        context=AdminActionContext('admin',sha256(b'synthetic-stopped-consumer-session').hexdigest(),runtime.tenant,runtime.domain)
                        runtime.service.confirm_source_governance(event.source_id,source_version=event.source_version,
                            expected_governance_version=None,ownership='confirmed',use=event.purpose,audiences=['legal'],valid_until=until,basis='synthetic review',context=context)
                        with runtime.storage.admin_transaction(tenant_id=runtime.tenant,domain=runtime.domain) as conn:
                            candidate=str(conn.execute('SELECT candidate_id FROM knowledge_candidates').fetchone()[0])
                        publication=runtime.service.publish_candidate(candidate,expected_version=1,use=event.purpose,audiences=['legal'],valid_until=until,idempotency_key='stopped-consumer',basis='synthetic publish',context=context)
                        def assert_pending():
                            availability=runtime.service.evaluate_availability(candidate_id=None,publication_id=publication,consumer='legal',use=event.purpose,now=datetime.now(timezone.utc))
                            self.assertEqual('pending',availability.delivery_status)
                            self.assertEqual(1,availability.pending_event_count)
                            self.assertEqual((),availability.reuse_assets)
                            with runtime.storage.admin_transaction(tenant_id=runtime.tenant,domain=runtime.domain) as conn:
                                self.assertEqual(0,conn.execute('SELECT count(*) FROM consumer_receipts').fetchone()[0])
                                self.assertEqual(0,conn.execute('SELECT count(*) FROM knowledge_consumer_assets').fetchone()[0])
                        assert_pending()
                        await self.protected_protocol_matrix(client,runtime)
                        assert_pending()
            asyncio.run(exercise())

    def test_existing_durable_intent_gate_still_blocks_supplier(self):
        with synthetic_governance_runtime() as runtime:
            async def exercise():
                async with runtime.app.router.lifespan_context(runtime.app):
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=runtime.app), base_url="http://gateway") as client:
                        with patch("audit.audit_intent.durable_commit", side_effect=DurableWriteError("synthetic intent write failure")):
                            for path, model in PROTOCOLS:
                                response = await client.post(path, json=model_body(model, False),
                                    headers={"authorization": "Bearer synthetic-key"})
                                self.assertEqual(response.status_code, 503, response.text)
                                self.assertEqual(response.json()["error"]["code"], "AUDIT_WRITE_FAILED")
                                self.assertNotIn("甲公司", response.text)
                        self.assertEqual(runtime.fixture.calls, [])
            asyncio.run(exercise())

    def test_admin_load_preserves_event_loop_and_detection_queue_budgets(self):
        async def measure(runtime, enabled):
            app = runtime.app
            lags, queues, latencies = [], [], []
            stop = asyncio.Event()
            async def heartbeat():
                while not stop.is_set():
                    due = time.monotonic() + HEARTBEAT_INTERVAL_SECONDS
                    await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)
                    lags.append(max(0.0, time.monotonic() - due))
                    queues.append(app.state.runtime_pipelines[0].detector._executor.snapshot()[1])
            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gateway") as client:
                    warmup = await client.post(PROTOCOLS[0][0], json=model_body(PROTOCOLS[0][1], False), headers={"authorization": "Bearer synthetic-key"})
                    self.assert_model_result(warmup)
                    headers = await login(client) if enabled else None
                    if enabled:
                        await asyncio.to_thread(runtime.builder.build_once)
                        self.assertEqual(runtime.builder.backlog(), 0)
                    task = asyncio.create_task(heartbeat())
                    async def model_samples():
                        for index in range(MODEL_SAMPLES):
                            path, model = PROTOCOLS[index % len(PROTOCOLS)]
                            started = time.monotonic()
                            response = await client.post(path, json=model_body(model, False), headers={"authorization": "Bearer synthetic-key"})
                            latencies.append(time.monotonic() - started)
                            self.assert_model_result(response)
                    async def audit_load():
                        for _ in range(2):
                            listing = await client.get("/api/admin/audit/records?limit=25", headers=headers)
                            self.assertEqual(listing.status_code, 200, listing.text)
                            self.assertEqual(len(listing.json()["items"]), 25)
                            row = listing.json()["items"][0]
                            detail = await client.get("/api/admin/audit/records/" + row["record_id"], headers=headers)
                            self.assertEqual(detail.status_code, 200, detail.text)
                            self.assertTrue(detail.json()["plaintext"])
                            self.assertTrue(listing.json()["next_cursor"])
                    try:
                        jobs = [model_samples()]
                        if enabled:
                            jobs.extend(audit_load() for _ in range(LOAD_CONCURRENCY))
                            jobs.append(asyncio.to_thread(runtime.builder.build_once))
                        await asyncio.gather(*jobs)
                    finally:
                        stop.set()
                        await task
            self.assertTrue(lags)
            self.assertEqual(len(latencies), MODEL_SAMPLES)
            return max(latencies), max(lags), max(queues)

        with synthetic_governance_runtime(enable_management=False) as baseline:
            off = asyncio.run(measure(baseline, False))
        with synthetic_governance_runtime() as loaded:
            seed_load_records(loaded)
            on = asyncio.run(measure(loaded, True))
        self.assertLessEqual(on[0], off[0] + MAX_ADDED_MODEL_LATENCY_SECONDS, (off, on))
        self.assertLessEqual(on[1], off[1] + MAX_ADDED_EVENT_LOOP_LAG_SECONDS, (off, on))
        self.assertLessEqual(on[2], off[2] + 1, (off, on))
