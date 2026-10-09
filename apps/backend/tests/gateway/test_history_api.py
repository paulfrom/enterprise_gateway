"""Admin-session history reads; storage internals have separate real-PG tests."""
from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from httpx import ASGITransport, AsyncClient

from gateway.admin_auth import SESSION_COOKIE_NAME, AdminAuthService
from gateway.admin_storage import AdminStateStore
from gateway.app import create_app
from request_history.models import HistoryNotFound, HistoryUnavailable

ORIGIN = "http://history.test"


class StoreBoundary:
    def __init__(self):
        self.access = []
        self.reads = 0
        self.failure = None
        self.request_id = str(uuid4())

    def audit_access(self, **event):
        if self.failure:
            raise self.failure
        self.access.append(event)

    def list_requests(self, **kwargs):
        if self.failure:
            raise self.failure
        self.reads += 1
        self.last_list = kwargs
        return {"items": [{"request_id": self.request_id, "model": "approved-model"}],
                "next_cursor": None}

    def get_request(self, request_id, **kwargs):
        if self.failure:
            raise self.failure
        self.reads += 1
        self.last_get = (request_id, kwargs)
        if request_id != self.request_id:
            raise HistoryNotFound()
        return {"request_id": request_id,
                "stages": [{"stage": "input", "body": "<script>synthetic</script>"}]}


class HistoryApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.auth_store = AdminStateStore(Path(self.temp.name) / "admin")
        await asyncio.to_thread(
            self.auth_store.initialize, salt=b"s" * 16, derived_key=b"d" * 32,
            scrypt_n=2 ** 17, scrypt_r=8, scrypt_p=1, dklen=32)
        self.service = AdminAuthService(self.auth_store, scope="tenant-a/domain-b")
        self.store = StoreBoundary()
        self.app = create_app(admin_service=self.service, history_store=self.store)
        self.client = AsyncClient(transport=ASGITransport(app=self.app), base_url=ORIGIN)
        self.addCleanup(self.client.aclose)
        seed = b"synthetic-history-session".ljust(32, b"\0")
        self.token = seed.hex()
        self.digest = hashlib.sha256(seed).hexdigest()
        await asyncio.to_thread(self.auth_store.create_session, self.digest)
        self.cookie = {"cookie": f"{SESSION_COOKIE_NAME}={self.token}"}

    async def test_admin_session_lists_and_reads_all_bound_records(self):
        response = await self.client.get("/api/admin/requests", headers=self.cookie)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["items"][0]["request_id"], self.store.request_id)
        detail = await self.client.get("/api/admin/requests/" + self.store.request_id,
                                       headers=self.cookie)
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["stages"][0]["body"], "<script>synthetic</script>")
        self.assertEqual(detail.headers["cache-control"], "no-store")
        self.assertIn("frame-ancestors 'none'", detail.headers["content-security-policy"])

    async def test_history_audit_binds_admin_actor_and_session_reference(self):
        await self.client.get("/api/admin/requests", headers=self.cookie)
        self.assertEqual(self.store.last_list["actor"], "admin")
        self.assertEqual(self.store.last_list["session_reference"], self.digest[:16])
        await self.client.get("/api/admin/requests/" + self.store.request_id,
                              headers=self.cookie)
        request_id, kwargs = self.store.last_get
        self.assertEqual(request_id, self.store.request_id)
        self.assertEqual(kwargs["actor"], "admin")
        self.assertEqual(kwargs["session_reference"], self.digest[:16])

    async def test_unauthenticated_reads_never_reach_the_store(self):
        from uuid import uuid4 as new_id
        for path in ("/api/admin/requests", f"/api/admin/requests/{new_id()}"):
            for headers in ({}, {"authorization": "Bearer " + "0" * 64},
                            {"x-api-key": "vendor"}, {"x-admin-actor": "admin"}):
                response = await self.client.get(path, headers=headers)
                self.assertEqual(response.status_code, 401, (path, headers))
                self.assertEqual(response.json(), {"error": {"code": "ADMIN_SESSION_INVALID"}})
        self.assertEqual(self.store.reads, 0)
        self.assertEqual(self.store.access, [])

    async def test_untrusted_path_is_not_written_to_access_audit(self):
        response = await self.client.get("/api/admin/requests/SYNTHETIC-secret-path",
                                         headers=self.cookie)
        self.assertEqual(response.status_code, 404)
        self.assertNotIn("SYNTHETIC-secret-path", response.text)
        self.assertEqual(self.store.reads, 0)
        self.assertEqual(self.store.access, [])

    async def test_unknown_record_is_404(self):
        response = await self.client.get(f"/api/admin/requests/{uuid4()}",
                                         headers=self.cookie)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json(), {"error": {"code": "HISTORY_NOT_FOUND"}})

    async def test_bad_filters_duplicate_and_unknown_query_refuse_without_reads(self):
        queries = ("limit=0", "limit=101", "limit=SYNTHETIC-private",
                   "status=unknown", "protocol=unknown", "error_code=NOT_A_CODE",
                   "created_after=not-a-time", "created_before=2026-01-01",
                   "model=" + "m" * 300, "limit=1&limit=2", "api_key=synthetic",
                   "q=synthetic")
        for query in queries:
            response = await self.client.get("/api/admin/requests?" + query,
                                             headers=self.cookie)
            self.assertEqual(response.status_code, 422, query)
            self.assertEqual(response.json(), {"error": {"code": "INVALID_HISTORY_QUERY"}})
            self.assertNotIn("synthetic", response.text)
            self.assertNotIn("SYNTHETIC", response.text)
        self.assertEqual(self.store.reads, 0)

    async def test_metadata_filters_are_forwarded_to_the_store(self):
        response = await self.client.get(
            "/api/admin/requests?limit=7&model=approved-model"
            "&protocol=deepseek-chat-completions&status=blocked&error_code=SECRET_DETECTED"
            "&created_after=2026-01-01T00:00:00%2B00:00&created_before=2026-12-31T23:59:59%2B00:00",
            headers=self.cookie)
        self.assertEqual(response.status_code, 200)
        forwarded = self.store.last_list
        self.assertEqual(forwarded["limit"], 7)
        self.assertEqual(forwarded["model"], "approved-model")
        self.assertEqual(forwarded["protocol"], "deepseek-chat-completions")
        self.assertEqual(forwarded["status"], "blocked")
        self.assertEqual(forwarded["error_code"], "SECRET_DETECTED")
        self.assertEqual(forwarded["created_after"].isoformat(), "2026-01-01T00:00:00+00:00")
        self.assertEqual(forwarded["created_before"].isoformat(), "2026-12-31T23:59:59+00:00")

    async def test_store_failure_never_echoes_exception(self):
        self.store.failure = RuntimeError("SYNTHETIC-private-dsn-key-body")
        response = await self.client.get("/api/admin/requests", headers=self.cookie)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"error": {"code": "HISTORY_UNAVAILABLE"}})
        self.assertNotIn("SYNTHETIC", response.text)

    async def test_revalidation_failure_releases_no_body(self):
        original = self.auth_store.validate_session
        calls = {"count": 0}

        def revoke_after_first(digest, refresh_idle):
            record = original(digest, refresh_idle)
            calls["count"] += 1
            if calls["count"] == 1:
                self.auth_store.revoke_session(digest)
            return record

        from unittest.mock import patch
        with patch.object(self.auth_store, "validate_session", side_effect=revoke_after_first):
            response = await self.client.get("/api/admin/requests/" + self.store.request_id,
                                             headers=self.cookie)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), {"error": {"code": "ADMIN_SESSION_INVALID"}})
        self.assertNotIn("<script>synthetic</script>", response.text)


if __name__ == "__main__":
    unittest.main()
