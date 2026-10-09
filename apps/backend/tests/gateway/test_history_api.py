"""HTTP credential and rendering boundaries; storage has separate real-PG tests."""
from __future__ import annotations

import unittest
from uuid import uuid4

from httpx import ASGITransport, AsyncClient

from gateway.app import create_app
from gateway.history_api import install_history_routes
from request_history.models import HistoryNotFound


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
        return {"items": [{"request_id": self.request_id, "model": "approved-model"}], "next_cursor": None}

    def get_request(self, request_id):
        if self.failure:
            raise self.failure
        self.reads += 1
        if request_id != self.request_id:
            raise HistoryNotFound()
        return {"request_id": request_id, "stages": [{"stage": "input", "body": "<script>synthetic</script>"}]}


class HistoryApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store = StoreBoundary()
        self.app = create_app()
        self.key = b"k" * 32
        install_history_routes(self.app, self.store, self.key)
        self.client = AsyncClient(transport=ASGITransport(app=self.app), base_url="http://history")
        self.headers = {"authorization": "Bearer " + self.key.hex()}

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_operator_key_lists_all_bound_records_without_supplier_call(self):
        response = await self.client.get("/api/requests", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["items"][0]["request_id"], self.store.request_id)
        detail = await self.client.get("/api/requests/" + self.store.request_id, headers=self.headers)
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["stages"][0]["body"], "<script>synthetic</script>")
        self.assertEqual(detail.headers["cache-control"], "no-store")
        self.assertIn("frame-ancestors 'none'", detail.headers["content-security-policy"])

    async def test_missing_wrong_supplier_and_ambiguous_keys_never_read(self):
        cases = [[], [("authorization", "Bearer synthetic-supplier-key")],
                 [("authorization", "Bearer " + "0" * 64)],
                 [("authorization", self.headers["authorization"])] * 2,
                 [("authorization", self.headers["authorization"]), ("x-api-key", "vendor")]]
        for headers in cases:
            response = await self.client.get("/api/requests", headers=headers)
            self.assertEqual(response.status_code, 401)
            self.assertNotIn("synthetic-supplier-key", response.text)
            self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(self.store.reads, 0)
        self.assertEqual(len(self.store.access), len(cases))

    async def test_untrusted_paths_are_not_written_to_access_audit(self):
        response = await self.client.get("/api/requests/SYNTHETIC-secret-path")
        self.assertEqual(response.status_code, 401)
        self.assertIsNone(self.store.access[-1]["request_id"])
        self.assertNotIn("SYNTHETIC-secret-path", response.text)

    async def test_bad_limits_status_duplicate_and_unknown_query_refuse(self):
        for query in ("limit=0", "limit=101", "limit=SYNTHETIC-private", "q=" + "SYNTHETIC" * 100,
                      "status=unknown", "q=a&q=b", "api_key=synthetic"):
            response = await self.client.get("/api/requests?" + query, headers=self.headers)
            self.assertEqual(response.status_code, 400)
            self.assertNotIn("synthetic", response.text)
            self.assertNotIn("SYNTHETIC", response.text)
        self.assertEqual(self.store.reads, 0)

    async def test_audit_and_store_failure_never_echo_exception(self):
        self.store.failure = RuntimeError("SYNTHETIC-private-dsn-key-body")
        for headers in ({}, self.headers):
            response = await self.client.get("/api/requests", headers=headers)
            self.assertEqual(response.status_code, 503)
            self.assertNotIn("SYNTHETIC", response.text)

    async def test_page_assets_are_same_origin_and_not_arbitrary_files(self):
        for path in ("/history", "/history/assets/history.css", "/history/assets/history.js"):
            response = await self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers["x-content-type-options"], "nosniff")
            self.assertEqual(response.headers["cache-control"], "no-store")
        response = await self.client.get("/history/assets/config.toml")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
