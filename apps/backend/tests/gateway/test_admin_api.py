"""Admin HTTP assembly: login/session/logout, page guard, CSRF, origin, old-route removal."""
from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
import tempfile
import unittest

from httpx import ASGITransport, AsyncClient

from gateway.admin_auth import (
    ADMIN_USERNAME, SESSION_COOKIE_NAME, AdminAuthService, initialize_admin_state,
)
from gateway.admin_storage import AdminStateStore
from gateway.app import create_app
from infra.errors import SafetyError

PASSWORD = "admin@123"
ORIGIN = "http://admin.test"
FOREIGN_ORIGIN = "http://foreign.example"
SESSION_KEYS = {"actor_id", "scope", "authenticated_at", "idle_expires_at",
                "absolute_expires_at", "csrf_token"}


class FakeClock:
    def __init__(self, start=1_700_000_000.0):
        self.moment = float(start)

    def __call__(self):
        return self.moment

    def advance(self, seconds):
        self.moment += seconds


def issue_session(store, seed=b"synthetic-session-seed"):
    seed = seed.ljust(32, b"\0")[:32]
    token = seed.hex()
    store.create_session(hashlib.sha256(seed).hexdigest())
    return token


class _ZeroCallHistoryStore:
    """Every admin history read must short-circuit before touching the store."""

    def __init__(self):
        self.calls = 0

    def list_requests(self, **kwargs):
        self.calls += 1
        return {"items": [], "next_cursor": None}

    def get_request(self, request_id, **kwargs):
        self.calls += 1
        raise AssertionError("unreachable")


class AdminApiTests(unittest.IsolatedAsyncioTestCase):
    """Session routes and page guard over directly-issued sessions (no scrypt cost)."""

    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.clock = FakeClock()
        self.store = AdminStateStore(Path(self.temp.name) / "admin", now=self.clock)
        await asyncio.to_thread(
            self.store.initialize, salt=b"s" * 16, derived_key=b"d" * 32,
            scrypt_n=2 ** 17, scrypt_r=8, scrypt_p=1, dklen=32)
        self.service = AdminAuthService(self.store, scope="tenant-a/domain-b")
        self.history = _ZeroCallHistoryStore()
        self.app = create_app(admin_service=self.service, history_store=self.history)
        self.client = AsyncClient(transport=ASGITransport(app=self.app),
                                  base_url=ORIGIN)
        self.addCleanup(self.client.aclose)

    def cookie(self, token):
        return {"cookie": f"{SESSION_COOKIE_NAME}={token}"}

    async def csrf(self, token):
        response = await self.client.get("/api/admin/session", headers=self.cookie(token))
        self.assertEqual(response.status_code, 200)
        return response.json()["csrf_token"]

    async def test_login_page_is_public_html_with_security_headers(self):
        response = await self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])

    async def test_login_page_redirects_authenticated_admin_to_console(self):
        token = issue_session(self.store)
        response = await self.client.get("/login", headers=self.cookie(token))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["location"], "/admin")

    async def test_admin_pages_redirect_anonymous_and_serve_authenticated(self):
        for path in ("/admin", "/admin/requests"):
            response = await self.client.get(path)
            self.assertEqual(response.status_code, 302, path)
            self.assertEqual(response.headers["location"], "/login")
        token = issue_session(self.store)
        for path in ("/admin", "/admin/requests"):
            response = await self.client.get(path, headers=self.cookie(token))
            self.assertEqual(response.status_code, 200, path)
            self.assertIn("text/html", response.headers["content-type"])
            self.assertEqual(response.headers["cache-control"], "no-store")

    async def test_session_payload_shape_and_poll_variant(self):
        token = issue_session(self.store)
        response = await self.client.get("/api/admin/session", headers=self.cookie(token))
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(set(body), SESSION_KEYS)
        self.assertEqual(body["actor_id"], ADMIN_USERNAME)
        self.assertEqual(body["scope"], "tenant-a/domain-b")
        self.assertEqual(len(body["csrf_token"]), 64)
        int(body["csrf_token"], 16)
        self.assertTrue(body["authenticated_at"].endswith("+00:00"))
        self.assertEqual(response.headers["cache-control"], "no-store")

    async def test_session_poll_does_not_refresh_idle_deadline(self):
        token = issue_session(self.store)
        first = (await self.client.get("/api/admin/session", headers=self.cookie(token))).json()
        self.clock.advance(300)
        second = (await self.client.get("/api/admin/session", headers=self.cookie(token))).json()
        self.assertEqual(first["idle_expires_at"], second["idle_expires_at"])
        self.assertNotEqual(first["authenticated_at"], "")

    async def test_logout_requires_csrf_and_revokes_persistently(self):
        token = issue_session(self.store)
        cookie = self.cookie(token)
        for headers in ({**cookie, "origin": ORIGIN},
                        {**cookie, "origin": ORIGIN, "x-admin-csrf": "0" * 64}):
            response = await self.client.post("/api/admin/logout", headers=headers)
            self.assertEqual(response.status_code, 403)
            self.assertEqual(response.json(), {"error": {"code": "ADMIN_CSRF_INVALID"}})
        csrf = await self.csrf(token)
        response = await self.client.post("/api/admin/logout",
                                          headers={**cookie, "origin": ORIGIN, "x-admin-csrf": csrf})
        self.assertEqual(response.status_code, 200)
        self.assertIn(f"{SESSION_COOKIE_NAME}=\"\"", response.headers["set-cookie"])
        self.assertIn("httponly", response.headers["set-cookie"].lower())
        self.assertIn("samesite=strict", response.headers["set-cookie"].lower())
        # The revoked cookie is replayed nowhere: every admin route refuses it.
        replay = await self.client.get("/api/admin/session", headers=cookie)
        self.assertEqual(replay.status_code, 401)
        again = await self.client.post("/api/admin/logout",
                                       headers={**cookie, "origin": ORIGIN, "x-admin-csrf": csrf})
        self.assertEqual(again.status_code, 401)

    async def test_logout_rejects_cross_origin(self):
        token = issue_session(self.store)
        csrf = await self.csrf(token)
        response = await self.client.post(
            "/api/admin/logout",
            headers={**self.cookie(token), "origin": FOREIGN_ORIGIN, "x-admin-csrf": csrf})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {"error": {"code": "ADMIN_ORIGIN_REJECTED"}})
        # The session survives the rejected attempt.
        self.assertEqual((await self.client.get("/api/admin/session",
                                                headers=self.cookie(token))).status_code, 200)

    async def test_admin_routes_require_session_before_any_service_call(self):
        from uuid import uuid4
        routes = [("GET", "/api/admin/session"), ("POST", "/api/admin/logout"),
                  ("GET", "/api/admin/requests"), ("GET", f"/api/admin/requests/{uuid4()}")]
        for method, path in routes:
            for headers in ({}, {"origin": ORIGIN}, {"authorization": "Bearer " + "0" * 64},
                            {"x-admin-actor": "admin"}):
                response = await self.client.request(method, path, headers=headers)
                self.assertEqual(response.status_code, 401, (method, path, headers))
                self.assertEqual(response.json(), {"error": {"code": "ADMIN_SESSION_INVALID"}})
                self.assertEqual(response.headers["cache-control"], "no-store")
                self.assertNotIn("set-cookie", response.headers)
        self.assertEqual(self.history.calls, 0)

    async def test_old_query_key_routes_are_gone(self):
        from uuid import uuid4
        for path in ("/history", "/history/", "/history/assets/history.css",
                     "/history/assets/history.js", "/api/requests", f"/api/requests/{uuid4()}"):
            for headers in ({}, {"authorization": "Bearer " + "ab" * 32}):
                response = await self.client.get(path, headers=headers)
                self.assertEqual(response.status_code, 404, (path, headers))
                self.assertEqual(response.json()["error"]["code"], "UNSUPPORTED_ENDPOINT")


class AdminLoginFlowTests(unittest.IsolatedAsyncioTestCase):
    """Real scrypt login flow through HTTP; one initialized state per test."""

    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "admin"
        self.clock = FakeClock()
        self.store = AdminStateStore(self.directory, now=self.clock)
        await asyncio.to_thread(initialize_admin_state, self.store, PASSWORD)
        self.service = AdminAuthService(self.store, scope="tenant-a/domain-b")
        self.app = create_app(admin_service=self.service)
        self.client = AsyncClient(transport=ASGITransport(app=self.app), base_url=ORIGIN)
        self.addCleanup(self.client.aclose)

    def login(self, payload, *, origin=ORIGIN, content_type="application/json"):
        headers = {"content-type": content_type}
        if origin is not None:
            headers["origin"] = origin
        if isinstance(payload, bytes):
            return self.client.post("/api/admin/login", headers=headers, content=payload)
        return self.client.post("/api/admin/login", headers=headers, json=payload)

    async def test_correct_login_sets_cookie_and_returns_session_payload(self):
        response = await self.login({"username": ADMIN_USERNAME, "password": PASSWORD})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(set(body), SESSION_KEYS)
        self.assertEqual(body["actor_id"], ADMIN_USERNAME)
        cookie = response.headers["set-cookie"]
        self.assertIn(f"{SESSION_COOKIE_NAME}=", cookie)
        self.assertIn("path=/", cookie.lower())
        self.assertIn("httponly", cookie.lower())
        self.assertIn("samesite=strict", cookie.lower())
        self.assertNotIn("domain=", cookie.lower())
        self.assertNotIn("secure", cookie.lower())
        # The issued cookie immediately authenticates the poll endpoint.
        session = await self.client.get("/api/admin/session")
        self.assertEqual(session.status_code, 200)
        self.assertEqual(session.json()["csrf_token"], body["csrf_token"])

    async def test_https_login_marks_cookie_secure(self):
        secure_client = AsyncClient(transport=ASGITransport(app=self.app),
                                    base_url="https://admin.test")
        self.addCleanup(secure_client.aclose)
        response = await secure_client.post(
            "/api/admin/login", headers={"origin": "https://admin.test"},
            json={"username": ADMIN_USERNAME, "password": PASSWORD})
        self.assertEqual(response.status_code, 200)
        self.assertIn("secure", response.headers["set-cookie"].lower())

    async def test_wrong_username_and_password_are_indistinguishable(self):
        bodies = []
        for payload in ({"username": ADMIN_USERNAME, "password": "wrong-password"},
                        {"username": "root", "password": PASSWORD},
                        {"username": ADMIN_USERNAME, "password": ""}):
            response = await self.login(payload)
            self.assertEqual(response.status_code, 401)
            bodies.append(response.text)
            self.assertEqual(response.json(), {"error": {"code": "ADMIN_LOGIN_FAILED"}})
            self.assertNotIn("set-cookie", response.headers)
        self.assertEqual(len(set(bodies)), 1)

    async def test_login_rejects_unknown_duplicate_and_malformed_fields(self):
        cases = [
            {"username": ADMIN_USERNAME, "password": PASSWORD, "role": "admin"},
            {"username": ADMIN_USERNAME},
            {"password": PASSWORD},
            {"username": [ADMIN_USERNAME], "password": PASSWORD},
            [ADMIN_USERNAME, PASSWORD],
        ]
        for payload in cases:
            response = await self.login(payload)
            self.assertEqual(response.status_code, 422, payload)
            self.assertEqual(response.json(), {"error": {"code": "ADMIN_REQUEST_INVALID"}})
        duplicate = b'{"username":"admin","username":"admin","password":"x"}'
        self.assertEqual((await self.login(duplicate)).status_code, 422)
        self.assertEqual((await self.login(b"not json")).status_code, 422)
        self.assertEqual((await self.login({"username": ADMIN_USERNAME, "password": PASSWORD},
                                           content_type="text/plain")).status_code, 422)
        self.assertNotIn(PASSWORD, (await self.login(b"not json")).text)

    async def test_login_requires_same_origin_signal(self):
        for origin in (FOREIGN_ORIGIN, "null", None):
            response = await self.login({"username": ADMIN_USERNAME, "password": PASSWORD},
                                        origin=origin)
            self.assertEqual(response.status_code, 403, origin)
            self.assertEqual(response.json(), {"error": {"code": "ADMIN_ORIGIN_REJECTED"}})
            self.assertNotIn("set-cookie", response.headers)

    async def test_sixth_failed_login_is_throttled(self):
        for _ in range(5):
            response = await self.login({"username": ADMIN_USERNAME, "password": "bad"})
            self.assertEqual(response.status_code, 401)
        # The sixth attempt is throttled before verification, even with the right password.
        response = await self.login({"username": ADMIN_USERNAME, "password": PASSWORD})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.json(), {"error": {"code": "ADMIN_LOGIN_THROTTLED"}})
        self.assertNotIn("set-cookie", response.headers)


class AdminAssemblyTests(unittest.IsolatedAsyncioTestCase):
    async def test_history_disabled_still_allows_login_and_session(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        store = AdminStateStore(Path(temp.name) / "admin")
        await asyncio.to_thread(initialize_admin_state, store, PASSWORD)
        service = AdminAuthService(store, scope="tenant-a/domain-b")
        app = create_app(admin_service=service)  # no history store at all
        client = AsyncClient(transport=ASGITransport(app=app), base_url=ORIGIN)
        self.addCleanup(client.aclose)
        response = await client.post("/api/admin/login", headers={"origin": ORIGIN},
                                     json={"username": ADMIN_USERNAME, "password": PASSWORD})
        self.assertEqual(response.status_code, 200)
        session = await client.get("/api/admin/session")
        self.assertEqual(session.status_code, 200)
        self.assertEqual((await client.get("/api/admin/requests")).status_code, 404)

    async def test_uninitialized_admin_state_fails_closed(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        store = AdminStateStore(Path(temp.name) / "admin")  # never initialized
        service = AdminAuthService(store, scope="tenant-a/domain-b")
        app = create_app(admin_service=service)
        client = AsyncClient(transport=ASGITransport(app=app), base_url=ORIGIN)
        self.addCleanup(client.aclose)
        response = await client.post("/api/admin/login", headers={"origin": ORIGIN},
                                     json={"username": ADMIN_USERNAME, "password": PASSWORD})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"error": {"code": "ADMIN_STORAGE_UNAVAILABLE"}})
        session = await client.get("/api/admin/session",
                                   headers={"cookie": f"{SESSION_COOKIE_NAME}={'ab' * 32}"})
        self.assertEqual(session.status_code, 503)

    async def test_history_reads_stay_closed_without_admin_service(self):
        # A recording-only store never opens read routes; fail closed with 404.
        app = create_app(history_store=_ZeroCallHistoryStore())
        client = AsyncClient(transport=ASGITransport(app=app), base_url=ORIGIN)
        self.addCleanup(client.aclose)
        self.assertEqual((await client.get("/api/admin/requests")).status_code, 404)
        with self.assertRaises(SafetyError):
            create_app(admin_service=object())


if __name__ == "__main__":
    unittest.main()
