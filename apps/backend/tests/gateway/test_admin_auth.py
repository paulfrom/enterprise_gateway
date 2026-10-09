"""Admin authentication: scrypt login, session dependency variants, throttling, revalidation."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from datetime import timedelta
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from gateway.admin_auth import (
    ABSOLUTE_TIMEOUT_SECONDS, ADMIN_USERNAME, IDLE_TIMEOUT_SECONDS, SESSION_COOKIE_NAME,
    AdminAuthService, AdminContext, AdminLoginFailed, AdminLoginThrottled,
    initialize_admin_state,
)
from gateway.admin_storage import (
    AdminStateStore, AdminStorageUnavailable, SessionInvalid,
)

BACKEND = Path(__file__).resolve().parents[2]
SCRIPT = BACKEND / "scripts" / "prepare_admin_state.py"
SCRIPT_ENV = {**os.environ, "PYTHONPATH": str(BACKEND / "src")}
PASSWORD = "admin@123"
SOURCE = "198.51.100.20"


class FakeClock:
    def __init__(self, start=1_700_000_000.0):
        self.moment = float(start)

    def __call__(self):
        return self.moment

    def advance(self, seconds):
        self.moment += seconds


def make_service(directory, clock, *, scope="tenant-a/domain-b", **kwargs):
    store = AdminStateStore(directory, now=clock)
    return AdminAuthService(store, scope=scope, **kwargs), store


class AdminAuthTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "state" / "admin"
        self.clock = FakeClock()
        self.service, self.store = make_service(self.directory, self.clock)

    async def initialize(self, password=PASSWORD):
        await asyncio.to_thread(initialize_admin_state, self.store, password)

    async def test_initialize_and_login_issues_usable_session(self):
        await self.initialize()
        token, context = await self.service.login(username=ADMIN_USERNAME, password=PASSWORD,
                                                  source=SOURCE)
        self.assertEqual(len(token), 64)
        int(token, 16)
        self.assertEqual(context.actor_id, "admin")
        self.assertEqual(context.scope, "tenant-a/domain-b")
        self.assertEqual(len(context.session_reference), 16)
        self.assertNotIn(context.session_reference, token)
        start = self.clock.moment
        self.assertEqual(context.authenticated_at.timestamp(), start)
        self.assertEqual(context.idle_expires_at.timestamp(), start + IDLE_TIMEOUT_SECONDS)
        self.assertEqual(context.absolute_expires_at.timestamp(), start + ABSOLUTE_TIMEOUT_SECONDS)
        self.assertEqual(context.authenticated_at.utcoffset(), timedelta(0))
        again = await self.service.authenticate(token, source=SOURCE, refresh_idle=False)
        self.assertEqual(again.session_reference, context.session_reference)
        second, _ = await self.service.login(username=ADMIN_USERNAME, password=PASSWORD,
                                             source=SOURCE)
        self.assertNotEqual(token, second)
        # Only the token digest is persisted, never the presented token.
        for path in self.directory.rglob("*"):
            if path.is_file():
                self.assertNotIn(token.encode(), path.read_bytes())

    async def test_login_failures_are_uniform_and_audited(self):
        await self.initialize()
        failures = []
        for username, password in ((ADMIN_USERNAME, "wrong-password"), ("root", PASSWORD),
                                   ("admin ", PASSWORD), (ADMIN_USERNAME, "")):
            with self.assertRaises(AdminLoginFailed) as caught:
                await self.service.login(username=username, password=password, source=SOURCE)
            failures.append(str(caught.exception))
        self.assertEqual(len(set(failures)), 1)
        events = sorted((self.directory / "events").glob("*.json"))
        self.assertEqual(len(events), 4)
        for path in events:
            body = path.read_bytes()
            record = json.loads(body)
            self.assertEqual((record["event"], record["outcome"], record["category"]),
                             ("login", "refused", "invalid_credentials"))
            self.assertEqual(record["source"], SOURCE)
            self.assertNotIn(PASSWORD.encode(), body)
            self.assertNotIn(b"wrong-password", body)
        self.assertTrue(self.store.login_permitted(SOURCE))
        self.store.register_login_failure(SOURCE)
        self.assertFalse(self.store.login_permitted(SOURCE))

    async def test_sixth_failure_is_throttled_persistent_and_precedes_verification(self):
        await self.initialize()
        for _ in range(5):
            with self.assertRaises(AdminLoginFailed):
                await self.service.login(username=ADMIN_USERNAME, password="bad", source=SOURCE)
        # The sixth attempt is refused before any password comparison, even a correct one.
        with self.assertRaises(AdminLoginThrottled):
            await self.service.login(username=ADMIN_USERNAME, password=PASSWORD, source=SOURCE)
        restarted, _ = make_service(self.directory, self.clock)
        with self.assertRaises(AdminLoginThrottled):
            await restarted.login(username=ADMIN_USERNAME, password="bad", source=SOURCE)
        events = [json.loads(path.read_bytes())
                  for path in sorted((self.directory / "events").glob("*.json"))]
        categories = [event["category"] for event in events]
        self.assertEqual(categories.count("invalid_credentials"), 5)
        self.assertEqual(categories.count("throttled"), 2)
        self.clock.advance(61)
        with self.assertRaises(AdminLoginFailed):
            await restarted.login(username=ADMIN_USERNAME, password="bad", source=SOURCE)

    async def test_successful_login_resets_throttle(self):
        await self.initialize()
        for _ in range(4):
            with self.assertRaises(AdminLoginFailed):
                await self.service.login(username=ADMIN_USERNAME, password="bad", source=SOURCE)
        await self.service.login(username=ADMIN_USERNAME, password=PASSWORD, source=SOURCE)
        with self.assertRaises(AdminLoginFailed):
            await self.service.login(username=ADMIN_USERNAME, password="bad", source=SOURCE)
        self.assertTrue(self.store.login_permitted(SOURCE))

    async def test_no_plaintext_password_or_salt_derived_confusion_in_state(self):
        await self.initialize()
        await self.service.login(username=ADMIN_USERNAME, password=PASSWORD, source=SOURCE)
        for path in self.directory.rglob("*"):
            if path.is_file():
                self.assertNotIn(PASSWORD.encode(), path.read_bytes())
        state = json.loads((self.directory / "admin.json").read_bytes())
        self.assertNotEqual(bytes.fromhex(state["derived_key"]), PASSWORD.encode())
        self.assertGreaterEqual(len(bytes.fromhex(state["salt"])), 16)
        self.assertEqual((state["scrypt_n"], state["scrypt_r"], state["scrypt_p"]),
                         (2 ** 17, 8, 1))

    async def test_storage_failure_is_refused_closed(self):
        await self.initialize()
        (self.directory / "admin.json").write_bytes(b"corrupt")
        with self.assertRaises(AdminStorageUnavailable):
            await self.service.login(username=ADMIN_USERNAME, password=PASSWORD, source=SOURCE)
        with self.assertRaises(AdminStorageUnavailable):
            await self.service.authenticate("ab" * 32, source=SOURCE, refresh_idle=False)

    async def test_login_input_shape_and_concurrency_limit(self):
        await self.initialize()
        for username, password, source in (("", PASSWORD, SOURCE), (ADMIN_USERNAME, PASSWORD, ""),
                                           (ADMIN_USERNAME, PASSWORD, "x" * 300)):
            with self.assertRaises((ValueError, AdminLoginFailed)):
                await self.service.login(username=username, password=password, source=source)
        limited, limited_store = make_service(Path(self.temp.name) / "limited", self.clock,
                                              max_concurrent_verifications=2)
        self.assertEqual(limited._verify_semaphore._value, 2)
        await asyncio.to_thread(initialize_admin_state, limited_store, PASSWORD)
        results = await asyncio.gather(*(
            limited.login(username=ADMIN_USERNAME, password=PASSWORD, source=SOURCE)
            for _ in range(3)))
        self.assertEqual(len({token for token, _ in results}), 3)


class AdminDependencyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "state" / "admin"
        self.clock = FakeClock()
        self.service, self.store = make_service(self.directory, self.clock)
        await asyncio.to_thread(
            self.store.initialize, salt=b"s" * 16, derived_key=b"d" * 32,
            scrypt_n=2 ** 17, scrypt_r=8, scrypt_p=1, dklen=32)
        self.app = FastAPI()

        @self.app.get("/protected")
        async def protected(context: AdminContext = Depends(self.service.require_admin())):
            return {"actor_id": context.actor_id, "scope": context.scope,
                    "session_reference": context.session_reference,
                    "idle_expires_at": context.idle_expires_at.timestamp()}

        @self.app.get("/poll")
        async def poll(context: AdminContext = Depends(self.service.require_admin_poll())):
            return {"idle_expires_at": context.idle_expires_at.timestamp()}

        self.client = AsyncClient(transport=ASGITransport(app=self.app),
                                  base_url="http://admin.test")
        self.addCleanup(self.client.aclose)

    async def issue_session(self, seed=b"synthetic-token"):
        seed = seed.ljust(32, b"\0")[:32]
        digest = hashlib.sha256(seed).hexdigest()
        await asyncio.to_thread(self.store.create_session, digest)
        return seed.hex(), digest

    async def test_dependency_accepts_cookie_and_rejects_absent_forged_and_header_identity(self):
        token, digest = await self.issue_session()
        for headers in ({}, {"authorization": "Bearer " + token},
                        {"x-admin-actor": "admin"}, {"x-forwarded-for": "203.0.113.99"}):
            response = await self.client.get("/protected", headers=headers)
            self.assertEqual(response.status_code, 401, headers)
        response = await self.client.get("/protected",
                                         headers={"cookie": f"{SESSION_COOKIE_NAME}={'ab' * 32}"})
        self.assertEqual(response.status_code, 401)
        response = await self.client.get("/protected", headers={"cookie": f"{SESSION_COOKIE_NAME}={token}"})
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["actor_id"], "admin")
        self.assertEqual(body["scope"], "tenant-a/domain-b")
        self.assertEqual(body["session_reference"], digest[:16])

    async def test_refresh_variant_extends_idle_poll_variant_does_not(self):
        token, digest = await self.issue_session()
        cookie = {"cookie": f"{SESSION_COOKIE_NAME}={token}"}
        initial = (await self.client.get("/poll", headers=cookie)).json()["idle_expires_at"]
        self.clock.advance(300)
        polled = (await self.client.get("/poll", headers=cookie)).json()["idle_expires_at"]
        self.assertEqual(polled, initial)
        refreshed = (await self.client.get("/protected", headers=cookie)).json()["idle_expires_at"]
        self.assertEqual(refreshed, self.clock.moment + IDLE_TIMEOUT_SECONDS)
        record = await asyncio.to_thread(self.store.validate_session, digest, False)
        self.assertEqual(record.idle_expires_at, refreshed)

    async def test_logout_revokes_persistently(self):
        token, _ = await self.issue_session()
        cookie = {"cookie": f"{SESSION_COOKIE_NAME}={token}"}
        self.assertEqual((await self.client.get("/protected", headers=cookie)).status_code, 200)
        context = await self.service.authenticate(token, source=SOURCE, refresh_idle=False)
        await self.service.logout(context, source=SOURCE)
        self.assertEqual((await self.client.get("/protected", headers=cookie)).status_code, 401)
        restarted, _ = make_service(self.directory, self.clock)
        with self.assertRaises(SessionInvalid):
            await restarted.authenticate(token, source=SOURCE, refresh_idle=False)
        events = [json.loads(path.read_bytes())
                  for path in sorted((self.directory / "events").glob("*.json"))]
        self.assertIn(("logout", "success"), [(event["event"], event["outcome"])
                                              for event in events])

    async def test_server_clock_enforces_idle_and_absolute_deadlines(self):
        token, _ = await self.issue_session()
        cookie = {"cookie": f"{SESSION_COOKIE_NAME}={token}"}
        self.clock.advance(IDLE_TIMEOUT_SECONDS + 1)
        self.assertEqual((await self.client.get("/protected", headers=cookie)).status_code, 401)
        token, _ = await self.issue_session(b"synthetic-token-two")
        cookie = {"cookie": f"{SESSION_COOKIE_NAME}={token}"}
        self.clock.advance(ABSOLUTE_TIMEOUT_SECONDS + 1)
        self.assertEqual((await self.client.get("/poll", headers=cookie)).status_code, 401)

    async def test_denied_session_events_use_connection_peer_not_forwarded_headers(self):
        response = await self.client.get(
            "/protected",
            headers={"cookie": f"{SESSION_COOKIE_NAME}={'cd' * 32}",
                     "x-forwarded-for": "203.0.113.99"})
        self.assertEqual(response.status_code, 401)
        events = [json.loads(path.read_bytes())
                  for path in sorted((self.directory / "events").glob("*.json"))]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "session")
        self.assertEqual(events[0]["outcome"], "refused")
        self.assertEqual(events[0]["source"], "127.0.0.1")

    async def test_storage_failure_maps_to_503_not_anonymous_fallback(self):
        token, digest = await self.issue_session()
        (self.directory / "sessions" / (digest + ".json")).unlink()
        (self.directory / "admin.json").write_bytes(b"corrupt")
        response = await self.client.get("/protected", headers={"cookie": f"{SESSION_COOKIE_NAME}={token}"})
        self.assertEqual(response.status_code, 503)

    async def test_revalidate_before_release(self):
        token, _ = await self.issue_session()
        context = await self.service.authenticate(token, source=SOURCE, refresh_idle=False)
        fresh = await self.service.revalidate(context, source=SOURCE)
        self.assertEqual(fresh.session_reference, context.session_reference)
        await self.service.logout(context, source=SOURCE)
        with self.assertRaises(SessionInvalid):
            await self.service.revalidate(context, source=SOURCE)
        token, _ = await self.issue_session(b"synthetic-token-three")
        context = await self.service.authenticate(token, source=SOURCE, refresh_idle=False)
        self.clock.advance(ABSOLUTE_TIMEOUT_SECONDS + 1)
        with self.assertRaises(SessionInvalid):
            await self.service.revalidate(context, source=SOURCE)


class PrepareAdminStateScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name) / "state"

    def run_script(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                              capture_output=True, text=True, timeout=120, env=SCRIPT_ENV)

    def test_initializes_once_and_refuses_overwrite(self):
        result = self.run_script("--state-dir", self.state)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(PASSWORD, result.stdout + result.stderr)
        state_file = self.state / "admin" / "admin.json"
        committed = state_file.read_bytes()
        again = self.run_script("--state-dir", self.state)
        self.assertEqual(again.returncode, 2)
        self.assertNotIn(PASSWORD, again.stdout + again.stderr)
        self.assertEqual(state_file.read_bytes(), committed)
        clock = FakeClock(time.time())
        store = AdminStateStore(self.state / "admin", now=clock)
        service = AdminAuthService(store, scope="tenant-a/domain-b")
        token, context = asyncio.run(
            service.login(username="admin", password=PASSWORD, source="198.51.100.30"))
        self.assertEqual(context.actor_id, "admin")
        self.assertEqual(len(token), 64)

    def test_refuses_missing_arguments(self):
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertFalse((self.state / "admin").exists())


if __name__ == "__main__":
    unittest.main()
