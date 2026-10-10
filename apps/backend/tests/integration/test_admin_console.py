"""Real-browser L2 slice and TestClient full-chain integration for the admin console.

The TestClient case composes the existing synthetic history runtime (real
detector/FileKMS/isolated PostgreSQL, finite echo supplier) and walks the whole
admin chain: assembly -> real login -> list -> four-stage detail bodies ->
filters/pagination -> logout -> cookie replay refusal -> retired route 404.

The browser cases drive system Chrome through playwright against the real
preview service (``scripts/serve_history_preview.py``) started by this process
on a random loopback port. All supplier payloads and history text are
synthetic. No cookie, token, or password is ever printed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import threading
import time
import unittest
from uuid import uuid4

import httpx

from scripts.prepare_admin_state import INITIAL_ADMIN_PASSWORD
from tests.request_history.pg_support import configuration
from tests.request_history.test_local_e2e import synthetic_history_runtime, synthetic_requests
from starlette.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[4]
BACKEND = REPO_ROOT / "apps" / "backend"
PG_CONFIG = REPO_ROOT / ".runtime_state" / "sdd" / "env" / "pg-history.json"
PG_ENV = "GATEWAY_HISTORY_PG_CONFIG"
EVIDENCE_DIR = REPO_ROOT / ".runtime_state" / "sdd" / "reports" / "task-4-screenshots"
WRONG_PASSWORD = "synthetic-wrong-password"


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class _PreviewServer:
    """Owns a real preview subprocess; startup is reported on stdout as JSON."""

    def __init__(self) -> None:
        self.port = _free_port()
        self.base_url = "http://127.0.0.1:" + str(self.port)
        self._process = None
        self._output = []

    def _drain(self, lines: queue.Queue) -> None:
        for line in self._process.stdout:
            self._output.append(line)
            lines.put(line)

    def __enter__(self) -> "_PreviewServer":
        command = [sys.executable, str(BACKEND / "scripts" / "serve_history_preview.py"),
                   "--pg-config", str(PG_CONFIG), "--port", str(self.port)]
        self._process = subprocess.Popen(command, cwd=str(BACKEND), stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, text=True)
        lines: queue.Queue = queue.Queue()
        threading.Thread(target=self._drain, args=(lines,), daemon=True).start()
        deadline = time.monotonic() + 180
        while True:
            try:
                line = lines.get(timeout=max(1.0, deadline - time.monotonic()))
            except queue.Empty:
                self._stop()
                raise RuntimeError("synthetic preview never reported startup") from None
            if not line.startswith("{"):
                continue  # interpreter/library diagnostics on the merged stream
            if "login_url" in line:
                break
            self._stop()
            raise RuntimeError("synthetic preview failed: " + line.strip())
        deadline = time.monotonic() + 60
        while True:
            try:
                if httpx.get(self.base_url + "/login", timeout=2).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.monotonic() > deadline or self._process.poll() is not None:
                self._stop()
                raise RuntimeError("synthetic preview port never became ready")
            time.sleep(0.25)
        return self

    def _stop(self) -> None:
        if self._process is None:
            return
        if self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=10)
        if self._process.stdout is not None:
            self._process.stdout.close()

    def __exit__(self, *_exc) -> None:
        self._stop()


class _BrowserTestBase(unittest.TestCase):
    """Shared preview server and one real Chrome instance per class."""

    @classmethod
    def setUpClass(cls) -> None:
        if not PG_CONFIG.is_file():
            raise unittest.SkipTest("Explicit isolated history PostgreSQL configuration required")
        cls._server = _PreviewServer()
        cls._server.__enter__()
        try:
            from playwright.sync_api import sync_playwright
            cls._playwright = sync_playwright().start()
            try:
                cls._browser = cls._playwright.chromium.launch(channel="chrome", headless=True)
            except Exception as error:
                cls._playwright.stop()
                raise RuntimeError(
                    "system Chrome via playwright channel=chrome is required: "
                    + type(error).__name__) from None
        except Exception:
            cls._server.__exit__(None, None, None)
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls._browser.close()
            cls._playwright.stop()
        finally:
            cls._server.__exit__(None, None, None)

    def setUp(self) -> None:
        self._console_errors = []
        self._page_errors = []

    def tearDown(self) -> None:
        context = getattr(self, "_context", None)
        if context is not None:
            context.close()

    def _new_page(self, **context_options):
        self._context = self._browser.new_context(base_url=self._server.base_url, **context_options)
        page = self._context.new_page()
        page.on("pageerror", lambda error: self._page_errors.append(type(error).__name__))

        def on_console(message):
            if message.type != "error":
                return
            if "Failed to load resource" in message.text or "favicon" in message.text:
                return
            self._console_errors.append(message.text[:120])

        page.on("console", on_console)
        return page

    def _assert_clean_browser(self) -> None:
        self.assertEqual([], self._page_errors, "Uncaught page exceptions")
        self.assertEqual([], self._console_errors, "Console errors")

    def _login(self, page) -> None:
        page.goto("/login")
        page.fill("#login-username", "admin")
        page.fill("#login-password", INITIAL_ADMIN_PASSWORD)
        page.click("#login-submit")
        page.wait_for_url("**/admin", timeout=20000)
        page.wait_for_selector("#session-identity .actor", timeout=20000)

    def _wait_items(self, page, count: int) -> None:
        page.wait_for_function(
            "expected => document.querySelectorAll('#request-list .request-item').length === expected",
            arg=count, timeout=20000)

    def _open_record(self, page, request_id: str) -> None:
        page.click("#request-" + request_id)
        page.wait_for_function(
            "rid => { const node = document.querySelector('#record-content .record-meta code');"
            " return node !== null && node.textContent === rid; }",
            arg=request_id, timeout=20000)

    def _admin_cookie(self):
        cookies = [c for c in self._context.cookies() if c["name"] == "admin_session"]
        self.assertEqual(1, len(cookies), "Admin session cookie missing")
        return cookies[0]

    def _screenshot(self, page, name: str) -> None:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(EVIDENCE_DIR / name), full_page=True)


class AdminConsoleBrowserTests(_BrowserTestBase):
    """Real Chrome against the real preview service; one login failure budget is never exhausted."""

    def test_01_correct_login_shows_shell_and_session_recovered_server_side(self):
        page = self._new_page()
        self._login(page)
        identity = page.text_content("#session-identity")
        self.assertIn("admin", identity)
        self.assertIn("管理范围", identity)
        self.assertIn("synthetic-history-", identity)
        self.assertIn("空闲截止", identity)
        self.assertIn("绝对截止", identity)
        self.assertEqual("page", page.get_attribute("#nav-requests", "aria-current"))
        cookie = self._admin_cookie()
        self.assertTrue(cookie["httpOnly"])
        self.assertEqual("Strict", cookie["sameSite"])
        self.assertEqual("127.0.0.1", cookie["domain"])
        with httpx.Client(base_url=self._server.base_url,
                          cookies={"admin_session": cookie["value"]}) as http:
            session = http.get("/api/admin/session")
            self.assertEqual(200, session.status_code)
            payload = session.json()
            self.assertEqual("admin", payload["actor_id"])
            self.assertIn("synthetic-history-", payload["scope"])
            self.assertIn("csrf_token", payload)
        page.goto("/login")
        page.wait_for_url("**/admin", timeout=20000)
        page.reload()
        page.wait_for_selector("#session-identity .actor", timeout=20000)
        self.assertIn("/admin", page.url)
        self._screenshot(page, "01-admin-shell.png")
        self._assert_clean_browser()

    def test_02_wrong_password_uniform_error_no_redirect(self):
        page = self._new_page()
        page.goto("/login")
        page.fill("#login-username", "admin")
        page.fill("#login-password", WRONG_PASSWORD)
        page.click("#login-submit")
        page.wait_for_function(
            "() => document.querySelector('#login-error').hidden === false"
            " && document.querySelector('#login-error').textContent.length > 0")
        self.assertEqual("用户名或密码错误。", page.text_content("#login-error"))
        self.assertIn("/login", page.url)
        self.assertEqual("", page.input_value("#login-password"))
        self._assert_clean_browser()

    def test_03_unauthenticated_admin_pages_redirect_to_login(self):
        page = self._new_page()
        for path in ("/admin", "/admin/requests"):
            with self.subTest(path=path):
                page.goto(path)
                page.wait_for_url("**/login", timeout=20000)
                self.assertIn("/login", page.url)
                page.wait_for_selector("#login-form", timeout=10000)
        self._assert_clean_browser()

    def test_04_server_side_revocation_clears_page_and_returns_to_login(self):
        page = self._new_page()
        self._login(page)
        page.goto("/admin/requests")
        self._wait_items(page, 4)
        page.wait_for_selector("#record-content .panel", timeout=20000)
        cookie = self._admin_cookie()
        with httpx.Client(base_url=self._server.base_url,
                          cookies={"admin_session": cookie["value"]}) as http:
            csrf = http.get("/api/admin/session").json()["csrf_token"]
            revoked = http.post("/api/admin/logout",
                                headers={"Origin": self._server.base_url, "X-Admin-CSRF": csrf})
            self.assertEqual(200, revoked.status_code)
            self.assertEqual({"revoked": True}, revoked.json())
            recheck = http.get("/api/admin/session")
            self.assertEqual(401, recheck.status_code)
            self.assertEqual("ADMIN_SESSION_INVALID", recheck.json()["error"]["code"])
        page.click("#refresh-history")
        page.wait_for_function(
            "() => document.querySelectorAll('#request-list .request-item').length === 0"
            " && document.querySelectorAll('#record-content .panel').length === 0"
            " && document.querySelector('#session-identity').textContent.trim() === ''"
            " && document.querySelector('#toast').textContent.includes('会话已失效')",
            timeout=20000)
        page.wait_for_url("**/login", timeout=10000)
        page.wait_for_selector("#login-form", timeout=10000)
        self._assert_clean_browser()

    def test_05_logout_race_blocks_late_render_and_direct_access(self):
        page = self._new_page()
        self._login(page)
        page.goto("/admin/requests")
        self._wait_items(page, 4)
        page.wait_for_selector("#record-content .panel", timeout=20000)
        cookie = self._admin_cookie()
        page.click("#logout-button")
        page.wait_for_url("**/login", timeout=10000)
        page.wait_for_selector("#login-form", timeout=10000)
        for path in ("/admin", "/admin/requests"):
            page.goto(path)
            page.wait_for_url("**/login", timeout=20000)
        page.go_back()
        page.wait_for_load_state("load")
        self.assertIn("/login", page.url)
        self.assertEqual(0, len(page.locator(".panel").all()))
        with httpx.Client(base_url=self._server.base_url,
                          cookies={"admin_session": cookie["value"]}) as http:
            replay = http.get("/api/admin/session")
            self.assertEqual(401, replay.status_code)
            self.assertEqual("ADMIN_SESSION_INVALID", replay.json()["error"]["code"])
            replay_list = http.get("/api/admin/requests")
            self.assertEqual(401, replay_list.status_code)
        self._assert_clean_browser()

    def test_06_full_history_four_stage_bodies_visible_and_copyable(self):
        page = self._new_page()
        self._login(page)
        page.goto("/admin/requests")
        self._wait_items(page, 4)
        self.assertEqual("4 条", page.text_content("#history-count").strip())
        pills = page.eval_on_selector_all(
            "#request-list .status-pill", "nodes => nodes.map(node => node.textContent)")
        self.assertEqual(3, pills.count("完成"))
        self.assertEqual(1, pills.count("被阻断"))
        ids = page.eval_on_selector_all(
            "#request-list .request-item", "nodes => nodes.map(node => node.id.slice('request-'.length))")
        completed = ids[pills.index("完成")]
        self._open_record(page, completed)
        self.assertEqual(4, len(page.locator("#record-content .journey-step.complete").all()))
        bodies = page.locator("#record-content .panel .text-content")
        self.assertEqual(4, bodies.count())
        for index in range(4):
            self.assertTrue(bodies.nth(index).is_visible())
        copies = page.locator("#record-content .copy-btn")
        self.assertEqual(4, copies.count())
        for index in range(4):
            self.assertTrue(copies.nth(index).is_enabled())
        self.assertEqual(0, page.locator("text=显示原文").count())
        blocked = ids[pills.index("被阻断")]
        self._open_record(page, blocked)
        self.assertEqual(2, len(page.locator("#record-content .missing-content").all()))
        disabled = page.locator("#record-content .copy-btn:disabled")
        self.assertEqual(2, disabled.count())
        self.assertIn("未产生", page.text_content("#record-content"))
        self._screenshot(page, "06-four-stage-bodies.png")
        self._assert_clean_browser()

    def test_07_filters_narrow_and_reset(self):
        page = self._new_page()
        self._login(page)
        page.goto("/admin/requests")
        self._wait_items(page, 4)
        page.select_option("#filter-protocol", "claude-messages")
        page.click(".filter-apply")
        self._wait_items(page, 1)
        self.assertIn("claude-fixture", page.text_content("#request-list .request-item"))
        page.click("#filter-reset")
        self._wait_items(page, 4)
        page.select_option("#filter-status", "blocked")
        page.click(".filter-apply")
        self._wait_items(page, 1)
        self.assertEqual("被阻断", page.text_content("#request-list .status-pill"))
        page.click("#filter-reset")
        self._wait_items(page, 4)
        self._assert_clean_browser()

    def test_08_malicious_html_renders_as_text_without_execution(self):
        page = self._new_page()
        self._login(page)
        page.goto("/admin/requests")
        self._wait_items(page, 4)
        probe_id = None
        for item in self._context.request.get("/api/admin/requests").json()["items"]:
            detail = self._context.request.get("/api/admin/requests/" + item["request_id"]).json()
            if any("onerror" in (stage["body"] or "") for stage in detail["stages"]):
                probe_id = item["request_id"]
                break
        self.assertIsNotNone(probe_id, "Seeded HTML probe record missing")
        scripts_before = page.evaluate("() => document.getElementsByTagName('script').length")
        self._open_record(page, probe_id)
        self.assertTrue(page.evaluate("() => window.__history_html_executed === undefined"))
        self.assertEqual(0, page.evaluate("() => document.querySelectorAll('img[src=\"x\"]').length"))
        self.assertEqual(scripts_before,
                         page.evaluate("() => document.getElementsByTagName('script').length"))
        rendered = page.eval_on_selector_all(
            "#record-content .panel .text-content",
            "nodes => nodes.map(node => node.textContent).join('\\n')")
        self.assertIn('<img src=x onerror="window.__history_html_executed=true">', rendered)
        self.assertIn("<script>window.__history_html_executed=true</script>", rendered)
        self._screenshot(page, "08-html-probe-as-text.png")
        self._assert_clean_browser()

    def test_09_legit_actions_and_nonexistent_record_404_semantics(self):
        page = self._new_page()
        self._login(page)
        page.goto("/admin/requests")
        self._wait_items(page, 4)
        page.click("#refresh-history")
        self._wait_items(page, 4)
        missing = self._context.request.get("/api/admin/requests/" + str(uuid4()))
        self.assertEqual(404, missing.status)
        self.assertEqual("HISTORY_NOT_FOUND", missing.json()["error"]["code"])
        response = page.goto("/api/admin/requests/" + str(uuid4()))
        self.assertEqual(404, response.status)
        self.assertIn("HISTORY_NOT_FOUND", page.content())
        page.goto("/admin/requests")
        self._wait_items(page, 4)
        self._assert_clean_browser()

    def test_10_mobile_390px_layout_usable(self):
        page = self._new_page(viewport={"width": 390, "height": 844})
        page.goto("/login")
        page.wait_for_selector("#login-form", timeout=10000)
        self.assertLessEqual(page.evaluate("() => document.documentElement.scrollWidth"), 391)
        self._login(page)
        page.goto("/admin/requests")
        self._wait_items(page, 4)
        self.assertLessEqual(page.evaluate("() => document.documentElement.scrollWidth"), 391)
        self._wait_detail_ready(page)
        stacked = page.evaluate(
            "() => Array.from(document.querySelectorAll('#record-content .panel'))"
            ".map(panel => panel.getBoundingClientRect().y)")
        self.assertEqual(4, len(stacked))
        self.assertTrue(all(later > earlier for earlier, later in zip(stacked, stacked[1:])))
        self._screenshot(page, "10-mobile-390px.png")
        self._assert_clean_browser()

    def _wait_detail_ready(self, page) -> None:
        page.wait_for_selector("#record-content .panel", timeout=20000)
        page.wait_for_function(
            "() => document.querySelectorAll('#record-content .panel').length === 4", timeout=20000)


class AdminLoginThrottleBrowserTests(_BrowserTestBase):
    """Dedicated preview server: the per-source failure budget is exhausted here."""

    def test_repeated_failures_show_throttle_message(self):
        page = self._new_page()
        page.goto("/login")
        for attempt in range(5):
            page.fill("#login-username", "admin")
            page.fill("#login-password", WRONG_PASSWORD)
            page.click("#login-submit")
            page.wait_for_function(
                "() => document.querySelector('#login-error').hidden === false"
                " && document.querySelector('#login-error').textContent.length > 0")
            self.assertEqual("用户名或密码错误。", page.text_content("#login-error"))
            self.assertIn("/login", page.url)
        page.fill("#login-password", WRONG_PASSWORD)
        page.click("#login-submit")
        page.wait_for_function(
            "() => document.querySelector('#login-error').hidden === false"
            " && document.querySelector('#login-error').textContent.includes('频繁')")
        self.assertEqual("登录尝试过于频繁，请稍后重试。", page.text_content("#login-error"))
        self.assertIn("/login", page.url)
        with httpx.Client(base_url=self._server.base_url) as http:
            throttled = http.post("/api/admin/login", headers={"Origin": self._server.base_url},
                                  json={"username": "admin", "password": WRONG_PASSWORD})
            self.assertEqual(429, throttled.status_code)
            self.assertEqual("ADMIN_LOGIN_THROTTLED", throttled.json()["error"]["code"])
            even_correct = http.post("/api/admin/login", headers={"Origin": self._server.base_url},
                                     json={"username": "admin", "password": INITIAL_ADMIN_PASSWORD})
            self.assertEqual(429, even_correct.status_code)
        self._assert_clean_browser()


class AdminConsoleFullChainTests(unittest.TestCase):
    """TestClient full chain over the real runtime assembly and isolated PostgreSQL."""

    @classmethod
    def setUpClass(cls) -> None:
        if not PG_CONFIG.is_file():
            raise unittest.SkipTest("Explicit isolated history PostgreSQL configuration required")
        cls._pg_env = os.environ.get(PG_ENV)
        os.environ[PG_ENV] = str(PG_CONFIG)
        configuration()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls._pg_env is None:
            os.environ.pop(PG_ENV, None)
        else:
            os.environ[PG_ENV] = cls._pg_env

    def test_admin_console_full_chain_over_real_http_stack(self):
        with synthetic_history_runtime() as runtime, TestClient(runtime.app) as client:
            self.assertEqual(200, client.get("/readyz").status_code)
            refused = client.get("/api/admin/requests")
            self.assertEqual(401, refused.status_code)
            self.assertEqual("ADMIN_SESSION_INVALID", refused.json()["error"]["code"])
            for path in ("/history", "/history/assets/history.js", "/api/requests",
                         "/api/requests/" + str(uuid4())):
                with self.subTest(retired=path):
                    self.assertEqual(404, client.get(path).status_code)
            self.assertEqual(302, client.get("/admin", follow_redirects=False).status_code)
            self.assertEqual(200, client.get("/login").status_code)
            for index, (path, headers, payload) in enumerate(synthetic_requests(preview=True)):
                response = client.post(path, headers=headers, json=payload)
                if index < 3:
                    self.assertEqual(200, response.status_code)
                else:
                    self.assertGreaterEqual(response.status_code, 400)
            login = client.post("/api/admin/login", headers={"Origin": "http://testserver"},
                                json={"username": "admin", "password": INITIAL_ADMIN_PASSWORD})
            self.assertEqual(200, login.status_code)
            set_cookie = "\n".join(login.headers.get_list("set-cookie"))
            for attribute in ("admin_session=", "Path=/", "HttpOnly"):
                self.assertIn(attribute, set_cookie)
            self.assertIn("samesite=strict", set_cookie.lower())
            self.assertNotIn("domain=", set_cookie.lower())
            session = client.get("/api/admin/session")
            self.assertEqual(200, session.status_code)
            self.assertEqual("admin", session.json()["actor_id"])
            self.assertEqual({"actor_id", "scope", "authenticated_at", "idle_expires_at",
                              "absolute_expires_at", "csrf_token"}, set(session.json()))
            csrf = session.json()["csrf_token"]
            listing = client.get("/api/admin/requests")
            self.assertEqual(200, listing.status_code)
            items = listing.json()["items"]
            self.assertEqual(4, len(items))
            self.assertEqual(["blocked", "completed", "completed", "completed"],
                             sorted(item["status"] for item in items))
            probe_seen = blocked_seen = False
            for item in items:
                detail_response = client.get("/api/admin/requests/" + item["request_id"])
                self.assertEqual(200, detail_response.status_code)
                detail = detail_response.json()
                stages = {stage["stage"]: stage for stage in detail["stages"]}
                self.assertEqual({"input", "redacted", "upstream", "restored"}, set(stages))
                self.assertNotIn("synthetic-key", json.dumps(detail))
                if detail["status"] == "completed":
                    for stage in stages.values():
                        self.assertEqual("complete", stage["state"])
                        self.assertIsInstance(stage["body"], str)
                    if "onerror" in stages["restored"]["body"]:
                        probe_seen = True
                if detail["status"] == "blocked":
                    blocked_seen = True
                    self.assertEqual("not_produced", stages["redacted"]["state"])
                    self.assertEqual("not_produced", stages["upstream"]["state"])
                    self.assertIsNone(stages["upstream"]["body"])
                    self.assertIsInstance(stages["restored"]["body"], str)
            self.assertTrue(probe_seen, "Seeded HTML probe record missing")
            self.assertTrue(blocked_seen, "Seeded blocked record missing")
            self.assertEqual(1, len(client.get(
                "/api/admin/requests?protocol=claude-messages").json()["items"]))
            self.assertEqual(1, len(client.get(
                "/api/admin/requests?status=blocked").json()["items"]))
            self.assertEqual(2, len(client.get(
                "/api/admin/requests?model=chat-fixture&status=completed").json()["items"]))
            seen, cursor = set(), None
            while True:
                params = {"limit": 1}
                if cursor:
                    params["cursor"] = cursor
                page = client.get("/api/admin/requests", params=params).json()
                self.assertEqual(1, len(page["items"]))
                seen.add(page["items"][0]["request_id"])
                cursor = page["next_cursor"]
                if cursor is None:
                    break
            self.assertEqual(4, len(seen))
            missing = client.get("/api/admin/requests/" + str(uuid4()))
            self.assertEqual(404, missing.status_code)
            self.assertEqual("HISTORY_NOT_FOUND", missing.json()["error"]["code"])
            self.assertEqual(404, client.get("/api/admin/requests/not-a-uuid").status_code)
            token = client.cookies.get("admin_session")
            self.assertIsNotNone(token)
            logout = client.post("/api/admin/logout", headers={
                "Origin": "http://testserver", "X-Admin-CSRF": csrf})
            self.assertEqual(200, logout.status_code)
            self.assertEqual({"revoked": True}, logout.json())
            self.assertIn("Max-Age=0", "\n".join(logout.headers.get_list("set-cookie")))
            self.assertEqual(401, client.get("/api/admin/session").status_code)
            replay = client.get("/api/admin/session", headers={"Cookie": "admin_session=" + token})
            self.assertEqual(401, replay.status_code)
            self.assertEqual("ADMIN_SESSION_INVALID", replay.json()["error"]["code"])
            self.assertEqual(401, client.get("/api/admin/requests").status_code)


if __name__ == "__main__":
    unittest.main()
