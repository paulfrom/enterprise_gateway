"""Real backend login/history integration; React browser tests live in admin-web/e2e."""
import json
import unittest
from uuid import uuid4
from scripts.prepare_admin_state import INITIAL_ADMIN_PASSWORD
from tests.request_history.pg_support import configuration
from tests.request_history.test_local_e2e import synthetic_history_runtime, synthetic_requests
from starlette.testclient import TestClient
class AdminConsoleFullChainTests(unittest.TestCase):
    """TestClient full chain over the real runtime assembly and shared PostgreSQL."""

    @classmethod
    def setUpClass(cls):
        # Missing explicit configuration is a gate failure, never a skip.
        configuration()

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
            self.assertEqual(404, client.get("/admin", follow_redirects=False).status_code)
            self.assertEqual(404, client.get("/login").status_code)
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
