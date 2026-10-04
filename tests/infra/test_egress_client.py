"""Bound egress client contract tests: timeouts, retries, and circuit breaker.

All verification is local: loopback spy servers on 127.0.0.1 ephemeral ports,
httpx.MockTransport spies, and injected resolver hooks. No real supplier,
no real DNS, no real proxy is ever contacted. The vendor credential is a
synthetic canary injected in code, never read from disk.

Note: each ``httpx.Client`` construction loads the platform trust store
(~1s on the review host), so clients and spy servers are shared per test
class instead of per test method; per-test isolation of recorded traffic is
preserved by clearing the spy log in ``setUp``.
"""

import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import httpx

from infra.egress_client import (
    EGRESS_HEADER_WHITELIST,
    BoundEgressClient,
    BoundUpstream,
)
from infra.errors import SafetyCode, SafetyError
from protocol.identity import FORBIDDEN_CLIENT_IDENTITY_HEADERS

FIXTURES = Path(__file__).parent / "fixtures" / "egress_client"

CREDENTIAL = "Bearer CNRY-p17-cred-4f2c91"
BODY_CANARY = "CNRY-P17-body-8d21"
LOOPBACK = "127.0.0.1"


def binding_template() -> dict:
    template = json.loads((FIXTURES / "channel_binding.json").read_text(encoding="utf-8"))
    template.pop("note", None)
    template.pop("host")
    return template


def request_body() -> bytes:
    return (FIXTURES / "chat_request.json").read_bytes()


def make_binding(port: int, **overrides) -> BoundUpstream:
    fields = binding_template()
    fields.update(overrides)
    return BoundUpstream(
        host=LOOPBACK,
        port=port,
        credential=CREDENTIAL,
        allowed_addresses=frozenset({LOOPBACK}),
        **fields,
    )


def loopback_resolver(host: str):
    return (LOOPBACK,)


class _SpyHandler(BaseHTTPRequestHandler):
    server_version = "P17Spy/1.0"

    def _dispatch(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        self.server.recorded.append(
            {
                "method": self.command,
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body,
            }
        )
        route = self.server.routes.get(self.path)
        if route is None:
            payload = b'{"error":"spy-no-route"}'
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        status, headers, payload = route
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _dispatch
    do_POST = _dispatch
    do_PUT = _dispatch

    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        pass


class _SpyServer(ThreadingHTTPServer):
    def __init__(self, routes: dict | None = None) -> None:
        super().__init__((LOOPBACK, 0), _SpyHandler)
        self.recorded = []
        self.routes = routes or {}

    @property
    def port(self) -> int:
        return self.server_address[1]

    def start(self) -> None:
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.shutdown()
        self.server_close()


def spy_server(routes: dict | None = None) -> _SpyServer:
    server = _SpyServer(routes)
    server.start()
    return server


class _CountingTransport(httpx.BaseTransport):
    def __init__(self) -> None:
        self.calls = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        return httpx.Response(200, json={"ok": True}, request=request)


class BoundUpstreamConfigTests(unittest.TestCase):
    def test_valid_config_normalizes_and_exposes_base_url(self):
        binding = BoundUpstream(
            channel_id="ch-1",
            scheme="HTTP",
            host="Example.LOCAL",
            port=8443,
            path_prefix="/v1",
            credential=CREDENTIAL,
            timeout_seconds=5,
            allowed_addresses=frozenset({"127.0.0.1", "::1"}),
        )
        self.assertEqual(binding.scheme, "http")
        self.assertEqual(binding.host, "example.local")
        self.assertEqual(binding.base_url, "http://example.local:8443")
        self.assertEqual(binding.timeout_seconds, 5.0)

    def test_invalid_config_fields_fail_closed(self):
        base = dict(
            channel_id="ch-1",
            scheme="http",
            host=LOOPBACK,
            port=8000,
            path_prefix="/v1",
            credential=CREDENTIAL,
            timeout_seconds=5.0,
            allowed_addresses=frozenset({LOOPBACK}),
        )
        bad = [
            ("channel_id", ""),
            ("scheme", "ftp"),
            ("scheme", "Http://x"),
            ("host", ""),
            ("host", "evil.example/x"),
            ("host", "user@evil.example"),
            ("host", "bad host"),
            ("port", 0),
            ("port", 65536),
            ("port", True),
            ("port", "8000"),
            ("path_prefix", "v1"),
            ("path_prefix", "/v1/../v2"),
            ("path_prefix", "http://x/v1"),
            ("credential", ""),
            ("credential", 123),
            ("timeout_seconds", 0),
            ("timeout_seconds", -1.5),
            ("timeout_seconds", float("inf")),
            ("timeout_seconds", True),
            ("allowed_addresses", frozenset()),
            ("allowed_addresses", frozenset({"not-an-ip"})),
            ("allowed_addresses", {"127.0.0.1"}),
            ("max_redirects", -1),
            ("max_redirects", 9),
            ("max_redirects", True),
        ]
        for field, value in bad:
            with self.subTest(field=field, value=value):
                kwargs = dict(base)
                kwargs[field] = value
                with self.assertRaises(SafetyError) as ctx:
                    BoundUpstream(**kwargs)
                self.assertEqual(ctx.exception.code, SafetyCode.INVALID_UPSTREAM)
                self.assertNotIn(CREDENTIAL, str(ctx.exception))

    def test_resolve_declares_bound_addresses(self):
        binding = BoundUpstream.resolve(
            channel_id="ch-1",
            scheme="http",
            host="supplier.local",
            port=8000,
            path_prefix="/v1",
            credential=None,
            timeout_seconds=5.0,
            resolver=lambda host: ("10.1.2.3", "10.1.2.4"),
        )
        self.assertEqual(binding.allowed_addresses, frozenset({"10.1.2.3", "10.1.2.4"}))

    def test_resolve_failure_or_empty_is_invalid_upstream(self):
        def failing(host: str):
            raise OSError("dns down")

        for resolver in (failing, lambda host: ()):
            with self.subTest(resolver=resolver):
                with self.assertRaises(SafetyError) as ctx:
                    BoundUpstream.resolve(
                        channel_id="ch-1",
                        scheme="http",
                        host="supplier.local",
                        port=8000,
                        path_prefix="/v1",
                        credential=None,
                        timeout_seconds=5.0,
                        resolver=resolver,
                    )
                self.assertEqual(ctx.exception.code, SafetyCode.INVALID_UPSTREAM)

    def test_resolve_default_uses_getaddrinfo(self):
        addrinfo = [(2, 1, 6, "", ("10.9.9.9", 0)), (2, 1, 6, "", ("10.9.9.9", 0))]
        with patch("socket.getaddrinfo", return_value=addrinfo):
            binding = BoundUpstream.resolve(
                channel_id="ch-1",
                scheme="http",
                host="supplier.local",
                port=8000,
                path_prefix="/v1",
                credential=None,
                timeout_seconds=5.0,
            )
        self.assertEqual(binding.allowed_addresses, frozenset({"10.9.9.9"}))


class BoundEgressClientPositiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = spy_server(
            {
                "/v1/chat/completions": (
                    200,
                    {"Content-Type": "application/json", "X-Spy": "p17"},
                    b'{"choices":[{"message":{"content":"p17-ok"}}]}',
                ),
                "/v1/start": (302, {"Location": "/v1/final"}, b""),
                "/v1/final": (200, {"Content-Type": "application/json"}, b'{"done":true}'),
                "/v1/abs": (
                    302,
                    {"Location": ""},  # rewritten per test once the port is known
                    b"",
                ),
                "/v1/hop-a": (307, {"Location": "/v1/hop-b"}, b""),
                "/v1/hop-b": (200, {}, b"ok"),
            }
        )
        cls.server.routes["/v1/abs"] = (
            302,
            {"Location": f"http://{LOOPBACK}:{cls.server.port}/v1/chat/completions"},
            b"",
        )
        cls.client = BoundEgressClient(
            make_binding(cls.server.port), resolver=loopback_resolver
        )
        cls.follow_client = BoundEgressClient(
            make_binding(cls.server.port, max_redirects=2), resolver=loopback_resolver
        )

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        cls.follow_client.close()
        cls.server.stop()

    def setUp(self):
        self.server.recorded.clear()

    def test_request_reaches_bound_target_and_response_passthrough(self):
        response = self.client.request(
            "POST",
            "/v1/chat/completions",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            content=request_body(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            json.loads(response.content),
            {"choices": [{"message": {"content": "p17-ok"}}]},
        )
        self.assertEqual(response.headers["x-spy"], "p17")
        self.assertEqual(len(self.server.recorded), 1)
        seen = self.server.recorded[0]
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["path"], "/v1/chat/completions")
        self.assertEqual(seen["body"], request_body())
        self.assertEqual(seen["headers"]["authorization"], CREDENTIAL)
        self.assertEqual(seen["headers"]["content-type"], "application/json")
        self.assertIn(seen["headers"]["host"], {LOOPBACK, f"{LOOPBACK}:{self.server.port}"})

    def test_injected_transport_sees_only_bound_target(self):
        seen_urls = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_urls.append(str(request.url))
            return httpx.Response(200, json={"ok": True}, request=request)

        transport = httpx.MockTransport(handler)
        client = BoundEgressClient(
            make_binding(self.server.port), transport=transport, resolver=loopback_resolver
        )
        try:
            response = client.request("POST", "/v1/chat/completions", content=b"{}")
        finally:
            client.close()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            seen_urls, [f"http://{LOOPBACK}:{self.server.port}/v1/chat/completions"]
        )
        self.assertEqual(len(self.server.recorded), 0)

    def test_prefix_boundary_paths_are_admitted(self):
        root = self.client.request("POST", "/v1", content=b"{}")
        nested = self.client.request("POST", "/v1/chat/completions", content=b"{}")
        self.assertEqual(root.status_code, 404)  # reached the spy; route simply missing
        self.assertEqual(nested.status_code, 200)
        self.assertEqual(
            [r["path"] for r in self.server.recorded], ["/v1", "/v1/chat/completions"]
        )

    def test_relative_redirect_within_binding_is_followed(self):
        response = self.follow_client.request(
            "POST", "/v1/start", content=BODY_CANARY.encode()
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content), {"done": True})
        self.assertEqual([r["path"] for r in self.server.recorded], ["/v1/start", "/v1/final"])
        self.assertEqual(self.server.recorded[1]["body"], BODY_CANARY.encode())

    def test_absolute_redirect_within_binding_is_followed(self):
        response = self.follow_client.request("POST", "/v1/abs", content=b"{}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [r["path"] for r in self.server.recorded],
            ["/v1/abs", "/v1/chat/completions"],
        )

    def test_credential_travels_with_every_same_binding_hop(self):
        self.follow_client.request("POST", "/v1/hop-a", content=b"{}")
        self.assertEqual(len(self.server.recorded), 2)
        for seen in self.server.recorded:
            self.assertEqual(seen["path"] in ("/v1/hop-a", "/v1/hop-b"), True)
            self.assertEqual(seen["headers"]["authorization"], CREDENTIAL)


class BoundEgressClientGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = spy_server(
            {
                "/v1/chat/completions": (200, {}, b"ok"),
                "/v1/loop-a": (302, {"Location": "/v1/loop-b"}, b""),
                "/v1/loop-b": (302, {"Location": "/v1/loop-a"}, b""),
                "/v1/escape": (302, {"Location": "/public/status"}, b""),
                "/v1/offhost": (302, {"Location": "http://other.supplier.example/v1/x"}, b""),
                "/v1/userinfo": (302, {"Location": "http://user:pw@127.0.0.1/v1/x"}, b""),
            }
        )
        cls.client = BoundEgressClient(
            make_binding(cls.server.port), resolver=loopback_resolver
        )
        cls.follow_client = BoundEgressClient(
            make_binding(cls.server.port, max_redirects=3), resolver=loopback_resolver
        )

    @classmethod
    def tearDownClass(cls):
        cls.client.close()
        cls.follow_client.close()
        cls.server.stop()

    def setUp(self):
        self.server.recorded.clear()

    def assert_violation(self, ctx, code=SafetyCode.UPSTREAM_BINDING_VIOLATION):
        self.assertEqual(ctx.exception.code, code)
        message = str(ctx.exception)
        self.assertNotIn(CREDENTIAL, message)
        self.assertNotIn(BODY_CANARY, message)

    def test_absolute_url_is_rejected_before_any_connection(self):
        with self.assertRaises(SafetyError) as ctx:
            self.client.request("POST", "http://evil.example/v1/chat/completions", content=b"{}")
        self.assert_violation(ctx)
        self.assertEqual(self.server.recorded, [])

    def test_scheme_relative_smuggling_is_rejected(self):
        with self.assertRaises(SafetyError) as ctx:
            self.client.request("POST", "//evil.example/v1", content=b"{}")
        self.assert_violation(ctx)
        self.assertEqual(self.server.recorded, [])

    def test_path_outside_bound_prefix_is_rejected(self):
        for path in ("/v2/x", "/v10/x", "/v1/../v2", "/public"):
            with self.subTest(path=path):
                with self.assertRaises(SafetyError) as ctx:
                    self.client.request("POST", path, content=b"{}")
                self.assert_violation(ctx)
        self.assertEqual(self.server.recorded, [])

    def test_internal_headers_are_never_sent(self):
        internal = {name: f"CNRY-{name}" for name in sorted(FORBIDDEN_CLIENT_IDENTITY_HEADERS)}
        headers = {
            **internal,
            "X-Debug-Internal": "CNRY-debug",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.client.request("POST", "/v1/chat/completions", headers=headers, content=b"{}")
        self.assertEqual(len(self.server.recorded), 1)
        sent = self.server.recorded[0]["headers"]
        for name in internal:
            self.assertNotIn(name, sent)
        self.assertNotIn("x-debug-internal", sent)
        self.assertEqual(sent["content-type"], "application/json")
        self.assertEqual(sent["accept"], "application/json")

    def test_whitelist_covers_all_internal_header_names(self):
        self.assertTrue(FORBIDDEN_CLIENT_IDENTITY_HEADERS.isdisjoint(EGRESS_HEADER_WHITELIST))

    def test_caller_authorization_is_replaced_by_injected_credential(self):
        self.client.request(
            "POST",
            "/v1/chat/completions",
            headers={"Authorization": "Bearer CNRY-caller-rogue-1"},
            content=b"{}",
        )
        sent = self.server.recorded[0]["headers"]
        self.assertEqual(sent["authorization"], CREDENTIAL)
        self.assertNotIn("CNRY-caller-rogue-1", json.dumps(sent))

    def test_caller_x_api_key_is_stripped_and_anthropic_injected(self):
        anthropic_binding = BoundUpstream(
            channel_id="anthropic-channel",
            scheme="http",
            host=LOOPBACK,
            port=self.server.port,
            path_prefix="/v1",
            credential="sk-ant-test-key-12345",
            timeout_seconds=5.0,
            allowed_addresses=frozenset([LOOPBACK]),
            package_version="1.2.3",
        )
        client = BoundEgressClient(anthropic_binding, resolver=loopback_resolver)
        try:
            client.request(
                "POST",
                "/v1/messages",
                headers={
                    "x-api-key": "caller-secret-key-rogue",
                    "Authorization": "Bearer caller-auth",
                },
                content=b"{}",
            )
            sent = self.server.recorded[-1]["headers"]
            self.assertEqual(sent["x-api-key"], "sk-ant-test-key-12345")
            self.assertEqual(sent["anthropic-version"], "2023-06-01")
            self.assertEqual(sent["x-protection-package-version"], "1.2.3")
            self.assertNotIn("authorization", sent)
            self.assertNotIn("caller-secret-key-rogue", json.dumps(sent))
        finally:
            client.close()

    def test_caller_headers_must_be_a_mapping(self):
        with self.assertRaises(TypeError):
            self.client.request("POST", "/v1/chat/completions", headers=["x-a", "1"])
        self.assertEqual(self.server.recorded, [])

    def test_request_signature_accepts_no_url_or_metadata_overrides(self):
        # The contract admits no caller-supplied URL/host/metadata channel at
        # all: such keyword arguments do not exist in the signature.
        with self.assertRaises(TypeError):
            self.client.request("POST", "/v1/chat/completions", url="http://evil.example/")
        with self.assertRaises(TypeError):
            self.client.request("POST", "/v1/chat/completions", metadata={"trace_id": "x"})
        self.assertEqual(self.server.recorded, [])

    def test_redirect_preserves_query_string(self):
        self.server.routes["/v1/qstart"] = (302, {"Location": "/v1/landing?tok=abc"}, b"")
        self.server.routes["/v1/landing?tok=abc"] = (200, {}, b"q-ok")
        response = self.follow_client.request("GET", "/v1/qstart")
        self.assertEqual(response.content, b"q-ok")
        self.assertEqual(
            [r["path"] for r in self.server.recorded], ["/v1/qstart", "/v1/landing?tok=abc"]
        )

    def test_303_redirect_converts_post_to_get_and_drops_body(self):
        self.server.routes["/v1/s303"] = (303, {"Location": "/v1/after303"}, b"")
        self.server.routes["/v1/after303"] = (200, {}, b"after")
        response = self.follow_client.request("POST", "/v1/s303", content=b"payload")
        self.assertEqual(response.content, b"after")
        hops = self.server.recorded
        self.assertEqual([r["method"] for r in hops], ["POST", "GET"])
        self.assertEqual(hops[1]["body"], b"")

    def test_caller_host_header_is_not_forwarded(self):
        self.client.request(
            "POST",
            "/v1/chat/completions",
            headers={"Host": "spoofed.internal"},
            content=b"{}",
        )
        seen = self.server.recorded[0]["headers"]
        self.assertNotEqual(seen["host"], "spoofed.internal")
        self.assertEqual(seen["host"], f"{LOOPBACK}:{self.server.port}")

    def test_default_policy_does_not_follow_redirects(self):
        response = self.client.request("POST", "/v1/escape", content=b"{}")
        self.assertEqual(response.status_code, 302)
        self.assertEqual([r["path"] for r in self.server.recorded], ["/v1/escape"])

    def test_redirect_outside_prefix_is_refused(self):
        with self.assertRaises(SafetyError) as ctx:
            self.follow_client.request("POST", "/v1/escape", content=b"{}")
        self.assert_violation(ctx)
        self.assertEqual([r["path"] for r in self.server.recorded], ["/v1/escape"])

    def test_redirect_to_other_port_is_refused_and_foreign_spy_sees_nothing(self):
        foreign = spy_server({"/v1/x": (200, {}, b"stolen")})
        try:
            self.server.routes["/v1/offport"] = (
                302,
                {"Location": f"http://{LOOPBACK}:{foreign.port}/v1/x"},
                b"",
            )
            with self.assertRaises(SafetyError) as ctx:
                self.follow_client.request("POST", "/v1/offport", content=BODY_CANARY.encode())
            self.assert_violation(ctx)
            self.assertEqual(foreign.recorded, [])
            self.assertEqual([r["path"] for r in self.server.recorded], ["/v1/offport"])
        finally:
            del self.server.routes["/v1/offport"]
            foreign.stop()

    def test_redirect_to_other_hostname_is_refused(self):
        with self.assertRaises(SafetyError) as ctx:
            self.follow_client.request("POST", "/v1/offhost", content=b"{}")
        self.assert_violation(ctx)
        self.assertEqual([r["path"] for r in self.server.recorded], ["/v1/offhost"])

    def test_redirect_with_userinfo_is_refused(self):
        with self.assertRaises(SafetyError) as ctx:
            self.follow_client.request("POST", "/v1/userinfo", content=b"{}")
        self.assert_violation(ctx)
        self.assertEqual([r["path"] for r in self.server.recorded], ["/v1/userinfo"])

    def test_redirect_loop_exhausts_budget_with_controlled_failure(self):
        with self.assertRaises(SafetyError) as ctx:
            self.follow_client.request("POST", "/v1/loop-a", content=BODY_CANARY.encode())
        self.assert_violation(ctx)
        self.assertEqual(len(self.server.recorded), 4)  # initial + 3 followed hops
        self.assertNotIn(CREDENTIAL, str(ctx.exception))

    def test_proxy_environment_variables_are_ignored(self):
        dead_proxy = f"http://{LOOPBACK}:1"
        env = {
            "HTTP_PROXY": dead_proxy,
            "http_proxy": dead_proxy,
            "HTTPS_PROXY": dead_proxy,
            "https_proxy": dead_proxy,
            "ALL_PROXY": dead_proxy,
            "all_proxy": dead_proxy,
        }
        with patch.dict(os.environ, env):
            response = self.client.request("POST", "/v1/chat/completions", content=b"{}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.server.recorded), 1)
        self.assertEqual(self.server.recorded[0]["headers"].get("authorization"), CREDENTIAL)

    def test_dns_answer_outside_declared_set_is_rejected(self):
        transport = _CountingTransport()

        def foreign(host: str):
            return ("203.0.113.99",)

        client = BoundEgressClient(
            make_binding(self.server.port), transport=transport, resolver=foreign
        )
        try:
            with self.assertRaises(SafetyError) as ctx:
                client.request("POST", "/v1/chat/completions", content=BODY_CANARY.encode())
        finally:
            client.close()
        self.assert_violation(ctx, SafetyCode.INVALID_UPSTREAM)
        self.assertEqual(transport.calls, 0)
        self.assertEqual(self.server.recorded, [])

    def test_dns_partial_mismatch_is_rejected(self):
        transport = _CountingTransport()

        def mixed(host: str):
            return (LOOPBACK, "198.51.100.7")

        client = BoundEgressClient(
            make_binding(self.server.port), transport=transport, resolver=mixed
        )
        try:
            with self.assertRaises(SafetyError) as ctx:
                client.request("POST", "/v1/chat/completions", content=b"{}")
        finally:
            client.close()
        self.assert_violation(ctx, SafetyCode.INVALID_UPSTREAM)
        self.assertEqual(transport.calls, 0)
        self.assertEqual(self.server.recorded, [])

    def test_dns_failure_is_invalid_upstream(self):
        transport = _CountingTransport()

        def failing(host: str):
            raise OSError("resolver down")

        client = BoundEgressClient(
            make_binding(self.server.port), transport=transport, resolver=failing
        )
        try:
            with self.assertRaises(SafetyError) as ctx:
                client.request("POST", "/v1/chat/completions", content=b"{}")
        finally:
            client.close()
        self.assert_violation(ctx, SafetyCode.INVALID_UPSTREAM)
        self.assertEqual(transport.calls, 0)
        self.assertEqual(self.server.recorded, [])


if __name__ == "__main__":
    unittest.main()
