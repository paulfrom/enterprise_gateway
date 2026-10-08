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


class ByokCredentialGuardTests(unittest.TestCase):
    def test_ipv6_literal_remains_bound_across_relative_redirect(self):
        seen = []
        binding = BoundUpstream(channel_id="ipv6", scheme="http", host="::1",
            port=8080, path_prefix="/v1", timeout_seconds=5,
            max_redirects=1, allowed_addresses=frozenset({"::1"}))
        def respond(request):
            seen.append(str(request.url))
            if request.url.path == "/v1/start":
                return httpx.Response(307, headers={"location": "/v1/final"})
            return httpx.Response(200)
        with BoundEgressClient(binding, transport=httpx.MockTransport(respond), resolver=lambda _: ("::1",)) as client:
            response = client.request("POST", "/v1/start", headers={"Authorization": CREDENTIAL})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(seen, ["http://[::1]:8080/v1/start", "http://[::1]:8080/v1/final"])

    def test_conversion_is_per_request_and_version_header_has_one_case(self):
        for credential_header in ("authorization", "x-api-key"):
            seen = []
            binding = BoundUpstream(channel_id="byok", scheme="https", host="supplier.example",
                port=443, path_prefix="/v1", timeout_seconds=5,
                credential_header=credential_header, allowed_addresses=frozenset({LOOPBACK}))
            def respond(request):
                seen.append(request)
                return httpx.Response(200, content=b"ok")
            with BoundEgressClient(binding, transport=httpx.MockTransport(respond), resolver=loopback_resolver) as client:
                client.request("POST", "/v1/chat/completions", headers={"Authorization": "Bearer synthetic-one"})
                stream = client.open_stream("POST", "/v1/chat/completions",
                    headers={"x-api-key": "synthetic-two", "Anthropic-Version": "2023-06-01"})
                stream.read()
                stream.close()
            for index, key in enumerate(("synthetic-one", "synthetic-two")):
                headers = seen[index].headers
                expected = key if credential_header == "x-api-key" else f"Bearer {key}"
                self.assertEqual(headers[credential_header], expected)
                other = "authorization" if credential_header == "x-api-key" else "x-api-key"
                self.assertNotIn(other, headers)
                if credential_header == "x-api-key":
                    versions = [value for name, value in headers.multi_items() if name == "anthropic-version"]
                    self.assertEqual(versions, ["2023-06-01"])

    def test_invalid_byok_never_calls_transport(self):
        transport = _CountingTransport()
        binding = BoundUpstream(channel_id="byok", scheme="https", host="supplier.example",
            port=443, path_prefix="/v1", timeout_seconds=5,
            allowed_addresses=frozenset({LOOPBACK}))
        with BoundEgressClient(binding, transport=transport, resolver=loopback_resolver) as client:
            bad = [None, {}, {"authorization": ""}, {"x-api-key": ""},
                   {"authorization": "Basic synthetic-key"}, {"authorization": "Bearer "},
                   {"authorization": "Bearer key with space"}, {"x-api-key": "key\r\nsecret"},
                   {"authorization": "Bearer key", "x-api-key": "other"},
                   {"authorization": "Bearer key", "Authorization": "Bearer key"}]
            for headers in bad:
                for send in (client.request, client.open_stream):
                    with self.subTest(headers=headers, send=send.__name__):
                        with self.assertRaises(SafetyError):
                            send("POST", "/v1/chat/completions", headers=headers, content=b"{}")
            self.assertEqual(transport.calls, 0)


class BoundUpstreamConfigTests(unittest.TestCase):
    def test_https_rejects_untrusted_or_wrong_host_certificate_without_http_retry(self):
        import ssl
        import tempfile
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        with tempfile.TemporaryDirectory() as directory:
            certfile, keyfile = Path(directory) / "cert.pem", Path(directory) / "key.pem"
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
                    .sign(key, hashes.SHA256()))
            certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile, keyfile)
            server = _SpyServer({"/v1/chat/completions": (200, {}, b"ok")})
            server.socket = context.wrap_socket(server.socket, server_side=True)
            server.start()
            try:
                binding = BoundUpstream(channel_id="tls", scheme="https", host=LOOPBACK,
                    port=server.port, path_prefix="/v1", timeout_seconds=5,
                    allowed_addresses=frozenset({LOOPBACK}))
                # Default httpx trust rejects an untrusted issuer; explicit trust still
                # rejects the certificate's localhost SAN for a 127.0.0.1 target.
                for transport in (None, httpx.HTTPTransport(verify=ssl.create_default_context(cafile=certfile))):
                    with BoundEgressClient(binding, transport=transport, resolver=loopback_resolver) as client:
                        for send in (client.request, client.open_stream):
                            with self.assertRaises(SafetyError) as rejected:
                                send("POST", "/v1/chat/completions",
                                     headers={"Authorization": CREDENTIAL}, content=BODY_CANARY.encode())
                            self.assertEqual(SafetyCode.INVALID_UPSTREAM, rejected.exception.code)
                            self.assertNotIn(CREDENTIAL, str(rejected.exception))
                            self.assertEqual("https", client.binding.scheme)
                self.assertEqual([], server.recorded)
            finally:
                server.stop()

    def test_nonloopback_http_binding_constructs_and_sends_with_byok(self):
        for host, addresses in (("supplier.example", frozenset({"203.0.113.1"})),
                                ("supplier.example", frozenset({LOOPBACK})),
                                ("203.0.113.1", frozenset({"203.0.113.1"})),
                                ("10.0.0.1", frozenset({"10.0.0.1"})),
                                ("192.168.1.1", frozenset({"192.168.1.1"})),
                                ("fd00::1", frozenset({"fd00::1"})),
                                ("localhost", frozenset({LOOPBACK, "10.0.0.1"})),
                                (LOOPBACK, frozenset({"10.0.0.1"}))):
            for header, path in (("authorization", "/v1/chat/completions"),
                                 ("x-api-key", "/v1/messages")):
                with self.subTest(host=host, addresses=addresses, header=header):
                    seen = []
                    def respond(request):
                        seen.append(request)
                        return httpx.Response(200, content=b"protected-response")
                    binding = BoundUpstream(channel_id="plaintext", scheme="http", host=host, port=80,
                        path_prefix="/v1", timeout_seconds=5, allowed_addresses=addresses,
                        credential_header=header)
                    with BoundEgressClient(binding, transport=httpx.MockTransport(respond),
                                           resolver=lambda _: addresses) as client:
                        response = client.request("POST", path,
                            headers={"Authorization": CREDENTIAL}, content=b"protected-body")
                        self.assertEqual(200, response.status_code)
                        stream = client.open_stream("POST", path,
                            headers={"x-api-key": "CNRY-stream-key"}, content=b"protected-stream-body")
                        self.assertEqual(b"protected-response", stream.read())
                        stream.close()
                    self.assertEqual(2, len(seen))
                    for request, key, body in zip(seen, (CREDENTIAL[7:], "CNRY-stream-key"),
                                                 (b"protected-body", b"protected-stream-body")):
                        self.assertEqual("http", request.url.scheme)
                        self.assertEqual(host, request.url.host)
                        self.assertEqual(path, request.url.path)
                        self.assertEqual(80, request.url.port or 80)
                        self.assertEqual(body, request.content)
                        self.assertEqual(key if header == "x-api-key" else f"Bearer {key}",
                                         request.headers[header])
                        other = "authorization" if header == "x-api-key" else "x-api-key"
                        self.assertNotIn(other, request.headers)

    def test_http_resolve_binds_all_declared_addresses(self):
        for addresses in (("127.0.0.1", "::1"), ("127.0.0.1", "10.0.0.1")):
            binding = BoundUpstream.resolve(channel_id="local", scheme="http", host="localhost",
                port=1234, path_prefix="/v1", timeout_seconds=5,
                resolver=lambda _: addresses)
            self.assertEqual(binding.scheme, "http")
            self.assertEqual(frozenset(addresses), binding.allowed_addresses)

    def test_nonloopback_http_does_not_bypass_dns_or_scheme_binding(self):
        for scheme, port in (("http", 80), ("https", 443)):
            for mismatch in ("dns", "scheme"):
                with self.subTest(scheme=scheme, mismatch=mismatch):
                    seen = []
                    def respond(request):
                        seen.append(request)
                        target_scheme = "https" if scheme == "http" else "http"
                        return httpx.Response(307, headers={"location":
                            f"{target_scheme}://supplier.example:{port}/v1/landing"})
                    binding = BoundUpstream(channel_id="fixed", scheme=scheme,
                        host="supplier.example", port=port, path_prefix="/v1",
                        timeout_seconds=5, max_redirects=1,
                        allowed_addresses=frozenset({"10.0.0.1"}))
                    addresses = ("10.0.0.2",) if mismatch == "dns" else ("10.0.0.1",)
                    with BoundEgressClient(binding, transport=httpx.MockTransport(respond),
                                           resolver=lambda _: addresses) as client:
                        for send in (client.request, client.open_stream) if mismatch == "dns" else (client.request,):
                            with self.assertRaises(SafetyError) as rejected:
                                send("POST", "/v1/start", headers={"Authorization": CREDENTIAL})
                            expected = SafetyCode.INVALID_UPSTREAM if mismatch == "dns" else SafetyCode.UPSTREAM_BINDING_VIOLATION
                            self.assertEqual(expected, rejected.exception.code)
                    self.assertEqual(0 if mismatch == "dns" else 1, len(seen))

    def test_redirect_with_explicit_zero_port_is_not_treated_as_default(self):
        for scheme, port in (("https", 443), ("http", 80)):
            with self.subTest(scheme=scheme):
                host = LOOPBACK if scheme == "http" else "supplier.example"
                seen = []
                def respond(request):
                    seen.append(request)
                    return httpx.Response(302, headers={"location":
                        f"{scheme}://{host}:0/v1/landing"})
                binding = BoundUpstream(channel_id="redirect-port", scheme=scheme,
                    host=host, port=port, path_prefix="/v1",
                    timeout_seconds=5, max_redirects=1,

                    allowed_addresses=frozenset({LOOPBACK}))
                with BoundEgressClient(binding, transport=httpx.MockTransport(respond),
                                       resolver=loopback_resolver) as client:
                    with self.assertRaises(SafetyError):
                        client.request("GET", "/v1/start", headers={"Authorization": CREDENTIAL})
                    self.assertEqual(1, len(seen))

    def test_default_ports_are_valid_origins_and_other_ports_are_blocked(self):
        for scheme, port in (("https", 443), ("http", 80)):
            with self.subTest(scheme=scheme):
                host = LOOPBACK if scheme == "http" else "supplier.example"
                seen = []
                def respond(request):
                    seen.append(request)
                    return httpx.Response(200, content=b"protected-response")
                binding = BoundUpstream(channel_id="default-port", scheme=scheme,
                    host=host, port=port, path_prefix="/v1",
                    timeout_seconds=5,

                    allowed_addresses=frozenset({LOOPBACK}))
                with BoundEgressClient(binding, transport=httpx.MockTransport(respond),
                                       resolver=loopback_resolver) as client:
                    self.assertEqual(200, client.request("POST", "/v1/chat/completions", headers={"Authorization": CREDENTIAL}).status_code)
                    response = client.open_stream("POST", "/v1/chat/completions", headers={"Authorization": CREDENTIAL})
                    self.assertEqual(b"protected-response", response.read())
                    response.close()
                    self.assertEqual(2, len(seen))
                    for wrong_port in (0, 8443):
                        with self.assertRaises(SafetyError) as rejected:
                            client._client.get(f"{scheme}://{host}:{wrong_port}/v1/chat/completions")
                        self.assertEqual(SafetyCode.UPSTREAM_BINDING_VIOLATION, rejected.exception.code)
                        self.assertEqual(2, len(seen))

    def test_binding_diagnostic_repr_keeps_credential_private(self):
        binding = make_binding(8443)
        self.assertNotIn(CREDENTIAL, repr(binding))
        self.assertNotIn(CREDENTIAL, str(binding))
        self.assertIn(binding.channel_id, repr(binding))
        self.assertFalse(hasattr(binding, "credential"))

    def test_valid_config_normalizes_and_exposes_base_url(self):
        binding = BoundUpstream(
            channel_id="ch-1",
            scheme="HTTPS",
            host="Example.LOCAL",
            port=8443,
            path_prefix="/v1",

            timeout_seconds=5,
            allowed_addresses=frozenset({"127.0.0.1", "::1"}),
        )
        self.assertEqual(binding.scheme, "https")
        self.assertEqual(binding.host, "example.local")
        self.assertEqual(binding.base_url, "https://example.local:8443")
        self.assertEqual(binding.timeout_seconds, 5.0)

    def test_invalid_config_fields_fail_closed(self):
        base = dict(
            channel_id="ch-1",
            scheme="http",
            host=LOOPBACK,
            port=8000,
            path_prefix="/v1",

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
            scheme="https",
            host="supplier.local",
            port=8000,
            path_prefix="/v1",

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
                        scheme="https",
                        host="supplier.local",
                        port=8000,
                        path_prefix="/v1",

                        timeout_seconds=5.0,
                        resolver=resolver,
                    )
                self.assertEqual(ctx.exception.code, SafetyCode.INVALID_UPSTREAM)

    def test_resolve_default_uses_getaddrinfo(self):
        addrinfo = [(2, 1, 6, "", ("10.9.9.9", 0)), (2, 1, 6, "", ("10.9.9.9", 0))]
        with patch("socket.getaddrinfo", return_value=addrinfo):
            binding = BoundUpstream.resolve(
                channel_id="ch-1",
                scheme="https",
                host="supplier.local",
                port=8000,
                path_prefix="/v1",

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
            headers={"Authorization": CREDENTIAL, "Content-Type": "application/json", "Accept": "application/json"},
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
            response = client.request("POST", "/v1/chat/completions", content=b"{}", headers={"Authorization": CREDENTIAL})
        finally:
            client.close()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            seen_urls, [f"http://{LOOPBACK}:{self.server.port}/v1/chat/completions"]
        )
        self.assertEqual(len(self.server.recorded), 0)

    def test_prefix_boundary_paths_are_admitted(self):
        root = self.client.request("POST", "/v1", content=b"{}", headers={"Authorization": CREDENTIAL})
        nested = self.client.request("POST", "/v1/chat/completions", content=b"{}", headers={"Authorization": CREDENTIAL})
        self.assertEqual(root.status_code, 404)  # reached the spy; route simply missing
        self.assertEqual(nested.status_code, 200)
        self.assertEqual(
            [r["path"] for r in self.server.recorded], ["/v1", "/v1/chat/completions"]
        )

    def test_relative_redirect_within_binding_is_followed(self):
        response = self.follow_client.request(
            "POST", "/v1/start", content=BODY_CANARY.encode()
        , headers={"Authorization": CREDENTIAL})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.content), {"done": True})
        self.assertEqual([r["path"] for r in self.server.recorded], ["/v1/start", "/v1/final"])
        self.assertEqual(self.server.recorded[1]["body"], BODY_CANARY.encode())

    def test_absolute_redirect_within_binding_is_followed(self):
        response = self.follow_client.request("POST", "/v1/abs", content=b"{}", headers={"Authorization": CREDENTIAL})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [r["path"] for r in self.server.recorded],
            ["/v1/abs", "/v1/chat/completions"],
        )

    def test_credential_travels_with_every_same_binding_hop(self):
        self.follow_client.request("POST", "/v1/hop-a", content=b"{}", headers={"Authorization": CREDENTIAL})
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
            self.client.request("POST", "http://evil.example/v1/chat/completions", content=b"{}", headers={"Authorization": CREDENTIAL})
        self.assert_violation(ctx)
        self.assertEqual(self.server.recorded, [])

    def test_scheme_relative_smuggling_is_rejected(self):
        with self.assertRaises(SafetyError) as ctx:
            self.client.request("POST", "//evil.example/v1", content=b"{}", headers={"Authorization": CREDENTIAL})
        self.assert_violation(ctx)
        self.assertEqual(self.server.recorded, [])

    def test_path_outside_bound_prefix_is_rejected(self):
        for path in ("/v2/x", "/v10/x", "/v1/../v2", "/public"):
            with self.subTest(path=path):
                with self.assertRaises(SafetyError) as ctx:
                    self.client.request("POST", path, content=b"{}", headers={"Authorization": CREDENTIAL})
                self.assert_violation(ctx)
        self.assertEqual(self.server.recorded, [])

    def test_internal_headers_are_never_sent(self):
        internal = {name: f"CNRY-{name}" for name in sorted(FORBIDDEN_CLIENT_IDENTITY_HEADERS)}
        headers = {
            **internal,
            "Authorization": CREDENTIAL,
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

    def test_each_request_uses_its_own_byok(self):
        self.client.request(
            "POST",
            "/v1/chat/completions",
            headers={"Authorization": "Bearer CNRY-caller-rogue-1"},
            content=b"{}",
        )
        sent = self.server.recorded[0]["headers"]
        self.assertEqual(sent["authorization"], "Bearer CNRY-caller-rogue-1")

    def test_claude_uses_caller_byok_and_one_version_header(self):
        anthropic_binding = BoundUpstream(
            channel_id="anthropic-channel",
            scheme="http",
            host=LOOPBACK,
            port=self.server.port,
            path_prefix="/v1",

            credential_header="x-api-key",
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
                    "Anthropic-Version": "2023-06-01",
                },
                content=b"{}",
            )
            sent = self.server.recorded[-1]["headers"]
            self.assertEqual(sent["x-api-key"], "caller-secret-key-rogue")
            self.assertEqual(sent["anthropic-version"], "2023-06-01")
            self.assertEqual(sent["x-protection-package-version"], "1.2.3")
            self.assertNotIn("authorization", sent)
            self.assertEqual(len([name for name in sent if name.lower() == "anthropic-version"]), 1)
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
            self.client.request("POST", "/v1/chat/completions", url="http://evil.example/", headers={"Authorization": CREDENTIAL})
        with self.assertRaises(TypeError):
            self.client.request("POST", "/v1/chat/completions", metadata={"trace_id": "x"}, headers={"Authorization": CREDENTIAL})
        self.assertEqual(self.server.recorded, [])

    def test_redirect_preserves_query_string(self):
        self.server.routes["/v1/qstart"] = (302, {"Location": "/v1/landing?tok=abc"}, b"")
        self.server.routes["/v1/landing?tok=abc"] = (200, {}, b"q-ok")
        response = self.follow_client.request("GET", "/v1/qstart", headers={"Authorization": CREDENTIAL})
        self.assertEqual(response.content, b"q-ok")
        self.assertEqual(
            [r["path"] for r in self.server.recorded], ["/v1/qstart", "/v1/landing?tok=abc"]
        )

    def test_303_redirect_converts_post_to_get_and_drops_body(self):
        self.server.routes["/v1/s303"] = (303, {"Location": "/v1/after303"}, b"")
        self.server.routes["/v1/after303"] = (200, {}, b"after")
        response = self.follow_client.request("POST", "/v1/s303", content=b"payload", headers={"Authorization": CREDENTIAL})
        self.assertEqual(response.content, b"after")
        hops = self.server.recorded
        self.assertEqual([r["method"] for r in hops], ["POST", "GET"])
        self.assertEqual(hops[1]["body"], b"")

    def test_caller_host_header_is_not_forwarded(self):
        self.client.request(
            "POST",
            "/v1/chat/completions",
            headers={"Authorization": CREDENTIAL, "Host": "spoofed.internal"},
            content=b"{}",
        )
        seen = self.server.recorded[0]["headers"]
        self.assertNotEqual(seen["host"], "spoofed.internal")
        self.assertEqual(seen["host"], f"{LOOPBACK}:{self.server.port}")

    def test_default_policy_does_not_follow_redirects(self):
        response = self.client.request("POST", "/v1/escape", content=b"{}", headers={"Authorization": CREDENTIAL})
        self.assertEqual(response.status_code, 302)
        self.assertEqual([r["path"] for r in self.server.recorded], ["/v1/escape"])

    def test_redirect_outside_prefix_is_refused(self):
        with self.assertRaises(SafetyError) as ctx:
            self.follow_client.request("POST", "/v1/escape", content=b"{}", headers={"Authorization": CREDENTIAL})
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
                self.follow_client.request("POST", "/v1/offport", content=BODY_CANARY.encode(), headers={"Authorization": CREDENTIAL})
            self.assert_violation(ctx)
            self.assertEqual(foreign.recorded, [])
            self.assertEqual([r["path"] for r in self.server.recorded], ["/v1/offport"])
        finally:
            del self.server.routes["/v1/offport"]
            foreign.stop()

    def test_redirect_to_other_hostname_is_refused(self):
        with self.assertRaises(SafetyError) as ctx:
            self.follow_client.request("POST", "/v1/offhost", content=b"{}", headers={"Authorization": CREDENTIAL})
        self.assert_violation(ctx)
        self.assertEqual([r["path"] for r in self.server.recorded], ["/v1/offhost"])

    def test_redirect_with_userinfo_is_refused(self):
        with self.assertRaises(SafetyError) as ctx:
            self.follow_client.request("POST", "/v1/userinfo", content=b"{}", headers={"Authorization": CREDENTIAL})
        self.assert_violation(ctx)
        self.assertEqual([r["path"] for r in self.server.recorded], ["/v1/userinfo"])

    def test_redirect_loop_exhausts_budget_with_controlled_failure(self):
        with self.assertRaises(SafetyError) as ctx:
            self.follow_client.request("POST", "/v1/loop-a", content=BODY_CANARY.encode(), headers={"Authorization": CREDENTIAL})
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
            response = self.client.request("POST", "/v1/chat/completions", content=b"{}", headers={"Authorization": CREDENTIAL})
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
                client.request("POST", "/v1/chat/completions", content=BODY_CANARY.encode(), headers={"Authorization": CREDENTIAL})
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
                client.request("POST", "/v1/chat/completions", content=b"{}", headers={"Authorization": CREDENTIAL})
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
                client.request("POST", "/v1/chat/completions", content=b"{}", headers={"Authorization": CREDENTIAL})
        finally:
            client.close()
        self.assert_violation(ctx, SafetyCode.INVALID_UPSTREAM)
        self.assertEqual(transport.calls, 0)
        self.assertEqual(self.server.recorded, [])


if __name__ == "__main__":
    unittest.main()
