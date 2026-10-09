"""Channel-bound outbound client: the URL is always the binding's, never the caller's.

Capability boundary: this module proves the egress-side binding contract for a
single admitted channel — fixed scheme/host/port/path prefix, caller BYOK
credential, timeout budget, no caller-selectable URL (there is no ``url``
parameter anywhere on the API), no proxy environment influence
(``trust_env=False``), same-binding-only redirect policy, an egress header
whitelist that never carries internal identity/tenant metadata, and a local
resolution guard that fails closed when address resolution returns anything
outside the declared address set.

The resolution guard is a local guard over the injected resolver hook; it is
not a production network-isolation proof — production network drills belong to
R-04. This module performs no real vendor calls: tests use loopback spies and
injected transports. The sync client is the L1 contract; an async adapter for
the FastAPI shell belongs to the later integration batch.

Failure-code mapping (all raised as ``SafetyError`` whose public message
contains only the code and static structural detail):

- ``INVALID_UPSTREAM`` — binding configuration is invalid (scheme/host/port/
  path prefix/timeout/credential/address set), host resolution at bind time
  fails or yields nothing.
- ``UPSTREAM_BINDING_VIOLATION`` — a caller supplies an absolute URL or a path
  outside the bound prefix, a redirect target leaves the binding, the
  redirect budget is exhausted, or an outgoing request at the transport layer
  targets anything other than the bound origin.
- ``TypeError`` — a non-mapping ``headers`` container; these are
  programmer errors, not business inputs.
"""

from __future__ import annotations

import ipaddress
import math
import socket
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import NoReturn

import httpx

from infra.errors import SafetyCode, SafetyError
from protocol.identity import FORBIDDEN_CLIENT_IDENTITY_HEADERS, extract_byok_credential

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_MAX_REDIRECTS = 8

# Outbound headers the protocols need. Everything else — including every name
# in identity.FORBIDDEN_CLIENT_IDENTITY_HEADERS — is dropped before sending.
# One caller-supplied credential is transformed to the bound protocol header.
# Host is not caller-settable: it is derived from the bound URL by httpx.
EGRESS_HEADER_WHITELIST: frozenset[str] = frozenset(
    {
        "content-type",
        "accept",
        "authorization",
        "x-api-key",
        "anthropic-version",
        "x-protection-package-version",
    }
)

Resolver = Callable[[str], Iterable[str]]


def _default_resolver(host: str) -> tuple[str, ...]:
    infos = socket.getaddrinfo(host, None)
    return tuple({info[4][0] for info in infos})


def _resolve_host(host: str, resolver: Resolver | None) -> tuple[str, ...]:
    resolve = resolver or _default_resolver
    try:
        addresses = tuple(resolve(host))
    except Exception:
        addresses = ()
    if not addresses:
        raise SafetyError(SafetyCode.INVALID_UPSTREAM, "host resolution")
    return addresses


def _within_prefix(prefix: str, path: str) -> bool:
    if prefix == "/":
        return path.startswith("/")
    return path == prefix or path.startswith(prefix + "/")


def _normalize_addresses(raw: object) -> frozenset[str]:
    if not isinstance(raw, frozenset):
        raise SafetyError(SafetyCode.INVALID_UPSTREAM, "allowed_addresses")
    normalized: set[str] = set()
    for address in raw:
        try:
            normalized.add(str(ipaddress.ip_address(address)))
        except ValueError:
            raise SafetyError(SafetyCode.INVALID_UPSTREAM, "allowed_addresses") from None
    if not normalized:
        raise SafetyError(SafetyCode.INVALID_UPSTREAM, "allowed_addresses")
    return frozenset(normalized)


@dataclass(frozen=True, slots=True)
class BoundUpstream:
    """Immutable binding of one channel to one fixed supplier origin.

    No supplier credential is stored on a binding. Every send requires the
    current caller's BYOK. Validation failures contain static detail only.
    """

    channel_id: str
    scheme: str
    host: str
    port: int
    path_prefix: str
    timeout_seconds: float
    allowed_addresses: frozenset[str]
    max_redirects: int = 0
    package_version: str | None = None
    credential_header: str = 'authorization'

    def __post_init__(self) -> None:
        if self.credential_header not in ('authorization', 'x-api-key'):
            raise SafetyError(SafetyCode.INVALID_UPSTREAM,'credential header')
        if not isinstance(self.channel_id, str) or not self.channel_id.strip():
            raise SafetyError(SafetyCode.INVALID_UPSTREAM, "channel_id")
        if not isinstance(self.scheme, str) or self.scheme.lower() not in _ALLOWED_SCHEMES:
            raise SafetyError(SafetyCode.INVALID_UPSTREAM, "scheme")
        if not isinstance(self.host, str) or not self.host.strip():
            raise SafetyError(SafetyCode.INVALID_UPSTREAM, "host")
        host = self.host.strip().lower()
        if any(char.isspace() for char in host) or "/" in host or "@" in host:
            raise SafetyError(SafetyCode.INVALID_UPSTREAM, "host")
        if (
            not isinstance(self.port, int)
            or isinstance(self.port, bool)
            or not 1 <= self.port <= 65535
        ):
            raise SafetyError(SafetyCode.INVALID_UPSTREAM, "port")
        if (
            not isinstance(self.path_prefix, str)
            or not self.path_prefix.startswith("/")
            or "://" in self.path_prefix
            or ".." in self.path_prefix
        ):
            raise SafetyError(SafetyCode.INVALID_UPSTREAM, "path_prefix")
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise SafetyError(SafetyCode.INVALID_UPSTREAM, "timeout_seconds")
        if self.package_version is not None and (
            not isinstance(self.package_version, str) or not self.package_version.strip()
        ):
            raise SafetyError(SafetyCode.INVALID_UPSTREAM, "package_version")
        addresses = _normalize_addresses(self.allowed_addresses)
        if (
            not isinstance(self.max_redirects, int)
            or isinstance(self.max_redirects, bool)
            or not 0 <= self.max_redirects <= _MAX_REDIRECTS
        ):
            raise SafetyError(SafetyCode.INVALID_UPSTREAM, "max_redirects")
        object.__setattr__(self, "scheme", self.scheme.lower())
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "timeout_seconds", float(self.timeout_seconds))
        object.__setattr__(self, "allowed_addresses", addresses)

    @classmethod
    def resolve(
        cls,
        *,
        channel_id: str,
        scheme: str,
        host: str,
        port: int,
        path_prefix: str,
        timeout_seconds: float,
        resolver: Resolver | None = None,
        max_redirects: int = 0,
        credential_header: str = 'authorization',
    ) -> BoundUpstream:
        """Construct a binding with the declared address set resolved from host.

        Resolution failure or an empty result fails closed with
        ``INVALID_UPSTREAM``.
        """
        addresses = frozenset(_resolve_host(host, resolver))
        return cls(
            channel_id=channel_id,
            scheme=scheme,
            host=host,
            port=port,
            path_prefix=path_prefix,
            timeout_seconds=timeout_seconds,
            allowed_addresses=addresses,
            max_redirects=max_redirects,
            credential_header=credential_header,
        )

    @property
    def base_url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.scheme}://{host}:{self.port}"


class _BoundTransport(httpx.BaseTransport):
    """Final guard: every outgoing request must target the bound origin, and
    every resolution of the bound host must stay inside the declared set."""

    def __init__(
        self, binding: BoundUpstream, inner: httpx.BaseTransport, resolver: Resolver
    ) -> None:
        self._binding = binding
        self._inner = inner
        self._resolver = resolver

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        effective_port = url.port if url.port is not None else (443 if url.scheme == "https" else 80)
        if (
            url.scheme != self._binding.scheme
            or url.host != self._binding.host
            or effective_port != self._binding.port
        ):
            raise SafetyError(SafetyCode.UPSTREAM_BINDING_VIOLATION, "transport target")
        self._assert_resolution()
        return self._inner.handle_request(request)

    def _assert_resolution(self) -> None:
        try:
            results = tuple(self._resolver(self._binding.host))
        except Exception:
            results = ()
        if not results:
            raise SafetyError(SafetyCode.INVALID_UPSTREAM, "resolution")
        for address in results:
            try:
                normalized = str(ipaddress.ip_address(address))
            except ValueError:
                raise SafetyError(SafetyCode.INVALID_UPSTREAM, "resolution") from None
            if normalized not in self._binding.allowed_addresses:
                raise SafetyError(SafetyCode.INVALID_UPSTREAM, "resolution")

    def close(self) -> None:
        self._inner.close()


def _is_redirect(response: httpx.Response) -> bool:
    return response.status_code in (301, 302, 303, 307, 308)


class BoundEgressClient:
    """Outbound client whose request target is derived solely from the binding.

    There is deliberately no ``url``/``host`` parameter: callers pass only a
    method, a bound-relative path, optional caller headers (filtered through
    :data:`EGRESS_HEADER_WHITELIST`), and content bytes."""

    def __init__(
        self,
        binding: BoundUpstream,
        *,
        transport: httpx.BaseTransport | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        if not isinstance(binding, BoundUpstream):
            raise TypeError("binding must be a BoundUpstream")
        self._binding = binding
        resolve = resolver or _default_resolver
        inner = transport if transport is not None else httpx.HTTPTransport()
        guard = _BoundTransport(binding, inner, resolve)
        self._client = httpx.Client(
            transport=guard,
            timeout=binding.timeout_seconds,
            trust_env=False,
            follow_redirects=False,
        )

    @property
    def binding(self) -> BoundUpstream:
        return self._binding

    def _bound_url(self, path: str) -> str:
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or "://" in path
            or ".." in path
        ):
            raise SafetyError(SafetyCode.UPSTREAM_BINDING_VIOLATION, "path")
        if not _within_prefix(self._binding.path_prefix, path):
            raise SafetyError(SafetyCode.UPSTREAM_BINDING_VIOLATION, "path prefix")
        return f"{self._binding.base_url}{path}"

    def _redirect_url(self, location: str) -> str:
        try:
            target = httpx.URL(location)
        except Exception:
            raise SafetyError(SafetyCode.UPSTREAM_BINDING_VIOLATION, "redirect") from None
        if target.username or target.password:
            raise SafetyError(SafetyCode.UPSTREAM_BINDING_VIOLATION, "redirect")
        scheme = target.scheme or self._binding.scheme
        host = target.host or self._binding.host
        if target.host:
            port = target.port if target.port is not None else (443 if scheme == "https" else 80)
        else:
            port = self._binding.port
        if (
            scheme != self._binding.scheme
            or host != self._binding.host
            or port != self._binding.port
        ):
            raise SafetyError(SafetyCode.UPSTREAM_BINDING_VIOLATION, "redirect")
        path = target.path or "/"
        if not _within_prefix(self._binding.path_prefix, path):
            raise SafetyError(SafetyCode.UPSTREAM_BINDING_VIOLATION, "redirect")
        url = f"{self._binding.base_url}{path}"
        if target.query:
            url = f"{url}?{target.query.decode('utf-8')}"
        return url

    def _filter_headers(self, headers: Mapping[str, str] | None) -> dict[str, str]:
        filtered: dict[str, str] = {}
        if headers is not None:
            if not isinstance(headers, Mapping):
                raise TypeError("headers must be a mapping")
            for name, value in headers.items():
                lowered = name.lower() if isinstance(name, str) else ""
                if lowered in ("authorization", "x-api-key"):
                    continue
                if lowered not in EGRESS_HEADER_WHITELIST:
                    continue
                if lowered in filtered:
                    raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "duplicate outbound header")
                filtered[lowered] = value

        key = extract_byok_credential(headers if headers is not None else {})
        if self._binding.credential_header == "x-api-key":
            filtered["x-api-key"] = key
            filtered.setdefault("anthropic-version", "2023-06-01")
        else:
            filtered["authorization"] = f"Bearer {key}"

        if self._binding.package_version is not None:
            filtered["x-protection-package-version"] = self._binding.package_version

        return filtered

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        content: str | bytes | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        """Send one request to the bound origin and return the response as-is.

        Redirects are followed only while ``max_redirects`` allows and every
        hop stays inside the binding; anything else fails closed with
        ``UPSTREAM_BINDING_VIOLATION``. Since hops never leave the bound
        origin, in-binding redirects replay the original method and body
        (307/308-style); the single exception is 303, which converts to GET
        and drops the body per RFC 7231.
        """
        url = self._bound_url(path)
        out_headers = self._filter_headers(headers)
        for _ in range(self._binding.max_redirects + 1):
            failed = False
            try:
                response = self._client.request(method, url, headers=out_headers, content=content, timeout=timeout or self._binding.timeout_seconds)
            except SafetyError: raise
            except Exception: failed = True
            if failed:
                raise SafetyError(SafetyCode.INVALID_UPSTREAM,'transport failure')
            if not _is_redirect(response) or self._binding.max_redirects == 0:
                return response
            location = response.headers.get("location")
            if location is None:
                return response
            url = self._redirect_url(location)
            if response.status_code == 303:
                method, content = "GET", None
        raise SafetyError(SafetyCode.UPSTREAM_BINDING_VIOLATION, "redirect limit")

    def open_stream(self, method: str, path: str, *, headers=None, content=None, timeout=None) -> httpx.Response:
        request = self._client.build_request(method,self._bound_url(path),headers=self._filter_headers(headers),content=content,timeout=timeout or self._binding.timeout_seconds)
        failed = False
        try:
            response = self._client.send(request,stream=True,follow_redirects=False)
        except SafetyError: raise
        except Exception: failed = True
        if failed:
            raise SafetyError(SafetyCode.INVALID_UPSTREAM,'transport failure')
        return response

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> BoundEgressClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


__all__ = [
    "BoundEgressClient",
    "BoundUpstream",
    "EGRESS_HEADER_WHITELIST",
    "FORBIDDEN_CLIENT_IDENTITY_HEADERS",
    "Resolver",
]
