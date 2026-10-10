"""Admin console HTTP assembly: login/session/logout, page guard, origin and CSRF.

All admin data routes authenticate through :class:`gateway.admin_auth.AdminAuthService`
dependencies; this module adds the browser-facing rules around them: same-origin
enforcement, the session-bound ``X-Admin-CSRF`` header for writes, strict login
payloads, uniform error bodies, and the page redirect contract. The CSRF token is
derived from the server-side session digest, so it is session-bound, needs no
storage of its own, and dies with revocation. Errors use the shared
``{"error": {"code": ...}}`` shape with ``_SECURITY_HEADERS``.
"""
from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response

from gateway.admin_auth import (
    SESSION_COOKIE_NAME, AdminAuthService, AdminContext, AdminLoginFailed,
    AdminLoginThrottled,
)
from gateway.admin_storage import AdminStorageUnavailable, SessionInvalid
from gateway.history_api import _SECURITY_HEADERS, _error, _source
from infra.strict_json import parse_strict_json

CSRF_HEADER = "x-admin-csrf"
_CSRF_HMAC_LABEL = b"enterprise-gateway-admin-csrf-v1"
MAX_LOGIN_BODY_BYTES = 4096

# Task-1 dependency details and this module's write-guard codes pass the generic
# HTTPException handler through unchanged; everything else stays UNSUPPORTED_ENDPOINT.
ADMIN_ERROR_CODES = frozenset({
    "ADMIN_SESSION_INVALID", "ADMIN_STORAGE_UNAVAILABLE",
    "ADMIN_ORIGIN_REJECTED", "ADMIN_CSRF_INVALID",
    "KNOWLEDGE_SCHEMA_INCOMPATIBLE",
    "KNOWLEDGE_SOURCE_NOT_FOUND",
    "KNOWLEDGE_SOURCE_WITHDRAWN",
    "KNOWLEDGE_SOURCE_EXPIRED",
    "KNOWLEDGE_GOVERNANCE_VERSION_CONFLICT",
    "KNOWLEDGE_GOVERNANCE_VERSION_INVALID",
    "KNOWLEDGE_CANDIDATE_NOT_FOUND",
    "KNOWLEDGE_CANDIDATE_VERSION_CONFLICT",
    "KNOWLEDGE_PUBLICATION_NOT_FOUND",
    "KNOWLEDGE_PUBLICATION_AUDIENCE_DENIED",
    "KNOWLEDGE_PUBLICATION_PURPOSE_DENIED",
    "KNOWLEDGE_PUBLISH_REJECTED",
    "KNOWLEDGE_VALIDITY_EXCEEDS_SOURCE",
    "KNOWLEDGE_ADMIN_UNAVAILABLE",
    "AUDIT_RECORD_NOT_FOUND",
    "AUDIT_RECORD_UNAVAILABLE",
    "AUDIT_EVIDENCE_CORRUPTED",
    "AUDIT_ACCESS_REJECTED",
    "AUDIT_WRITE_FAILED",
    "ADMIN_AUDIT_UNAVAILABLE",
    "ADMIN_REQUEST_INVALID",

})

_LOGIN_ASSETS = frozenset({"login.css", "login.js"})
_ADMIN_ASSETS = frozenset({
    "admin.css", "admin.js", "admin-session.js", "operations.js", "settings.js",
    "knowledge.js", "audit.js", "history.css", "history.js",
})

_LOGIN_PLACEHOLDER = (
    "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
    "<title>企业隐私网关管理登录</title></head><body>"
    "<p>登录页面资源尚未发布。</p></body></html>"
)
_ADMIN_PLACEHOLDER = (
    "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
    "<title>企业隐私网关管理控制台</title></head><body>"
    "<p>管理页面资源尚未发布。</p></body></html>"
)


def _csrf_token(context: AdminContext) -> str:
    """Session-bound token derived from the persisted digest; never stored itself."""
    return hmac.new(bytes.fromhex(context._token_digest), _CSRF_HMAC_LABEL,
                    hashlib.sha256).hexdigest()


def _session_payload(context: AdminContext) -> dict:
    return {
        "actor_id": context.actor_id,
        "scope": context.scope,
        "authenticated_at": context.authenticated_at.isoformat(),
        "idle_expires_at": context.idle_expires_at.isoformat(),
        "absolute_expires_at": context.absolute_expires_at.isoformat(),
        "csrf_token": _csrf_token(context),
    }


def _single_header(request: Request, name: str) -> str | None:
    values = request.headers.getlist(name)
    return values[0] if len(values) == 1 else None


def _same_origin(request: Request) -> bool:
    """Origin (else Referer) host must equal the request Host; ambiguity refuses."""
    host = _single_header(request, "host")
    if not host:
        return False
    origin = _single_header(request, "origin")
    referer = _single_header(request, "referer")
    signal = origin if origin is not None else referer
    if signal is None:
        return False
    parsed = urlsplit(signal)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return False
    return parsed.netloc.lower() == host.lower()


def _set_session_cookie(response: Response, request: Request, token: str) -> None:
    response.set_cookie(SESSION_COOKIE_NAME, token, path="/", httponly=True,
                        samesite="strict", secure=request.url.scheme == "https")


def _clear_session_cookie(response: Response, request: Request) -> None:
    response.set_cookie(SESSION_COOKIE_NAME, "", path="/", httponly=True,
                        samesite="strict", secure=request.url.scheme == "https",
                        max_age=0)


class _LoginPayloadInvalid(Exception):
    """Strict-parse failure; never carries submitted content."""


class _LoginRedirect(Exception):
    """Internal control flow: an unauthenticated page request goes to /login."""


def _page_dependency(service: AdminAuthService):
    authenticate = service.require_admin()

    async def dependency(request: Request) -> AdminContext:
        try:
            return await authenticate(request)
        except HTTPException as refused:
            if refused.status_code == 401:
                raise _LoginRedirect() from None
            raise

    return dependency


def write_dependency(service: AdminAuthService):
    authenticate = service.require_admin()

    async def dependency(request: Request) -> AdminContext:
        context = await authenticate(request)
        if not _same_origin(request):
            raise HTTPException(status_code=403, detail="ADMIN_ORIGIN_REJECTED") from None
        presented = _single_header(request, CSRF_HEADER)
        if presented is None or not hmac.compare_digest(presented, _csrf_token(context)):
            raise HTTPException(status_code=403, detail="ADMIN_CSRF_INVALID") from None
        return context

    return dependency


def _page_response(assets: Path, name: str, placeholder: str) -> Response:
    path = assets / name
    try:
        if path.is_file() and not path.is_symlink():
            return FileResponse(path, headers=_SECURITY_HEADERS)
    except OSError:
        pass
    # Page files ship with the frontend worker; the route contract is final now.
    return Response(content=placeholder, media_type="text/html", headers=_SECURITY_HEADERS)


def _asset_response(assets: Path, name: str, allowed: frozenset) -> Response:
    if name not in allowed:
        return _error("ADMIN_ASSET_NOT_FOUND", 404)
    path = assets / name
    try:
        if path.is_file() and not path.is_symlink():
            return FileResponse(path, headers=_SECURITY_HEADERS)
    except OSError:
        pass
    return _error("ADMIN_ASSET_NOT_FOUND", 404)


def install_admin_routes(app: FastAPI, auth_service: AdminAuthService) -> None:
    """Mount the console pages and session API; every route is fixed in the contract."""
    if not isinstance(auth_service, AdminAuthService):
        raise TypeError("auth_service must be an AdminAuthService")
    assets = Path(__file__).with_name("web")
    require_page = _page_dependency(auth_service)
    require_write = write_dependency(auth_service)
    require_poll = auth_service.require_admin_poll()

    @app.middleware("http")
    async def admin_security_headers(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if (path == "/login" or path.startswith("/login/")
                or path == "/admin" or path.startswith("/admin/")
                or path == "/api/admin" or path.startswith("/api/admin/")):
            response.headers.update(_SECURITY_HEADERS)
        return response

    @app.exception_handler(_LoginRedirect)
    async def login_redirect(_request: Request, _exc: _LoginRedirect) -> RedirectResponse:
        return RedirectResponse("/login", status_code=302, headers=_SECURITY_HEADERS)

    @app.get("/login")
    async def login_page(request: Request):
        try:
            await auth_service.authenticate(request.cookies.get(SESSION_COOKIE_NAME),
                                            source=_source(request), refresh_idle=True)
        except Exception:
            return _page_response(assets, "login.html", _LOGIN_PLACEHOLDER)
        return RedirectResponse("/admin", status_code=302, headers=_SECURITY_HEADERS)

    @app.get("/login/assets/{asset}")
    async def login_asset(asset: str):
        return _asset_response(assets, asset, _LOGIN_ASSETS)

    @app.get("/admin")
    @app.get("/admin/requests")
    async def admin_page(context: AdminContext = Depends(require_page)):
        return _page_response(assets, "admin.html", _ADMIN_PLACEHOLDER)

    @app.get("/admin/assets/{asset}")
    async def admin_asset(asset: str):
        return _asset_response(assets, asset, _ADMIN_ASSETS)

    @app.post("/api/admin/login")
    async def admin_login(request: Request):
        if not _same_origin(request):
            return _error("ADMIN_ORIGIN_REJECTED", 403)
        content_type = request.headers.get("content-type", "")
        if content_type.split(";")[0].strip().lower() != "application/json":
            return _error("ADMIN_REQUEST_INVALID", 422)
        body = await request.body()
        if len(body) > MAX_LOGIN_BODY_BYTES:
            return _error("ADMIN_REQUEST_INVALID", 422)

        def reject(_kind):
            raise _LoginPayloadInvalid()

        try:
            payload = parse_strict_json(body, reject=reject)
        except _LoginPayloadInvalid:
            return _error("ADMIN_REQUEST_INVALID", 422)
        if (not isinstance(payload, dict) or set(payload) != {"username", "password"}
                or not isinstance(payload["username"], str)
                or not isinstance(payload["password"], str)):
            return _error("ADMIN_REQUEST_INVALID", 422)
        try:
            token, context = await auth_service.login(
                username=payload["username"], password=payload["password"],
                source=_source(request))
        except AdminLoginThrottled:
            return _error("ADMIN_LOGIN_THROTTLED", 429)
        except AdminLoginFailed:
            return _error("ADMIN_LOGIN_FAILED", 401)
        except AdminStorageUnavailable:
            return _error("ADMIN_STORAGE_UNAVAILABLE", 503)
        except ValueError:
            return _error("ADMIN_REQUEST_INVALID", 422)
        response = JSONResponse(content=_session_payload(context), headers=_SECURITY_HEADERS)
        _set_session_cookie(response, request, token)
        return response

    @app.get("/api/admin/session")
    async def admin_session(context: AdminContext = Depends(require_poll)):
        return JSONResponse(content=_session_payload(context), headers=_SECURITY_HEADERS)

    @app.post("/api/admin/logout")
    async def admin_logout(request: Request,
                           context: AdminContext = Depends(require_write)):
        try:
            await auth_service.logout(context, source=_source(request))
        except SessionInvalid:
            return _error("ADMIN_SESSION_INVALID", 401)
        except AdminStorageUnavailable:
            return _error("ADMIN_STORAGE_UNAVAILABLE", 503)
        response = JSONResponse(content={"revoked": True}, headers=_SECURITY_HEADERS)
        _clear_session_cookie(response, request)
        return response
