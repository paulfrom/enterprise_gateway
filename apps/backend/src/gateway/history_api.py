"""Gateway-wide request history reads, separate from supplier credentials."""
from __future__ import annotations

import hmac
from pathlib import Path
from uuid import UUID

import anyio
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse

from request_history.models import HistoryNotFound


_SECURITY_HEADERS = {
    "cache-control": "no-store",
    "pragma": "no-cache",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "content-security-policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; img-src 'self'; font-src 'self'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    ),
    "vary": "Authorization",
}


def _error(code: str, status: int) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code}},
                        headers=_SECURITY_HEADERS)


def install_history_routes(app: FastAPI, store, read_key: bytes) -> None:
    """A single operator credential grants all history within the bound store.

    No account, vendor-key correlation, automatic identity or knowledge grants.
    Keys are 32-byte operator secrets represented as 64 hexadecimal characters.
    """
    if not isinstance(read_key, bytes) or len(read_key) != 32:
        raise ValueError("history read key must be exactly 32 bytes")
    expected = read_key.hex().encode("ascii")
    assets = Path(__file__).with_name("web")

    @app.middleware("http")
    async def history_headers(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path == "/history" or path.startswith("/history/") or path.startswith("/api/requests"):
            response.headers.update(_SECURITY_HEADERS)
        return response

    async def authorize(request: Request, *, operation: str, request_id: str | None = None):
        values = [value for name, value in request.scope["headers"] if name.lower() == b"authorization"]
        valid = False
        if len(values) == 1 and not any(name.lower() == b"x-api-key" for name, _ in request.scope["headers"]):
            value = values[0]
            if value.startswith(b"Bearer "):
                candidate = value[7:]
                valid = len(candidate) == 64 and hmac.compare_digest(candidate, expected)
        if not valid:
            try:
                await anyio.to_thread.run_sync(lambda: store.audit_access(
                    operation=operation, request_id=request_id, outcome="denied"))
            except Exception:
                return _error("HISTORY_UNAVAILABLE", 503)
            return _error("HISTORY_UNAUTHORIZED", 401)
        # Unknown and repeated query arguments are rejected without echoing them.
        allowed = {"limit", "cursor", "q", "status"} if operation == "list" else set()
        names = [name for name, _ in request.query_params.multi_items()]
        if any(name not in allowed for name in names) or len(names) != len(set(names)):
            return _error("INVALID_HISTORY_QUERY", 400)
        return None

    @app.get("/history")
    async def history_page():
        return FileResponse(assets / "history.html", headers=_SECURITY_HEADERS)

    @app.get("/history/assets/{asset}")
    async def history_asset(asset: str):
        if asset not in {"history.css", "history.js"}:
            return _error("HISTORY_NOT_FOUND", 404)
        return FileResponse(assets / asset, headers=_SECURITY_HEADERS)

    @app.get("/api/requests")
    async def request_list(request: Request):
        refusal = await authorize(request, operation="list")
        if refusal is not None:
            return refusal
        # Parse after authentication and never let framework validation echo input.
        try:
            raw_limit = request.query_params.get("limit", "50")
            if not raw_limit.isascii() or not raw_limit.isdigit():
                raise ValueError()
            limit = int(raw_limit)
            cursor = request.query_params.get("cursor")
            q = request.query_params.get("q", "")
            status = request.query_params.get("status")
            if not 1 <= limit <= 100 or len(q) > 128 or (cursor is not None and len(cursor) > 512):
                raise ValueError()
        except (ValueError, TypeError):
            return _error("INVALID_HISTORY_QUERY", 400)
        if status is not None and status not in {"processing", "completed", "blocked", "failed", "partial"}:
            return _error("INVALID_HISTORY_QUERY", 400)
        try:
            payload = await anyio.to_thread.run_sync(lambda: store.list_requests(
                limit=limit, cursor=cursor, query=q, status=status))
            return JSONResponse(content=payload, headers=_SECURITY_HEADERS)
        except (ValueError, TypeError):
            return _error("INVALID_HISTORY_QUERY", 400)
        except Exception:
            return _error("HISTORY_UNAVAILABLE", 503)

    @app.get("/api/requests/{request_id}")
    async def request_detail(request: Request, request_id: str):
        # Keep client-supplied paths out of durable access metadata.
        try:
            safe_id = str(UUID(request_id))
        except (ValueError, TypeError, AttributeError):
            safe_id = None
        refusal = await authorize(request, operation="get", request_id=safe_id)
        if refusal is not None:
            return refusal
        if safe_id is None or request_id != safe_id:
            return _error("HISTORY_NOT_FOUND", 404)
        try:
            payload = await anyio.to_thread.run_sync(lambda: store.get_request(safe_id))
            return JSONResponse(content=payload, headers=_SECURITY_HEADERS)
        except HistoryNotFound:
            return _error("HISTORY_NOT_FOUND", 404)
        except Exception:
            return _error("HISTORY_UNAVAILABLE", 503)
