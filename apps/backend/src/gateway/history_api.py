"""Admin-scoped request history reads; the standalone query-key entry is deleted.

Every route authenticates through the unified admin dependency (idle-refreshing
variant). Detail reads revalidate the session against deadlines before any stage
body is released, and a failed audit inside the store still releases nothing.
Listing filters are safe metadata predicates only; there is no body search.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

import anyio
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from gateway.admin_auth import AdminAuthService, AdminContext
from gateway.admin_storage import AdminStorageUnavailable, SessionInvalid
from request_history.models import ERROR_CODES, PROTOCOLS, STATUSES, HistoryNotFound


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

_FILTER_FIELDS = frozenset({"limit", "cursor", "model", "protocol", "status",
                            "error_code", "created_after", "created_before"})


def _error(code: str, status: int) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code}},
                        headers=_SECURITY_HEADERS)


def _source(request: Request) -> str:
    client = request.client
    return client.host if client is not None and client.host else "unknown"


def _parse_time(raw: str | None):
    if raw is None:
        return None
    try:
        moment = datetime.fromisoformat(raw)
    except ValueError:
        raise ValueError() from None
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError()
    return moment


def _parse_list_query(request: Request) -> dict:
    """Whitelist metadata filters; unknown or repeated arguments refuse without echo."""
    names = [name for name, _ in request.query_params.multi_items()]
    if any(name not in _FILTER_FIELDS for name in names) or len(names) != len(set(names)):
        raise ValueError()
    params = request.query_params
    raw_limit = params.get("limit", "50")
    if not raw_limit.isascii() or not raw_limit.isdigit():
        raise ValueError()
    limit = int(raw_limit)
    if not 1 <= limit <= 100:
        raise ValueError()
    cursor = params.get("cursor")
    if cursor is not None and (not cursor.isascii() or not cursor or len(cursor) > 512):
        raise ValueError()
    model = params.get("model")
    if model is not None and not 1 <= len(model) <= 256:
        raise ValueError()
    protocol = params.get("protocol")
    if protocol is not None and protocol not in PROTOCOLS:
        raise ValueError()
    status = params.get("status")
    if status is not None and status not in STATUSES:
        raise ValueError()
    error_code = params.get("error_code")
    if error_code is not None and error_code not in ERROR_CODES:
        raise ValueError()
    created_after = _parse_time(params.get("created_after"))
    created_before = _parse_time(params.get("created_before"))
    if (created_after is not None and created_before is not None
            and created_after > created_before):
        raise ValueError()
    return {"limit": limit, "cursor": cursor, "model": model, "protocol": protocol,
            "status": status, "error_code": error_code,
            "created_after": created_after, "created_before": created_before}


def install_history_routes(app: FastAPI, store, auth_service: AdminAuthService) -> None:
    """All bound history is visible to the admin session; no supplier-key or ACL filter."""
    if not isinstance(auth_service, AdminAuthService):
        raise TypeError("auth_service must be an AdminAuthService")
    require_admin = auth_service.require_admin()

    @app.get("/api/admin/requests")
    async def request_list(request: Request, context: AdminContext = Depends(require_admin)):
        try:
            filters = _parse_list_query(request)
        except (ValueError, TypeError):
            return _error("INVALID_HISTORY_QUERY", 422)
        try:
            payload = await anyio.to_thread.run_sync(lambda: store.list_requests(
                actor=context.actor_id, session_reference=context.session_reference,
                **filters))
        except Exception:
            return _error("HISTORY_UNAVAILABLE", 503)
        return JSONResponse(content=payload, headers=_SECURITY_HEADERS)

    @app.get("/api/admin/requests/{request_id}")
    async def request_detail(request: Request, request_id: str,
                             context: AdminContext = Depends(require_admin)):
        # Keep client-supplied paths out of durable access metadata.
        try:
            safe_id = str(UUID(request_id))
        except (ValueError, TypeError, AttributeError):
            return _error("HISTORY_NOT_FOUND", 404)
        if request_id != safe_id:
            return _error("HISTORY_NOT_FOUND", 404)
        try:
            payload = await anyio.to_thread.run_sync(lambda: store.get_request(
                safe_id, actor=context.actor_id,
                session_reference=context.session_reference))
        except HistoryNotFound:
            return _error("HISTORY_NOT_FOUND", 404)
        except Exception:
            return _error("HISTORY_UNAVAILABLE", 503)
        # Synchronized body release re-checks the session and its deadlines first.
        try:
            await auth_service.revalidate(context, source=_source(request))
        except SessionInvalid:
            return _error("ADMIN_SESSION_INVALID", 401)
        except AdminStorageUnavailable:
            return _error("ADMIN_STORAGE_UNAVAILABLE", 503)
        return JSONResponse(content=payload, headers=_SECURITY_HEADERS)
