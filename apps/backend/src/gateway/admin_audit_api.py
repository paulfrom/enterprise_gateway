"""Direct audit review in an isolated bounded executor, independent of knowledge PG.

A RELEASED event records the reader's successful decryption/result checkpoint.
Lifecycle, budget and session checks can still refuse HTTP delivery afterwards.
Catalog/access logs keep the T3 defaults: 64 MiB each and at most 20,000 scans.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from contextvars import ContextVar
from dataclasses import asdict
from datetime import datetime, timezone
from functools import partial
import threading
import time

from fastapi import Depends, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from typing import Annotated

from audit.admin_reader import AdminAuditContext
from gateway.admin_storage import SessionInvalid, AdminStorageUnavailable
from gateway.history_api import _error, _source
from infra.errors import SafetyCode, SafetyError

_AUDIT_BUDGET = 5.0
_OPS_LIMIT = 4
_checkpoint = ContextVar('admin_audit_checkpoint', default=None)


def _utcnow():
    return datetime.now(timezone.utc)


def revalidate_audit_session():
    """Runtime reader callback; request state remains local to its worker thread."""
    callback = _checkpoint.get()
    if callback is None:
        raise SessionInvalid('missing admin read context')
    callback()


def install_audit_admin_routes(app, auth_service, reader, builder):
    require = auth_service.require_admin()
    slots = threading.BoundedSemaphore(_OPS_LIMIT)
    executor = ThreadPoolExecutor(max_workers=_OPS_LIMIT, thread_name_prefix='admin-audit')
    app.state.admin_audit_executor = executor
    app.router.add_event_handler("shutdown", partial(executor.shutdown, wait=False, cancel_futures=True))

    def scope(context):
        # Admin scope is assembled by the launcher from deployment values.
        tenant, domain = context.scope.split('/', 1)
        return tenant, domain

    def run(context, request, call, release_check=None):
        if reader is None or not slots.acquire(blocking=False):
            return _error('ADMIN_AUDIT_UNAVAILABLE', 503)
        deadline = time.monotonic() + _AUDIT_BUDGET

        def checkpoint():
            if time.monotonic() >= deadline:
                raise SafetyError(SafetyCode.AUDIT_ACCESS_REJECTED)
            asyncio.run(auth_service.revalidate(context, source=_source(request)))
            if time.monotonic() >= deadline:
                raise SafetyError(SafetyCode.AUDIT_ACCESS_REJECTED)

        def work():
            token = _checkpoint.set(checkpoint)
            try:
                checkpoint()
                result = call(deadline)
                checkpoint()  # Final release checkpoint, including metadata.
                return jsonable_encoder(result)
            finally:
                _checkpoint.reset(token)
                slots.release()
        try:
            future = executor.submit(work)
        except Exception:
            slots.release()
            return _error('ADMIN_AUDIT_UNAVAILABLE', 503)
        try:
            result = future.result(timeout=max(0.001, deadline - time.monotonic()))
            checkpoint()  # Revalidate in the route immediately before HTTP body release.
            if release_check is not None:
                release_check()
            return result
        except HTTPException:
            raise
        except SessionInvalid:
            return _error('ADMIN_SESSION_INVALID', 401)
        except AdminStorageUnavailable:
            return _error('ADMIN_STORAGE_UNAVAILABLE', 503)
        except SafetyError as exc:
            code = str(exc.code.value)
            allowed = {'AUDIT_RECORD_NOT_FOUND', 'AUDIT_RECORD_UNAVAILABLE', 'AUDIT_EVIDENCE_CORRUPTED', 'AUDIT_ACCESS_REJECTED', 'AUDIT_WRITE_FAILED'}
            if code not in allowed:
                return _error('ADMIN_AUDIT_UNAVAILABLE', 503)
            return _error(code, 404 if code == 'AUDIT_RECORD_NOT_FOUND' else 403 if code == 'AUDIT_ACCESS_REJECTED' else 409 if code in {'AUDIT_RECORD_UNAVAILABLE', 'AUDIT_EVIDENCE_CORRUPTED'} else 503)
        except (ValueError, TypeError):
            return _error('ADMIN_REQUEST_INVALID', 422)
        except Exception:
            return _error('ADMIN_AUDIT_UNAVAILABLE', 503)

    @app.get('/api/admin/audit/records')
    def records(request: Request, purpose: str | None = None,
                limit: Annotated[int, Query(ge=1, le=100)] = 50,
                cursor: Annotated[str | None, Query(max_length=128, pattern=r'^[A-Za-z0-9._-]+$')] = None,
                context=Depends(require)):
        tenant, domain = scope(context)
        def read(deadline):
            entries, next_cursor = reader.list_records(tenant_id=tenant, domain=domain, purpose=purpose, limit=limit, cursor=cursor)
            return {'items': [asdict(entry) for entry in entries], 'next_cursor': next_cursor,
                    'catalog_backlog': builder.backlog() if builder is not None else None,
                    'catalog_error_code': getattr(app.state, 'audit_catalog_error_code', None)}
        return run(context, request, read)

    @app.get('/api/admin/audit/records/{record_id}')
    def record(request: Request, record_id: str, context=Depends(require)):
        tenant, domain = scope(context)
        release_entry = None
        def read(deadline):
            nonlocal release_entry
            entry = reader.get_record(record_id, tenant_id=tenant, domain=domain)
            plaintext = reader.read_plaintext(record_id, context=AdminAuditContext(
                actor_id='admin', session_digest=context.session_reference,
                tenant_id=tenant, domain=domain, deadline=deadline))
            release_entry = entry
            return {'item': asdict(entry), 'plaintext': plaintext.decode('utf-8')}
        def check_lifecycle():
            if release_entry.status != 'available' or _utcnow() >= release_entry.retention_until:
                raise SafetyError(SafetyCode.AUDIT_RECORD_UNAVAILABLE)
        return run(context, request, read, release_check=check_lifecycle)

    @app.get('/api/admin/audit/events')
    def events(request: Request, limit: Annotated[int, Query(ge=1, le=100)] = 50,
               cursor: Annotated[str | None, Query(max_length=128, pattern=r'^[A-Za-z0-9._-]+$')] = None,
               context=Depends(require)):
        tenant, domain = scope(context)
        return run(context, request, lambda deadline: reader.list_events(tenant_id=tenant, domain=domain, limit=limit, cursor=cursor, deadline=deadline))
