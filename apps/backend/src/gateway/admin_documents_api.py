"""Authenticated binary uploads; no filenames, paths, original text or mappings."""
from __future__ import annotations

from functools import partial
import threading
import time

import anyio
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from document.extract import DocumentError, FORMATS, MAX_FILE_BYTES
from document.service import FileRedactor
from gateway.admin_api import write_dependency
from gateway.admin_auth import AdminAuthService, AdminContext
from gateway.admin_contract import DocumentRedaction, ERROR_RESPONSES
from gateway.admin_storage import AdminStorageUnavailable, SessionInvalid
from gateway.history_api import _SECURITY_HEADERS, _error, _source
from infra.errors import SafetyCode, SafetyError

DOCUMENT_PATH = '/api/admin/documents/redact'
_UPLOAD_CONTRACT = {
    'parameters': [{'name': 'format', 'in': 'query', 'required': True,
                    'schema': {'type': 'string', 'enum': list(FORMATS)}}],
    'requestBody': {'required': True, 'content': {
        'application/octet-stream': {'schema': {'type': 'string', 'format': 'binary'}}}},
}


def install_document_routes(app: FastAPI, auth: AdminAuthService, redactor: FileRedactor | None):
    app.state.file_redactor = redactor
    require_write = write_dependency(auth)

    @app.post(DOCUMENT_PATH, response_model=DocumentRedaction,
              responses={**ERROR_RESPONSES, 413: ERROR_RESPONSES[422], 504: ERROR_RESPONSES[503]},
              openapi_extra=_UPLOAD_CONTRACT)
    async def redact_document(request: Request, context: AdminContext = Depends(require_write)):
        service = getattr(app.state, 'dictionary_service', None)
        if service is not None:
            if service.scope != context.scope:
                return _error('DOCUMENT_SCOPE_REJECTED', 403)
            try:
                await anyio.to_thread.run_sync(service.refresh)
            except Exception:
                return _error('DOCUMENT_DETECTION_UNAVAILABLE', 503)
        redactor = app.state.file_redactor
        if redactor is None or getattr(app.state, 'runtime_closed', False):
            return _error('DOCUMENT_SERVICE_UNAVAILABLE', 503)
        if context.scope != redactor.scope:
            return _error('DOCUMENT_SCOPE_REJECTED', 403)
        query = list(request.query_params.multi_items())
        if len(query) != 1 or query[0][0] != 'format' or query[0][1] not in FORMATS:
            return _error('DOCUMENT_FORMAT_UNSUPPORTED', 422)
        content_types = request.headers.getlist('content-type')
        if len(content_types) != 1 or content_types[0].lower() != 'application/octet-stream':
            return _error('ADMIN_REQUEST_INVALID', 422)
        if request.headers.get('content-encoding', 'identity') != 'identity':
            return _error('ADMIN_REQUEST_INVALID', 422)
        lengths = request.headers.getlist('content-length')
        if lengths:
            if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
                return _error('ADMIN_REQUEST_INVALID', 422)
            if len(lengths[0]) > 10:
                return _error('DOCUMENT_LIMIT_EXCEEDED', 413)
            if int(lengths[0]) > MAX_FILE_BYTES:
                return _error('DOCUMENT_LIMIT_EXCEEDED', 413)
        if not redactor.slot.acquire(blocking=False):
            return _error('DOCUMENT_BUSY', 429)
        deadline_at = time.monotonic() + 90
        cancel = threading.Event()
        try:
            raw = bytearray()
            with anyio.fail_after(30):
                async for chunk in request.stream():
                    if len(raw) + len(chunk) > MAX_FILE_BYTES:
                        return _error('DOCUMENT_LIMIT_EXCEEDED', 413)
                    raw.extend(chunk)
            result = await anyio.to_thread.run_sync(partial(redactor.redact, bytes(raw), query[0][1],
                deadline_at=deadline_at, cancel=cancel))
            # Revocation/expiry while parsing cannot release a late result.
            await auth.revalidate(context, source=_source(request))
            if time.monotonic() >= deadline_at:
                return _error('DOCUMENT_TIMEOUT', 504)
            return JSONResponse(content=result, headers=_SECURITY_HEADERS)
        except DocumentError as error:
            status = 504 if error.code == 'DOCUMENT_TIMEOUT' else 413 if error.code == 'DOCUMENT_LIMIT_EXCEEDED' else 422
            return _error(error.code, status)
        except SafetyError as error:
            if error.code == SafetyCode.SECRET_DETECTED:
                return _error('DOCUMENT_SECRET_DETECTED', 403)
            if error.code == SafetyCode.RESERVED_TOKEN_LITERAL:
                return _error('DOCUMENT_RESERVED_TOKEN', 422)
            if error.code == SafetyCode.INFERENCE_TIMEOUT:
                return _error('DOCUMENT_TIMEOUT', 504)
            return _error('DOCUMENT_DETECTION_UNAVAILABLE', 503)
        except SessionInvalid:
            return _error('ADMIN_SESSION_INVALID', 401)
        except AdminStorageUnavailable:
            return _error('ADMIN_STORAGE_UNAVAILABLE', 503)
        except TimeoutError:
            return _error('DOCUMENT_TIMEOUT', 504)
        except Exception:
            return _error('DOCUMENT_SERVICE_UNAVAILABLE', 503)
        finally:
            cancel.set()
            redactor.slot.release()
