"""Authenticated dictionary editing, with CSRF and scoped revision checks."""
from __future__ import annotations

from functools import partial
import re
import uuid

import anyio
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from detection.dictionary_store import (
    DictionaryEdit, DictionaryError, DictionaryPage, DictionaryRevisionRequest,
    DictionaryState, DictionaryVersions,
)
from gateway.admin_api import write_dependency
from gateway.admin_auth import AdminContext
from gateway.admin_contract import ERROR_RESPONSES
from gateway.admin_storage import AdminStorageUnavailable, SessionInvalid
from gateway.history_api import _SECURITY_HEADERS, _error, _source
from infra.errors import SafetyError
from infra.strict_json import parse_strict_json

BASE = '/api/admin/dictionary'
QUERY = {'parameters': [{'name': name, 'in': 'query', 'required': False, 'schema': schema}
    for name, schema in {
        'query': {'type': 'string', 'maxLength': 512},
        'entity_type': {'type': 'string', 'pattern': '^[A-Z][A-Z0-9_]{0,31}$'},
        'enabled': {'type': 'boolean'},
        'offset': {'type': 'integer', 'minimum': 0, 'maximum': 20000, 'default': 0},
        'limit': {'type': 'integer', 'minimum': 1, 'maximum': 100, 'default': 50},
    }.items()]}


def body_contract(model):
    return {'requestBody': {'required': True, 'content': {
        'application/json': {'schema': model.model_json_schema()}}}}


def parse_query(request):
    pairs = list(request.query_params.multi_items())
    if len({key for key, _ in pairs}) != len(pairs) or any(
            key not in {'query', 'entity_type', 'enabled', 'offset', 'limit'} for key, _ in pairs):
        raise ValueError()
    params = dict(pairs)
    query = params.get('query', '')
    entity_type = params.get('entity_type')
    enabled = params.get('enabled')
    if len(query) > 512 or (entity_type is not None and re.fullmatch(r'[A-Z][A-Z0-9_]{0,31}', entity_type) is None):
        raise ValueError()
    if enabled not in (None, 'true', 'false'):
        raise ValueError()
    numbers = []
    for name, default, maximum in (('offset', '0', 20000), ('limit', '50', 100)):
        raw = params.get(name, default)
        if not raw.isascii() or not raw.isdigit() or len(raw) > 5:
            raise ValueError()
        value = int(raw)
        if not (0 if name == 'offset' else 1) <= value <= maximum:
            raise ValueError()
        numbers.append(value)
    return dict(query=query, entity_type=entity_type, enabled=None if enabled is None else enabled == 'true',
                offset=numbers[0], limit=numbers[1])


async def parse_body(request, model):
    if request.query_params or request.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
        raise ValueError()
    if request.headers.get('content-encoding', 'identity') != 'identity':
        raise ValueError()
    raw = bytearray()
    with anyio.fail_after(10):
        async for chunk in request.stream():
            if len(raw) + len(chunk) > 8192:
                raise ValueError()
            raw.extend(chunk)
    def reject(_kind):
        raise ValueError()
    return model.model_validate(parse_strict_json(bytes(raw), reject=reject))


def install_dictionary_routes(app: FastAPI, auth):
    if not hasattr(app.state, 'dictionary_service'):
        app.state.dictionary_service = None
    require_read = auth.require_admin()
    require_write = write_dependency(auth)
    limiter = anyio.CapacityLimiter(2)

    async def execute(request, context, operation):
        try:
            service = app.state.dictionary_service
            if service is None or getattr(app.state, 'runtime_closed', False):
                raise DictionaryError()
            if service.scope != context.scope:
                raise DictionaryError('DICTIONARY_SCOPE_REJECTED')
            await auth.revalidate(context, source=_source(request))
            value = await operation(service, limiter)
            await auth.revalidate(context, source=_source(request))
            return JSONResponse(content=value.model_dump(mode='json'), headers=_SECURITY_HEADERS)
        except DictionaryError as error:
            status = {'DICTIONARY_SCOPE_REJECTED': 403, 'DICTIONARY_ENTRY_NOT_FOUND': 404,
                      'DICTIONARY_REVISION_CONFLICT': 409, 'DICTIONARY_ENTRY_CONFLICT': 409,
                      'DICTIONARY_EMPTY_PUBLICATION': 422, 'DICTIONARY_LIMIT_EXCEEDED': 422}.get(error.code, 503)
            return _error(error.code, status)
        except SessionInvalid:
            return _error('ADMIN_SESSION_INVALID', 401)
        except AdminStorageUnavailable:
            return _error('ADMIN_STORAGE_UNAVAILABLE', 503)
        except (ValueError, ValidationError, SafetyError, TimeoutError):
            return _error('ADMIN_REQUEST_INVALID', 422)
        except Exception:
            return _error('DICTIONARY_UNAVAILABLE', 503)

    @app.get(BASE, response_model=DictionaryPage, responses=ERROR_RESPONSES, openapi_extra=QUERY)
    async def entries(request: Request, context: AdminContext = Depends(require_read)):
        async def operation(service, limiter):
            return await anyio.to_thread.run_sync(partial(service.store.list_entries, **parse_query(request)), limiter=limiter)
        return await execute(request, context, operation)

    @app.get(BASE + '/versions', response_model=DictionaryVersions, responses=ERROR_RESPONSES)
    async def versions(request: Request, context: AdminContext = Depends(require_read)):
        async def operation(service, limiter):
            if request.query_params:
                raise ValueError()
            return await anyio.to_thread.run_sync(service.store.versions, limiter=limiter)
        return await execute(request, context, operation)

    async def edit(request, context, entry_id=None):
        async def operation(service, limiter):
            if entry_id is not None:
                uuid.UUID(entry_id)
            body = await parse_body(request, DictionaryEdit)
            await auth.revalidate(context, source=_source(request))
            return await anyio.to_thread.run_sync(partial(service.store.edit, body, context.actor_id, entry_id), limiter=limiter)
        return await execute(request, context, operation)

    @app.post(BASE + '/entries', response_model=DictionaryState, responses=ERROR_RESPONSES,
              openapi_extra=body_contract(DictionaryEdit))
    async def create_entry(request: Request, context: AdminContext = Depends(require_write)):
        return await edit(request, context)

    @app.post(BASE + '/entries/{entry_id}', response_model=DictionaryState, responses=ERROR_RESPONSES,
              openapi_extra=body_contract(DictionaryEdit))
    async def update_entry(entry_id: str, request: Request, context: AdminContext = Depends(require_write)):
        return await edit(request, context, entry_id)

    @app.post(BASE + '/entries/{entry_id}/delete', response_model=DictionaryState, responses=ERROR_RESPONSES,
              openapi_extra=body_contract(DictionaryRevisionRequest))
    async def delete_entry(entry_id: str, request: Request, context: AdminContext = Depends(require_write)):
        async def operation(service, limiter):
            uuid.UUID(entry_id)
            body = await parse_body(request, DictionaryRevisionRequest)
            await auth.revalidate(context, source=_source(request))
            return await anyio.to_thread.run_sync(partial(service.store.delete, entry_id, body.expected_revision, context.actor_id), limiter=limiter)
        return await execute(request, context, operation)

    @app.post(BASE + '/publish', response_model=DictionaryState, responses=ERROR_RESPONSES,
              openapi_extra=body_contract(DictionaryRevisionRequest))
    async def publish(request: Request, context: AdminContext = Depends(require_write)):
        async def operation(service, limiter):
            body = await parse_body(request, DictionaryRevisionRequest)
            await auth.revalidate(context, source=_source(request))
            return await anyio.to_thread.run_sync(partial(service.publish, body.expected_revision, context.actor_id), limiter=limiter)
        return await execute(request, context, operation)
