"""Authenticated knowledge governance; bounded work on a separate admin domain."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from functools import partial
from datetime import datetime, timezone
from typing import Annotated, Any, Literal
import threading

from fastapi import Depends, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from psycopg.rows import dict_row

from gateway.admin_api import ADMIN_ERROR_CODES, write_dependency
from gateway.history_api import _error
from knowledge.governance import AdminActionContext, GovernanceError
from knowledge.storage import KnowledgeSchemaError
from knowledge.knowledge import KnowledgeError
from infra.strict_json import parse_strict_json

_OPS_LIMIT = 4
_PG_ACQUIRE_TIMEOUT = 5.0
_BLOCKING_CODES = frozenset({'GOVERNANCE_MISSING', 'GOVERNANCE_SUPERSEDED', 'AUDIENCE_DENIED',
    'PURPOSE_DENIED', 'SOURCE_EXPIRED', 'SOURCE_WITHDRAWN', 'PUBLICATION_REVOKED', 'EVIDENCE_UNAVAILABLE'})
_Text = Annotated[str, Field(strict=True, min_length=1, max_length=4096)]
_Limit = Annotated[int, Query(ge=1, le=100)]
_Cursor = Annotated[str | None, Query(max_length=512, pattern=r'^[\x20-\x7e]*$')]


class _Body(BaseModel):
    model_config = ConfigDict(extra='forbid')

    @field_validator('*')
    @classmethod
    def nonblank(cls, value):
        if isinstance(value, str) and not value.strip():
            raise ValueError('blank value')
        return value


class Basis(_Body):
    basis: _Text


class Withdraw(Basis):
    source_version: _Text


class Governance(Withdraw):
    expected_governance_version: _Text | None = None
    ownership: Literal['confirmed', 'unassigned']
    use: _Text
    audiences: Annotated[list[_Text], Field(min_length=1, max_length=100)]
    valid_until: datetime

    @field_validator('audiences')
    @classmethod
    def audience_names(cls, value):
        if any(not audience.strip() for audience in value):
            raise ValueError('blank audience')
        return value

    @field_validator('valid_until')
    @classmethod
    def aware(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('aware time required')
        return value


class Publish(Basis):
    expected_version: Annotated[int, Field(strict=True, ge=1)]
    use: _Text
    audiences: Annotated[list[_Text], Field(min_length=1, max_length=100)]
    valid_until: datetime
    idempotency_key: _Text | None = None
    _aware = field_validator('valid_until')(Governance.aware.__func__)
    _audiences = field_validator('audiences')(Governance.audience_names.__func__)


class Revise(Basis):
    modifications: dict[str, Any]

    @field_validator('modifications')
    @classmethod
    def modifications_valid(cls, value):
        if set(value) - {'acl', 'purpose'}:
            raise ValueError('unsupported modification')
        if 'acl' in value and (not isinstance(value['acl'], list) or not value['acl']
                or len(value['acl']) > 100 or any(not isinstance(x, str) or not x.strip() for x in value['acl'])):
            raise ValueError('invalid audience')
        if 'purpose' in value and (not isinstance(value['purpose'], str) or not value['purpose'].strip()):
            raise ValueError('invalid purpose')
        return value


def _failure(exc):
    if isinstance(exc, KnowledgeSchemaError):
        return _error('KNOWLEDGE_SCHEMA_INCOMPATIBLE', 503)
    if isinstance(exc, GovernanceError) and exc.code in ADMIN_ERROR_CODES:
        code = exc.code
        status = 404 if code.endswith('_NOT_FOUND') else 409 if ('CONFLICT' in code or code.endswith('VERSION_INVALID')) else 503 if code in {'KNOWLEDGE_ADMIN_UNAVAILABLE', 'AUDIT_WRITE_FAILED'} else 422
        error = {'code': code}
        reasons = getattr(exc, 'blocking_reasons', ())
        if reasons:
            error['blocking_reasons'] = [x for x in reasons if x in _BLOCKING_CODES]
        return JSONResponse(status_code=status, content={'error': error})
    if isinstance(exc, KnowledgeError):
        return _error('ADMIN_REQUEST_INVALID', 422)
    return _error('KNOWLEDGE_ADMIN_UNAVAILABLE', 503)


def install_knowledge_admin_routes(app, auth_service, governance):
    """Mount even when unconfigured so authenticated clients receive a fixed 503."""
    def guarded(authenticate):
        async def dependency(request: Request):
            context = await authenticate(request)
            if isinstance(governance, KnowledgeSchemaError):
                raise HTTPException(503, 'KNOWLEDGE_SCHEMA_INCOMPATIBLE')
            if governance is None:
                raise HTTPException(503, 'KNOWLEDGE_ADMIN_UNAVAILABLE')
            parts = request.url.path.rstrip('/').split('/')
            resource = parts[3]
            allowed = {'cursor', 'limit'} if len(parts) == 4 else set()
            if resource == 'sources':
                allowed |= {'status', 'use', 'audience'} if len(parts) == 4 else {'version'} if len(parts) == 5 else set()
            if resource in {'candidates', 'publications'}:
                allowed |= {'consumer', 'use'}
                if resource == 'candidates' and len(parts) == 4:
                    allowed |= {'state', 'source_id'}
            if request.method == 'POST':
                body = await request.body()
                if len(body) > 16384 or request.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
                    raise HTTPException(422, 'ADMIN_REQUEST_INVALID')
                def reject(_kind):
                    raise HTTPException(422, 'ADMIN_REQUEST_INVALID')
                parse_strict_json(body, reject=reject)
            pairs = request.query_params.multi_items()
            if (len(pairs) != len(dict(pairs)) or any(key not in allowed or not value.strip() for key, value in pairs)
                    or request.query_params.get('status', 'active') not in {'active', 'withdrawn', 'expired'}
                    or request.query_params.get('state', 'proposed') not in {'proposed', 'published', 'rejected', 'withdrawn'}):
                raise HTTPException(422, 'ADMIN_REQUEST_INVALID')
            return context
        return dependency
    require = guarded(auth_service.require_admin())
    write = guarded(write_dependency(auth_service))
    slots = threading.BoundedSemaphore(_OPS_LIMIT)
    executor = ThreadPoolExecutor(max_workers=_OPS_LIMIT, thread_name_prefix="admin-knowledge")
    app.state.admin_knowledge_executor = executor
    app.router.add_event_handler("shutdown", partial(executor.shutdown, wait=False, cancel_futures=True))

    def respond(call):
        if governance is None or not slots.acquire(blocking=False):
            return _error('KNOWLEDGE_ADMIN_UNAVAILABLE', 503)
        def work():
            try:
                return jsonable_encoder(call())
            finally:
                slots.release()
        try:
            future = executor.submit(work)
        except Exception:
            slots.release()
            return _error('KNOWLEDGE_ADMIN_UNAVAILABLE', 503)
        try:
            return future.result(timeout=_PG_ACQUIRE_TIMEOUT)
        except Exception as exc:
            return _failure(exc)

    def availability(row, kind, consumer, use):
        result = asdict(governance.evaluate_availability(
            candidate_id=str(row['candidate_id']) if kind == 'candidate' else None,
            publication_id=str(row['publication_id']) if kind == 'publication' else None,
            consumer=consumer, use=use, now=datetime.now(timezone.utc)))
        result['blocking_reasons'] = [code for code in result['blocking_reasons'] if code in _BLOCKING_CODES]
        return dict(row, availability=result)

    def listing(method, kind=None, consumer=None, evaluated_use=None, **kwargs):
        rows, cursor = getattr(governance, method)(**kwargs)
        if kind:
            rows = [availability(row, kind, consumer, evaluated_use) for row in rows]
        return {'items': rows, 'next_cursor': cursor}

    def detail(table, key, value, code, *, version=None, kind=None, consumer=None, use=None):
        storage = governance._storage
        with storage.admin_transaction(tenant_id=governance._tenant_id, domain=governance._domain) as conn:
            query = f'SELECT * FROM {table} WHERE tenant_id=%s AND domain=%s AND {key}=%s'
            params = [governance._tenant_id, governance._domain, value]
            if table == 'knowledge_sources':
                if version is not None:
                    query += ' AND version=%s'; params.append(version)
                query += ' ORDER BY observed_at DESC,version DESC'
            query += ' LIMIT 1'
            # Real PG uses dict rows; lightweight injected stores may expose execute only.
            if hasattr(conn, 'cursor'):
                with conn.cursor(row_factory=dict_row) as cur:
                    row = cur.execute(query, params).fetchone()
            else:
                row = conn.execute(query, params).fetchone()
        if row is None:
            raise GovernanceError(code)
        return {'item': availability(row, kind, consumer, use) if kind else row}

    def action(method, object_id, body, context, response):
        scope = AdminActionContext(actor_id='admin', session_digest=context.session_reference,
            tenant_id=governance._tenant_id, domain=governance._domain)
        result = getattr(governance, method)(object_id, context=scope, **body.model_dump())
        return response(result)

    @app.get('/api/admin/sources')
    def sources(status: str | None = None, use: str | None = None, audience: str | None = None,
                limit: _Limit = 50, cursor: _Cursor = None, context=Depends(require)):
        return respond(lambda: listing('list_sources', status=status, use=use, audience=audience, limit=limit, cursor=cursor))

    @app.get('/api/admin/sources/{source_id}')
    def source(source_id: str, version: str | None = None, context=Depends(require)):
        return respond(lambda: detail('knowledge_sources', 'source_id', source_id, 'KNOWLEDGE_SOURCE_NOT_FOUND', version=version))

    @app.get('/api/admin/candidates')
    def candidates(state: str | None = None, source_id: str | None = None, limit: _Limit = 50,
                   cursor: _Cursor = None, consumer: str | None = None, use: str | None = None, context=Depends(require)):
        return respond(lambda: listing('list_candidates', 'candidate', consumer, use, state=state, source_id=source_id, limit=limit, cursor=cursor))

    @app.get('/api/admin/candidates/{candidate_id}')
    def candidate(candidate_id: str, consumer: str | None = None, use: str | None = None, context=Depends(require)):
        return respond(lambda: detail('knowledge_candidates', 'candidate_id', candidate_id, 'KNOWLEDGE_CANDIDATE_NOT_FOUND', kind='candidate', consumer=consumer, use=use))

    @app.get('/api/admin/publications')
    def publications(limit: _Limit = 50, cursor: _Cursor = None, consumer: str | None = None,
                     use: str | None = None, context=Depends(require)):
        return respond(lambda: listing('list_publications', 'publication', consumer, use, limit=limit, cursor=cursor))

    @app.get('/api/admin/publications/{publication_id}')
    def publication(publication_id: str, consumer: str | None = None, use: str | None = None, context=Depends(require)):
        return respond(lambda: detail('knowledge_publications', 'publication_id', publication_id, 'KNOWLEDGE_PUBLICATION_NOT_FOUND', kind='publication', consumer=consumer, use=use))

    @app.get('/api/admin/observations')
    def observations(limit: _Limit = 50, cursor: _Cursor = None, context=Depends(require)):
        return respond(lambda: listing('list_observations', limit=limit, cursor=cursor))

    @app.get('/api/admin/observations/{observation_id}')
    def observation(observation_id: str, context=Depends(require)):
        return respond(lambda: detail('knowledge_observations', 'dedup_key', observation_id, 'KNOWLEDGE_SOURCE_NOT_FOUND'))

    @app.post('/api/admin/sources/{source_id}/governance')
    def confirm(source_id: str, body: Governance, context=Depends(write)):
        return respond(lambda: action('confirm_source_governance', source_id, body, context, lambda result: {'governance_version_id': result}))

    @app.post('/api/admin/sources/{source_id}/withdraw')
    def withdraw(source_id: str, body: Withdraw, context=Depends(write)):
        return respond(lambda: action('withdraw_source', source_id, body, context, lambda result: {'source_version': body.source_version, 'withdrawn': True}))

    @app.post('/api/admin/candidates/{candidate_id}/publish')
    def publish(candidate_id: str, body: Publish, context=Depends(write)):
        return respond(lambda: action('publish_candidate', candidate_id, body, context, lambda result: {'publication_id': result}))

    @app.post('/api/admin/candidates/{candidate_id}/reject')
    def reject(candidate_id: str, body: Basis, context=Depends(write)):
        return respond(lambda: action('reject_candidate', candidate_id, body, context, lambda result: {'rejected': True}))

    @app.post('/api/admin/candidates/{candidate_id}/revise')
    def revise(candidate_id: str, body: Revise, context=Depends(write)):
        return respond(lambda: action('revise_candidate', candidate_id, body, context, lambda result: {'candidate_id': result}))

    @app.post('/api/admin/publications/{publication_id}/revoke')
    def revoke(publication_id: str, body: Basis, context=Depends(write)):
        return respond(lambda: action('revoke_publication', publication_id, body, context, lambda result: {'revoked': True}))
