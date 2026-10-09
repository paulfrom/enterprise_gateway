"""BYOK HTTP ingress with explicit trusted classification and protected routing."""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException
from fastapi.responses import StreamingResponse
import asyncio
import anyio
import hashlib
import threading
import time
import json

from infra.config import ReviewSettings
from infra.errors import SafetyCode, SafetyError
from masking.mapping import MappingContext
from protocol.identity import ByokAuthenticator
from gateway.provider_router import ProviderRouter
from gateway.pipeline import ProtectedPipeline
from gateway.client_compatibility import compatible_headers, compatible_payload
from infra.strict_json import parse_strict_json, JsonRejectKind
from typing import Callable


PRODUCTION_GATES = (
    "trusted_identity_and_data_policy",
    "admitted_protocol_and_provider",
    "validated_detection_pipeline",
    "durable_audit_and_key_lifecycle",
    "network_egress_and_release_evidence",
    "knowledge_consent_acl_and_retention",
)


def _render_safety_error(exc: SafetyError) -> JSONResponse:
    code = exc.code
    status_code = 400
    if code in (
        SafetyCode.MISSING_IDENTITY,
        SafetyCode.INVALID_IDENTITY,
        SafetyCode.AUTH_EXPIRED,
        SafetyCode.FUTURE_DATED_AUTH,
    ):
        status_code = 401
    elif code in (
        SafetyCode.ACCESS_DENIED,
        SafetyCode.UNAUTHORIZED_PURPOSE,
        SafetyCode.MISSING_REQUIRED_ROLE,
        SafetyCode.SCOPE_MISMATCH,
        SafetyCode.POLICY_REJECTED,
        SafetyCode.MISSING_CATEGORY,
        SafetyCode.UNKNOWN_CATEGORY,
        SafetyCode.CATEGORY_NOT_APPROVED,
        SafetyCode.SECRET_DETECTED,
    ):
        status_code = 403
    elif code in (
        SafetyCode.ADMISSION_LIMIT_EXCEEDED,
    ):
        status_code = 429
    elif code in (
        SafetyCode.UNSUPPORTED_PROTOCOL,
        SafetyCode.CONTRACT_VIOLATION,
        SafetyCode.PROTOCOL_VIOLATION,
        SafetyCode.MALFORMED_JSON,
        SafetyCode.DUPLICATE_JSON_KEY,
        SafetyCode.UNTRUSTED_HEADER_REJECTED,
        SafetyCode.RESERVED_TOKEN_LITERAL,
        SafetyCode.UNSAFE_REPLACEMENT,
    ):
        status_code = 400
    elif code in (SafetyCode.SPOOL_WRITE_FAILED, SafetyCode.AUDIT_WRITE_FAILED):
        status_code = 503
    elif code == SafetyCode.INFERENCE_TIMEOUT:
        status_code = 504
    else:
        status_code = 500

    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code.value, "message": "请求已根据安全规则拦截。"}},
    )


def create_app(
    settings: ReviewSettings | None = None,
    *,
    router: ProviderRouter | None = None,
    authenticator: ByokAuthenticator | None = None,
    classifier: Callable[[bytes], str] | None = None,
    hmac_key: bytes | None = None,
    history_store=None,
    client_profile: str = 'compatible',
) -> FastAPI:
    """BYOK ingress. Classification is supplied only by trusted server integration."""
    if client_profile not in ('compatible', 'strict'):
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, 'unknown client profile')
    settings = settings or ReviewSettings()
    app = FastAPI(title="Enterprise Privacy Gateway", docs_url=None,
                  redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.router = router
    app.state.authenticator = authenticator
    app.state.classifier = classifier
    app.state.hmac_key = hmac_key
    app.state.history_store = history_store
    app.state.client_profile = client_profile

    sensitive_headers = frozenset(
        {"authorization", "x-api-key", "cookie", "set-cookie", "proxy-authorization"}
    )

    @app.middleware("http")
    async def log_request_ingress(request: Request, call_next):
        client = f"{request.client.host}:{request.client.port}" if request.client else "unknown"
        headers_str = "\n".join(
            f"  {k}: {'<redacted>' if k.lower() in sensitive_headers else v}"
            for k, v in request.headers.items()
        )
        try:
            raw_body = await request.body()
            if raw_body:
                body_str = f"<{len(raw_body)} bytes, sha256={hashlib.sha256(raw_body).hexdigest()[:16]}>"
            else:
                body_str = ""
        except Exception as exc:
            body_str = f"<failed to read body: {exc}>"

        print(
            f"\n==================== [GATEWAY INGRESS REQUEST] ====================\n"
            f"Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}\n"
            f"Method: {request.method}\n"
            f"URL: {request.url.path}\n"
            f"Client: {client}\n"
            f"Headers:\n{headers_str if headers_str else '  (none)'}\n"
            f"Body: {body_str if body_str else '(empty)'}\n"
            f"===================================================================\n",
            flush=True,
        )
        return await call_next(request)

    def missing_gates():
        missing = []
        bound = app.state.router
        if not isinstance(bound, ProviderRouter):
            missing.append("admitted_protocol_and_provider")
        else:
            try:
                for model in bound.supported_models:
                    pipeline = bound.get_pipeline(model)
                    if not isinstance(pipeline, ProtectedPipeline):
                        raise ValueError("protected pipeline required")
                    if not pipeline.evidence_bucket or pipeline.spool_writer is None:
                        raise ValueError("durable collection required")
                    if pipeline.evidence_gate._evidence_directory is None or pipeline.evidence_gate._kms is None:
                        raise ValueError("encrypted evidence required")
                    probe = b'\x00' * 32
                    for kms, purpose, bucket in (
                        (pipeline.evidence_gate._kms, 'model-query', pipeline.evidence_bucket),
                        (pipeline.spool_writer._kms, 'knowledge-accumulation:knowledge-spool', 'standard-retention'),
                    ):
                        wrapped = kms.wrap(probe, purpose=purpose, bucket=bucket)
                        if kms.unwrap(wrapped, purpose=purpose, bucket=bucket) != probe:
                            raise ValueError("key lifecycle unavailable")
                    for directory in (pipeline.evidence_gate._intent_directory,
                                      pipeline.evidence_gate._evidence_directory,
                                      pipeline.spool_writer._directory):
                        if not directory.is_dir():
                            raise ValueError("durable directory unavailable")
                    pipeline.version_handle.manifest.require_complete()
                    pipeline.version_handle.manifest.verify_payloads(pipeline._component_payloads())
                    pipeline.watermark_guard.check_egress_permitted()
                    if pipeline.egress_client._client.is_closed or pipeline.detector._executor._closed:
                        raise ValueError("closed runtime")
                if getattr(app.state, 'runtime_closed', False):
                    raise ValueError("closed runtime")
            except Exception:
                missing.append("validated_protection_and_durable_resources")
        if not isinstance(app.state.authenticator, ByokAuthenticator):
            missing.append("restricted_source_context")
        if not callable(app.state.classifier):
            missing.append("trusted_data_classification")
        if not isinstance(app.state.hmac_key, bytes) or len(app.state.hmac_key) < 32:
            missing.append("durable_audit_and_key_lifecycle")
        if app.state.history_store is not None:
            try:
                app.state.history_store.check_ready()
            except Exception:
                missing.append('request_history_resources')
        return missing

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "alive", "profile": "local-review"}

    @app.get("/readyz")
    async def readiness() -> JSONResponse:
        missing = missing_gates()
        if missing:
            return JSONResponse(status_code=503, content={
                "ready": False,
                "code": "PRODUCTION_NOT_ADMITTED",
                "missing_gates": missing,
            })
        return JSONResponse(status_code=200, content={
            "ready": True, "scope": "protected-runtime", "production_admission": False,
        })

    @app.post("/v1/chat/completions")
    @app.post("/v1/messages")
    async def model_call(request: Request) -> JSONResponse:
        if not isinstance(app.state.router, ProviderRouter) or getattr(app.state, 'runtime_closed', False):
            return JSONResponse(status_code=503, content={"error": {"code": "CHANNEL_NOT_ADMITTED"}})
        if not callable(app.state.classifier):
            return JSONResponse(status_code=503, content={"error": {"code": "CLASSIFICATION_NOT_CONFIGURED"}})
        p = None
        headers = dict(request.headers)
        if client_profile == 'compatible':
            headers = compatible_headers(headers)
        if not isinstance(app.state.authenticator, ByokAuthenticator):
            return JSONResponse(
                status_code=401,
                content={"error": {"code": "MISSING_IDENTITY", "message": "缺少可信身份上下文。"}},
            )

        key = app.state.hmac_key
        cancel = threading.Event()
        context = None
        history_recorder = None
        def attach_request_id(response):
            if history_recorder is not None:
                response.headers['x-request-id'] = history_recorder.request_id
            return response
        async def record_failure(response, status, code):
            if history_recorder is not None:
                try:
                    await asyncio.to_thread(history_recorder.write, 'restored', response.body)
                    await asyncio.to_thread(history_recorder.finish, status, code)
                except Exception:
                    response = JSONResponse(status_code=503, content={'error': {'code': 'HISTORY_UNAVAILABLE'}})
            return attach_request_id(response)
        try:
            req_timeout = p.request_timeout if p is not None else 180.0
            deadline_at = time.monotonic() + req_timeout
            auth_count = sum(name.lower() == b'authorization' for name, _ in request.scope['headers'])
            x_api_count = sum(name.lower() == b'x-api-key' for name, _ in request.scope['headers'])
            if auth_count > 1 or x_api_count > 1:
                raise SafetyError(SafetyCode.INVALID_IDENTITY, 'ambiguous credential')
            identity = app.state.authenticator.authenticate(headers)
            if not isinstance(key, bytes) or len(key) < 32:
                raise SafetyError(SafetyCode.INVALID_HMAC_KEY)
            
            body_limit = p.body_limit if p is not None else 10485760 # 10MB default
            raw = bytearray()
            incoming = request.stream().__aiter__()
            while True:
                remaining = deadline_at - time.monotonic()
                if remaining <= 0: raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
                try: chunk = await asyncio.wait_for(anext(incoming), timeout=remaining)
                except StopAsyncIteration: break
                except TimeoutError: raise SafetyError(SafetyCode.INFERENCE_TIMEOUT) from None
                if len(raw) + len(chunk) > body_limit: raise SafetyError(SafetyCode.ADMISSION_LIMIT_EXCEEDED, 'body')
                raw.extend(chunk)
            raw_body = bytes(raw)

            def reject_json(kind):
                code = SafetyCode.DUPLICATE_JSON_KEY if kind == JsonRejectKind.DUPLICATE_KEY else SafetyCode.MALFORMED_JSON
                raise SafetyError(code)
            payload = parse_strict_json(raw_body, reject=reject_json)
            if not isinstance(payload, dict) or not isinstance(payload.get('model'), str):
                raise SafetyError(SafetyCode.MALFORMED_JSON)
            p = app.state.router.get_pipeline(payload['model'])
            if isinstance(p, ProtectedPipeline) and (p.detector._executor._closed or p.egress_client._client.is_closed):
                return JSONResponse(status_code=503, content={"error": {"code": "CHANNEL_NOT_ADMITTED"}})
            deadline_at = min(deadline_at, time.monotonic() + p.request_timeout)
            if len(raw_body) > p.body_limit:
                raise SafetyError(SafetyCode.ADMISSION_LIMIT_EXCEEDED)
            if p.path != request.url.path:
                raise SafetyError(SafetyCode.UNSUPPORTED_PROTOCOL, 'endpoint binding')
            processing_body = raw_body
            if client_profile == 'compatible':
                processing_body = json.dumps(compatible_payload(payload), ensure_ascii=False,
                                             separators=(',', ':')).encode('utf-8')
                if len(processing_body) > p.body_limit:
                    raise SafetyError(SafetyCode.ADMISSION_LIMIT_EXCEEDED)
            if app.state.history_store is not None:
                await asyncio.to_thread(app.state.history_store.check_ready)
                history_recorder = await asyncio.to_thread(app.state.history_store.begin,
                    protocol=p.protocol, model=payload['model'], raw_body=raw_body)
            category = app.state.classifier(raw_body)
            if not isinstance(category, str) or not category.strip():
                raise SafetyError(SafetyCode.POLICY_REJECTED)
            context = MappingContext(p.domain, 'v1', key)
            context.__enter__()
            work = asyncio.create_task(asyncio.to_thread(p.process_request,
                    raw_body=processing_body,
                    headers=headers,
                    identity=identity,
                    category=category,
                    context=context,
                    auto_collect=True,
                    deadline_at=deadline_at,
                    cancel=cancel,
                      history_recorder=history_recorder,
                ))
            try:
                while not work.done():
                    if await request.is_disconnected() or time.monotonic() >= deadline_at:
                        cancel.set()
                        await work
                        raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
                    await asyncio.wait({work},timeout=0.02)
                res = await work
            except BaseException:
                cancel.set()
                # A synchronous send may finish after the client disappeared.
                # Join the bounded worker and close any response it produced
                # before the StreamingResponse took ownership.
                with anyio.CancelScope(shield=True):
                    try:
                        abandoned = await asyncio.shield(work)
                    except BaseException:
                        pass
                    else:
                        if abandoned.upstream_stream is not None:
                            await asyncio.to_thread(abandoned.upstream_stream.close)
                raise
            if res.upstream_stream is not None:
                from gateway.streaming import PassthroughStream, iter_protected_stream
                client_model=res.client_model
                stream = PassthroughStream(protocol=res.protocol,expected_model=res.redacted_request.model,client_model=client_model,context=context,allowed_tools=res.allowed_tools,deadline_at=deadline_at,state_validator=res.state_validator,state_version=res.state_version,allowed_models=(frozenset(p.allowed_models) | {res.redacted_request.model}) if p is not None else None)
                upstream = res.upstream_stream
                iterator = upstream.iter_bytes()
                marker = object()
                async def source():
                    while True:
                        chunk = await asyncio.to_thread(next,iterator,marker)
                        if chunk is marker: break
                        yield chunk
                async def close():
                    cancel.set()
                    try: await asyncio.to_thread(upstream.close)
                    finally: context.__exit__(None,None,None)
                async def protected():
                    try:
                        async for chunk in iter_protected_stream(source(),stream,disconnected=request.is_disconnected,close=close,
                                                                history_recorder=history_recorder):
                            yield chunk
                    except Exception as exc:
                        from request_history.models import HistoryUnavailable
                        if isinstance(exc, HistoryUnavailable):
                            return
                        code = 'STREAM_PROTECTION_FAILED' if isinstance(exc, SafetyError) else 'STREAM_TRANSPORT_FAILED'
                        frame = ('event: error\ndata: {"error":{"code":"' + code + '"}}\n\n').encode()
                        if history_recorder is not None:
                            try:
                                await asyncio.to_thread(history_recorder.write, 'restored', frame,
                                    media_type='text/event-stream', state='partial', append=True)
                            except Exception:
                                stream._history_write_failed = True
                                return
                        yield frame
                    finally:
                        if (history_recorder is not None and not getattr(stream, '_history_success_committed', False)
                                and not getattr(stream, '_history_write_failed', False)
                                and getattr(stream, '_history_cleanup_succeeded', False)):
                            with anyio.CancelScope(shield=True):
                                try:
                                    await asyncio.to_thread(history_recorder.finish,
                                        getattr(stream, '_history_status', 'partial'),
                                        getattr(stream, '_history_error_code', 'STREAM_INTERRUPTED'))
                                except Exception:
                                    pass  # Persisted processing means the terminal outcome is unknown.
                return attach_request_id(StreamingResponse(protected(),media_type='text/event-stream'))
            else:
                context.__exit__(None,None,None)
                response = JSONResponse(
                    status_code=200,
                    content=res.response.model_dump(exclude_unset=True),
                )
                if history_recorder is not None:
                    await asyncio.to_thread(history_recorder.write, 'restored', response.body)
                    if time.monotonic() >= deadline_at or cancel.is_set():
                        raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
                    await asyncio.to_thread(history_recorder.finish, 'completed')
                    if time.monotonic() >= deadline_at or cancel.is_set():
                        return attach_request_id(Response(status_code=504))
                return attach_request_id(response)
        except SafetyError as exc:
            if context is not None: context.__exit__(None,None,None)
            return await record_failure(_render_safety_error(exc), 'blocked', exc.code.value)
        except Exception as exc:
            from gateway.pipeline import UpstreamFailure
            if context is not None: context.__exit__(None,None,None)
            if isinstance(exc,UpstreamFailure):
                return await record_failure(JSONResponse(status_code=exc.response.status_code,content=exc.response.body,headers=exc.response.headers),
                                            'failed', 'UPSTREAM_FAILURE')
            from request_history.models import HistoryUnavailable
            if isinstance(exc, HistoryUnavailable):
                return attach_request_id(JSONResponse(status_code=503, content={'error': {'code': 'HISTORY_UNAVAILABLE'}}))
            return await record_failure(JSONResponse(status_code=500,content={'error':{'code':'INTERNAL_FAILURE','message':'请求处理失败，已停止。'}}),
                                        'failed', 'INTERNAL_FAILURE')
        except BaseException:
            cancel.set()
            if context is not None: context.__exit__(None,None,None)
            raise

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        # Default FastAPI validation responses embed the submitted input; never echo it.
        return JSONResponse(status_code=422, content={"error": {
            "code": "INVALID_REQUEST", "message": "请求不符合契约，已拒绝。",
        }})

    @app.exception_handler(HTTPException)
    async def route_error(_request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"error": {
            "code": "UNSUPPORTED_ENDPOINT", "message": "该端点或方法未获准。",
        }})

    @app.exception_handler(Exception)
    async def internal_error(_request: Request, _exc: Exception) -> JSONResponse:
        return JSONResponse(status_code=500, content={"error": {
            "code": "INTERNAL_FAILURE", "message": "请求处理失败，已停止。",
        }})

    return app


app = create_app()
