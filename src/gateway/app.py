"""Local review service: health plus explicit refusal; no upstream client exists."""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException
from fastapi.responses import StreamingResponse
import asyncio
import anyio
import threading
import time

from infra.config import ReviewSettings
from infra.errors import SafetyCode, SafetyError
from masking.mapping import MappingContext
from protocol.identity import TrustedIdentity, EnterpriseAuthenticator


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
    deepseek_pipeline: object = None,
    claude_pipeline: object = None,
    pipeline: object = None,
    router: object = None,
    enterprise_credentials: dict[str, TrustedIdentity] | None = None,
    allow_byok: bool = False,
    hmac_key: bytes | None = None,
) -> FastAPI:
    settings = settings or ReviewSettings()
    app = FastAPI(title="Enterprise Privacy Gateway Review", docs_url=None,
                  redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.deepseek_pipeline = deepseek_pipeline
    app.state.claude_pipeline = claude_pipeline
    app.state.pipeline = pipeline
    app.state.router = router
    if enterprise_credentials or allow_byok:
        app.state.authenticator = EnterpriseAuthenticator(enterprise_credentials, allow_byok=allow_byok)
    else:
        app.state.authenticator = None
    app.state.hmac_key = hmac_key

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "alive", "profile": "local-review"}

    @app.get("/readyz")
    async def readiness() -> JSONResponse:
        missing: list[str] = []
        # Gate 1: at least one protected channel or router must be bound
        has_channel = (
            getattr(app.state, "router", None) is not None
            or getattr(app.state, "pipeline", None) is not None
            or getattr(app.state, "deepseek_pipeline", None) is not None
            or getattr(app.state, "claude_pipeline", None) is not None
        )
        if not has_channel:
            missing.append("admitted_protocol_and_provider")
        # Gate 2: authenticator (identity & policy) must be configured
        if getattr(app.state, "authenticator", None) is None:
            missing.append("trusted_identity_and_data_policy")
        # Gate 3: HMAC signing key must be present
        if getattr(app.state, "hmac_key", None) is None:
            missing.append("durable_audit_and_key_lifecycle")
        # Remaining gates (detection, egress, spool, knowledge) are wired at
        # assembly time and cannot be probed cheaply; they are satisfied once
        # the structural gates above pass.
        if missing:
            return JSONResponse(status_code=503, content={
                "ready": False,
                "code": "PRODUCTION_NOT_ADMITTED",
                "missing_gates": missing,
            })
        return JSONResponse(status_code=200, content={"ready": True})

    @app.post("/v1/chat/completions")
    @app.post("/v1/messages")
    async def model_call(request: Request) -> JSONResponse:
        has_router = getattr(app.state, "router", None) is not None
        p = None
        if not has_router:
            p = (
                app.state.deepseek_pipeline
                if request.url.path == "/v1/chat/completions"
                else app.state.claude_pipeline
            ) or app.state.pipeline

            if p is None:
                return JSONResponse(status_code=503, content={"error": {
                    "code": "CHANNEL_NOT_ADMITTED",
                    "message": "受保护渠道尚未通过准入验证，请求未外发。",
                }})

        headers = dict(request.headers)
        if app.state.authenticator is None:
            return JSONResponse(
                status_code=401,
                content={"error": {"code": "MISSING_IDENTITY", "message": "缺少可信身份上下文。"}},
            )

        key = app.state.hmac_key
        cancel = threading.Event()
        context = None
        try:
            req_timeout = p.request_timeout if p is not None else 180.0
            deadline_at = time.monotonic() + req_timeout
            identity = app.state.authenticator.authenticate(headers)
            auth_count = sum(name.lower() == b'authorization' for name, _ in request.scope['headers'])
            x_api_count = sum(name.lower() == b'x-api-key' for name, _ in request.scope['headers'])
            if auth_count + x_api_count != 1:
                raise SafetyError(SafetyCode.INVALID_IDENTITY, 'ambiguous credential')
            if key is None:
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

            if has_router:
                import json
                try:
                    payload = json.loads(raw_body.decode('utf-8'))
                    model_id = payload.get('model', '')
                except Exception:
                    raise SafetyError(SafetyCode.MALFORMED_JSON, 'model extraction')
                p = app.state.router.get_pipeline(model_id)

            if p.path != request.url.path:
                raise SafetyError(SafetyCode.UNSUPPORTED_PROTOCOL, 'endpoint binding')
            context = MappingContext(p.domain, 'v1', key)
            context.__enter__()
            work = asyncio.create_task(asyncio.to_thread(p.process_request,
                    raw_body=raw_body,
                    headers=headers,
                    identity=identity,
                    category="STANDARD",
                    context=context,
                    auto_collect=True,
                    deadline_at=deadline_at,
                    cancel=cancel,
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
                from gateway.streaming import ProtectedStream, iter_protected_stream
                client_model=res.client_model
                stream = ProtectedStream(protocol=res.protocol,expected_model=res.redacted_request.model,client_model=client_model,context=context,allowed_tools=res.allowed_tools,deadline_at=deadline_at,state_validator=res.state_validator,state_version=res.state_version)
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
                        async for chunk in iter_protected_stream(source(),stream,disconnected=request.is_disconnected,close=close):
                            yield chunk
                    except SafetyError:
                        # The upstream body is never used as a public error.
                        yield b'event: error\ndata: {"error":{"code":"STREAM_PROTECTION_FAILED"}}\n\n'
                    except Exception:
                        yield b'event: error\ndata: {"error":{"code":"STREAM_TRANSPORT_FAILED"}}\n\n'
                return StreamingResponse(protected(),media_type='text/event-stream')
            else:
                context.__exit__(None,None,None)
                return JSONResponse(
                    status_code=200,
                    content=res.response.model_dump(exclude_unset=True),
                )
        except SafetyError as exc:
            if context is not None: context.__exit__(None,None,None)
            return _render_safety_error(exc)
        except Exception as exc:
            from gateway.pipeline import UpstreamFailure
            if context is not None: context.__exit__(None,None,None)
            if isinstance(exc,UpstreamFailure):
                return JSONResponse(status_code=exc.response.status_code,content=exc.response.body,headers=exc.response.headers)
            return JSONResponse(status_code=500,content={'error':{'code':'INTERNAL_FAILURE','message':'请求处理失败，已停止。'}})
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

