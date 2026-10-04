"""Local review service: health plus explicit refusal; no upstream client exists."""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from infra.config import ReviewSettings
from infra.errors import SafetyCode, SafetyError
from masking.mapping import MappingContext
from protocol.identity import TrustedIdentity


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
        SafetyCode.RATE_LIMITED,
        SafetyCode.ADMISSION_BODY_TOO_LARGE,
        SafetyCode.ADMISSION_CONCURRENCY_EXCEEDED,
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
    ):
        status_code = 400
    elif code in (SafetyCode.SPOOL_WRITE_FAILED, SafetyCode.AUDIT_WRITE_FAILED):
        status_code = 503
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
    trusted_identity: TrustedIdentity | None = None,
    hmac_key: bytes | None = None,
) -> FastAPI:
    settings = settings or ReviewSettings()
    app = FastAPI(title="Enterprise Privacy Gateway Review", docs_url=None,
                  redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.deepseek_pipeline = deepseek_pipeline
    app.state.claude_pipeline = claude_pipeline
    app.state.pipeline = pipeline
    app.state.trusted_identity = trusted_identity
    app.state.hmac_key = hmac_key

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "alive", "profile": "local-review"}

    @app.get("/readyz")
    async def readiness() -> JSONResponse:
        return JSONResponse(status_code=503, content={
            "ready": False, "code": "PRODUCTION_NOT_ADMITTED",
            "missing_gates": list(PRODUCTION_GATES),
        })

    @app.post("/v1/chat/completions")
    @app.post("/v1/messages")
    async def model_call(request: Request) -> JSONResponse:
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

        raw_body = await request.body()
        headers = dict(request.headers)
        identity = getattr(request.state, "identity", None) or app.state.trusted_identity
        if identity is None:
            return JSONResponse(
                status_code=401,
                content={"error": {"code": "MISSING_IDENTITY", "message": "缺少可信身份上下文。"}},
            )

        key = app.state.hmac_key or b"0123456789abcdef0123456789abcdef"
        try:
            with MappingContext(p.domain, "v1", key) as context:
                res = p.process_request(
                    raw_body=raw_body,
                    headers=headers,
                    identity=identity,
                    category="STANDARD",
                    context=context,
                    auto_collect=True,
                )
                return JSONResponse(
                    status_code=200,
                    content=res.response.model_dump(),
                )
        except SafetyError as exc:
            return _render_safety_error(exc)

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

