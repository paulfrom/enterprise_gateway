"""Local review service: health plus explicit refusal; no upstream client exists."""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from .config import ReviewSettings


PRODUCTION_GATES = (
    "trusted_identity_and_data_policy",
    "admitted_protocol_and_provider",
    "validated_detection_pipeline",
    "durable_audit_and_key_lifecycle",
    "network_egress_and_release_evidence",
    "knowledge_consent_acl_and_retention",
)


def create_app(settings: ReviewSettings | None = None) -> FastAPI:
    settings = settings or ReviewSettings()
    app = FastAPI(title="Enterprise Privacy Gateway Review", docs_url=None,
                  redoc_url=None, openapi_url=None)
    app.state.settings = settings

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
    async def model_call() -> JSONResponse:
        # No body reads, raw-body logging, transport client or environment escape hatch.
        return JSONResponse(status_code=503, content={"error": {
            "code": "CHANNEL_NOT_ADMITTED",
            "message": "受保护渠道尚未通过准入验证，请求未外发。",
        }})

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

