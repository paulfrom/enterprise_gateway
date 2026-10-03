"""Upstream error sanitizer and response mapper (P-13).

Purges raw error bodies, credentials, prompts, internal IPs, and stack traces
emitted by upstream providers or proxy layers. Preserves authorized status codes
and safe flow-control headers (e.g. Retry-After) while mapping errors to standard,
controlled enterprise gateway responses.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping


# Standard safe mapping from HTTP status codes to controlled error codes and safe messages
_SAFE_ERROR_MAPPINGS: dict[int, tuple[str, str]] = {
    400: ("UPSTREAM_BAD_REQUEST", "上游服务拒绝了请求。"),
    401: ("UPSTREAM_AUTH_FAILURE", "上游服务认证失败。"),
    403: ("UPSTREAM_ACCESS_DENIED", "上游服务访问被拒绝。"),
    404: ("UPSTREAM_NOT_FOUND", "请求的上游模型或资源不存在。"),
    408: ("UPSTREAM_TIMEOUT", "上游服务请求超时。"),
    413: ("UPSTREAM_PAYLOAD_TOO_LARGE", "请求载荷超出上游模型处理限制。"),
    429: ("UPSTREAM_RATE_LIMITED", "上游模型服务触发限流，请稍后重试。"),
    500: ("UPSTREAM_INTERNAL_ERROR", "上游模型服务遇到内部故障。"),
    502: ("UPSTREAM_BAD_GATEWAY", "上游网关连接异常。"),
    503: ("UPSTREAM_SERVICE_UNAVAILABLE", "上游模型服务暂不可用。"),
    504: ("UPSTREAM_GATEWAY_TIMEOUT", "上游网关响应超时。"),
}

_SAFE_PASS_THROUGH_HEADERS = frozenset({"retry-after"})


@dataclass(frozen=True, slots=True)
class SanitizedErrorResponse:
    """A sanitized error representation safe for delivery to callers."""

    status_code: int
    headers: dict[str, str]
    body: dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(self.body, ensure_ascii=False)


class ErrorSanitizer:
    """Sanitizes upstream error responses before client delivery."""

    @staticmethod
    def sanitize(
        upstream_status: int,
        upstream_headers: Mapping[str, str] | None = None,
        upstream_raw_body: str | bytes | None = None,
    ) -> SanitizedErrorResponse:
        # Determine status code
        status = upstream_status if isinstance(upstream_status, int) and 400 <= upstream_status < 600 else 502

        # Extract only approved flow-control headers (case-insensitive)
        safe_headers: dict[str, str] = {}
        if upstream_headers:
            for k, v in upstream_headers.items():
                if isinstance(k, str) and k.lower() in _SAFE_PASS_THROUGH_HEADERS and isinstance(v, str):
                    safe_headers[k.lower()] = v.strip()

        # Resolve controlled code and safe message; raw upstream body is completely discarded!
        code, message = _SAFE_ERROR_MAPPINGS.get(
            status, ("UPSTREAM_FAILURE", "上游模型调用失败，已安全终止。")
        )

        controlled_body = {
            "error": {
                "code": code,
                "message": message,
            }
        }

        return SanitizedErrorResponse(
            status_code=status,
            headers=safe_headers,
            body=controlled_body,
        )
