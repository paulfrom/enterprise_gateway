"""P-09 and P-10 bounded tool call parameter buffer and release verifier.

Enforces:
- P-09: Strict per-tool (64KB = 65536 bytes) and request-wide parameter size bounds.
- P-10: Complete parameter buffering, token restoration, strict JSON validation,
  and schema verification before any executable arguments are released. Zero release on failure.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping, NoReturn

from infra.errors import SafetyCode, SafetyError
from infra.strict_json import JsonRejectKind, parse_strict_json
from masking.mapping import MappingContext

MAX_SINGLE_TOOL_BYTES = 65536  # 64 KB
MAX_TOTAL_TOOL_BYTES = 262144  # 256 KB


def _reject_tool_json(kind: JsonRejectKind) -> NoReturn:
    if kind is JsonRejectKind.DUPLICATE_KEY:
        raise SafetyError(SafetyCode.DUPLICATE_JSON_KEY, "duplicate key in tool arguments")
    if kind is JsonRejectKind.INVALID_UTF8:
        raise SafetyError(SafetyCode.INVALID_UTF8, "invalid UTF-8 in tool arguments")
    raise SafetyError(SafetyCode.MALFORMED_JSON, "malformed JSON in tool arguments")


class BoundedToolCallBuffer:
    """Buffers, bounds, and verifies tool call arguments prior to release (P-09, P-10)."""

    def __init__(
        self,
        max_single_bytes: int = MAX_SINGLE_TOOL_BYTES,
        max_total_bytes: int = MAX_TOTAL_TOOL_BYTES,
    ) -> None:
        self.max_single_bytes = max_single_bytes
        self.max_total_bytes = max_total_bytes
        self._buffers: dict[str, bytearray] = {}
        self._tool_names: dict[str, str] = {}
        self._total_bytes: int = 0

    def register_tool(self, tool_id: str, name: str) -> None:
        """Register a new tool call invocation."""
        if not tool_id or not name:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "tool_id and name required")
        self._tool_names[tool_id] = name
        if tool_id not in self._buffers:
            self._buffers[tool_id] = bytearray()

    def feed_argument_delta(self, tool_id: str, delta: str | bytes) -> None:
        """Feed an incremental chunk of tool arguments for a specific tool call (P-09)."""
        if tool_id not in self._buffers:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, f"unregistered tool_id: {tool_id}")

        delta_bytes = delta.encode("utf-8") if isinstance(delta, str) else delta
        delta_len = len(delta_bytes)

        # 1. Check single tool budget (strict 65536 boundary)
        current_len = len(self._buffers[tool_id])
        if current_len + delta_len > self.max_single_bytes:
            raise SafetyError(
                SafetyCode.ADMISSION_LIMIT_EXCEEDED,
                f"tool {tool_id} argument size exceeded single-tool budget of {self.max_single_bytes} bytes",
            )

        # 2. Check total tool budget across request
        if self._total_bytes + delta_len > self.max_total_bytes:
            raise SafetyError(
                SafetyCode.ADMISSION_LIMIT_EXCEEDED,
                f"total tool arguments exceeded request budget of {self.max_total_bytes} bytes",
            )

        self._buffers[tool_id].extend(delta_bytes)
        self._total_bytes += delta_len

    def finalize_and_verify(
        self,
        tool_id: str,
        context: MappingContext,
        allowed_tools: Mapping[str, type | dict] | None = None,
    ) -> dict[str, Any]:
        """Verify, restore tokens, and validate schema before releasing arguments (P-10).

        Zero arguments are released if JSON parsing, token restoration, or
        schema verification fails.
        """
        if tool_id not in self._buffers:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, f"unknown tool_id: {tool_id}")
        context.require_active()

        tool_name = self._tool_names.get(tool_id, "")
        if allowed_tools is not None and tool_name not in allowed_tools:
            # Unknown tool fails closed
            raise SafetyError(
                SafetyCode.CONTRACT_VIOLATION,
                f"tool name '{tool_name}' is not in allowed tool whitelist",
            )

        raw_bytes = bytes(self._buffers[tool_id])
        try:
            raw_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SafetyError(SafetyCode.INVALID_UTF8, "corrupted tool arguments") from exc

        # 1. Parse strict JSON
        try:
            parsed = parse_strict_json(raw_text, reject=_reject_tool_json)
        except SafetyError:
            raise
        except Exception as exc:
            raise SafetyError(SafetyCode.MALFORMED_JSON, "invalid tool call arguments JSON") from exc

        if not isinstance(parsed, dict):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "tool arguments must be a JSON object")

        # 2. Restore any tokens within strings in the parsed arguments
        restored = self._restore_dict_tokens(parsed, context)

        # 3. Validate against schema if registered
        if allowed_tools is not None and tool_name in allowed_tools:
            expected_spec = allowed_tools[tool_name]
            self._validate_spec(restored, expected_spec)

        return restored

    def _restore_dict_tokens(self, data: Any, context: MappingContext) -> Any:
        if isinstance(data, str):
            return context.restore(data)
        elif isinstance(data, dict):
            return {k: self._restore_dict_tokens(v, context) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._restore_dict_tokens(item, context) for item in data]
        return data

    def _validate_spec(self, data: dict[str, Any], spec: Any) -> None:
        if isinstance(spec, dict) and "required" in spec:
            required = spec.get("required", [])
            for field in required:
                if field not in data:
                    raise SafetyError(
                        SafetyCode.CONTRACT_VIOLATION,
                        f"missing required parameter '{field}' for tool",
                    )
        elif hasattr(spec, "model_validate"):
            try:
                spec.model_validate(data)
            except Exception as exc:
                raise SafetyError(
                    SafetyCode.CONTRACT_VIOLATION,
                    f"tool parameters failed Pydantic schema validation: {exc}",
                ) from exc

    def cancel_tool(self, tool_id: str) -> None:
        """P-14: Clear resources for canceled tool call."""
        buf = self._buffers.pop(tool_id, None)
        if buf:
            self._total_bytes -= len(buf)
        self._tool_names.pop(tool_id, None)

    def cancel_all(self) -> None:
        """P-14: Clean up all tool buffers."""
        self._buffers.clear()
        self._tool_names.clear()
        self._total_bytes = 0
