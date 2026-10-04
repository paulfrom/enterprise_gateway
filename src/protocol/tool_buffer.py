"""P-09 and P-10 bounded tool call parameter buffer and release verifier.

Enforces:
- P-09: Strict per-tool (64KB = 65536 bytes) and request-wide parameter size bounds.
- P-10: Complete parameter buffering, token restoration, strict JSON validation,
  and schema verification before any executable arguments are released. Zero release on failure.
"""

from __future__ import annotations

import json
from typing import Any, Mapping, NoReturn

from jsonschema import validators, exceptions
from referencing.exceptions import Unresolvable

from infra.errors import SafetyCode, SafetyError
from infra.strict_json import JsonRejectKind, parse_strict_json
from masking.mapping import MappingContext
from masking.mapping import check_text

MAX_SINGLE_TOOL_BYTES = 65536  # 64 KB
MAX_TOTAL_TOOL_BYTES = 262144  # 256 KB
MAX_TOOL_CALLS = 128


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
        if type(max_single_bytes) is not int or type(max_total_bytes) is not int or max_single_bytes <= 0 or max_total_bytes <= 0:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "invalid tool byte budgets")
        self.max_single_bytes = max_single_bytes
        self.max_total_bytes = max_total_bytes
        self._buffers: dict[str, bytearray] = {}
        self._tool_names: dict[str, str] = {}
        self._total_bytes: int = 0
        self._restored_sizes: dict[str, int] = {}

    def register_tool(self, tool_id: str, name: str) -> None:
        """Register a new tool call invocation."""
        if not tool_id or not name:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "tool_id and name required")
        check_text(tool_id)
        check_text(name)
        if len(self._tool_names) >= MAX_TOOL_CALLS:
            raise SafetyError(SafetyCode.ADMISSION_LIMIT_EXCEEDED, "tool invocation count exceeded")
        if tool_id in self._tool_names:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "duplicate tool invocation")
        self._tool_names[tool_id] = name
        if tool_id not in self._buffers:
            self._buffers[tool_id] = bytearray()

    def feed_argument_delta(self, tool_id: str, delta: str | bytes) -> None:
        """Feed an incremental chunk of tool arguments for a specific tool call (P-09)."""
        if tool_id not in self._buffers:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "unregistered tool invocation")
        if tool_id in self._restored_sizes:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "arguments after tool completion")

        if isinstance(delta, str):
            check_text(delta)
        elif not isinstance(delta, bytes):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "tool argument delta must be text or bytes")
        delta_bytes = delta.encode("utf-8") if isinstance(delta, str) else delta
        delta_len = len(delta_bytes)

        # 1. Check single tool budget (strict 65536 boundary)
        current_len = len(self._buffers[tool_id])
        if current_len + delta_len > self.max_single_bytes:
            raise SafetyError(
                SafetyCode.ADMISSION_LIMIT_EXCEEDED,
                "tool argument size exceeded single-tool budget",
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
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "unknown tool invocation")
        context.require_active()

        tool_name = self._tool_names.get(tool_id, "")
        if allowed_tools is not None and tool_name not in allowed_tools:
            # Unknown tool fails closed
            raise SafetyError(
                SafetyCode.CONTRACT_VIOLATION,
                "tool not in whitelist",
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
        if allowed_tools is None:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "tool schema required before release")

        size = len(json.dumps(restored, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        other_size = sum(self._restored_sizes.values()) - self._restored_sizes.get(tool_id, 0)
        # Every unfinished call retains its encoded budget; restored expansion
        # cannot consume the capacity reserved by another call.
        pending_size = sum(len(buf) for key, buf in self._buffers.items() if key != tool_id and key not in self._restored_sizes)
        if size > self.max_single_bytes or other_size + pending_size + size > self.max_total_bytes:
            raise SafetyError(SafetyCode.ADMISSION_LIMIT_EXCEEDED, "restored tool arguments exceed budget")

        # 3. Validate against schema if registered
        if allowed_tools is not None and tool_name in allowed_tools:
            expected_spec = allowed_tools[tool_name]
            self._validate_spec(restored, expected_spec)
        self._restored_sizes[tool_id] = size
        return restored

    def _restore_dict_tokens(self, data: Any, context: MappingContext) -> Any:
        if isinstance(data, str):
            return context.restore(data)
        elif isinstance(data, dict):
            for key in data:
                if context.restore(key) != key:
                    raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "token in tool argument key")
            return {k: self._restore_dict_tokens(v, context) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._restore_dict_tokens(item, context) for item in data]
        return data

    def _validate_spec(self, data: dict[str, Any], spec: Any) -> None:
        if isinstance(spec, dict):
            # No remote schema resolution, which would introduce an unbound
            # network path. Local references use the standard validator.
            def check_refs(value: Any) -> None:
                if isinstance(value, dict):
                    for key, item in value.items():
                        if key in ("$ref", "$dynamicRef") and (not isinstance(item, str) or not item.startswith("#")):
                            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "external tool schema reference")
                        check_refs(item)
                elif isinstance(value, list):
                    for item in value:
                        check_refs(item)
            check_refs(spec)
            try:
                validator = validators.validator_for(spec, default=None) if "$schema" in spec else validators.Draft202012Validator
                if validator is None:
                    raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "unsupported tool schema dialect")
                validator.check_schema(spec)
                validator(spec).validate(data)
            except (exceptions.ValidationError, exceptions.SchemaError, Unresolvable, RecursionError):
                raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "tool JSON Schema validation failed") from None
        elif hasattr(spec, "model_validate"):
            try:
                spec.model_validate(data)
            except Exception:
                raise SafetyError(
                    SafetyCode.CONTRACT_VIOLATION,
                    "tool parameters failed Pydantic schema validation",
                ) from None
        else:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "unsupported tool schema")

    def cancel_tool(self, tool_id: str) -> None:
        """P-14: Clear resources for canceled tool call."""
        buf = self._buffers.pop(tool_id, None)
        if buf:
            self._total_bytes -= len(buf)
        self._tool_names.pop(tool_id, None)
        self._restored_sizes.pop(tool_id, None)

    def cancel_all(self) -> None:
        """P-14: Clean up all tool buffers."""
        self._buffers.clear()
        self._tool_names.clear()
        self._total_bytes = 0
        self._restored_sizes.clear()
