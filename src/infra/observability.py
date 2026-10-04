"""A-07 observability whitelist: ordinary logs/metrics/errors/traces carry metadata only.

Contract (DESIGN §6/§8): routine observability records must never carry request
bodies, prompts, credentials, or employee content. The boundary is enforced
structurally, not by trusting authors:

1. Field whitelist — ``scan_record`` accepts ONLY the field names registered
   in :data:`FIELD_VALIDATORS`; any other key (including ``payload``,
   ``body``, ``prompt``, ``api_key``) is an ``OBSERVABILITY_VIOLATION``.
2. Value shape constraints — scalar types only. Containers (dict/list) are
   always rejected: a nested mapping is exactly how a body or credential
   bundle would smuggle past a name check.
3. String hygiene — string values must be short printable tokens/text:
   no control characters, no structural delimiters (``{}[]\\"``) that could
   hide a nested payload, length-capped per field. Long free text is treated
   as suspect, not logged.
4. Credential backstop — even inside an allowed field, values matching
   planted-secret shapes (PEM private key blocks, ``sk-``/``ak-`` style key
   tokens, ``password:``/``bearer`` patterns) are rejected. This layer is a
   tripwire, not a detector; the whitelist and shape rules are the boundary.

Known boundary, by design: a short free-text fragment (≤ 256 chars) without
structural delimiters can pass the ``message`` field — the contract is that
``message`` carries only short static catalog text chosen by the operator,
never submitted content. Tightening beyond that requires a static message
catalog, which is a deployment-time decision, not a scanner heuristic.

A positive control must exist (records planted with canary body/credentials
are caught) so the scanner cannot degrade into an always-pass stub.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Mapping

from infra.errors import SafetyCode, SafetyError

__all__ = ["ALLOWED_FIELDS", "scan_record", "scan_sanitized_error"]

# Tripwire patterns for planted secrets inside otherwise-allowed values.
_SECRET_PATTERNS = (
    re.compile(r"-----begin [a-z0-9 ]*private key-----", re.IGNORECASE),
    re.compile(r"\b(?:sk|ak)-[a-z0-9]{8,}\b", re.IGNORECASE),
    re.compile(r"\bpassword\b\s*[:=]", re.IGNORECASE),
    re.compile(r"\bbearer\s+[a-z0-9._\-]{8,}\b", re.IGNORECASE),
)

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_STRUCTURAL_DELIMITERS = frozenset("{}[]\"\\")
_ISO_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$"
)
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")

_MAX_TEXT_LEN = 256
_MAX_METRIC = 10**15
_LEVELS = frozenset({"debug", "info", "warning", "error", "critical"})


def _is_timestamp(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return 0 <= value <= 10**15
    return isinstance(value, str) and _ISO_TIMESTAMP_RE.fullmatch(value) is not None


def _is_token(value: Any) -> bool:
    return isinstance(value, str) and _SAFE_TOKEN_RE.fullmatch(value) is not None


def _is_level(value: Any) -> bool:
    return isinstance(value, str) and value in _LEVELS


def _is_text(value: Any) -> bool:
    """Safe human-readable text: printable, no nested-payload delimiters."""
    if not isinstance(value, str):
        return False
    if not value or len(value) > _MAX_TEXT_LEN:
        return False
    if _CONTROL_CHAR_RE.search(value):
        return False
    if any(ch in _STRUCTURAL_DELIMITERS for ch in value):
        return False
    return True


def _is_status_code(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 100 <= value <= 599


def _is_metric(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and 0 <= value <= _MAX_METRIC
    )


FIELD_VALIDATORS: dict[str, Callable[[Any], bool]] = {
    "timestamp": _is_timestamp,
    "level": _is_level,
    "event_code": _is_token,
    "error_code": _is_token,
    "component": _is_token,
    "domain": _is_token,
    "category": _is_token,
    "purpose": _is_token,
    "policy_version": _is_token,
    "package_version": _is_token,
    "intent_id": _is_token,
    "permit_id": _is_token,
    "record_id": _is_token,
    "status": _is_token,
    "status_code": _is_status_code,
    "message": _is_text,
    "count": _is_metric,
    "duration_ms": _is_metric,
    "retry_after": _is_token,
}

ALLOWED_FIELDS = frozenset(FIELD_VALIDATORS)


def _value_ok(field: str, value: Any) -> bool:
    if not FIELD_VALIDATORS[field](value):
        return False
    if isinstance(value, str):
        for pattern in _SECRET_PATTERNS:
            if pattern.search(value):
                return False
    return True


def scan_record(record: Mapping[str, Any]) -> tuple[tuple[str, Any], ...]:
    """Validate one flat observation record against the whitelist.

    Returns the validated entries on success. Raises
    ``SafetyError(OBSERVABILITY_VIOLATION)`` on any unknown field, wrong type,
    oversize/suspect string, container value, or planted secret shape. The
    detail is static text only: unknown field names are caller input and are
    never echoed; whitelisted (static) field names may be referenced.
    """
    if not isinstance(record, Mapping):
        raise TypeError("record must be a mapping")
    for key, value in record.items():
        if key not in FIELD_VALIDATORS:
            raise SafetyError(SafetyCode.OBSERVABILITY_VIOLATION, "field:unknown")
        if not _value_ok(key, value):
            raise SafetyError(SafetyCode.OBSERVABILITY_VIOLATION, f"value:{key}")
    return tuple(sorted(record.items()))


def scan_sanitized_error(response) -> tuple[tuple[str, Any], ...]:
    """Whitelist-check a P-13 sanitized error response before it is logged/traced.

    Maps the :class:`enterprise_gateway.error_sanitizer.SanitizedErrorResponse`
    onto whitelist fields (status code, controlled error code, safe message,
    approved pass-through headers) and scans the result, so the P-13 output
    contract and this whitelist cannot drift apart silently.
    """
    record: dict[str, Any] = {
        "status_code": response.status_code,
        "error_code": response.body["error"]["code"],
        "message": response.body["error"]["message"],
    }
    for name, value in response.headers.items():
        if name.lower() == "retry-after":
            record["retry_after"] = value
    return scan_record(record)
