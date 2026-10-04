"""Shared strict JSON parsing for trusted contract documents.

Parser-level failures (bad UTF-8, malformed JSON, duplicate keys, non-standard
constants, excessive nesting) are reported through the caller-supplied
``reject`` callback as :class:`JsonRejectKind` values; each contract module
maps them onto its own SafetyCode semantics and raises. This module never
raises contract errors itself and never sees document schemas.

``reject`` is always invoked outside of any active exception handling, so the
exception it raises carries no ``__context__``/``__cause__`` chain back to
parser exceptions that embed submitted document text.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any, Callable, NoReturn


class JsonRejectKind(StrEnum):
    INVALID_UTF8 = "INVALID_UTF8"
    MALFORMED_JSON = "MALFORMED_JSON"
    DUPLICATE_KEY = "DUPLICATE_KEY"
    NESTING_TOO_DEEP = "NESTING_TOO_DEEP"


def parse_strict_json(
    source: str | bytes, *, reject: Callable[[JsonRejectKind], NoReturn]
) -> Any:
    """Parse JSON text with unique-key and constant rejection.

    ``reject`` is invoked with the failure kind for every parser-level failure
    and must raise; it is never invoked with submitted document content.
    """
    if isinstance(source, bytes):
        decode_failed = False
        text = ""
        try:
            text = source.decode("utf-8")
        except UnicodeDecodeError:
            decode_failed = True
        if decode_failed:
            reject(JsonRejectKind.INVALID_UTF8)
    else:
        text = source

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                reject(JsonRejectKind.DUPLICATE_KEY)
            result[key] = value
        return result

    def reject_constant(value: str) -> NoReturn:
        reject(JsonRejectKind.MALFORMED_JSON)

    failure: JsonRejectKind | None = None
    try:
        return json.loads(
            text, object_pairs_hook=unique_pairs, parse_constant=reject_constant
        )
    except json.JSONDecodeError:
        failure = JsonRejectKind.MALFORMED_JSON
    except RecursionError:
        failure = JsonRejectKind.NESTING_TOO_DEEP
    reject(failure)
