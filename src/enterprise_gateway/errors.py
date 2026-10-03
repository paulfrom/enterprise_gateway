"""Controlled failure types and their code registry.

Codes are the contract: tests and callers reference enum members, never
free-form strings. Public messages never contain business text.
"""

from enum import StrEnum


class SafetyCode(StrEnum):
    INVALID_SCOPE = "INVALID_SCOPE"
    INVALID_CLASSIFICATION = "INVALID_CLASSIFICATION"
    UNCLASSIFIED_DATA = "UNCLASSIFIED_DATA"
    LOCAL_ONLY_DATA = "LOCAL_ONLY_DATA"
    DETECTION_INCOMPLETE = "DETECTION_INCOMPLETE"
    UNKNOWN_DETECTOR = "UNKNOWN_DETECTOR"
    DETECTION_FAILED = "DETECTION_FAILED"
    INVALID_TEXT = "INVALID_TEXT"
    INVALID_UNICODE = "INVALID_UNICODE"
    RESERVED_TOKEN_LITERAL = "RESERVED_TOKEN_LITERAL"
    INVALID_KEY_VERSION = "INVALID_KEY_VERSION"
    INVALID_HMAC_KEY = "INVALID_HMAC_KEY"
    MAPPING_LIFECYCLE = "MAPPING_LIFECYCLE"
    MAPPING_NOT_ACTIVE = "MAPPING_NOT_ACTIVE"
    INVALID_ENTITY_TYPE = "INVALID_ENTITY_TYPE"
    EMPTY_ENTITY = "EMPTY_ENTITY"
    TOKEN_COLLISION = "TOKEN_COLLISION"
    MALFORMED_TOKEN = "MALFORMED_TOKEN"
    UNKNOWN_TOKEN = "UNKNOWN_TOKEN"
    INVALID_TEXT_LENGTH = "INVALID_TEXT_LENGTH"
    INVALID_SPAN = "INVALID_SPAN"
    SECRET_DETECTED = "SECRET_DETECTED"


class SafetyError(ValueError):
    """A controlled failure whose public message never contains business text."""

    def __init__(self, code: SafetyCode) -> None:
        if not isinstance(code, SafetyCode):
            raise TypeError("SafetyError requires a registered SafetyCode")
        self.code = code
        super().__init__(code.value)
