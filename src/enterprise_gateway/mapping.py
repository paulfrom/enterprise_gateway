"""Request-local exact-value token mapping; not detection or persistence.

One request's mapping lives only inside a single with block. No map is shared,
persisted, or recovered from an audit store.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field

from .errors import SafetyCode, SafetyError


_ENTITY_TYPE = re.compile(r"[A-Z][A-Z0-9_]{0,31}\Z")
_KEY_VERSION = re.compile(r"[A-Za-z0-9.-]{1,32}\Z")
_TOKEN = re.compile(r"<<ENT_[A-Za-z0-9.-]{1,32}_[0-9a-f]{32}>>")
_RESERVED_PREFIX = "<<ENT"


def check_text(text: str) -> None:
    if not isinstance(text, str):
        raise SafetyError(SafetyCode.INVALID_TEXT)
    try:
        text.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise SafetyError(SafetyCode.INVALID_UNICODE) from None


def reject_reserved_literals(text: str) -> None:
    """Reserve the token namespace instead of introducing an escape protocol."""
    check_text(text)
    if _RESERVED_PREFIX in text or text.endswith(("<<E", "<<EN")):
        raise SafetyError(SafetyCode.RESERVED_TOKEN_LITERAL)


@dataclass(slots=True)
class MappingContext:
    """One request's exact-value mapping, usable only inside a single with block.

    Closing drops references; Python cannot promise secure erasure of strings or
    key bytes. Single-threaded use: one context serves one request's logical flow.
    """

    scope: str
    key_version: str
    key: bytes = field(repr=False)
    _values: dict[str, tuple[str, str]] = field(default_factory=dict, init=False, repr=False)
    _active: bool = field(default=False, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.scope, str) or not self.scope.strip():
            raise SafetyError(SafetyCode.INVALID_SCOPE)
        check_text(self.scope)
        if not isinstance(self.key_version, str) or not _KEY_VERSION.fullmatch(self.key_version):
            raise SafetyError(SafetyCode.INVALID_KEY_VERSION)
        if not isinstance(self.key, bytes) or len(self.key) < hashlib.sha256().digest_size:
            raise SafetyError(SafetyCode.INVALID_HMAC_KEY)

    def __enter__(self) -> MappingContext:
        if self._active or self._closed:
            raise SafetyError(SafetyCode.MAPPING_LIFECYCLE)
        self._active = True
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self._values.clear()
        self.key = b""
        self._active = False
        self._closed = True

    def require_active(self) -> None:
        if not self._active:
            raise SafetyError(SafetyCode.MAPPING_NOT_ACTIVE)

    @property
    def entry_count(self) -> int:
        return len(self._values)

    def token_for(self, entity_type: str, original: str) -> str:
        self.require_active()
        if not isinstance(entity_type, str) or not _ENTITY_TYPE.fullmatch(entity_type):
            raise SafetyError(SafetyCode.INVALID_ENTITY_TYPE)
        reject_reserved_literals(original)
        if not original:
            raise SafetyError(SafetyCode.EMPTY_ENTITY)
        # A typed JSON array provides unambiguous framing. No Unicode, whitespace,
        # case, or alias normalization is performed on the original string.
        message = json.dumps(
            ["enterprise-gateway-token-v1", self.scope, self.key_version, entity_type, original],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hmac.digest(self.key, message, "sha256")[:16].hex()
        token = f"<<ENT_{self.key_version}_{digest}>>"
        value = (entity_type, original)
        if token in self._values and self._values[token] != value:
            raise SafetyError(SafetyCode.TOKEN_COLLISION)
        self._values[token] = value
        return token

    def restore(self, text: str) -> str:
        """Restore a complete logical string; streaming framing belongs elsewhere.

        Known token syntax and recognizable truncated prefixes fail closed.
        Arbitrary model edits that erase the reserved syntax cannot be detected by
        token matching; this method does not claim semantic output verification.
        """
        self.require_active()
        check_text(text)
        if text.endswith(("<<E", "<<EN")):
            raise SafetyError(SafetyCode.MALFORMED_TOKEN)
        parts: list[str] = []
        cursor = 0
        while True:
            start = text.find(_RESERVED_PREFIX, cursor)
            if start < 0:
                parts.append(text[cursor:])
                return "".join(parts)
            token_match = _TOKEN.match(text, start)
            if token_match is None:
                raise SafetyError(SafetyCode.MALFORMED_TOKEN)
            token = token_match.group()
            value = self._values.get(token)
            if value is None:
                raise SafetyError(SafetyCode.UNKNOWN_TOKEN)
            parts.extend((text[cursor:start], value[1]))
            cursor = token_match.end()
