"""Request-local exact mappings with readable, role-aware placeholders."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from infra.errors import SafetyCode, SafetyError

_ENTITY_TYPE = re.compile(r"[A-Z][A-Z0-9_]{0,31}\Z")
_TOKEN = re.compile(r"<[A-Z][A-Z0-9_]{0,31}_\d{3,}>")
_TOKEN_START = re.compile(r"<\s*(?:[A-Z][A-Z0-9_]{0,31}_|[A-Za-z][A-Za-z0-9_]{0,31}[-_]\s*(?=\d)|[A-Z][A-Z_]{0,31}(?=\d))")
_UNFINISHED = re.compile(r"<[A-Za-z][A-Za-z0-9_]*_\s*\d*\Z")


def check_text(text: str) -> None:
    if not isinstance(text, str):
        raise SafetyError(SafetyCode.INVALID_TEXT)
    try:
        text.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        invalid = True
    else:
        invalid = False
    if invalid:
        raise SafetyError(SafetyCode.INVALID_UNICODE)


def has_reserved_token(text: str) -> bool:
    """Recognize current placeholders and the retired HMAC namespace."""
    return bool(_TOKEN_START.search(text) or _UNFINISHED.search(text)
                or "<<ENT" in text or text.endswith(("<<E", "<<EN")))


def reject_reserved_literals(text: str) -> None:
    check_text(text)
    if has_reserved_token(text):
        raise SafetyError(SafetyCode.RESERVED_TOKEN_LITERAL)


@dataclass(slots=True)
class MappingContext:
    """One request's exact originals; counters and mappings stay in memory.

    Optional legacy constructor arguments are accepted during migration; they
    do not participate in placeholder allocation or restoration.
    """
    scope: str
    key_version: str | None = None
    key: bytes | None = field(default=None, repr=False)
    _values: dict[str, tuple[str, str]] = field(default_factory=dict, init=False, repr=False)
    _tokens: dict[tuple[str, str], str] = field(default_factory=dict, init=False, repr=False)
    _counters: dict[str, int] = field(default_factory=dict, init=False, repr=False)
    _roles: dict[tuple[str, str], str] = field(default_factory=dict, init=False, repr=False)
    _prefixes: set[str] = field(default_factory=set, init=False, repr=False)
    _bare_pattern: re.Pattern | None = field(default=None, init=False, repr=False)
    _active: bool = field(default=False, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.scope, str) or not self.scope.strip():
            raise SafetyError(SafetyCode.INVALID_SCOPE)
        check_text(self.scope)
        self.key = None

    def __enter__(self) -> MappingContext:
        if self._active or self._closed:
            raise SafetyError(SafetyCode.MAPPING_LIFECYCLE)
        self._active = True
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self._values.clear()
        self._tokens.clear()
        self._counters.clear()
        self._roles.clear()
        self._prefixes.clear()
        self._bare_pattern = None
        self.key = None
        self._active = False
        self._closed = True

    def require_active(self) -> None:
        if not self._active:
            raise SafetyError(SafetyCode.MAPPING_NOT_ACTIVE)

    @property
    def domain(self) -> str:
        return self.scope

    @property
    def entry_count(self) -> int:
        return len(self._values)

    def assign_roles(self, fragments: Iterable[tuple[str, Iterable[object]]]) -> None:
        """Resolve all role evidence before allocating any placeholders."""
        self.require_active()
        if self._values:
            raise SafetyError(SafetyCode.MAPPING_LIFECYCLE)
        from masking.roles import resolve_roles
        self._roles = resolve_roles(fragments)

    def token_for(self, entity_type: str, original: str) -> str:
        self.require_active()
        if not isinstance(entity_type, str) or not _ENTITY_TYPE.fullmatch(entity_type):
            raise SafetyError(SafetyCode.INVALID_ENTITY_TYPE)
        reject_reserved_literals(original)
        if not original:
            raise SafetyError(SafetyCode.EMPTY_ENTITY)
        identity = (entity_type, original)
        existing = self._tokens.get(identity)
        if existing is not None:
            return existing
        prefix = self._roles.get(identity, entity_type)
        number = self._counters.get(prefix, 0) + 1
        token = f"<{prefix}_{number:03d}>"
        if token in self._values:
            raise SafetyError(SafetyCode.TOKEN_COLLISION)
        self._counters[prefix] = number
        self._tokens[identity] = token
        self._values[token] = identity
        if prefix not in self._prefixes:
            self._prefixes.add(prefix)
            self._bare_pattern = None
        return token

    def restore(self, text: str) -> str:
        """Restore in one pass; subset and repeated references are permitted."""
        self.require_active()
        check_text(text)
        if "<<ENT" in text or text.endswith(("<<E", "<<EN")) or _UNFINISHED.search(text):
            raise SafetyError(SafetyCode.MALFORMED_TOKEN)
        if self._prefixes and self._bare_pattern is None:
            self._bare_pattern = re.compile(
                r'(?<!<)\b(?:' + '|'.join(re.escape(p) for p in sorted(self._prefixes)) + r')_\d{3,}\b(?!>)')
        if self._bare_pattern is not None and self._bare_pattern.search(text):
            raise SafetyError(SafetyCode.MALFORMED_TOKEN)
        tail = re.search(r'<[A-Z][A-Z0-9_]*\Z', text)
        if tail and any(('<' + prefix + '_').startswith(tail.group()) for prefix in self._prefixes):
            raise SafetyError(SafetyCode.MALFORMED_TOKEN)
        parts: list[str] = []
        cursor = 0
        for match in _TOKEN_START.finditer(text):
            start = match.start()
            end = text.find('>', start, start + 130)
            if end < 0:
                raise SafetyError(SafetyCode.MALFORMED_TOKEN)
            token = text[start:end + 1]
            if _TOKEN.fullmatch(token) is None:
                raise SafetyError(SafetyCode.MALFORMED_TOKEN)
            original = self._values.get(token)
            if original is None:
                raise SafetyError(SafetyCode.UNKNOWN_TOKEN)
            parts.extend((text[cursor:start], original[1]))
            cursor = end + 1
        parts.append(text[cursor:])
        return "".join(parts)
