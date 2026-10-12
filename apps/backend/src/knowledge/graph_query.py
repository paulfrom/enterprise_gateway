"""Compile a bounded Cypher subset with mandatory scope on every variable."""

from __future__ import annotations

import re

from knowledge.knowledge import KnowledgeError


_IDENTIFIER = re.compile(r'[A-Za-z][A-Za-z0-9_]*\Z')
_NUMBER = re.compile(r'-?\d+(?:\.\d+)?\Z')
_TOKEN = re.compile(
    r"\s*(\$[A-Za-z][A-Za-z0-9_]*|'(?:[^'\\]|\\.)*'|"
    r'"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|[A-Za-z][A-Za-z0-9_]*|'
    r'->|<=|>=|<>|!=|[()\[\]{},.:=<>-])'
)


def _unsupported():
    raise KnowledgeError('Unsupported governed Cypher: use labelled MATCH, simple AND filters, RETURN and LIMIT')


class _QueryParser:
    def __init__(self, query: str):
        if not isinstance(query, str) or len(query) > 8192:
            _unsupported()
        self.tokens: list[str] = []
        offset = 0
        while query[offset:].strip():
            match = _TOKEN.match(query, offset)
            if match is None:
                _unsupported()
            self.tokens.append(match[1])
            offset = match.end()
        self.position = 0
        self.variables: dict[str, str] = {}

    def take(self, expected: str) -> bool:
        if self.position < len(self.tokens) and self.tokens[self.position].upper() == expected.upper():
            self.position += 1
            return True
        return False

    def expect(self, expected: str):
        if not self.take(expected):
            _unsupported()

    def identifier(self) -> str:
        if self.position >= len(self.tokens) or not _IDENTIFIER.fullmatch(self.tokens[self.position]):
            _unsupported()
        value = self.tokens[self.position]
        self.position += 1
        return value

    def value(self) -> str:
        if self.position >= len(self.tokens):
            _unsupported()
        value = self.tokens[self.position]
        if not (value.startswith(('$', "'", '"')) or _NUMBER.fullmatch(value)
                or value.lower() in ('true', 'false', 'null')):
            _unsupported()
        self.position += 1
        return value

    def element(self, label: str, opening: str, closing: str) -> str:
        self.expect(opening)
        alias = self.identifier()
        if alias in self.variables:
            _unsupported()
        self.expect(':')
        self.expect(label)
        self.variables[alias] = label
        properties = []
        if self.take('{'):
            while True:
                key = self.identifier()
                self.expect(':')
                properties.append(f'{key}: {self.value()}')
                if not self.take(','):
                    break
            self.expect('}')
        self.expect(closing)
        attributes = ' {' + ', '.join(properties) + '}' if properties else ''
        return f'{opening}{alias}:{label}{attributes}{closing}'

    def reference(self, *, property_required=False) -> str:
        alias = self.identifier()
        if alias not in self.variables:
            _unsupported()
        if self.take('.'):
            return f'{alias}.{self.identifier()}'
        if property_required:
            _unsupported()
        return alias

    def compile(self) -> tuple[str, int]:
        self.expect('MATCH')
        pattern = self.element('Entity', '(', ')')
        hops = 0
        while self.take('-'):
            hops += 1
            if hops > 4:
                _unsupported()
            edge = self.element('Claim', '[', ']')
            direction = '->' if self.take('->') else '-'
            if direction == '-':
                self.expect('-')
            pattern += '-' + edge + direction + self.element('Entity', '(', ')')
        filters = []
        if self.take('WHERE'):
            while True:
                reference = self.reference(property_required=True)
                if self.position >= len(self.tokens) or self.tokens[self.position] not in ('=', '<>', '!=', '<', '>', '<=', '>='):
                    _unsupported()
                operator = self.tokens[self.position]
                self.position += 1
                filters.append(f'{reference} {operator} {self.value()}')
                if not self.take('AND'):
                    break
        self.expect('RETURN')
        distinct = 'DISTINCT ' if self.take('DISTINCT') else ''
        columns = []
        while True:
            if self.take('COUNT'):
                self.expect('(')
                projection = f'count({self.reference()})'
                self.expect(')')
            else:
                projection = self.reference()
            if self.take('AS'):
                projection += ' AS ' + self.identifier()
            columns.append(projection)
            if not self.take(','):
                break
        limit = 100
        if self.take('LIMIT'):
            if self.position >= len(self.tokens) or not self.tokens[self.position].isdigit():
                _unsupported()
            limit = int(self.tokens[self.position])
            self.position += 1
        if self.position != len(self.tokens) or len(columns) > 16 or limit > 1000:
            _unsupported()
        for alias, label in self.variables.items():
            filters.extend((f'{alias}.tenant_id = $_tenant_id', f'{alias}.domain = $_domain'))
            if label == 'Claim':
                filters.extend((f'{alias}.is_active = true', f'{alias}.valid_until_epoch > $_now_epoch'))
        return (f'MATCH {pattern} WHERE ' + ' AND '.join(filters)
                + ' RETURN ' + distinct + ', '.join(columns) + f' LIMIT {limit}', len(columns))


def compile_governed_cypher(query: str) -> tuple[str, int]:
    """Reject unhandled syntax rather than allowing a query to escape its scope."""
    return _QueryParser(query).compile()
