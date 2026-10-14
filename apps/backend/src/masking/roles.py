"""Two-pass transaction roles, following tuomin's role-aware placeholders.

Conflicting roles retain the entity type instead of silently choosing a role.
"""
from __future__ import annotations

import re
from typing import Iterable

_ELIGIBLE = frozenset({'ORG', 'SUPPLIER'})
_CUES = tuple((re.compile(pattern), role) for pattern, role in (
    ('甲方|发包人|发包方', 'PARTYA'),
    ('乙方|承包人|承包方', 'PARTYB'),
    ('总包|总承包(?:方|人)?', 'GENCON'),
    ('分包', 'SUBCON'),
    ('担保人|保证人', 'GUARANTOR'),
    ('监理', 'SUPERVISOR'),
    ('委托方|委托人', 'PRINCIPAL'),
    ('牵头方|牵头投资(?:方)?|主投', 'LEAD'),
    ('标的方|标的公司|投资标的|被投方|被投', 'TARGET'),
    ('合作方|合作伙伴|联合体', 'PARTNER'),
    ('投资方|投资人', 'INVESTOR'),
    ('转让方|出让方', 'TRANSFEROR'),
    ('受让方', 'TRANSFEREE'),
))


def resolve_roles(fragments: Iterable[tuple[str, Iterable[object]]]) -> dict[tuple[str, str], str]:
    evidence: dict[tuple[str, str], set[str]] = {}
    for text, spans in fragments:
        for span in spans:
            if span.entity_type not in _ELIGIBLE:
                continue
            window = text[max(0, span.start - 10):span.start]
            nearest = [(match.end(), len(match.group()), role)
                       for pattern, role in _CUES for match in pattern.finditer(window)
                       if re.fullmatch(r"(?:[：:\s（）()“\"']|名称|单位名称|公司名称|为|是)*",
                                       window[match.end():])]
            if nearest:
                position, length, _ = max(nearest)
                roles = {role for end, size, role in nearest
                         if (end, size) == (position, length)}
                identity = (span.entity_type, text[span.start:span.end])
                evidence.setdefault(identity, set()).update(roles)
    return {identity: next(iter(roles)) for identity, roles in evidence.items() if len(roles) == 1}
