"""Local relation extraction and candidate generation (K-05, K-11).

Extracts business relations (such as Predicate.SUPPLIES) from observed text with:
- Exact directional mapping (Supplier supplies Customer)
- Polarity detection (positive vs. negative assertion)
- Modality detection (asserted fact vs. hypothetical/plan vs. question)
- Evidence span verification and digest tracking
- Co-occurrence distinction (co-occurrence NEVER automatically becomes business facts)
- Source kind validation (model output cannot self-certify as enterprise truth)
"""

from __future__ import annotations

import re
from typing import Sequence
from uuid import UUID, uuid4

from knowledge.knowledge import (
    Candidate,
    Claim,
    Entity,
    Evidence,
    KnowledgeError,
    Modality,
    Polarity,
    Predicate,
    Source,
    SourceKind,
)

# Common regex patterns for procurement/supplying relationships in Chinese text
_SUPPLIES_POSITIVE = re.compile(
    r"(?P<buyer>[^\s，。！？、]+?)\s*(?:向|从)\s*(?P<supplier>[^\s，。！？、]+?)\s*(?:采购|购买|订购|购入)\s*(?P<item>[^\s，。！？、]+)?"
)
_SUPPLIES_NEGATIVE = re.compile(
    r"(?P<buyer>[^\s，。！？、]+?)\s*(?:未向|未曾向|未从|没有向|并未向)\s*(?P<supplier>[^\s，。！？、]+?)\s*(?:采购|购买|订购|购入)\s*(?P<item>[^\s，。！？、]+)?"
)
_HYPOTHETICAL_MARKERS = ("计划", "拟", "如果", "若", "打算", "预计", "准备", "拟定")
_QUESTION_MARKERS = ("吗", "？", "?", "是否", "能否", "可否")


class RelationExtractor:
    """Extracts typed claims from verified entities in text (K-11)."""

    def __init__(self, domain: str) -> None:
        self.domain = domain

    def extract_from_text(
        self,
        text: str,
        source: Source,
        entities: Sequence[Entity],
        content_sha256: str,
    ) -> list[Candidate]:
        """Extract business relation candidates from text given detected entities.

        Strict rules:
        - Direction: In 'A向B采购设备', B supplies A -> Claim(subject=B, predicate=SUPPLIES, object=A).
        - Polarity: Negative keywords flip polarity to NEGATIVE.
        - Modality: Hypothetical/planning keywords set HYPOTHETICAL; question marks set QUESTION.
        - Co-occurrence is never promoted to SUPPLIES without explicit relation predicate.
        - Model output sources cannot produce ASSERTED enterprise truth (marked HYPOTHETICAL).
        """
        if source.domain != self.domain:
            raise KnowledgeError("source domain mismatch in relation extraction")

        candidates: list[Candidate] = []
        if len(entities) < 2:
            return []

        # Check all ordered pairs (buyer, supplier)
        for buyer in entities:
            for supplier in entities:
                if buyer.entity_id == supplier.entity_id:
                    continue

                pattern = re.compile(
                    re.escape(buyer.name)
                    + r"\s*(?P<mid1>[^\s，。！？、]{0,10}?)\s*(?:向|从)\s*"
                    + re.escape(supplier.name)
                    + r"\s*(?P<mid2>[^\s，。！？、]{0,10}?)\s*(?:采购|购买|订购|购入)\s*(?P<item>[^\s，。！？、]+)?"
                )

                for match in pattern.finditer(text):
                    span_start, span_end = match.start(), match.end()
                    mid1 = match.group("mid1") or ""
                    mid2 = match.group("mid2") or ""

                    # Polarity check
                    neg_markers = ("未", "没有", "未曾", "并未", "不曾")
                    is_neg = any(m in mid1 or m in mid2 for m in neg_markers)
                    polarity = Polarity.NEGATIVE if is_neg else Polarity.POSITIVE

                    # Modality check
                    modality = self._detect_modality(text, span_start, span_end, source.source_kind, mid1, mid2)

                    claim = Claim(
                        subject=supplier,
                        predicate=Predicate.SUPPLIES,
                        object=buyer,
                        polarity=polarity,
                        modality=modality,
                    )
                    evidence = Evidence(source, content_sha256, span_start, span_end)
                    candidates.append(
                        Candidate(
                            candidate_id=uuid4(),
                            claim=claim,
                            evidence=(evidence,),
                            acl=source.acl,
                            purpose=source.purpose,
                        )
                    )

        return candidates

    def extract_co_occurrences(
        self,
        text: str,
        source: Source,
        entities: Sequence[Entity],
        content_sha256: str,
    ) -> list[Candidate]:
        """Extract co-occurrence relations between entities appearing in the same context (K-05).

        Co-occurrence is explicitly Predicate.CO_OCCURS_WITH and NEVER Predicate.SUPPLIES.
        """
        if len(entities) < 2:
            return []

        candidates: list[Candidate] = []
        for i in range(len(entities)):
            for j in range(i + 1, len(entities)):
                e1, e2 = entities[i], entities[j]
                if e1.entity_id == e2.entity_id:
                    continue
                claim = Claim(
                    subject=e1,
                    predicate=Predicate.CO_OCCURS_WITH,
                    object=e2,
                    polarity=Polarity.POSITIVE,
                    modality=Modality.ASSERTED,
                )
                evidence = Evidence(source, content_sha256, 0, len(text))
                candidates.append(
                    Candidate(
                        candidate_id=uuid4(),
                        claim=claim,
                        evidence=(evidence,),
                        acl=source.acl,
                        purpose=source.purpose,
                    )
                )
        return candidates

    def _detect_modality(
        self,
        text: str,
        span_start: int,
        span_end: int,
        source_kind: SourceKind,
        mid1: str = "",
        mid2: str = "",
    ) -> Modality:
        # Model output is untrusted by default
        if source_kind == SourceKind.MODEL_OUTPUT:
            return Modality.HYPOTHETICAL

        # Check sentence window around match
        window_start = max(0, span_start - 20)
        window_end = min(len(text), span_end + 20)
        context = text[window_start:window_end]

        # Check for question
        if any(qm in context for qm in _QUESTION_MARKERS):
            return Modality.QUESTION

        # Check for hypothetical / plan in mid1, mid2, or context
        if any(hm in mid1 or hm in mid2 or hm in context for hm in _HYPOTHETICAL_MARKERS):
            return Modality.HYPOTHETICAL

        return Modality.ASSERTED
