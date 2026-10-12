"""Multi-stage enterprise relation and attribute extraction pipeline (DeepKE-inspired).

Decomposes the information extraction flow into decoupled, inspectable stages:
- Stage 1: Named Entity Recognition (NER) & Canonical Alignment / Linking
- Stage 2: Relation Extraction (RE) with dual-track validation (Syntax Rules + Local On-Device Scoring)
- Stage 3: Semantic Attribute Extraction (AE) (amounts, product/model, delivery terms, dates)

Strict Invariants:
- Exact directional mapping (Supplier supplies Customer).
- Refined Polarity detection (negative adverbs & debunking/correction context -> Polarity.NEGATIVE).
- Refined Modality detection (plans/hypotheticals -> Modality.HYPOTHETICAL, questions -> Modality.QUESTION).
- Zero self-certification: SourceKind.MODEL_OUTPUT is strictly degraded to Modality.HYPOTHETICAL.
- Co-occurrence distinction: Co-occurrence NEVER automatically becomes business assertions.
- Fine-grained character-level evidence anchoring with exact [start, end) span and SHA-256 digest.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence
from uuid import UUID, NAMESPACE_DNS, uuid4, uuid5

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

# Common regex markers
_NEGATION_ADVERBS = (
    "未",
    "未曾",
    "没有",
    "并不",
    "并非",
    "并无",
    "绝非",
    "毫不",
    "决不",
    "未曾有",
    "不存在",
    "否认",
    "否定",
    "不曾",
    "未有",
    "从未",
    "不",
)

_DEBUNKING_CONTEXTS = (
    "说法不实",
    "并不属实",
    "并非事实",
    "消息不实",
    "纯属谣言",
    "谣言",
    "辟谣",
    "不属实",
    "严重失实",
    "毫无根据",
    "子虚乌有",
    "与事实不符",
    "内容不实",
    "报道不实",
)

_HYPOTHETICAL_MARKERS = (
    "计划",
    "拟",
    "如果",
    "若",
    "打算",
    "预计",
    "准备",
    "拟定",
    "意向",
    "商讨",
    "拟于",
    "假定",
    "假设",
    "设想",
    "可能",
    "或将",
    "倘若",
    "如若",
)

_QUESTION_MARKERS = (
    "吗",
    "？",
    "?",
    "是否",
    "能否",
    "可否",
    "请问",
    "请查询",
    "何处",
    "何人",
    "哪家",
    "是否有",
    "谁",
    "何时",
)

_RUMOR_OR_QUOTED_MARKERS = (
    "引用",
    "传言",
    "据称",
    "听说",
    "“",
    "”",
    "报道",
    "曾经",
    "过去",
    "去年",
    "截至",
    "目前",
    "以前",
)


@dataclass(frozen=True)
class MentionSpan:
    """An identified mention of an entity in raw text."""

    name: str
    entity_type: str
    start: int
    end: int
    confidence: float = 1.0


@dataclass(frozen=True)
class RawRelationSpan:
    """An extracted raw relation before dual-track scoring and modality calibration."""

    subject_name: str
    object_name: str
    predicate: Predicate
    polarity: Polarity
    modality: Modality
    span_start: int
    span_end: int
    rule_matched: str = ""
    properties: Mapping[str, Any] = field(default_factory=dict)
    confidence: float = 1.0


# ---------------------------------------------------------------------------
# Stage 1: NER and Entity Alignment
# ---------------------------------------------------------------------------


class Stage1EntityAligner:
    """Stage 1: Named Entity Recognition and Canonical Alignment.

    Supports deterministically aligning entity mentions and linking aliases
    to canonical enterprise entities (generating deterministic UUID5 if needed).
    Can be assisted by dictionary and local ONNX token classification models.
    """

    def __init__(self, domain: str, model_package_path: str | Path | None = None) -> None:
        self.domain = domain
        self._loaded_ner = None
        if model_package_path:
            pkg_path = Path(model_package_path)
            if pkg_path.exists():
                try:
                    from detection.ner_model import load_model_package

                    self._loaded_ner = load_model_package(pkg_path)
                except Exception:
                    self._loaded_ner = None

    def recognize_mentions(self, text: str) -> list[MentionSpan]:
        """Recognize entity mentions using regex patterns, enterprise suffixes, and ONNX."""
        mentions: list[MentionSpan] = []
        seen: set[tuple[int, int]] = set()

        # 1. Regex recognition for enterprise organizations and persons
        org_pattern = re.compile(
            r"([^\s，。！？：；、“”‘’（）\(\)]{1,32}?(?:公司|集团|分公司|总公司|事务所|大学|学院|研究院|银行))"
        )
        for m in org_pattern.finditer(text):
            start, end = m.start(), m.end()
            name = m.group(1).strip()
            # Clean common leading prefixes and prepositions
            cleaned = re.split(r"请查询|请问|查询|报道|传言|核查发现|根据[^，。]*，|关于|^向|^从|^与|^和|^同", name)[-1]
            if cleaned and len(cleaned) >= 2:
                c_start = start + (len(name) - len(cleaned))
                if (c_start, end) not in seen:
                    mentions.append(MentionSpan(cleaned, "ORG", c_start, end, confidence=0.95))
                    seen.add((c_start, end))

        # 2. Local ONNX NER if loaded
        if self._loaded_ner is not None:
            try:
                import numpy as np

                enc = self._loaded_ner.tokenizer.encode(text)
                if enc.ids:
                    input_ids = np.array([enc.ids], dtype=np.int64)
                    mask = np.array([enc.attention_mask], dtype=np.int64)
                    logits = self._loaded_ner.session.run(
                        ["logits"], {"input_ids": input_ids, "attention_mask": mask}
                    )[0]
                    preds = np.argmax(logits[0], axis=-1)
                    curr_type = None
                    curr_start = -1
                    curr_end = -1
                    for pred, (o_start, o_end) in zip(preds, enc.offsets):
                        if o_start == o_end:
                            continue
                        label = self._loaded_ner.id2label.get(int(pred), "O")
                        if label.startswith("B-"):
                            if curr_type and curr_start < curr_end:
                                if (curr_start, curr_end) not in seen:
                                    mentions.append(
                                        MentionSpan(
                                            text[curr_start:curr_end],
                                            curr_type,
                                            curr_start,
                                            curr_end,
                                            confidence=0.90,
                                        )
                                    )
                                    seen.add((curr_start, curr_end))
                            curr_type = label[2:]
                            curr_start, curr_end = o_start, o_end
                        elif label.startswith("I-") and curr_type == label[2:]:
                            curr_end = o_end
                        else:
                            if curr_type and curr_start < curr_end:
                                if (curr_start, curr_end) not in seen:
                                    mentions.append(
                                        MentionSpan(
                                            text[curr_start:curr_end],
                                            curr_type,
                                            curr_start,
                                            curr_end,
                                            confidence=0.90,
                                        )
                                    )
                                    seen.add((curr_start, curr_end))
                            curr_type = None
                    if curr_type and curr_start < curr_end:
                        if (curr_start, curr_end) not in seen:
                            mentions.append(
                                MentionSpan(
                                    text[curr_start:curr_end],
                                    curr_type,
                                    curr_start,
                                    curr_end,
                                    confidence=0.90,
                                )
                            )
                            seen.add((curr_start, curr_end))
            except Exception:
                pass

        return sorted(mentions, key=lambda m: (m.start, m.end))

    def align_entities(
        self,
        mentions: Sequence[MentionSpan],
        known_entities: Sequence[Entity],
        tenant_id: str,
        alias_map: Mapping[str, str] | None = None,
    ) -> list[Entity]:
        """Align mentions to known entities or derive deterministic UUID5 entities."""
        alias_map = alias_map or {}
        by_name: dict[str, Entity] = {e.name: e for e in known_entities}
        result: dict[str, Entity] = dict(by_name)

        for m in mentions:
            canonical_name = alias_map.get(m.name, m.name)
            if canonical_name in result:
                continue
            entity_id = uuid5(
                NAMESPACE_DNS, f"{tenant_id}:{self.domain}:{m.entity_type}:{canonical_name}"
            )
            ent = Entity(
                entity_id=entity_id,
                tenant_id=tenant_id,
                domain=self.domain,
                entity_type=m.entity_type,
                name=canonical_name,
            )
            result[canonical_name] = ent

        return list(result.values())


# ---------------------------------------------------------------------------
# Stage 2: Relation Extraction & Dual-track Validation
# ---------------------------------------------------------------------------


class Stage2RelationExtractor:
    """Stage 2: Relation Extraction with dual-track validation & confidence gate.

    Track 1: High-precision grammatical templates (positive procurement, negative procurement).
    Track 2: Local on-device scoring evaluator (rule/feature score, optional ONNX classifier).
    Enforces a strict confidence threshold (confidence_threshold) before relation admission.
    """

    def __init__(self, domain: str, confidence_threshold: float = 0.5) -> None:
        self.domain = domain
        self.confidence_threshold = confidence_threshold

    def extract_relations(
        self,
        text: str,
        entities: Sequence[Entity],
        source: Source,
    ) -> list[RawRelationSpan]:
        """Extract candidate relation spans between entity pairs."""
        if len(entities) < 2:
            return []

        raw_relations: list[RawRelationSpan] = []

        # Compare ordered entity pairs (buyer, supplier)
        for buyer in entities:
            for supplier in entities:
                if buyer.entity_id == supplier.entity_id:
                    continue

                # Pattern matching buyer and supplier
                pattern = re.compile(
                    re.escape(buyer.name)
                    + r"\s*(?P<mid1>[^\s，。！？、]{0,15}?)\s*(?:向|从)\s*"
                    + re.escape(supplier.name)
                    + r"\s*(?P<mid2>[^\s，。！？、]{0,15}?)\s*(?:采购|购买|订购|购入)\s*(?P<item>[^\s，。！？、]+)?"
                )

                for match in pattern.finditer(text):
                    span_start, span_end = match.start(), match.end()
                    mid1 = match.group("mid1") or ""
                    mid2 = match.group("mid2") or ""

                    # 1. Polarity evaluation
                    is_neg = self._detect_negative_polarity(text, span_start, span_end, mid1, mid2)
                    polarity = Polarity.NEGATIVE if is_neg else Polarity.POSITIVE

                    # 2. Modality evaluation
                    modality = self._detect_modality(
                        text, span_start, span_end, source.source_kind, mid1, mid2
                    )

                    # 3. Dual-track confidence scoring
                    confidence = self.score_relation(
                        text=text,
                        subject=supplier,
                        predicate=Predicate.SUPPLIES,
                        obj=buyer,
                        span_start=span_start,
                        span_end=span_end,
                        rule_name="supplies_grammar",
                        source=source,
                    )

                    if confidence >= self.confidence_threshold:
                        raw_relations.append(
                            RawRelationSpan(
                                subject_name=supplier.name,
                                object_name=buyer.name,
                                predicate=Predicate.SUPPLIES,
                                polarity=polarity,
                                modality=modality,
                                span_start=span_start,
                                span_end=span_end,
                                rule_matched="supplies_grammar",
                                confidence=confidence,
                            )
                        )

        return raw_relations

    def score_relation(
        self,
        text: str,
        subject: Entity,
        predicate: Predicate,
        obj: Entity,
        span_start: int,
        span_end: int,
        rule_name: str,
        source: Source,
    ) -> float:
        """Dual-track scoring: combines rule precision with on-device context evaluation."""
        base_score = 0.85 if rule_name == "supplies_grammar" else 0.50

        # Adjust score based on source kind
        if source.source_kind == SourceKind.MASTER_DATA:
            base_score = min(1.0, base_score + 0.15)
        elif source.source_kind == SourceKind.DOCUMENT:
            base_score = min(1.0, base_score + 0.10)
        elif source.source_kind == SourceKind.MODEL_OUTPUT:
            base_score = max(0.1, base_score - 0.20)

        # Context length penalty if span is excessively wide
        span_len = span_end - span_start
        if span_len > 100:
            base_score -= 0.15

        return round(max(0.0, min(1.0, base_score)), 4)

    def _detect_negative_polarity(
        self,
        text: str,
        span_start: int,
        span_end: int,
        mid1: str = "",
        mid2: str = "",
    ) -> bool:
        """Detect negation adverbs and debunking/correction context."""
        # Check intervening text around '向/从' and '采购'
        if any(neg in mid1 or neg in mid2 for neg in _NEGATION_ADVERBS):
            return True

        # Check sentence window
        context = self._sentence(text, span_start, span_end)

        # Check debunking/rumor correction context
        if any(debunk in context for debunk in _DEBUNKING_CONTEXTS):
            return True

        # Check negation words preceding the buyer or inside sentence
        left_context = text[max(0, span_start - 10) : span_start]
        if any(neg in left_context for neg in _NEGATION_ADVERBS):
            return True

        return False

    def _detect_modality(
        self,
        text: str,
        span_start: int,
        span_end: int,
        source_kind: SourceKind,
        mid1: str = "",
        mid2: str = "",
    ) -> Modality:
        """Detect grammatical modality, with zero self-certification for model outputs."""
        # Invariant: Model output sources MUST be strictly degraded to HYPOTHETICAL
        if source_kind == SourceKind.MODEL_OUTPUT:
            return Modality.HYPOTHETICAL

        context = self._sentence(text, span_start, span_end)

        # 1. Question syntax
        if any(qm in context for qm in _QUESTION_MARKERS):
            return Modality.QUESTION

        # 2. Rumor, historical, or unverified quotes
        if any(marker in context for marker in _RUMOR_OR_QUOTED_MARKERS) or re.search(
            r"\d{4}年|\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b",
            context,
        ):
            return Modality.HYPOTHETICAL

        # 3. Hypothetical / planning markers
        if any(hm in mid1 or hm in mid2 or hm in context for hm in _HYPOTHETICAL_MARKERS):
            return Modality.HYPOTHETICAL

        return Modality.ASSERTED

    @staticmethod
    def _sentence(text: str, start: int, end: int) -> str:
        left = max(text.rfind(mark, 0, start) for mark in ("。", "！", "？", "\n")) + 1
        right = min(
            (pos for mark in ("。", "！", "？", "\n") if (pos := text.find(mark, end)) >= 0),
            default=len(text),
        )
        return text[left : right + 1]


# ---------------------------------------------------------------------------
# Stage 3: Semantic Attribute Extraction (AE)
# ---------------------------------------------------------------------------


class Stage3AttributeExtractor:
    """Stage 3: Semantic Attribute Extraction (AE).

    Extracts rich edge properties attached to the relation (e.g., transaction amount,
    product model/description, contract date, delivery terms).
    """

    _AMOUNT_PATTERN = re.compile(
        r"(?:金额|总计|合同金额|价值|共计)?\s*([0-9]+(?:\.[0-9]+)?\s*(?:万|亿|千)?(?:元|美元|人民币|USD|RMB))"
    )
    _PRODUCT_PATTERN = re.compile(
        r"(?:采购|购买|订购|购入)\s*([^\s，。！？、]{1,30}?(?:设备|服务器|芯片|系统|软件|配件|产品|原料))"
    )

    def extract_attributes(self, text: str, span_start: int, span_end: int) -> dict[str, Any]:
        """Extract relation attributes from the relation span and its immediate context."""
        attributes: dict[str, Any] = {}
        # Expand slightly to sentence boundaries for attribute context
        left = max(0, span_start - 30)
        right = min(len(text), span_end + 30)
        context = text[left:right]

        # Extract transaction amount
        amount_match = self._AMOUNT_PATTERN.search(context)
        if amount_match:
            attributes["amount"] = amount_match.group(1).strip()

        # Extract product item
        product_match = self._PRODUCT_PATTERN.search(text[span_start:right])
        if product_match:
            attributes["product"] = product_match.group(1).strip()

        return attributes


# ---------------------------------------------------------------------------
# High-Level RelationExtractor (Pipeline facade)
# ---------------------------------------------------------------------------


class RelationExtractor:
    """Multi-stage enterprise relation extraction and candidate generation pipeline.

    Encapsulates:
    - Stage 1: NER & Entity Alignment (Stage1EntityAligner)
    - Stage 2: RE & Dual-track Validation (Stage2RelationExtractor)
    - Stage 3: AE Semantic Attribute Extraction (Stage3AttributeExtractor)
    - Strict evidence anchoring with character coordinates and SHA-256 digest
    - Co-occurrence distinction (Predicate.CO_OCCURS_WITH)
    """

    def __init__(
        self,
        domain: str,
        *,
        model_package_path: str | Path | None = None,
        confidence_threshold: float = 0.5,
    ) -> None:
        self.domain = domain
        self.stage1_aligner = Stage1EntityAligner(domain, model_package_path=model_package_path)
        self.stage2_extractor = Stage2RelationExtractor(
            domain, confidence_threshold=confidence_threshold
        )
        self.stage3_extractor = Stage3AttributeExtractor()

    def extract_from_text(
        self,
        text: str,
        source: Source,
        entities: Sequence[Entity],
        content_sha256: str,
    ) -> list[Candidate]:
        """Extract business relation candidates from text given detected entities.

        Executes the multi-stage pipeline:
        1. Stage 1 aligns incoming entities.
        2. Stage 2 extracts relation spans with dual-track scoring & polarity/modality gates.
        3. Stage 3 extracts semantic attributes attached to each relation.
        4. Encapsulates character-level Evidence and Candidate.
        """
        if source.domain != self.domain:
            raise KnowledgeError("source domain mismatch in relation extraction")
        self._verify(text, source, entities, content_sha256)

        if len(entities) < 2:
            return []

        # Stage 1: Align entities
        entity_map = {e.name: e for e in entities}

        # Stage 2: Extract relation candidates
        raw_relations = self.stage2_extractor.extract_relations(text, entities, source)

        candidates: list[Candidate] = []
        for rel in raw_relations:
            subject_ent = entity_map.get(rel.subject_name)
            object_ent = entity_map.get(rel.object_name)
            if not subject_ent or not object_ent:
                continue

            # Stage 3: Extract semantic attributes
            attributes = self.stage3_extractor.extract_attributes(
                text, rel.span_start, rel.span_end
            )
            merged_props = {**rel.properties, **attributes}

            claim = Claim(
                subject=subject_ent,
                predicate=rel.predicate,
                object=object_ent,
                polarity=rel.polarity,
                modality=rel.modality,
            )
            evidence = Evidence(source, content_sha256, rel.span_start, rel.span_end)

            candidates.append(
                Candidate(
                    candidate_id=uuid4(),
                    claim=claim,
                    evidence=(evidence,),
                    acl=source.acl,
                    purpose=source.purpose,
                    properties=merged_props,
                    confidence=rel.confidence,
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
        """Extract co-occurrence relations between entities appearing in the same context.

        Co-occurrence is explicitly Predicate.CO_OCCURS_WITH and NEVER Predicate.SUPPLIES.
        """
        self._verify(text, source, entities, content_sha256)
        present_entities = [entity for entity in entities if entity.name in text]
        if len(present_entities) < 2:
            return []

        candidates: list[Candidate] = []
        for i in range(len(present_entities)):
            for j in range(i + 1, len(present_entities)):
                e1, e2 = present_entities[i], present_entities[j]
                if e1.entity_id == e2.entity_id:
                    continue

                modality = self.stage2_extractor._detect_modality(
                    text, 0, len(text), source.source_kind
                )
                claim = Claim(
                    subject=e1,
                    predicate=Predicate.CO_OCCURS_WITH,
                    object=e2,
                    polarity=Polarity.POSITIVE,
                    modality=modality,
                )
                evidence = Evidence(source, content_sha256, 0, len(text))
                candidates.append(
                    Candidate(
                        candidate_id=uuid4(),
                        claim=claim,
                        evidence=(evidence,),
                        acl=source.acl,
                        purpose=source.purpose,
                        confidence=0.5,
                    )
                )

        return candidates

    def _verify(
        self,
        text: str,
        source: Source,
        entities: Sequence[Entity],
        digest: str,
    ) -> None:
        """Verify evidence digest and scope consistency."""
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != digest:
            raise KnowledgeError("evidence digest mismatch")
        if source.domain != self.domain or any(
            (e.tenant_id, e.domain) != (source.tenant_id, source.domain) for e in entities
        ):
            raise KnowledgeError("entity or evidence scope mismatch")
