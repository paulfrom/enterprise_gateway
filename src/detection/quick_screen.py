"""Bounded local risk estimation before NER; scores are heuristic, not calibrated probabilities."""
from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass

from ahocorasick_rs import AhoCorasick
from detection.dictionary import CompiledDictionary


@dataclass(frozen=True, slots=True)
class QuickScreenConfig:
    enabled: bool = True
    threshold: float = 0.35
    budget_ms: float = 2.0

    def __post_init__(self):
        if not isinstance(self.enabled, bool):
            raise ValueError("quick screen enabled must be boolean")
        for name, value, upper in (("threshold", self.threshold, 1.0),
                                   ("budget_ms", self.budget_ms, 10.0)):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= upper:
                raise ValueError(f"quick screen {name} must be > 0 and <= {upper}")


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: float
    requires_detection: bool
    reason: str


# Bounded, fixed expressions: no inference, networking, storage or unbounded quantifiers.
_SIGNALS = re.compile(
    r"[0-9@]|https?://|sk-|ak-|-----begin|password|passwd|api[_ -]?key|secret|token|"
    r"姓名|联系人|身份证|手机号|电话|地址|住址|账号|账户|合同|金额|密码|口令|密钥|"
    r"公司|科技|集团|有限|银行|医院|大学|学校|研究院|事务所|先生|女士|"
    r"(?:省|市|县|区|镇|村|街|路|号|室)(?:\b|[\u3400-\u9fff])",
    re.IGNORECASE,
)
_SURNAMES = re.compile(
    r"(?:^|[\s，。！？、:：=的叫是为与和])[赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱秦尤许何吕施张孔曹严华金魏陶姜"
    r"戚谢邹喻柏水窦章云苏潘葛奚范彭郎鲁韦昌马苗凤花方俞任袁柳鲍史唐"
    r"费廉岑薛雷贺倪汤滕殷罗毕郝邬安常乐于傅皮卞齐康伍余元顾孟平黄"
    r"和穆萧尹姚邵汪毛禹狄米贝明臧计伏成戴宋茅庞熊纪舒屈项祝董梁杜"
    r"阮蓝闵席季麻强贾江童颜郭梅盛林钟徐邱骆高夏蔡田樊胡凌霍虞万支"
    r"柯管卢莫房裘缪干解应宗丁宣邓郁单杭洪包诸左石崔吉龚程陆翁刘叶"
    r"龙司白侯廖谭欧阳上官司马诸葛][\u3400-\u9fff]{1,2}"
)
_NAMES = re.compile(r"\b[A-Z][a-z]{1,30}\b|[\u00c0-\u024f\u0400-\u04ff\u3040-\u30ff\uac00-\ud7af]")


class QuickRiskScreen:
    """Estimate each fragment independently, sharing one budget for the whole request.

    Scan all characters in bounded chunks with overlap. If the budget expires,
    remaining fragments go to full detection, never pass based on a partial scan.
    A dictionary entry longer than the chunk limit also forces full detection.
    """
    CHUNK_CHARS = 512
    FEATURE_OVERLAP = 64

    def __init__(self, dictionary: CompiledDictionary, config: QuickScreenConfig, *, policy_cues: tuple[str, ...] = (), custom_rules: bool = False):
        self.config = config
        self._dictionary = dictionary
        self._custom_rules = custom_rules
        patterns = tuple(e.text for e in dictionary.entries) + policy_cues
        self._longest = max((len(text) for text in patterns), default=1)
        # Standard matching can stop on any hit; build once, not on the request path.
        self._automaton = AhoCorasick(patterns) if patterns else None

    def assess_many(self, texts: tuple[str, ...]) -> tuple[RiskAssessment, ...]:
        if not self.config.enabled:
            return tuple(RiskAssessment(1.0, True, "disabled") for _ in texts)
        deadline = time.perf_counter_ns() + int(self.config.budget_ms * 1_000_000)
        return tuple(self._assess(text, deadline) for text in texts)

    def _assess(self, text: str, deadline: int) -> RiskAssessment:
        if not isinstance(text, str):
            raise TypeError("quick screen text must be a string")
        if self._custom_rules:
            return RiskAssessment(1.0, True, "custom_rules")
        if self._longest > self.CHUNK_CHARS:
            return RiskAssessment(1.0, True, "dictionary_window")
        overlap = max(self.FEATURE_OVERLAP, self._longest - 1)
        score, reason = 0.02, "low_risk"
        for offset in range(0, len(text), self.CHUNK_CHARS):
            if time.perf_counter_ns() >= deadline:
                return RiskAssessment(1.0, True, "budget_exhausted")
            chunk = text[max(0, offset - overlap):offset + self.CHUNK_CHARS]
            if self._automaton is not None and self._automaton.find_matches_as_indexes(chunk):
                score, reason = 1.0, "dictionary"
            elif _SIGNALS.search(chunk):
                score, reason = 1.0, "sensitive_format"
            elif _SURNAMES.search(chunk) or _NAMES.search(chunk):
                score, reason = max(score, 0.75), "entity_hint"
            if time.perf_counter_ns() >= deadline:
                return RiskAssessment(1.0, True, "budget_exhausted")
            if score >= self.config.threshold:
                return RiskAssessment(score, True, reason)
        if time.perf_counter_ns() >= deadline:
            return RiskAssessment(1.0, True, "budget_exhausted")
        return RiskAssessment(score, score >= self.config.threshold, reason)
