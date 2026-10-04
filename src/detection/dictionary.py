"""企业词典编译与最长匹配检测（D-06/D-07）。

词典是企业知识资产：批准的实体及别名以规范 JSON 描述（版本、保护域、
条目列表、文件级 SHA-256 自描述哈希），加载时严格校验并核验哈希。
校验通过后每次用 ahocorasick-rs 在本地从已校验 JSON 重建自动机；
索引二进制不持久化、不假定跨平台或跨版本可移植（DESIGN §8），
同一份 JSON 在任何宿主上重新编译都得到等价检测行为。

检测在编译产物上做最长匹配（``MATCHKIND_LEFTMOST_LONGEST``），
输出 ``spans.Span``：原始 Python 字符串的 Unicode code point
半开偏移 [start,end)——与 recognizers/spans 的坐标系一致
（ahocorasick-rs 的 ``find_matches_as_indexes`` 返回的即为 code point
偏移，含中文及增补平面字符场景，见 tests/test_dictionary.py 偏移断言）。
检测以单字段文本为输入单位：调用方逐字段调用，本模块不跨字段拼接。

受控失败：坏词典（缺字段/错类型/多余字段/重复条目/空文本/未知实体
类型格式/哈希不符/空条目表）→ ``DICTIONARY_INVALID``；同一文本映射到
不同 entity_type → ``DICTIONARY_CONFLICT``。公开错误消息只含静态结构
描述，不回显任何条目文本、实体名称或文档内容（词典内容属企业知识资产）。
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, NoReturn

from ahocorasick_rs import MATCHKIND_LEFTMOST_LONGEST, AhoCorasick
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from infra.errors import SafetyCode, SafetyError
from detection.spans import Span
from infra.strict_json import JsonRejectKind, parse_strict_json

__all__ = [
    "CompiledDictionary",
    "DictionaryDetection",
    "DictionaryDocument",
    "DictionaryEntry",
    "analyze_dictionary",
    "compile_dictionary",
    "compute_dictionary_hash",
]

# 词典命中不携带秘密语义，与规则识别器一致的最低档（spans 默认档）。
SPAN_PRIORITY = 3

_ENTITY_TYPE = re.compile(r"[A-Z][A-Z0-9_]{0,31}\Z")
_SHA256_HEX = re.compile(r"[0-9a-fA-F]{64}\Z")


def compute_dictionary_hash(
    dictionary_id: str,
    version: str,
    domain: str,
    entries: tuple[DictionaryEntry, ...],
) -> str:
    """对规范化结构计算文件级 SHA-256（不含 sha256 字段自身）。

    哈希规范化 JSON 结构（排序键、无空白分隔、UTF-8、ensure_ascii=False）
    而非拼接字符串，消除拼接歧义：不同的词典内容必然产生不同摘要。
    """
    canonical = json.dumps(
        {
            "dictionary_id": dictionary_id,
            "version": version,
            "domain": domain,
            "entries": [
                {"text": entry.text, "entity_type": entry.entity_type}
                for entry in entries
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class DictionaryEntry(BaseModel):
    """单条词典条目：实体/别名文本 + 实体类型；别名即独立条目。"""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    text: str
    entity_type: str

    @field_validator("text")
    @classmethod
    def _text_non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("entry text must not be empty or whitespace-only")
        return value

    @field_validator("entity_type")
    @classmethod
    def _entity_type_format(cls, value: str) -> str:
        if _ENTITY_TYPE.fullmatch(value) is None:
            raise ValueError("entity_type must match [A-Z][A-Z0-9_]{0,31}")
        return value


class DictionaryDocument(BaseModel):
    """规范词典 JSON 文档（文件级 SHA-256 自描述）。"""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    dictionary_id: str
    version: str
    domain: str
    entries: list[DictionaryEntry]
    sha256: str

    @field_validator("dictionary_id", "version", "domain")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("field must not be blank")
        return value

    @field_validator("sha256")
    @classmethod
    def _sha256_format(cls, value: str) -> str:
        if _SHA256_HEX.fullmatch(value) is None:
            raise ValueError("sha256 must be 64 lowercase/uppercase hex chars")
        return value.lower()


def _reject_json(kind: JsonRejectKind) -> NoReturn:
    raise SafetyError(SafetyCode.DICTIONARY_INVALID)


def _validate_semantics(document: DictionaryDocument) -> None:
    """结构校验之后的语义校验：非空、无重复、无冲突（均不回显条目文本）。"""
    if not document.entries:
        raise SafetyError(SafetyCode.DICTIONARY_INVALID, "entries must not be empty")
    entity_type_by_text: dict[str, str] = {}
    for entry in document.entries:
        previous = entity_type_by_text.get(entry.text)
        if previous is not None:
            if previous == entry.entity_type:
                raise SafetyError(SafetyCode.DICTIONARY_INVALID, "duplicate entry text")
            raise SafetyError(SafetyCode.DICTIONARY_CONFLICT, "entry text maps to multiple entity types")
        entity_type_by_text[entry.text] = entry.entity_type
    expected = compute_dictionary_hash(
        document.dictionary_id, document.version, document.domain, document.entries
    )
    if document.sha256 != expected:
        raise SafetyError(SafetyCode.DICTIONARY_INVALID, "sha256 mismatch with declared content")


@dataclass(frozen=True, slots=True)
class CompiledDictionary:
    """已校验词典及其本地重建的 ahocorasick-rs 自动机。

    自动机只在 ``compile_dictionary`` 内从已通过校验的 JSON 条目构建，
    每次编译都是全新构建：索引二进制不持久化、不跨平台/跨版本移植、
    不从快照恢复。``version`` 与 ``sha256`` 忠实携带源 JSON 声明的
    版本与内容哈希，构建产物可追溯（检测输出同时携带词典版本）。
    """

    dictionary_id: str
    version: str
    domain: str
    sha256: str
    entries: tuple[DictionaryEntry, ...]
    _entity_type_by_text: Mapping[str, str] = field(compare=False, repr=False)
    _automaton: AhoCorasick = field(compare=False, repr=False)


def compile_dictionary(source: str | bytes | Mapping[str, Any]) -> CompiledDictionary:
    """严格校验词典 JSON 并本地构建最长匹配自动机。

    解析器与校验器异常携带提交内容，因此拒绝统一在处理结束后以全新
    ``SafetyError`` 抛出：无 ``__context__``/``__cause__`` 链，公开
    消息只含静态结构描述，绝不回显条目文本或文档内容。
    """
    if isinstance(source, Mapping):
        payload: Any = source
    elif isinstance(source, (str, bytes)):
        payload = parse_strict_json(source, reject=_reject_json)
    else:
        raise TypeError(
            "dictionary source must be trusted JSON text or a mapping built by trusted code"
        )
    if not isinstance(payload, dict):
        raise SafetyError(SafetyCode.DICTIONARY_INVALID, "dictionary must be a JSON object")
    validation_failed = False
    try:
        document = DictionaryDocument.model_validate(payload)
    except ValidationError:
        validation_failed = True
    if validation_failed:
        raise SafetyError(SafetyCode.DICTIONARY_INVALID, "dictionary failed strict schema validation")
    _validate_semantics(document)
    patterns = [entry.text for entry in document.entries]
    automaton = AhoCorasick(
        patterns,
        matchkind=MATCHKIND_LEFTMOST_LONGEST,
        store_patterns=False,
    )
    return CompiledDictionary(
        dictionary_id=document.dictionary_id,
        version=document.version,
        domain=document.domain,
        sha256=document.sha256,
        entries=tuple(document.entries),
        _entity_type_by_text={entry.text: entry.entity_type for entry in document.entries},
        _automaton=automaton,
    )


@dataclass(frozen=True, slots=True)
class DictionaryDetection:
    """单次字段检测的结果：候选跨度 + 来源词典版本（可追溯）。"""

    spans: tuple[Span, ...]
    dictionary_version: str


def analyze_dictionary(text: str, compiled: CompiledDictionary) -> DictionaryDetection:
    """对单个字段文本做最长词典匹配，输出 code point 半开偏移跨度。

    检测以调用方给出的单字段文本为输入单位：两个各含半个实体名的
    字段分别调用均不命中，本模块不会替调用方拼接字段。
    """
    if not isinstance(text, str):
        raise SafetyError(SafetyCode.INVALID_TEXT, "text")
    if not isinstance(compiled, CompiledDictionary):
        raise TypeError("compiled must be a CompiledDictionary built by compile_dictionary")
    text_length = len(text)
    spans: list[Span] = []
    for pattern_index, start, end in compiled._automaton.find_matches_as_indexes(text):
        entity_type = compiled.entries[pattern_index].entity_type
        if not 0 <= start < end <= text_length:
            raise SafetyError(SafetyCode.INVALID_SPAN)
        spans.append(Span(start, end, entity_type, SPAN_PRIORITY))
    spans.sort(key=lambda span: (span.start, span.end, span.entity_type))
    return DictionaryDetection(spans=tuple(spans), dictionary_version=compiled.version)
