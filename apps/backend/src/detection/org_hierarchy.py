"""Deterministic extraction of hierarchical organization segments (方案 B).

When an upstream detector (NER, dictionary, or rule) detects an initial ORG
entity (e.g., "四川虹信软件股份有限公司"), following segments connected by
hierarchy delimiters (e.g., "/", "-", ">") that end with organizational
department/division/center suffixes are extracted as distinct ORG candidates.

This preserves the hierarchical structure while masking each sub-department
with independent placeholder tokens (e.g. <ORG_001>/<ORG_002>/<ORG_003>).
"""

from __future__ import annotations

import re
from typing import Sequence

from detection.span_resolver import DetectionCandidate

__all__ = ["extract_hierarchy_org_candidates"]

_ORG_SUFFIXES = (
    "业务中心", "技术中心", "研发中心", "数据中心", "创新中心", "运营中心", "营销中心", "服务中心",
    "信息中心", "计算中心", "网络中心", "管理中心", "调度中心", "支撑中心", "保障中心", "指挥中心",
    "事业部", "事业群", "业务部", "业务群", "产品线", "业务线",
    "分公司", "子公司", "支公司", "总公司", "母公司", "代表处", "办事处", "分部", "分局", "支局",
    "工作组", "项目组", "课题组", "班组", "小组", "特设组",
    "委员会", "理事会", "董事会", "监事会", "党支部", "团支部", "工会", "指挥部", "办公室",
    "实验室", "研究所", "研究院", "研发院", "科学院", "设计院",
    "学院", "学部", "系", "教研室",
    "中台", "平台",
    "分行", "支行", "网点", "门市部", "科室", "大队", "中队", "小队",
    "中心", "部门",
    "处", "室", "科", "所", "院", "馆", "站", "厅", "队", "部", "组",
)

_SUFFIX_RE = "|".join(sorted(_ORG_SUFFIXES, key=len, reverse=True))

_HIERARCHY_SEGMENT = re.compile(
    rf"^\s*([\/\\—–\->]|--)\s*([\u4e00-\u9fa5a-zA-Z0-9·]{{1,30}}?(?:{_SUFFIX_RE})(?:\s*[（\(][\u4e00-\u9fa5a-zA-Z0-9·]+[）\)])?)(?=[\\\/—–\->\s，。；！？,!?;:\n\r\t：\"'“”‘’]|$)"
)


def extract_hierarchy_org_candidates(
    text: str, candidates: Sequence[DetectionCandidate]
) -> tuple[DetectionCandidate, ...]:
    """Scan forward from detected ORG candidates along hierarchy delimiters.

    Returns new DetectionCandidate instances for each chained sub-department.
    """
    if not text or not candidates:
        return ()

    # Seed positions with all detected ORG candidates
    org_candidates = [c for c in candidates if c.entity_type == "ORG"]
    if not org_candidates:
        return ()

    derived: list[DetectionCandidate] = []
    # Track covered spans to avoid duplicate candidates
    visited_spans: set[tuple[int, int]] = {(c.start, c.end) for c in candidates}

    # Queue of endpoints to explore forward: (end_offset, priority)
    queue: list[tuple[int, int]] = [(c.end, c.priority) for c in org_candidates]

    while queue:
        curr_end, priority = queue.pop(0)
        if curr_end >= len(text):
            continue

        match = _HIERARCHY_SEGMENT.match(text[curr_end:])
        if not match:
            continue

        seg_start = curr_end + match.start(2)
        seg_end = curr_end + match.end(2)

        span_key = (seg_start, seg_end)
        if span_key not in visited_spans:
            visited_spans.add(span_key)
            candidate = DetectionCandidate(
                start=seg_start,
                end=seg_end,
                entity_type="ORG",
                priority=priority,
                source="rule:org_hierarchy",
            )
            derived.append(candidate)
            queue.append((seg_end, priority))

    return tuple(derived)
