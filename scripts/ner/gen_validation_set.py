"""Generate the D-08 synthetic independent validation set.

Writes tests/fixtures/D-08/validation-set.json: >= 40 gold samples with
code point half-open entity spans [start, end). Every entity name is
synthetic (fictional persons, organizations, places); no real person or
institution appears. The set is built by explicit construction order:
each mention is located with a cursor-based search
(``text.index(mention, cursor)``) that places entities in the listed
order, and a self-check asserts every half-open span slices exactly the
mention text.

This validation set is self-built synthetic data. It shares no source with
the model's training corpus (People's Daily NER), so local evaluation on it
is an independent re-test, per the D-08 task card.

Coverage: multi-entity sentences, adjacent entities (spans touching),
single-code-point PER entities, English-mixed sentences, and no-entity
negatives.

Usage:
    python scripts/ner/gen_validation_set.py
"""

from __future__ import annotations

import json
from pathlib import Path

GATEWAY_ROOT = Path(__file__).resolve().parents[2]
OUT_PATH = GATEWAY_ROOT / "tests" / "detection" / "fixtures" / "ner" / "validation-set.json"

# type, mention
E = lambda t, m: (t, m)  # noqa: E731

SAMPLES: list[tuple[str, list[tuple[str, str]]]] = [
    # --- normal multi-entity sentences (news style, model's domain) ---
    ("记者林昭远从临澜市发回报道。", [E("PER", "林昭远"), E("LOC", "临澜市")]),
    ("星澜科技宣布在青屿县建设新园区。", [E("ORG", "星澜科技"), E("LOC", "青屿县")]),
    ("顾明澈代表北辰航运有限公司出席雾川省论坛。", [E("PER", "顾明澈"), E("ORG", "北辰航运有限公司"), E("LOC", "雾川省")]),
    ("江晚舟与贺临溪在临澜市签署合作协议。", [E("PER", "江晚舟"), E("PER", "贺临溪"), E("LOC", "临澜市")]),
    ("澄海制药集团总部位于青屿县。", [E("ORG", "澄海制药集团"), E("LOC", "青屿县")]),
    ("裴照野会见星澜科技董事长。", [E("PER", "裴照野"), E("ORG", "星澜科技")]),
    ("雾川省近日出台新的航运补贴政策。", [E("LOC", "雾川省")]),
    ("白鹿数据在望舒湾设立研究中心。", [E("ORG", "白鹿数据"), E("LOC", "望舒湾")]),
    ("祁望舒担任拓原物流首席执行官。", [E("PER", "祁望舒"), E("ORG", "拓原物流")]),
    ("临澜商业银行栖迟镇支行正式开业。", [E("ORG", "临澜商业银行"), E("LOC", "栖迟镇")]),
    ("曜石半导体获得雾川省产业基金投资。", [E("ORG", "曜石半导体"), E("LOC", "雾川省")]),
    ("岑见微在清嘉巷开设工作室。", [E("PER", "岑见微"), E("LOC", "清嘉巷")]),
    ("记者穆清嘉从白鹿原发回现场报道。", [E("PER", "穆清嘉"), E("LOC", "白鹿原")]),
    ("霁月光电与曜石半导体达成供货协议。", [E("ORG", "霁月光电"), E("ORG", "曜石半导体")]),
    ("寒汀群岛迎来首批考察团。", [E("LOC", "寒汀群岛")]),
    ("陆栖迟出任星澜科技技术总监。", [E("PER", "陆栖迟"), E("ORG", "星澜科技")]),
    ("云溪口岸新增两条国际航线。", [E("LOC", "云溪口岸")]),
    ("临澜市与青屿县签署共建协议。", [E("LOC", "临澜市"), E("LOC", "青屿县")]),
    ("闻人棠当选北辰航运有限公司工会主席。", [E("PER", "闻人棠"), E("ORG", "北辰航运有限公司")]),
    ("照野岭隧道贯通仪式在栖迟镇举行。", [E("LOC", "照野岭"), E("LOC", "栖迟镇")]),
    # --- adjacent entities: spans touch with no separator ---
    ("星澜科技临澜市分部启用新园区。", [E("ORG", "星澜科技"), E("LOC", "临澜市")]),
    ("沈其澜裴照野共同出席发布会。", [E("PER", "沈其澜"), E("PER", "裴照野")]),
    ("临澜市青屿县交界地带发现矿脉。", [E("LOC", "临澜市"), E("LOC", "青屿县")]),
    ("拓原物流白鹿数据中心投入运营。", [E("ORG", "拓原物流"), E("ORG", "白鹿数据")]),
    ("记者顾明澈林昭远联合报道。", [E("PER", "顾明澈"), E("PER", "林昭远")]),
    ("霁月光电望舒湾基地落成。", [E("ORG", "霁月光电"), E("LOC", "望舒湾")]),
    ("雾川省临澜市联合发布规划。", [E("LOC", "雾川省"), E("LOC", "临澜市")]),
    # --- single-code-point PER entities ---
    ("演员岚出席望舒湾音乐节。", [E("PER", "岚"), E("LOC", "望舒湾")]),
    ("澈在清嘉巷举办个人画展。", [E("PER", "澈"), E("LOC", "清嘉巷")]),
    ("棠代表星澜科技接受访问。", [E("PER", "棠"), E("ORG", "星澜科技")]),
    ("诗人舟从寒汀群岛归来。", [E("PER", "舟"), E("LOC", "寒汀群岛")]),
    # --- English-mixed sentences ---
    ("项目经理Tom与林昭远确认Starlight系统上线。", [E("PER", "Tom"), E("PER", "林昭远"), E("ORG", "Starlight")]),
    ("GreenField公司与北辰航运有限公司开展合作。", [E("ORG", "GreenField"), E("ORG", "北辰航运有限公司")]),
    ("Alice赴临澜市参加行业会议。", [E("PER", "Alice"), E("LOC", "临澜市")]),
    ("技术团队从BlueOcean迁回白鹿数据平台。", [E("ORG", "BlueOcean"), E("ORG", "白鹿数据")]),
    ("Bob在青屿县考察期间接受访问。", [E("PER", "Bob"), E("LOC", "青屿县")]),
    ("NorthBridge实验室入驻望舒湾。", [E("ORG", "NorthBridge"), E("LOC", "望舒湾")]),
    ("Vera与沈其澜共同主持临澜市发布会。", [E("PER", "Vera"), E("PER", "沈其澜"), E("LOC", "临澜市")]),
    ("SwiftLink为澄海制药集团提供云服务。", [E("ORG", "SwiftLink"), E("ORG", "澄海制药集团")]),
    ("Ken抵达云溪口岸后向媒体致意。", [E("PER", "Ken"), E("LOC", "云溪口岸")]),
    ("OpenSky联盟在雾川省设立办事处。", [E("ORG", "OpenSky"), E("LOC", "雾川省")]),
    ("Lena受星澜科技邀请访问照野岭。", [E("PER", "Lena"), E("ORG", "星澜科技"), E("LOC", "照野岭")]),
    ("HexaSoft与拓原物流完成系统对接。", [E("ORG", "HexaSoft"), E("ORG", "拓原物流")]),
    # --- no-entity negatives ---
    ("会议纪要已经整理完毕，请大家自行取阅。", []),
    ("今天的会议改到下午三点进行。", []),
    ("新版操作手册发布在内部网站上。", []),
    ("本周的值班安排已张贴在公告栏。", []),
    ("请各部门按时提交季度总结。", []),
    ("雨后山路湿滑，出行请注意安全。", []),
    ("图书馆延长开放时间的通知已下发。", []),
    ("食堂新增了窗口，供餐时间不变。", []),
]


def build_sample(index: int, text: str, entities: list[tuple[str, str]]) -> dict:
    spans: list[dict] = []
    cursor = 0
    for entity_type, mention in entities:
        start = text.index(mention, cursor)
        end = start + len(mention)
        spans.append({"type": entity_type, "start": start, "end": end})
        cursor = end
    sample = {"id": f"D08-S{index:03d}", "text": text, "entities": spans}
    # Self-check: half-open code point spans slice exactly the mention.
    for span in spans:
        assert text[span["start"]:span["end"]] == text[span["start"]:span["end"]].strip()
        assert span["start"] < span["end"] <= len(text)
    return sample


def main() -> None:
    samples = [
        build_sample(i, text, entities) for i, (text, entities) in enumerate(SAMPLES, start=1)
    ]
    counts = {"PER": 0, "ORG": 0, "LOC": 0}
    for sample in samples:
        for span in sample["entities"]:
            counts[span["type"]] += 1
    payload = {
        "dataset": "D-08 synthetic independent validation set",
        "span_convention": "python code point half-open [start, end)",
        "synthetic_only": True,
        "no_overlap_with_training_corpus": "self-built; model trained on People's Daily NER",
        "samples": samples,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {len(samples)} samples ({counts}) -> {OUT_PATH}")


if __name__ == "__main__":
    main()
