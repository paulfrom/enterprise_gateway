"""Privacy detection orchestrator tests: multi-engine dispatch, span merging, and fail-closed gate.

真实组件优先：规则路用真实识别器、词典路用 ``compile_dictionary`` 真实
编译产物、NER 路正例用 D-08 mini-valid-package 经真实 executor spawn 的
工作进程（进程内 ``load_model_package`` + 切窗推理）；NER 反例（超时/
挂起、worker 异常、偏移不可恢复）用模块级可 pickle 的受控 worker 或
真实篡改包（重算 manifest 哈希后加载成功、推理时 logits 形状不符 →
``NER_OFFSET_UNRECOVERABLE``）。注入 worker 只经构造函数显式传入，模拟
慢/挂起推理验证时间预算路径，不改变检测语义。

全部为合成夹具：词典条目、文本、NER 包均合成，无真实人名/机构/密钥。
canary 断言：受控错误公开消息不得含业务正文。
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from presidio_analyzer import Pattern, PatternRecognizer

from detection.detection_orchestrator import (
    DetectionOrchestrator,
    NerProvenance,
    _ner_worker,
)
from detection.dictionary import (
    CompiledDictionary,
    DictionaryEntry,
    analyze_dictionary,
    compile_dictionary,
    compute_dictionary_hash,
)
from infra.errors import SafetyCode, SafetyError
from detection.inference_executor import InferenceExecutor
from detection.ner_windowing import EntitySpan
from detection.recognizers import default_recognizers
from detection.span_resolver import ResolvedSpan

FIXTURES = Path(__file__).parent / "fixtures"
MINI_PACKAGE = FIXTURES / "ner" / "mini-valid-package"

CANARY = "d12-canary-7e1f9a2c"
SECRET_CANARY = "sk-ABCDEFGH123456789"

DICTIONARY_ID = "dict-d12-synthetic"
DICTIONARY_VERSION = "2026.10.04"
DICTIONARY_DOMAIN = "synthetic-domain"
DICTIONARY_ENTRIES = (
    DictionaryEntry(text="星云科技", entity_type="ORG"),
    DictionaryEntry(text="zhangli", entity_type="PER"),
)

FAKE_PROVENANCE = ("test-ner-artifact", "2026-10-04T00:00:00Z", "ab" * 32)

COMPILED: CompiledDictionary | None = None
EXECUTOR: InferenceExecutor | None = None


def setUpModule() -> None:
    global COMPILED, EXECUTOR
    payload = {
        "dictionary_id": DICTIONARY_ID,
        "version": DICTIONARY_VERSION,
        "domain": DICTIONARY_DOMAIN,
        "entries": [
            {"text": entry.text, "entity_type": entry.entity_type}
            for entry in DICTIONARY_ENTRIES
        ],
        "sha256": compute_dictionary_hash(
            DICTIONARY_ID, DICTIONARY_VERSION, DICTIONARY_DOMAIN, DICTIONARY_ENTRIES
        ),
    }
    COMPILED = compile_dictionary(payload)
    EXECUTOR = InferenceExecutor()


def tearDownModule() -> None:
    EXECUTOR.close()


def _orchestrator(**overrides: object) -> DetectionOrchestrator:
    params = {"executor": EXECUTOR}
    params.update(overrides)
    return DetectionOrchestrator(**params)  # type: ignore[arg-type]


# -- 注入 NER worker（模块级，spawn 可 pickle；行为恒定，不依赖父进程状态） --


def _worker_empty(package_dir, text, window_length, stride):
    return (), FAKE_PROVENANCE


def _worker_entities(package_dir, text, window_length, stride):
    return (
        EntitySpan(start=12, end=19, entity_type="PER"),
        EntitySpan(start=23, end=29, entity_type="ORG"),
    ), FAKE_PROVENANCE


def _worker_hang(package_dir, text, window_length, stride):
    while True:
        time.sleep(0.2)


def _worker_value_error(package_dir, text, window_length, stride):
    raise ValueError(f"boom {CANARY}")


# -- 规则路/词典路测试替身（内联调用，无 pickle 约束） --


class _ExplodingRecognizer(PatternRecognizer):
    """analyze 抛非受控异常的识别器（模拟识别器内部 bug）。"""

    def __init__(self) -> None:
        super().__init__(
            supported_entity="PHONE_NUMBER",
            name="ExplodingRecognizer",
            supported_language="zh",
            patterns=[Pattern("digits", r"\d+", 1.0)],
        )

    def analyze(self, text, entities, nlp_artifacts=None, **kwargs):
        raise RuntimeError(f"boom {CANARY}")


class _RaisingAutomaton:
    """篡改词典：自动机调用抛非受控异常（模拟运行时词典损坏）。"""

    def find_matches_as_indexes(self, text):
        raise RuntimeError(f"tampered {CANARY}")


class _BadOffsetAutomaton:
    """篡改词典：自动机返回越界偏移 → analyze_dictionary 抛 INVALID_SPAN。"""

    def find_matches_as_indexes(self, text):
        return iter([(0, len(text) + 5, 0)])


def _retampered_dictionary(automaton: object) -> CompiledDictionary:
    assert COMPILED is not None
    return CompiledDictionary(
        dictionary_id=COMPILED.dictionary_id,
        version=COMPILED.version,
        domain=COMPILED.domain,
        sha256=COMPILED.sha256,
        entries=COMPILED.entries,
        _entity_type_by_text={entry.text: entry.entity_type for entry in COMPILED.entries},
        _automaton=automaton,
    )


def _build_label_mismatch_package(target: Path) -> None:
    """构建哈希自洽但 config 声明 10 标签的变体包（模型实际输出 9 标签）。

    load_model_package 全部通过；切窗推理时 logits 形状与 id2label 不符 →
    ``NER_OFFSET_UNRECOVERABLE``（真实 worker 进程内路径）。
    """
    for name in ("model.onnx", "tokenizer.json", "license-excerpt.json"):
        shutil.copyfile(MINI_PACKAGE / name, target / name)
    config = json.loads((MINI_PACKAGE / "config.json").read_text(encoding="utf-8"))
    config["id2label"]["9"] = "B-MISC"
    config["num_labels"] = 10
    config_raw = json.dumps(config, ensure_ascii=False, indent=2).encode("utf-8")
    (target / "config.json").write_bytes(config_raw)
    manifest = json.loads((MINI_PACKAGE / "manifest.json").read_text(encoding="utf-8"))
    manifest["files"]["config.json"] = {
        "sha256": hashlib.sha256(config_raw).hexdigest(),
        "bytes": len(config_raw),
    }
    (target / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _mini_model_sha256() -> str:
    manifest = json.loads((MINI_PACKAGE / "manifest.json").read_text(encoding="utf-8"))
    return manifest["files"]["model.onnx"]["sha256"]


class PositivePathTests(unittest.TestCase):
    """正例：三路成功 → 合并 + 可追溯元数据 + 确定性。"""

    def test_all_real_three_paths_success_and_metadata(self) -> None:
        text = "星云科技联系人手机号13800138000"
        orchestrator = _orchestrator(
            dictionary=COMPILED,
            ner_package_dir=MINI_PACKAGE,
            ner_worker=_ner_worker,
        )
        outcome = orchestrator.detect(text)
        # 元数据可追溯：词典版本、启用识别器清单、NER 包标识/哈希。
        self.assertEqual(outcome.dictionary_version, DICTIONARY_VERSION)
        self.assertEqual(
            outcome.recognizer_names, tuple(r.name for r in default_recognizers())
        )
        self.assertEqual(
            outcome.ner,
            NerProvenance(
                artifact="mini-valid-package",
                created_utc="2026-10-03T09:46:28Z",
                model_sha256=_mini_model_sha256(),
            ),
        )
        spans = outcome.spans
        # 合并不缩小覆盖：规则手机跨度 [10,21) 与词典跨度 [0,4) 必被覆盖
        # （NER 为随机权重 mini 模型，只断言管线语义，不断言识别质量）。
        self.assertTrue(
            any(s.start <= 10 and s.end >= 21 for s in spans),
            f"phone coverage lost: {spans}",
        )
        self.assertTrue(
            any(s.start == 0 and s.end >= 4 for s in spans),
            f"dictionary coverage lost: {spans}",
        )
        # 来源可溯源且只来自已知检测路。
        known = {"dict", "ner", *(f"rule:{name}" for name in outcome.recognizer_names)}
        for span in spans:
            self.assertTrue(span.sources, "span without sources")
            for source in span.sources:
                self.assertIn(source, known)

    def test_merge_sources_and_dedup(self) -> None:
        # "13800138000 zhangli at qixing"：
        #   规则路   → PHONE_NUMBER [0,11)            source rule:CnPhoneRecognizer
        #   词典路   → PER [12,19)（zhangli 条目）     source dict
        #   NER 注入 → PER [12,19)、ORG [23,29)        source ner
        # PER 两路同坐标合并为一个跨度、来源取并集且排序；ORG 仅 NER 提出。
        text = "13800138000 zhangli at qixing"
        orchestrator = _orchestrator(
            dictionary=COMPILED,
            ner_package_dir="unused-by-injected-worker",
            ner_worker=_worker_entities,
        )
        outcome = orchestrator.detect(text)
        self.assertEqual(
            outcome.spans,
            (
                ResolvedSpan(0, 11, "PHONE_NUMBER", 3, ("rule:CnPhoneRecognizer",)),
                ResolvedSpan(12, 19, "PER", 3, ("dict", "ner")),
                ResolvedSpan(23, 29, "ORG", 3, ("ner",)),
            ),
        )
        self.assertEqual(
            outcome.ner,
            NerProvenance(
                artifact=FAKE_PROVENANCE[0],
                created_utc=FAKE_PROVENANCE[1],
                model_sha256=FAKE_PROVENANCE[2],
            ),
        )

    def test_deterministic_across_runs(self) -> None:
        text = "13800138000 zhangli at qixing"
        orchestrator = _orchestrator(
            dictionary=COMPILED,
            ner_package_dir="unused-by-injected-worker",
            ner_worker=_worker_entities,
        )
        first = orchestrator.detect(text)
        second = orchestrator.detect(text)
        self.assertEqual(first, second)

    def test_empty_text_all_paths_empty(self) -> None:
        orchestrator = _orchestrator(
            dictionary=COMPILED,
            ner_package_dir="unused-by-injected-worker",
            ner_worker=_worker_empty,
        )
        outcome = orchestrator.detect("")
        self.assertEqual(outcome.spans, ())
        self.assertEqual(outcome.dictionary_version, DICTIONARY_VERSION)


class BlockingPathTests(unittest.TestCase):
    """反例：任一必需路失败 → 整请求 fail-closed，无部分结果。"""

    def test_secret_hit_blocks_whole_request(self) -> None:
        orchestrator = _orchestrator(
            dictionary=COMPILED,
            ner_package_dir="unused-by-injected-worker",
            ner_worker=_worker_entities,
        )
        with self.assertRaises(SafetyError) as ctx:
            orchestrator.detect(f"token {SECRET_CANARY} tail")
        self.assertEqual(ctx.exception.code, SafetyCode.SECRET_DETECTED)
        self.assertNotIn(SECRET_CANARY, str(ctx.exception))

    def test_ner_not_configured_refuses_not_degrades(self) -> None:
        orchestrator = _orchestrator(dictionary=COMPILED, ner_package_dir=None)
        with self.assertRaises(SafetyError) as ctx:
            orchestrator.detect("any text")
        self.assertEqual(ctx.exception.code, SafetyCode.DETECTION_INCOMPLETE)
        self.assertEqual(str(ctx.exception), "DETECTION_INCOMPLETE (ner)")

    def test_dictionary_not_configured_refuses_not_degrades(self) -> None:
        orchestrator = _orchestrator(dictionary=None, ner_package_dir=MINI_PACKAGE)
        with self.assertRaises(SafetyError) as ctx:
            orchestrator.detect("any text")
        self.assertEqual(ctx.exception.code, SafetyCode.DETECTION_INCOMPLETE)
        self.assertEqual(str(ctx.exception), "DETECTION_INCOMPLETE (dictionary)")

    def test_rule_path_unexpected_error_blocks(self) -> None:
        orchestrator = _orchestrator(
            recognizers=[_ExplodingRecognizer()],
            dictionary=COMPILED,
            ner_package_dir="unused-by-injected-worker",
            ner_worker=_worker_entities,
        )
        with self.assertRaises(SafetyError) as ctx:
            orchestrator.detect(f"digits 12345 {CANARY}")
        self.assertEqual(ctx.exception.code, SafetyCode.DETECTION_FAILED)
        self.assertEqual(str(ctx.exception), "DETECTION_FAILED (rule)")
        self.assertNotIn(CANARY, str(ctx.exception))
        self.assertIsNone(ctx.exception.__cause__)
        self.assertIsNone(ctx.exception.__context__)

    def test_rule_path_safety_error_propagates_by_true_reason(self) -> None:
        orchestrator = _orchestrator(
            dictionary=COMPILED,
            ner_package_dir="unused-by-injected-worker",
            ner_worker=_worker_entities,
        )
        with self.assertRaises(SafetyError) as ctx:
            orchestrator.detect(123)  # type: ignore[arg-type]
        self.assertEqual(ctx.exception.code, SafetyCode.INVALID_TEXT)

    def test_dictionary_tampered_blocks(self) -> None:
        orchestrator = _orchestrator(
            dictionary=_retampered_dictionary(_RaisingAutomaton()),
            ner_package_dir="unused-by-injected-worker",
            ner_worker=_worker_entities,
        )
        with self.assertRaises(SafetyError) as ctx:
            orchestrator.detect(f"任意文本 {CANARY}")
        self.assertEqual(ctx.exception.code, SafetyCode.DETECTION_FAILED)
        self.assertEqual(str(ctx.exception), "DETECTION_FAILED (dictionary)")
        self.assertNotIn(CANARY, str(ctx.exception))

    def test_dictionary_invalid_span_propagates_by_true_reason(self) -> None:
        orchestrator = _orchestrator(
            dictionary=_retampered_dictionary(_BadOffsetAutomaton()),
            ner_package_dir="unused-by-injected-worker",
            ner_worker=_worker_entities,
        )
        with self.assertRaises(SafetyError) as ctx:
            orchestrator.detect("任意文本")
        self.assertEqual(ctx.exception.code, SafetyCode.INVALID_SPAN)

    def test_dictionary_spans_are_real(self) -> None:
        # 防替身自欺：真实编译词典确实产出词典跨度与版本。
        detection = analyze_dictionary("联系星云科技", COMPILED)
        self.assertEqual(detection.dictionary_version, DICTIONARY_VERSION)
        self.assertEqual(
            [(s.start, s.end, s.entity_type) for s in detection.spans], [(2, 6, "ORG")]
        )

    def test_ner_timeout_reclaims_worker(self) -> None:
        orchestrator = _orchestrator(
            dictionary=COMPILED,
            ner_package_dir="unused-by-injected-worker",
            ner_worker=_worker_hang,
            ner_timeout=5.0,
        )
        started = time.monotonic()
        with self.assertRaises(SafetyError) as ctx:
            orchestrator.detect("hang on this field")
        elapsed = time.monotonic() - started
        self.assertEqual(ctx.exception.code, SafetyCode.INFERENCE_TIMEOUT)
        self.assertLess(elapsed, 15.0, "hung worker was not reclaimed promptly")
        # 超时后执行器无残留 worker/pending（进程已真实回收）。
        # submit 返回与 slot 线程的 _running 记账之间存在微小竞态，
        # 轮询至收敛而不是断言瞬时值。
        deadline = time.monotonic() + 5.0
        while EXECUTOR.snapshot() != (0, 0) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(EXECUTOR.snapshot(), (0, 0))

    def test_ner_worker_unexpected_error_blocks(self) -> None:
        orchestrator = _orchestrator(
            dictionary=COMPILED,
            ner_package_dir="unused-by-injected-worker",
            ner_worker=_worker_value_error,
        )
        with self.assertRaises(SafetyError) as ctx:
            orchestrator.detect("any text")
        self.assertEqual(ctx.exception.code, SafetyCode.DETECTION_FAILED)
        self.assertEqual(str(ctx.exception), "DETECTION_FAILED (ner)")
        self.assertNotIn(CANARY, str(ctx.exception))
        self.assertIsNone(ctx.exception.__cause__)
        self.assertIsNone(ctx.exception.__context__)

    def test_ner_offset_unrecoverable_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp) / "label-mismatch-package"
            package.mkdir()
            _build_label_mismatch_package(package)
            orchestrator = _orchestrator(
                dictionary=COMPILED,
                ner_package_dir=package,
                ner_worker=_ner_worker,
            )
            with self.assertRaises(SafetyError) as ctx:
                orchestrator.detect("zhang li at qixing")
        self.assertEqual(ctx.exception.code, SafetyCode.NER_OFFSET_UNRECOVERABLE)

    def test_ner_model_invalid_blocks(self) -> None:
        orchestrator = _orchestrator(
            dictionary=COMPILED,
            ner_package_dir=MINI_PACKAGE / "does-not-exist",
            ner_worker=_ner_worker,
        )
        with self.assertRaises(SafetyError) as ctx:
            orchestrator.detect("any text")
        self.assertEqual(ctx.exception.code, SafetyCode.NER_MODEL_INVALID)

    def test_empty_recognizers_rejected(self) -> None:
        orchestrator = _orchestrator(
            recognizers=[],
            dictionary=COMPILED,
            ner_package_dir=MINI_PACKAGE,
        )
        with self.assertRaises(SafetyError) as ctx:
            orchestrator.detect("any text")
        self.assertEqual(ctx.exception.code, SafetyCode.DETECTION_INCOMPLETE)


if __name__ == "__main__":
    unittest.main()
