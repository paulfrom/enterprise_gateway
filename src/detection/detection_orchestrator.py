"""D-12 必需检测编排器：规则 + 词典 + NER 三路必需检测的 fail-closed 编排。

对单字段文本执行三条必需检测路并合并为最终跨度集合：

1. **规则路**（recognizers.py）：按政策配置启用的识别器逐个本地运行，
   候选来源标识为 ``"rule:<name>"``；
2. **词典路**（dictionary.py）：``analyze_dictionary`` 最长匹配，候选来源
   标识为 ``"dict"``，结果携带词典版本；
3. **NER 路**（ner_windowing.py）：**必须**经 inference_executor 在隔离
   工作进程内运行（原生推理运行时无法从线程可靠中断），带独立时间预算；
   ONNX 会话不可 pickle，因此传入包路径、由 worker 进程内
   ``load_model_package`` 加载并推理，跨进程只返回可 pickle 的
   ``EntitySpan`` 元组与包溯源信息，候选来源标识为 ``"ner"``。

Fail-closed 语义：三路全部成功才产出 ``DetectionOutcome``（最终
``ResolvedSpan`` 元组 + 词典版本/启用识别器清单/NER 包标识与哈希等
可追溯元数据）；任何一路失败、超时、抛错、偏移不可恢复 → 整请求
``SafetyError``，无部分结果。错误按真实原因传播：各路自身抛出的
``SafetyError`` 原样传播（如 ``INVALID_TEXT``/``INVALID_SPAN``/
``NER_OFFSET_UNRECOVERABLE``/``NER_MODEL_INVALID``）；NER 超时经
执行器真实回收进程后抛 ``INFERENCE_TIMEOUT``；识别器/词典/worker
抛出非受控异常时统一包为 ``DETECTION_FAILED``（detail 只含路名静态
标识，异常链断开，公开消息无业务正文）；NER 路或词典路未配置
（``None``）→ ``DETECTION_INCOMPLETE``，拒绝而非降级为两路/一路。

执行顺序固定为规则 → 词典 → NER → 合并，因此多路同时异常时先执行
路的错误先抛出（确定性错误优先级）；合并由 span_resolver 完成，
P0 秘密候选在合并时整请求阻断（``SECRET_DETECTED``）。

本模块只做检测编排与合并，不做准入、外发许可或留存决策
（归 admission/evidence_gate/egress 系列）。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from presidio_analyzer import EntityRecognizer

from detection.dictionary import CompiledDictionary, analyze_dictionary
from infra.errors import SafetyCode, SafetyError
from detection.inference_executor import InferenceExecutor
from detection.ner_model import load_model_package
from detection.ner_windowing import (
    DEFAULT_STRIDE,
    DEFAULT_WINDOW_LENGTH,
    EntitySpan,
    NerWindowMerger,
)
from detection.recognizers import analyze_text, default_recognizers
from detection.span_resolver import (
    DetectionCandidate,
    ResolvedSpan,
    candidate_from,
    resolve_spans,
)

__all__ = ["DetectionOutcome", "DetectionOrchestrator", "NerProvenance", "DEFAULT_NER_TIMEOUT"]

DEFAULT_NER_TIMEOUT = 30.0


def _ner_worker(
    package_dir: str, text: str, window_length: int, stride: int
) -> tuple[tuple[EntitySpan, ...], tuple[str, str, str]]:
    """NER 工作进程入口：进程内加载模型包并推理（spawn 可 pickle）。

    ``load_model_package`` 的产物（onnxruntime 会话、tokenizer）不可
    pickle，因此跨进程只传包路径，由 worker 进程内完成加载校验、切窗
    推理与偏移恢复；返回值只含可 pickle 的 ``EntitySpan`` 元组与包
    溯源三元组 ``(artifact, created_utc, model_sha256)``。
    """
    package = load_model_package(package_dir)
    merger = NerWindowMerger(
        package.tokenizer,
        package.session,
        package.id2label,
        window_length=window_length,
        stride=stride,
    )
    spans = merger.extract(text)
    return spans, (
        package.manifest.artifact,
        package.manifest.created_utc,
        package.manifest.files["model.onnx"].sha256,
    )


@dataclass(frozen=True, slots=True)
class NerProvenance:
    """NER 包溯源：制品标识、清单创建时间与模型文件哈希。"""

    artifact: str
    created_utc: str
    model_sha256: str


@dataclass(frozen=True, slots=True)
class DetectionOutcome:
    """三路全部成功后的放行检测结果（可追溯元数据 + 最终跨度）。

    ``spans`` 是 span_resolver 合并后的确定性最终跨度集合，每个
    ``ResolvedSpan.sources`` 可溯源到提出它的检测路
    （``"rule:<name>"`` / ``"dict"`` / ``"ner"``）。
    """

    spans: tuple[ResolvedSpan, ...]
    dictionary_version: str
    recognizer_names: tuple[str, ...]
    ner: NerProvenance


class DetectionOrchestrator:
    """三路必需检测的 fail-closed 编排器。

    参数
    ----
    recognizers:
        启用的规则识别器（``EntityRecognizer``）；``None`` 使用
        ``default_recognizers()`` 七路默认识别器。非
        ``EntityRecognizer`` 输入 → ``INVALID_RECOGNIZER``。
    dictionary:
        ``compile_dictionary`` 产物；``None`` 表示词典路未配置，
        ``detect`` 时拒绝（``DETECTION_INCOMPLETE``），不降级。
    ner_package_dir:
        D-08 NER 包目录；``None`` 表示 NER 路未配置，``detect`` 时
        拒绝（``DETECTION_INCOMPLETE``），不降级为两路。包的真实
        校验在 worker 进程内由 ``load_model_package`` 完成。
    executor:
        ``InferenceExecutor``；``None`` 时编排器自建一个并持有
        （``close()`` 时一并关闭）。传入外部执行器时不接管其生命周期。
    ner_worker:
        NER worker 入口（模块级可 pickle 可调用，签名同
        ``_ner_worker``）；``None`` 使用真实 worker。仅用于注入
        受控的慢/挂起推理来验证时间预算路径，不改变检测语义。
    ner_timeout:
        NER 路单次调用时间预算（秒，含排队与进程启动），必须 > 0。
    window_length / stride:
        NER 切窗几何（含特殊 token 预算），校验规则同
        ``NerWindowMerger``，非法值 → ``ValueError``。

    线程模型：规则路与词典路为纯 CPU 本地调用，内联执行；NER 路
    经执行器隔离进程 + 时间预算。
    """

    def __init__(
        self,
        *,
        recognizers: Iterable[EntityRecognizer] | None = None,
        dictionary: CompiledDictionary | None = None,
        ner_package_dir: str | os.PathLike[str] | None = None,
        executor: InferenceExecutor | None = None,
        ner_worker: Callable[..., Any] | None = None,
        ner_timeout: float = DEFAULT_NER_TIMEOUT,
        window_length: int = DEFAULT_WINDOW_LENGTH,
        stride: int = DEFAULT_STRIDE,
    ) -> None:
        if recognizers is None:
            active = default_recognizers()
        else:
            try:
                active = tuple(recognizers)
            except TypeError:
                raise SafetyError(SafetyCode.INVALID_RECOGNIZER, "recognizers") from None
            for recognizer in active:
                if not isinstance(recognizer, EntityRecognizer):
                    raise SafetyError(SafetyCode.INVALID_RECOGNIZER, "recognizers")
        if dictionary is not None and not isinstance(dictionary, CompiledDictionary):
            raise TypeError(
                "dictionary must be a CompiledDictionary built by compile_dictionary or None"
            )
        if ner_package_dir is not None and not isinstance(ner_package_dir, (str, os.PathLike)):
            raise TypeError("ner_package_dir must be a path or None")
        if ner_worker is not None and not callable(ner_worker):
            raise TypeError("ner_worker must be callable or None")
        if not isinstance(ner_timeout, (int, float)) or isinstance(ner_timeout, bool):
            raise TypeError("ner_timeout must be a number")
        if ner_timeout <= 0:
            raise ValueError("ner_timeout must be > 0")
        capacity = window_length - 2
        if capacity < 1:
            raise ValueError("window_length must leave room for content tokens")
        if not 1 <= stride <= capacity:
            raise ValueError("stride must be between 1 and the content capacity")
        if (capacity - stride) % 2 != 0:
            raise ValueError("capacity minus stride must be even")
        self._recognizers = active
        self._dictionary = dictionary
        self._ner_package_dir = os.fspath(ner_package_dir) if ner_package_dir is not None else None
        self._owns_executor = executor is None
        self._executor = executor if executor is not None else InferenceExecutor()
        self._ner_worker = ner_worker if ner_worker is not None else _ner_worker
        self._ner_timeout = float(ner_timeout)
        self._window_length = window_length
        self._stride = stride

    def detect(self, text: str) -> DetectionOutcome:
        """执行三路必需检测并合并；任何一路失败 → 整请求 ``SafetyError``。

        执行顺序固定：规则 → 词典 → NER → 合并。错误优先级确定性：
        多路同时异常时先执行路的错误先抛出；秘密（P0）候选在合并阶段
        整请求阻断（``SECRET_DETECTED``）。
        """
        if not isinstance(text, str):
            raise SafetyError(SafetyCode.INVALID_TEXT, "text")
        if self._dictionary is None:
            raise SafetyError(SafetyCode.DETECTION_INCOMPLETE, "dictionary")
        if self._ner_package_dir is None:
            raise SafetyError(SafetyCode.DETECTION_INCOMPLETE, "ner")
        candidates: list[DetectionCandidate] = []
        for recognizer in self._recognizers:
            source = f"rule:{recognizer.name}"
            rule_failed = False
            try:
                spans = analyze_text(text, (recognizer,))
            except SafetyError:
                raise
            except Exception:
                rule_failed = True
            if rule_failed:
                # 映射在 except 块外抛出（ADR-0004）：新 SafetyError 不带
                # __cause__/__context__ 链，公开消息只含静态路名。
                raise SafetyError(SafetyCode.DETECTION_FAILED, "rule") from None
            candidates.extend(candidate_from(span, source=source) for span in spans)
        dict_failed = False
        try:
            detection = analyze_dictionary(text, self._dictionary)
        except SafetyError:
            raise
        except Exception:
            dict_failed = True
        if dict_failed:
            raise SafetyError(SafetyCode.DETECTION_FAILED, "dictionary") from None
        candidates.extend(candidate_from(span, source="dict") for span in detection.spans)
        ner_failed = False
        try:
            ner_result = self._executor.submit(
                self._ner_worker,
                self._ner_package_dir,
                text,
                self._window_length,
                self._stride,
                timeout=self._ner_timeout,
            )
        except SafetyError:
            # INFERENCE_TIMEOUT（进程已真实回收）/ NER_OFFSET_UNRECOVERABLE /
            # NER_MODEL_INVALID 等按真实原因原样传播（执行器已断开链、丢弃 detail 外的正文）。
            raise
        except RuntimeError:
            ner_failed = True
        if ner_failed:
            raise SafetyError(SafetyCode.DETECTION_FAILED, "ner") from None
        try:
            ner_spans, (artifact, created_utc, model_sha256) = ner_result
        except (TypeError, ValueError):
            raise SafetyError(SafetyCode.DETECTION_FAILED, "ner") from None
        candidates.extend(candidate_from(span, source="ner") for span in ner_spans)
        resolved = resolve_spans(candidates, text_length=len(text))
        return DetectionOutcome(
            spans=resolved,
            dictionary_version=detection.dictionary_version,
            recognizer_names=tuple(recognizer.name for recognizer in self._recognizers),
            ner=NerProvenance(
                artifact=artifact, created_utc=created_utc, model_sha256=model_sha256
            ),
        )

    def close(self) -> None:
        """关闭编排器自持的资源（自建执行器）；外部传入的执行器不接管。"""
        if self._owns_executor:
            self._executor.close()

    def __enter__(self) -> "DetectionOrchestrator":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()
