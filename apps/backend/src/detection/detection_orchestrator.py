"""必需检测编排器：规则 + 词典 + NER 三路必需检测的 fail-closed 编排。

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

编排器可选装配一个检测结果缓存度量钩子（``configure_cache_probe``，M1
影子度量，见 ``detection_cache_probe``）：它只统计 ``(文本, 装配指纹)``
重复度与可复用工作量，不改变任何检测/合并/失败语义。

本模块只做检测编排与合并，不做准入、外发许可或留存决策
（归 admission/evidence_gate/egress 系列）。
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from presidio_analyzer import EntityRecognizer

from detection.detection_cache import DetectionResultCache
from detection.detection_cache_probe import DetectionCacheProbe
from detection.dictionary import CompiledDictionary, analyze_dictionary
from detection.quick_screen import QuickRiskScreen, QuickScreenConfig
from infra.errors import SafetyCode, SafetyError
from detection.inference_executor import InferenceExecutor
from detection.ner_model import load_model_package, model_manifest_digest
from detection.ner_runtime import NerBatchResult, NerRuntime
from detection.ner_worker_pool import NerWorkerPool
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


def _ner_batch_worker(package_dir: str, texts: tuple[str, ...], window_length: int, stride: int,
                      *, profile: bool = False, intra_op_threads: int | None = None):
    """Single-use process path retained for compatibility and baseline comparisons."""
    entered_at = time.monotonic()
    digest = model_manifest_digest(package_dir)
    runtime = NerRuntime(package_dir, window_length, stride, digest, intra_op_threads)
    result = runtime.run(texts, digest, profile, verify_package=False)
    if not profile:
        return result.results
    metrics = dict(result.metrics)
    for key, value in runtime.initialization_metrics.items():
        metrics[key] = metrics.get(key, 0.0) + value
    metrics['worker_entry_at'] = entered_at
    return NerBatchResult(result.results, metrics, result.worker_pid)


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
        NER 包目录；``None`` 表示 NER 路未配置，``detect`` 时
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
        executor: InferenceExecutor | NerWorkerPool | None = None,
        ner_worker: Callable[..., Any] | None = None,
        ner_timeout: float = DEFAULT_NER_TIMEOUT,
        window_length: int = DEFAULT_WINDOW_LENGTH,
        stride: int = DEFAULT_STRIDE,
        quick_screen: QuickScreenConfig | None = None,
        ner_max_workers: int = 1,
        ner_max_pending: int = 4,
        ner_max_tasks_per_worker: int = 8192,
        ner_intra_op_threads: int | None = None,
        ner_max_age_seconds: int = 3600,
        ner_max_rss_kib: int = 2097152,
        ner_batch_wait_ms: int = 0,
        ner_max_batch_jobs: int = 1,
        ner_max_batch_chars: int = 512,
        ner_batch_tokens: int = 4096,
        ner_sentence_boundaries: bool = False,
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
        if executor is not None:
            self._executor = executor
        elif ner_package_dir is not None and ner_worker is None:
            self._executor = NerWorkerPool(os.fspath(ner_package_dir), max_workers=ner_max_workers,
                max_pending=ner_max_pending, max_tasks_per_worker=ner_max_tasks_per_worker,
                window_length=window_length, stride=stride, intra_op_threads=ner_intra_op_threads,
                max_age_seconds=ner_max_age_seconds, max_rss_kib=ner_max_rss_kib,
                batch_wait_ms=ner_batch_wait_ms, max_batch_jobs=ner_max_batch_jobs,
                max_batch_chars=ner_max_batch_chars, batch_tokens=ner_batch_tokens,
                sentence_boundaries=ner_sentence_boundaries)
        else:
            self._executor = InferenceExecutor(max_workers=ner_max_workers, max_pending=ner_max_pending)
        if isinstance(self._executor, NerWorkerPool) and ner_worker is not None:
            raise TypeError('custom ner_worker requires the single-use executor')
        self._ner_intra_op_threads = ner_intra_op_threads
        self._ner_worker = ner_worker if ner_worker is not None else _ner_worker
        self._ner_timeout = float(ner_timeout)
        self._window_length = window_length
        self._stride = stride
        if quick_screen is not None and not isinstance(quick_screen, QuickScreenConfig):
            raise TypeError("quick_screen must be QuickScreenConfig or None")
        self._risk_screener = None
        if quick_screen is not None and dictionary is not None:
            policy_cues = tuple(value for r in active if type(r).__module__ == 'detection.recognizers'
                                and vars(r).get('_policy') is not None
                                for name, values in vars(vars(r)['_policy']).items()
                                if name.endswith(('contexts', 'prefixes')) for value in values)
            self._risk_screener = QuickRiskScreen(dictionary, quick_screen, policy_cues=policy_cues,
                custom_rules=any(type(r).__module__ != 'detection.recognizers' for r in active))
        # 检测结果缓存（M1 影子度量 / M2 真实缓存）默认未装配，语义与现状一致。
        # 两者互斥：M1 只度量、复用同一指纹绑定；M2 直接复用 DetectionOutcome。
        self._cache_probe: DetectionCacheProbe | None = None
        self._detection_cache: DetectionResultCache | None = None
        self._detection_fingerprint: bytes | None = None

    def configure_cache(self, cache: DetectionResultCache | None, detection_fingerprint: bytes | None = None) -> None:
        """装配真实检测结果缓存（M2）；命中直接复用 ``DetectionOutcome``。

        ``detection_fingerprint`` 必须绑定完整检测装配（规则+词典+NER）。
        传 ``(None, None)`` 关闭缓存；只传缓存或只传指纹一律拒绝，避免
        出现「有缓存却拿不到装配指纹」的跨装配误命中。
        """
        if cache is None:
            if detection_fingerprint is not None:
                raise ValueError("detection fingerprint requires a cache")
            self._detection_cache = None
            self._detection_fingerprint = None
            return
        if not isinstance(cache, DetectionResultCache):
            raise TypeError("cache must be a DetectionResultCache or None")
        if not isinstance(detection_fingerprint, (bytes, bytearray)) or not detection_fingerprint:
            raise TypeError("detection_fingerprint must be non-empty bytes")
        self._detection_cache = cache
        self._detection_fingerprint = bytes(detection_fingerprint)
        self._cache_probe = None

    def configure_cache_probe(self, probe: DetectionCacheProbe | None, detection_fingerprint: bytes | None = None) -> None:
        """装配检测结果缓存度量钩子（M1 影子探测，不返回缓存结果）。

        ``detection_fingerprint`` 必须绑定完整检测装配（规则+词典+NER）。
        传 ``(None, None)`` 关闭度量；只传 probe 或只传指纹一律拒绝，避免
        出现「有探测器却拿不到装配指纹」的静默失配。
        """
        if probe is None:
            if detection_fingerprint is not None:
                raise ValueError("detection fingerprint requires a cache probe")
            self._cache_probe = None
            self._detection_fingerprint = None
            return
        if not isinstance(probe, DetectionCacheProbe):
            raise TypeError("probe must be a DetectionCacheProbe or None")
        if not isinstance(detection_fingerprint, (bytes, bytearray)) or not detection_fingerprint:
            raise TypeError("detection_fingerprint must be non-empty bytes")
        self._cache_probe = probe
        self._detection_cache = None
        self._detection_fingerprint = bytes(detection_fingerprint)

    def detect(self, text: str) -> DetectionOutcome:
        return self.detect_many((text,))[0]

    def detect_many(self, texts: tuple[str, ...], *, deadline_at: float | None = None, cancel=None,
                    metrics: dict[str, float] | None = None) -> tuple[DetectionOutcome, ...]:
        if any(not isinstance(text,str) for text in texts):
            raise SafetyError(SafetyCode.INVALID_TEXT)
        if not self._recognizers: raise SafetyError(SafetyCode.DETECTION_INCOMPLETE,'rule')
        if self._dictionary is None: raise SafetyError(SafetyCode.DETECTION_INCOMPLETE,'dictionary')
        if self._ner_package_dir is None: raise SafetyError(SafetyCode.DETECTION_INCOMPLETE,'ner')
        timeout = self._ner_timeout if deadline_at is None else min(self._ner_timeout, deadline_at - time.monotonic())
        if timeout <= 0 or (cancel is not None and cancel.is_set()):
            raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
        if self._detection_cache is not None:
            return self._detect_many_cached(texts, deadline_at=deadline_at, cancel=cancel, metrics=metrics)
        probe = self._cache_probe
        fingerprint = self._detection_fingerprint
        hit_flags = probe.classify(fingerprint, texts) if probe is not None else None
        outcomes = self._detect_uncached(texts, deadline_at=deadline_at, cancel=cancel, metrics=metrics)
        if probe is not None and hit_flags is not None and fingerprint is not None:
            probe.record(fingerprint, texts, hit_flags,
                         tuple(len(outcome.spans) for outcome in outcomes))
            if metrics is not None:
                metrics['cache_hits'] = sum(hit_flags)
                metrics['cache_misses'] = len(hit_flags) - sum(hit_flags)
                metrics['cache_avoided_fragments'] = metrics['cache_hits']
                metrics['cache_avoided_chars'] = sum(
                    len(text) for text, hit in zip(texts, hit_flags, strict=True) if hit)
                metrics['cache_avoided_spans'] = sum(
                    len(outcome.spans) for outcome, hit in zip(outcomes, hit_flags, strict=True) if hit)
                snapshot = probe.snapshot()
                metrics['cache_entries'] = snapshot.entries
                metrics['cache_evictions'] = snapshot.evictions
        return outcomes

    def _detect_many_cached(self, texts, *, deadline_at, cancel, metrics) -> tuple[DetectionOutcome, ...]:
        """真实缓存分区：命中直接复用，只对未命中集合执行三路检测与 NER 合批。

        输出顺序严格保持与原输入一致；任一未命中文本检测失败则整请求抛出，
        且本批不写缓存（先全部成功、再整体回填），保持 fail-closed 语义。
        """
        cache = self._detection_cache
        fingerprint = self._detection_fingerprint
        cached = cache.get_many(fingerprint, texts)
        miss_texts = tuple(text for text, outcome in zip(texts, cached, strict=True)
                           if outcome is None)
        miss_outcomes = (self._detect_uncached(miss_texts, deadline_at=deadline_at, cancel=cancel, metrics=metrics)
                         if miss_texts else ())
        if miss_texts:
            cache.put_many(fingerprint, miss_texts, miss_outcomes)
        if metrics is not None:
            hits = len(texts) - len(miss_texts)
            snapshot = cache.snapshot()
            metrics['cache_hits'] = hits
            metrics['cache_misses'] = len(miss_texts)
            metrics['cache_avoided_fragments'] = hits
            metrics['cache_avoided_chars'] = sum(
                len(text) for text, outcome in zip(texts, cached, strict=True) if outcome is not None)
            metrics['cache_avoided_spans'] = sum(
                len(outcome.spans) for outcome in cached if outcome is not None)
            metrics['cache_entries'] = snapshot.entries
            metrics['cache_spans'] = snapshot.spans
            metrics['cache_evictions'] = snapshot.evictions
        miss_iter = iter(miss_outcomes)
        return tuple(outcome if outcome is not None else next(miss_iter) for outcome in cached)

    def _detect_uncached(self, texts, *, deadline_at, cancel, metrics) -> tuple[DetectionOutcome, ...]:
        """对给定文本集合执行规则→词典→NER→合并（原 ``detect_many`` 正文）。"""
        if not texts:
            return ()
        timeout = self._ner_timeout if deadline_at is None else min(self._ner_timeout, deadline_at - time.monotonic())
        if timeout <= 0 or (cancel is not None and cancel.is_set()):
            raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
        try:
            if isinstance(self._executor, NerWorkerPool):
                result = self._executor.infer_profiled(texts, timeout=timeout, cancel=cancel, profile=metrics is not None)
                ner_results = result.results
                if metrics is not None:
                    metrics.update(result.metrics)
            elif self._ner_worker is _ner_worker:
                started = time.monotonic()
                result = self._executor.submit(_ner_batch_worker, self._ner_package_dir, texts,
                    self._window_length, self._stride, timeout=timeout, cancel=cancel,
                    profile=metrics is not None, intra_op_threads=self._ner_intra_op_threads)
                if metrics is None:
                    ner_results = result
                else:
                    ner_results = result.results
                    metrics.update(result.metrics)
                    metrics['queue_and_worker_startup_ms'] = (metrics.pop('worker_entry_at') - started) * 1000
                    metrics['total_ms'] = (time.monotonic() - started) * 1000
            else:
                ner_results = []
                for text in texts:
                    timeout = self._ner_timeout if deadline_at is None else min(self._ner_timeout, deadline_at-time.monotonic())
                    if timeout <= 0: raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
                    ner_results.append(self._executor.submit(self._ner_worker, self._ner_package_dir, text, self._window_length, self._stride, timeout=timeout, cancel=cancel))
        except RuntimeError:
            ner_results = None
        if ner_results is None:
            raise SafetyError(SafetyCode.DETECTION_FAILED,'ner') from None
        return tuple(self._detect_with_ner(text, result, metrics=metrics)
                     for text, result in zip(texts, ner_results, strict=True))

    def _detect_with_ner(self, text: str, ner_result, *, metrics: dict[str, float] | None = None) -> DetectionOutcome:
        """执行三路必需检测并合并；任何一路失败 → 整请求 ``SafetyError``。

        执行顺序固定：规则 → 词典 → NER → 合并。错误优先级确定性：
        多路同时异常时先执行路的错误先抛出；秘密（P0）候选在合并阶段
        整请求阻断（``SECRET_DETECTED``）。
        """
        if not isinstance(text, str):
            raise SafetyError(SafetyCode.INVALID_TEXT, "text")
        if not self._recognizers:
            raise SafetyError(SafetyCode.DETECTION_INCOMPLETE, "rule")
        if self._dictionary is None:
            raise SafetyError(SafetyCode.DETECTION_INCOMPLETE, "dictionary")
        if self._ner_package_dir is None:
            raise SafetyError(SafetyCode.DETECTION_INCOMPLETE, "ner")
        candidates: list[DetectionCandidate] = []
        started = time.perf_counter() if metrics is not None else 0.0
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
        if metrics is not None:
            metrics['rules_ms'] = metrics.get('rules_ms', 0.0) + (time.perf_counter() - started) * 1000
            started = time.perf_counter()
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
        if metrics is not None:
            metrics['dictionary_ms'] = metrics.get('dictionary_ms', 0.0) + (time.perf_counter() - started) * 1000
            started = time.perf_counter()
        try:
            ner_spans, (artifact, created_utc, model_sha256) = ner_result
        except (TypeError, ValueError):
            raise SafetyError(SafetyCode.DETECTION_FAILED, "ner") from None
        candidates.extend(candidate_from(span, source="ner") for span in ner_spans)
        resolved = resolve_spans(candidates, text_length=len(text))
        if metrics is not None:
            metrics['span_resolve_ms'] = metrics.get('span_resolve_ms', 0.0) + (time.perf_counter() - started) * 1000
        return DetectionOutcome(
            spans=resolved,
            dictionary_version=detection.dictionary_version,
            recognizer_names=tuple(recognizer.name for recognizer in self._recognizers),
            ner=NerProvenance(
                artifact=artifact, created_utc=created_utc, model_sha256=model_sha256
            ),
        )

    def warmup(self, *, timeout=120):
        if isinstance(self._executor, NerWorkerPool):
            return self._executor.warmup(timeout=timeout)
        return ()

    def close(self) -> None:
        """关闭编排器自持的资源（自建执行器）；外部传入的执行器不接管。"""
        if self._owns_executor:
            self._executor.close()

    def __enter__(self) -> "DetectionOrchestrator":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()
