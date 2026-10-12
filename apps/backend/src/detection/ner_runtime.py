"""Worker-local NER resources and content-free performance measurements."""

from __future__ import annotations

import os
import resource
import time
from dataclasses import dataclass

from detection.ner_model import load_model_package, model_manifest_digest, verify_loaded_package, _load_json
from detection.ner_windowing import EntitySpan, NerWindowMerger
from detection.ner_snapshot import SealedNerSnapshot, load_snapshot
from infra.errors import SafetyCode, SafetyError


@dataclass(frozen=True, slots=True)
class NerBatchResult:
    results: tuple[tuple[tuple[EntitySpan, ...], tuple[str, str, str]], ...]
    metrics: dict[str, float]
    worker_pid: int


class NerRuntime:
    """Own exactly one tokenizer/session; retain no request data between calls."""

    def __init__(self, package_dir: str, window_length: int, stride: int,
                 expected_digest: str, intra_op_threads: int | None = None,
                 options: dict | None = None) -> None:
        started = time.perf_counter()
        self.initialization_metrics: dict[str, float] = {}
        sealed = isinstance(package_dir, SealedNerSnapshot)
        loader = load_snapshot if sealed else load_model_package
        self.package = loader(package_dir, timings=self.initialization_metrics,
                              intra_op_threads=intra_op_threads)
        digest = package_dir.digest if sealed else model_manifest_digest(package_dir)
        if digest != expected_digest:
            raise SafetyError(SafetyCode.NER_MODEL_INVALID, "manifest_version_changed")
        self.digest = expected_digest
        config_path = package_dir.path('config.json') if sealed else self.package.package_dir / 'config.json'
        maximum = _load_json(config_path).get('max_position_embeddings')
        if maximum is not None and (type(maximum) is not int or window_length > maximum):
            raise SafetyError(SafetyCode.NER_MODEL_INVALID, 'window_exceeds_model_positions')
        self.merger = NerWindowMerger(self.package.tokenizer, self.package.session,
                                     self.package.id2label, window_length=window_length, stride=stride,
                                     **(options or {}))
        manifest = self.package.manifest
        self.provenance = (manifest.artifact, manifest.created_utc, manifest.files["model.onnx"].sha256)
        self.initialization_metrics['worker_initialization_ms'] = (time.perf_counter() - started) * 1000

    def warmup(self) -> None:
        started = time.perf_counter()
        self.merger.extract('预热：联系人示例就职于示例有限公司。')
        self.initialization_metrics['warmup_ms'] = (time.perf_counter() - started) * 1000

    def run(self, texts: tuple[str, ...], expected_digest: str, profile: bool,
            *, verify_package: bool = True) -> NerBatchResult:
        if expected_digest != self.digest:
            raise SafetyError(SafetyCode.NER_MODEL_INVALID, "manifest_version_changed")
        started = time.perf_counter()
        # Sealed packages check immutable descriptor identity/version; mutable
        # control runs still hash every payload before each task.
        if verify_package:
            verify_loaded_package(self.package, expected_digest)
        metrics = {"package_verify_ms": (time.perf_counter() - started) * 1000}
        results = tuple((spans, self.provenance) for spans in
                        self.merger.extract_many(texts, metrics=metrics if profile else None))
        metrics["worker_task_ms"] = (time.perf_counter() - started) * 1000
        metrics['worker_peak_rss_kib'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return NerBatchResult(results, metrics, os.getpid())


def create_ner_runtime(package_dir: str, window_length: int, stride: int,
                       expected_digest: str, intra_op_threads: int | None = None,
                       options: dict | None = None) -> NerRuntime:
    return NerRuntime(package_dir, window_length, stride, expected_digest, intra_op_threads, options)
