"""历史消息检测结果缓存 M1 合成长会话度量：确认命中率与可省工作量。

方案 ``docs/plans/history-detection-cache.md`` §8 要求先量后开。本测试用
N 轮递增历史走真实编排器（注入合成 worker，避免依赖真实 NER 权重），确认：

* 每轮只有新增消息未命中，历史消息全部命中（M2 真实缓存下这 k-1 段无需再跑
  NER/规则/词典）；
* 影子表条目只随唯一片段线性增长，累计可省片段为三角数 O(N^2)，与方案预期
  的「累计从 O(n^2) 降为 O(n)」一致；
* 影子表不含正文，失败与超时路径不产生条目。

真实样本与耗时报告按仓库规范存于仓库外；此处只保留确定性断言与紧凑基准表。
"""

from __future__ import annotations

import time
import unittest

from detection.detection_cache import DetectionResultCache
from detection.detection_cache_probe import DetectionCacheProbe
from detection.detection_orchestrator import DetectionOrchestrator
from detection.dictionary import (
    CompiledDictionary,
    DictionaryEntry,
    compile_dictionary,
    compute_dictionary_hash,
)
from detection.ner_windowing import EntitySpan
from detection.recognizers import default_recognizers
from infra.errors import SafetyCode, SafetyError

CANARY = "d12-benchmark-canary-7e1f9a2c"
FINGERPRINT = b"f" * 32
PROBE_KEY = b"k" * 32
FAKE_PROVENANCE = ("benchmark-artifact", "2026-10-04T00:00:00Z", "ab" * 32)
ROUNDS = 20
DOMAIN = "synthetic-domain"
WORKER_CALLS: list[str] = []
ENTRIES = (
    DictionaryEntry(text="星云科技", entity_type="ORG"),
    DictionaryEntry(text="zhangli", entity_type="PER"),
)


def _worker_spans(package_dir, text, window_length, stride):
    if not text:
        return (), FAKE_PROVENANCE
    return (EntitySpan(start=0, end=min(2, len(text)), entity_type="ORG"),), FAKE_PROVENANCE


def _counting_worker(package_dir, text, window_length, stride):
    WORKER_CALLS.append(text)
    return _worker_spans(package_dir, text, window_length, stride)


class _InlineExecutor:
    def submit(self, worker, *args, timeout, cancel=None, **kwargs):
        if cancel is not None and cancel.is_set():
            raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
        return worker(*args, **kwargs)


class GrowingHistoryMeasurement(unittest.TestCase):
    def test_twenty_round_history_hits_only_new_messages(self) -> None:
        compiled = compile_dictionary({
            "dictionary_id": "dict-benchmark",
            "version": "2026.10.04",
            "domain": DOMAIN,
            "entries": [
                {"text": entry.text, "entity_type": entry.entity_type}
                for entry in ENTRIES
            ],
            "sha256": compute_dictionary_hash("dict-benchmark", "2026.10.04", DOMAIN, ENTRIES),
        })
        probe = DetectionCacheProbe(hmac_key=PROBE_KEY, max_entries=4096)
        detector = DetectionOrchestrator(
            recognizers=default_recognizers(),
            dictionary=compiled,
            ner_package_dir="unused-by-injected-worker",
            ner_worker=_worker_spans,
            executor=_InlineExecutor(),
        )
        detector.configure_cache_probe(probe, FINGERPRINT)

        history: list[str] = []
        baseline_fragments = 0
        timings: list[float] = []
        rows: list[tuple[int, int, int, float]] = []
        for round_index in range(1, ROUNDS + 1):
            history.append(f"{CANARY}-round-{round_index} 星云科技 联系人")
            texts = tuple(history)
            metrics: dict[str, float] = {}
            started = time.perf_counter()
            detector.detect_many(texts, metrics=metrics)
            elapsed_ms = (time.perf_counter() - started) * 1000
            timings.append(elapsed_ms)
            baseline_fragments += len(texts)
            self.assertEqual(metrics["cache_misses"], 1)
            self.assertEqual(metrics["cache_hits"], round_index - 1)
            rows.append((round_index, int(metrics["cache_hits"]), len(texts), elapsed_ms))

        snapshot = probe.snapshot()
        expected_avoided_fragments = ROUNDS * (ROUNDS - 1) // 2
        expected_avoided_chars = sum(
            len(history[index]) * (ROUNDS - 1 - index) for index in range(len(history) - 1)
        )
        self.assertEqual(snapshot.avoided_fragments, expected_avoided_fragments)
        self.assertEqual(snapshot.avoided_chars, expected_avoided_chars)
        self.assertEqual(snapshot.entries, ROUNDS)
        self.assertEqual(snapshot.hits, expected_avoided_fragments)
        self.assertEqual(snapshot.misses, ROUNDS)
        # 影子表不得留存业务正文。
        self.assertNotIn(CANARY.encode("utf-8"), b"".join(probe._entries.keys()))
        # 基准表：每轮检测片段数的 O(n^2) 来源与缓存可省部分（M1 只度量）。
        print("\nround  new  total  hits  avoidable  ms")
        for round_index, hits, total, elapsed_ms in rows:
            print(f"{round_index:>5}  {1:>3}  {total:>5}  {hits:>4}  "
                  f"{hits / total:>9.0%}  {elapsed_ms:>6.2f}")
        print(f"baseline_fragments={baseline_fragments} unique={ROUNDS} "
              f"avoided={snapshot.avoided_fragments} "
              f"total_ms={sum(timings):.2f}")
        detector.close()


class GrowingHistoryResultCacheBenchmark(unittest.TestCase):
    def test_twenty_round_history_runs_ner_once_per_new_message(self) -> None:
        compiled = compile_dictionary({
            "dictionary_id": "dict-benchmark",
            "version": "2026.10.04",
            "domain": DOMAIN,
            "entries": [
                {"text": entry.text, "entity_type": entry.entity_type}
                for entry in ENTRIES
            ],
            "sha256": compute_dictionary_hash("dict-benchmark", "2026.10.04", DOMAIN, ENTRIES),
        })
        cache = DetectionResultCache(hmac_key=PROBE_KEY, max_entries=4096,
                                     max_spans=65536, ttl_seconds=900.0)
        detector = DetectionOrchestrator(
            recognizers=default_recognizers(),
            dictionary=compiled,
            ner_package_dir="unused-by-injected-worker",
            ner_worker=_counting_worker,
            executor=_InlineExecutor(),
        )
        detector.configure_cache(cache, FINGERPRINT)
        WORKER_CALLS.clear()

        history: list[str] = []
        baseline_fragments = 0
        timings: list[float] = []
        rows: list[tuple[int, int, int, int, float]] = []
        for round_index in range(1, ROUNDS + 1):
            history.append(f"{CANARY}-round-{round_index} 星云科技 联系人")
            texts = tuple(history)
            metrics: dict[str, float] = {}
            before = len(WORKER_CALLS)
            started = time.perf_counter()
            detector.detect_many(texts, metrics=metrics)
            elapsed_ms = (time.perf_counter() - started) * 1000
            timings.append(elapsed_ms)
            baseline_fragments += len(texts)
            ner_calls = len(WORKER_CALLS) - before
            self.assertEqual(metrics["cache_hits"], round_index - 1)
            self.assertEqual(metrics["cache_misses"], 1)
            self.assertEqual(ner_calls, 1)
            rows.append((round_index, int(metrics["cache_hits"]), len(texts), ner_calls, elapsed_ms))

        snapshot = cache.snapshot()
        self.assertEqual(len(WORKER_CALLS), ROUNDS)
        self.assertEqual(snapshot.entries, ROUNDS)
        self.assertEqual(snapshot.hits, ROUNDS * (ROUNDS - 1) // 2)
        self.assertNotIn(CANARY.encode("utf-8"), b"".join(cache._entries.keys()))
        print("\nround  new  total  ner_calls  ms")
        for round_index, _, total, ner_calls, elapsed_ms in rows:
            print(f"{round_index:>5}  {1:>3}  {total:>5}  {ner_calls:>9}  {elapsed_ms:>6.2f}")
        print(f"baseline_fragments={baseline_fragments} unique={ROUNDS} "
              f"ner_calls={len(WORKER_CALLS)} total_ms={sum(timings):.2f}")
        detector.close()


if __name__ == "__main__":
    unittest.main()
