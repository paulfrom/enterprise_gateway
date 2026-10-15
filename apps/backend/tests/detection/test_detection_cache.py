"""历史消息检测结果缓存 M2 单测：有界结果缓存 + 编排器命中分区。

全部为合成夹具：词典条目、文本、worker 均为合成，无真实人名/机构/密钥。
canary 断言：缓存条目/键内不得出现业务正文；失败/秘密阻断不得产生可复用结果。
"""

from __future__ import annotations

import hashlib
import threading
import unittest

from detection.detection_cache import (
    CACHE_KEY_DOMAIN,
    DetectionCacheSnapshot,
    DetectionResultCache,
)
from detection.detection_cache_probe import DetectionCacheProbe
from detection.detection_orchestrator import (
    DetectionOrchestrator,
    DetectionOutcome,
    NerProvenance,
)
from detection.dictionary import (
    CompiledDictionary,
    DictionaryEntry,
    compile_dictionary,
    compute_dictionary_hash,
)
from detection.ner_windowing import EntitySpan
from detection.recognizers import default_recognizers
from detection.span_resolver import ResolvedSpan
from infra.errors import SafetyCode, SafetyError

CANARY = "d12-result-cache-canary-7e1f9a2c"
SECRET_CANARY = "sk-ABCDEFGH123456789"
FINGERPRINT = b"f" * 32
OTHER_FINGERPRINT = b"e" * 32
CACHE_KEY = b"k" * 32
FAKE_PROVENANCE = ("cache-artifact", "2026-10-04T00:00:00Z", "ab" * 32)

DICTIONARY_ID = "dict-cache-synthetic"
DICTIONARY_VERSION = "2026.10.04"
DICTIONARY_DOMAIN = "synthetic-domain"
DICTIONARY_ENTRIES = (
    DictionaryEntry(text="星云科技", entity_type="ORG"),
    DictionaryEntry(text="zhangli", entity_type="PER"),
)

COMPILED: CompiledDictionary | None = None
NER_CALLS: list[str] = []


def setUpModule() -> None:
    global COMPILED
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


def _fake_outcome(span_count: int = 1) -> DetectionOutcome:
    return DetectionOutcome(
        spans=tuple(ResolvedSpan(i, i + 1, "PER", 3, ("ner",)) for i in range(span_count)),
        dictionary_version=DICTIONARY_VERSION,
        recognizer_names=("SyntheticRecognizer",),
        ner=NerProvenance(*FAKE_PROVENANCE),
    )


class _InlineExecutor:
    """同步执行注入 worker：缓存语义测试不依赖真实进程启动。"""

    def submit(self, worker, *args, timeout, cancel=None, **kwargs):
        if cancel is not None and cancel.is_set():
            raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
        try:
            return worker(*args, **kwargs)
        except SafetyError:
            raise
        except Exception:
            raise RuntimeError("NER worker failed") from None


INLINE_EXECUTOR = _InlineExecutor()


def _counting_worker(package_dir, text, window_length, stride):
    NER_CALLS.append(text)
    if not text:
        return (), FAKE_PROVENANCE
    return (EntitySpan(start=0, end=min(4, len(text)), entity_type="ORG"),), FAKE_PROVENANCE


def _failing_worker(package_dir, text, window_length, stride):
    NER_CALLS.append(text)
    if text.startswith("fail"):
        raise ValueError(f"boom {CANARY}")
    return (EntitySpan(start=0, end=min(4, len(text)), entity_type="ORG"),), FAKE_PROVENANCE


def _orchestrator(**overrides: object) -> DetectionOrchestrator:
    params = {
        "executor": INLINE_EXECUTOR,
        "recognizers": default_recognizers(),
        "dictionary": COMPILED,
        "ner_package_dir": "unused-by-injected-worker",
        "ner_worker": _counting_worker,
    }
    params.update(overrides)
    return DetectionOrchestrator(**params)  # type: ignore[arg-type]


class DetectionResultCacheUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        NER_CALLS.clear()

    def test_cold_miss_then_warm_hit_returns_same_outcome(self) -> None:
        cache = DetectionResultCache(hmac_key=CACHE_KEY)
        outcome = _fake_outcome(2)
        self.assertEqual(cache.get_many(FINGERPRINT, ("alpha",)), (None,))
        cache.put_many(FINGERPRINT, ("alpha",), (outcome,))
        self.assertEqual(cache.get_many(FINGERPRINT, ("alpha",)), (outcome,))
        snapshot = cache.snapshot()
        self.assertEqual((snapshot.hits, snapshot.misses), (1, 1))
        self.assertEqual((snapshot.entries, snapshot.spans), (1, 2))
        self.assertEqual(snapshot.hit_rate, 0.5)

    def test_fingerprint_isolation(self) -> None:
        cache = DetectionResultCache(hmac_key=CACHE_KEY)
        cache.put_many(FINGERPRINT, ("alpha",), (_fake_outcome(),))
        self.assertEqual(cache.get_many(OTHER_FINGERPRINT, ("alpha",)), (None,))
        self.assertIsNotNone(cache.get_many(FINGERPRINT, ("alpha",))[0])

    def test_entry_bound_evicts_lru(self) -> None:
        cache = DetectionResultCache(hmac_key=CACHE_KEY, max_entries=2)
        cache.put_many(FINGERPRINT, ("a", "b", "c"), tuple(_fake_outcome() for _ in range(3)))
        snapshot = cache.snapshot()
        self.assertEqual((snapshot.entries, snapshot.evictions), (2, 1))
        results = cache.get_many(FINGERPRINT, ("a", "b", "c"))
        self.assertEqual([result is None for result in results], [True, False, False])

    def test_span_bound_evicts_lru(self) -> None:
        cache = DetectionResultCache(hmac_key=CACHE_KEY, max_entries=10, max_spans=3)
        cache.put_many(FINGERPRINT, ("a", "b", "c"), tuple(_fake_outcome(1) for _ in range(3)))
        self.assertEqual(cache.snapshot().spans, 3)
        cache.put_many(FINGERPRINT, ("d",), (_fake_outcome(1),))
        snapshot = cache.snapshot()
        self.assertEqual((snapshot.entries, snapshot.spans, snapshot.evictions), (3, 3, 1))
        self.assertIsNone(cache.get_many(FINGERPRINT, ("a",))[0])
        self.assertIsNotNone(cache.get_many(FINGERPRINT, ("d",))[0])

    def test_oversized_single_outcome_is_not_cached(self) -> None:
        cache = DetectionResultCache(hmac_key=CACHE_KEY, max_spans=2)
        cache.put_many(FINGERPRINT, ("wide",), (_fake_outcome(3),))
        snapshot = cache.snapshot()
        self.assertEqual((snapshot.entries, snapshot.spans, snapshot.evictions), (0, 0, 1))
        self.assertIsNone(cache.get_many(FINGERPRINT, ("wide",))[0])

    def test_overwrite_adjusts_span_budget(self) -> None:
        cache = DetectionResultCache(hmac_key=CACHE_KEY, max_entries=10, max_spans=10)
        cache.put_many(FINGERPRINT, ("alpha",), (_fake_outcome(3),))
        cache.put_many(FINGERPRINT, ("alpha",), (_fake_outcome(1),))
        snapshot = cache.snapshot()
        self.assertEqual((snapshot.entries, snapshot.spans), (1, 1))

    def test_ttl_expiry_forces_miss(self) -> None:
        now = [0.0]
        cache = DetectionResultCache(hmac_key=CACHE_KEY, ttl_seconds=10.0, clock=lambda: now[0])
        cache.put_many(FINGERPRINT, ("alpha",), (_fake_outcome(),))
        now[0] = 9.9
        self.assertIsNotNone(cache.get_many(FINGERPRINT, ("alpha",))[0])
        now[0] = 20.0
        self.assertIsNone(cache.get_many(FINGERPRINT, ("alpha",))[0])
        self.assertEqual(cache.snapshot().evictions, 1)

    def test_clear_resets_entries_and_counters(self) -> None:
        cache = DetectionResultCache(hmac_key=CACHE_KEY)
        cache.put_many(FINGERPRINT, ("alpha",), (_fake_outcome(),))
        cache.clear()
        self.assertEqual(cache.snapshot(), DetectionCacheSnapshot(0, 0, 0, 0, 0))
        self.assertIsNone(cache.get_many(FINGERPRINT, ("alpha",))[0])

    def test_key_is_keyed_and_entries_hide_plaintext(self) -> None:
        cache = DetectionResultCache(hmac_key=CACHE_KEY)
        cache.put_many(FINGERPRINT, (CANARY,), (_fake_outcome(),))
        keys = tuple(cache._entries.keys())
        self.assertEqual(len(keys), 1)
        self.assertEqual(len(keys[0]), 32)
        self.assertNotEqual(keys[0], hashlib.sha256(CANARY.encode("utf-8")).digest())
        self.assertNotIn(CANARY.encode("utf-8"), keys[0])
        self.assertNotIn(CANARY, repr(keys))
        other = DetectionResultCache(hmac_key=b"z" * 32)
        self.assertNotEqual(other._digest(FINGERPRINT, CANARY), keys[0])
        self.assertEqual(CACHE_KEY_DOMAIN[:11], b"detection-r")

    def test_thread_safety_counts_are_exact(self) -> None:
        cache = DetectionResultCache(hmac_key=CACHE_KEY)
        outcomes = {f"fragment-{index}": _fake_outcome() for index in range(50)}

        def worker() -> None:
            cache.get_many(FINGERPRINT, tuple(outcomes))
            cache.put_many(FINGERPRINT, tuple(outcomes), tuple(outcomes.values()))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        snapshot = cache.snapshot()
        self.assertEqual(snapshot.hits + snapshot.misses, 50 * 8)
        self.assertEqual(snapshot.entries, 50)

    def test_invalid_inputs_rejected(self) -> None:
        with self.assertRaises(ValueError):
            DetectionResultCache(hmac_key=b"short")
        with self.assertRaises(ValueError):
            DetectionResultCache(hmac_key=CACHE_KEY, max_entries=0)
        with self.assertRaises(ValueError):
            DetectionResultCache(hmac_key=CACHE_KEY, max_spans=0)
        with self.assertRaises(ValueError):
            DetectionResultCache(hmac_key=CACHE_KEY, ttl_seconds=0)
        cache = DetectionResultCache(hmac_key=CACHE_KEY)
        with self.assertRaises(TypeError):
            cache.get_many(b"", ("alpha",))
        with self.assertRaises(TypeError):
            cache.get_many(FINGERPRINT, (123,))
        with self.assertRaises(ValueError):
            cache.put_many(FINGERPRINT, ("a", "b"), (_fake_outcome(),))


class OrchestratorResultCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        NER_CALLS.clear()

    def _bound(self, cache: DetectionResultCache, **overrides: object) -> DetectionOrchestrator:
        detector = _orchestrator(**overrides)
        detector.configure_cache(cache, FINGERPRINT)
        return detector

    def test_warm_hit_reuses_outcome_and_skips_ner(self) -> None:
        cache = DetectionResultCache(hmac_key=CACHE_KEY)
        detector = self._bound(cache)
        cold = detector.detect_many(("alpha", "beta"))
        self.assertEqual(sorted(NER_CALLS), ["alpha", "beta"])
        NER_CALLS.clear()
        warm = detector.detect_many(("alpha", "beta"))
        self.assertEqual(warm, cold)
        self.assertEqual(NER_CALLS, [])
        snapshot = cache.snapshot()
        self.assertEqual((snapshot.hits, snapshot.misses), (2, 2))

    def test_mixed_batch_runs_only_misses_and_preserves_order(self) -> None:
        cache = DetectionResultCache(hmac_key=CACHE_KEY)
        detector = self._bound(cache)
        detector.detect_many(("alpha", "beta"))
        NER_CALLS.clear()
        metrics: dict[str, float] = {}
        outcomes = detector.detect_many(("beta", "gamma", "alpha"), metrics=metrics)
        self.assertEqual(NER_CALLS, ["gamma"])
        self.assertEqual(metrics["cache_hits"], 2)
        self.assertEqual(metrics["cache_misses"], 1)
        self.assertGreater(metrics["cache_avoided_chars"], 0)
        self.assertGreaterEqual(metrics["cache_avoided_spans"], 0)
        self.assertEqual(metrics["cache_entries"], 3)
        self.assertEqual(metrics["cache_spans"], cache.snapshot().spans)
        direct = detector.detect_many(("beta", "gamma", "alpha"))
        self.assertEqual(outcomes, direct)

    def test_failure_is_not_cached_and_reruns(self) -> None:
        cache = DetectionResultCache(hmac_key=CACHE_KEY)
        detector = self._bound(cache, ner_worker=_failing_worker)
        with self.assertRaises(SafetyError) as ctx:
            detector.detect("fail-please")
        self.assertEqual(ctx.exception.code, SafetyCode.DETECTION_FAILED)
        self.assertEqual(cache.snapshot().entries, 0)
        NER_CALLS.clear()
        with self.assertRaises(SafetyError):
            detector.detect("fail-please")
        self.assertEqual(NER_CALLS, ["fail-please"])

    def test_secret_block_is_not_cached(self) -> None:
        cache = DetectionResultCache(hmac_key=CACHE_KEY)
        detector = self._bound(cache)
        secret = f"token {SECRET_CANARY} tail"
        with self.assertRaises(SafetyError) as ctx:
            detector.detect(secret)
        self.assertEqual(ctx.exception.code, SafetyCode.SECRET_DETECTED)
        self.assertEqual(cache.snapshot().entries, 0)
        with self.assertRaises(SafetyError):
            detector.detect(secret)

    def test_fingerprint_change_forces_miss(self) -> None:
        cache = DetectionResultCache(hmac_key=CACHE_KEY)
        detector = _orchestrator()
        detector.configure_cache(cache, FINGERPRINT)
        detector.detect("alpha")
        NER_CALLS.clear()
        detector.configure_cache(cache, OTHER_FINGERPRINT)
        detector.detect("alpha")
        self.assertEqual(NER_CALLS, ["alpha"])

    def test_configure_cache_rejects_partial_binding_and_probe_is_exclusive(self) -> None:
        cache = DetectionResultCache(hmac_key=CACHE_KEY)
        detector = _orchestrator()
        detector.configure_cache(None)
        with self.assertRaises(ValueError):
            detector.configure_cache(None, FINGERPRINT)
        with self.assertRaises(TypeError):
            detector.configure_cache(object(), FINGERPRINT)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            detector.configure_cache(cache, b"")
        probe = DetectionCacheProbe(hmac_key=CACHE_KEY)
        detector.configure_cache_probe(probe, FINGERPRINT)
        self.assertIsNone(detector._detection_cache)
        detector.configure_cache(cache, FINGERPRINT)
        self.assertIsNone(detector._cache_probe)

    def test_no_plaintext_in_cache_keys(self) -> None:
        cache = DetectionResultCache(hmac_key=CACHE_KEY)
        detector = self._bound(cache)
        detector.detect(CANARY)
        self.assertNotIn(CANARY.encode("utf-8"), b"".join(cache._entries.keys()))

    def test_cache_disabled_keeps_existing_semantics(self) -> None:
        detector = _orchestrator()
        first = detector.detect("alpha")
        NER_CALLS.clear()
        second = detector.detect("alpha")
        self.assertEqual(first, second)
        self.assertEqual(NER_CALLS, ["alpha"])


if __name__ == "__main__":
    unittest.main()
