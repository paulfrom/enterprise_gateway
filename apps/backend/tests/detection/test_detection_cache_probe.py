"""历史消息检测结果缓存 M1 度量测试：影子探测器的键、边界与失败不入表。

全部为合成夹具：词典条目、文本、worker 均为合成，无真实人名/机构/密钥。
canary 断言：影子表内不得出现任何业务正文；失败/秘密阻断不得产生可复用记录。
"""

from __future__ import annotations

import hashlib
import threading
import unittest

from detection.detection_cache_probe import (
    CACHE_KEY_DOMAIN,
    DetectionCacheProbe,
    DetectionCacheProbeSnapshot,
)
from detection.detection_orchestrator import DetectionOrchestrator
from detection.dictionary import (
    CompiledDictionary,
    DictionaryEntry,
    compute_dictionary_hash,
    compile_dictionary,
)
from detection.ner_windowing import EntitySpan
from detection.recognizers import default_recognizers
from infra.errors import SafetyCode, SafetyError

CANARY = "d12-probe-canary-7e1f9a2c"
SECRET_CANARY = "sk-ABCDEFGH123456789"
FINGERPRINT = b"f" * 32
OTHER_FINGERPRINT = b"e" * 32
PROBE_KEY = b"k" * 32
FAKE_PROVENANCE = ("probe-artifact", "2026-10-04T00:00:00Z", "ab" * 32)

DICTIONARY_ID = "dict-probe-synthetic"
DICTIONARY_VERSION = "2026.10.04"
DICTIONARY_DOMAIN = "synthetic-domain"
DICTIONARY_ENTRIES = (
    DictionaryEntry(text="星云科技", entity_type="ORG"),
    DictionaryEntry(text="zhangli", entity_type="PER"),
)

COMPILED: CompiledDictionary | None = None


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


def _worker_spans(package_dir, text, window_length, stride):
    if not text:
        return (), FAKE_PROVENANCE
    return (EntitySpan(start=0, end=min(4, len(text)), entity_type="ORG"),), FAKE_PROVENANCE


class _InlineExecutor:
    """同步执行注入 worker：度量测试不依赖真实进程启动。"""

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


def _orchestrator(**overrides: object) -> DetectionOrchestrator:
    params = {"executor": INLINE_EXECUTOR}
    params.update(overrides)
    return DetectionOrchestrator(**params)  # type: ignore[arg-type]


class ProbeUnitTests(unittest.TestCase):
    def test_first_batch_misses_then_hits(self) -> None:
        probe = DetectionCacheProbe(hmac_key=PROBE_KEY)
        self.assertEqual(probe.classify(FINGERPRINT, ("星云科技",)), (False,))
        probe.record(FINGERPRINT, ("星云科技",), (False,), (1,))
        self.assertEqual(probe.classify(FINGERPRINT, ("星云科技",)), (True,))
        snapshot = probe.snapshot()
        self.assertEqual((snapshot.hits, snapshot.misses), (1, 1))
        self.assertEqual(snapshot.entries, 1)

    def test_fingerprint_change_forces_miss(self) -> None:
        probe = DetectionCacheProbe(hmac_key=PROBE_KEY)
        probe.record(FINGERPRINT, ("星云科技",), (False,), (1,))
        self.assertEqual(probe.classify(OTHER_FINGERPRINT, ("星云科技",)), (False,))
        self.assertEqual(probe.classify(FINGERPRINT, ("星云科技",)), (True,))

    def test_intra_batch_duplicates_are_misses(self) -> None:
        probe = DetectionCacheProbe(hmac_key=PROBE_KEY)
        self.assertEqual(probe.classify(FINGERPRINT, ("alpha", "alpha")), (False, False))
        probe.record(FINGERPRINT, ("alpha", "alpha"), (False, False), (0, 0))
        self.assertEqual(probe.classify(FINGERPRINT, ("alpha", "alpha")), (True, True))

    def test_failure_path_does_not_record(self) -> None:
        probe = DetectionCacheProbe(hmac_key=PROBE_KEY)
        # 模拟失败：只查询、不回填。
        self.assertEqual(probe.classify(FINGERPRINT, ("alpha",)), (False,))
        snapshot = probe.snapshot()
        self.assertEqual(snapshot.entries, 0)
        self.assertEqual(snapshot.avoided_fragments, 0)
        self.assertEqual(probe.classify(FINGERPRINT, ("alpha",)), (False,))

    def test_avoided_work_accounting(self) -> None:
        probe = DetectionCacheProbe(hmac_key=PROBE_KEY)
        probe.record(FINGERPRINT, ("abcdef",), (False,), (2,))
        probe.record(FINGERPRINT, ("abcdef",), (True,), (2,))
        snapshot = probe.snapshot()
        self.assertEqual(snapshot.avoided_fragments, 1)
        self.assertEqual(snapshot.avoided_chars, 6)
        self.assertEqual(snapshot.avoided_spans, 2)

    def test_lru_bound_evicts_oldest(self) -> None:
        probe = DetectionCacheProbe(hmac_key=PROBE_KEY, max_entries=2)
        probe.record(FINGERPRINT, ("a", "b", "c"), (False, False, False), (0, 0, 0))
        snapshot = probe.snapshot()
        self.assertEqual(snapshot.entries, 2)
        self.assertEqual(snapshot.evictions, 1)
        self.assertEqual(probe.classify(FINGERPRINT, ("a", "b", "c")), (False, True, True))

    def test_ttl_expiry_forces_miss(self) -> None:
        now = [0.0]
        probe = DetectionCacheProbe(hmac_key=PROBE_KEY, ttl_seconds=10.0, clock=lambda: now[0])
        probe.record(FINGERPRINT, ("alpha",), (False,), (1,))
        now[0] = 9.9
        self.assertEqual(probe.classify(FINGERPRINT, ("alpha",)), (True,))
        now[0] = 20.0
        self.assertEqual(probe.classify(FINGERPRINT, ("alpha",)), (False,))
        self.assertEqual(probe.snapshot().evictions, 1)

    def test_clear_resets_entries_and_counters(self) -> None:
        probe = DetectionCacheProbe(hmac_key=PROBE_KEY)
        probe.record(FINGERPRINT, ("alpha",), (True,), (1,))
        probe.clear()
        self.assertEqual(probe.snapshot(), DetectionCacheProbeSnapshot(0, 0, 0, 0, 0, 0, 0))
        self.assertEqual(probe.classify(FINGERPRINT, ("alpha",)), (False,))

    def test_digest_is_keyed_not_plain_hash_and_hides_plaintext(self) -> None:
        canary_text = CANARY
        probe = DetectionCacheProbe(hmac_key=PROBE_KEY)
        probe.record(FINGERPRINT, (canary_text,), (False,), (0,))
        keys = tuple(probe._entries.keys())  # 内省：影子表只允许出现键摘要。
        self.assertEqual(len(keys), 1)
        self.assertEqual(len(keys[0]), 32)
        self.assertNotEqual(keys[0], hashlib.sha256(canary_text.encode("utf-8")).digest())
        self.assertNotIn(canary_text.encode("utf-8"), keys[0])
        self.assertNotIn(canary_text, repr(keys))
        # 另一把密钥对同一文本给出不同键：键不可作为已知明文猜测验证器。
        other = DetectionCacheProbe(hmac_key=b"z" * 32)
        self.assertNotEqual(other._digest(FINGERPRINT, canary_text), keys[0])
        self.assertEqual(CACHE_KEY_DOMAIN[:11], b"detection-r")

    def test_thread_safety_counts_are_exact(self) -> None:
        probe = DetectionCacheProbe(hmac_key=PROBE_KEY)
        texts = tuple(f"fragment-{index}" for index in range(50))

        def worker() -> None:
            flags = probe.classify(FINGERPRINT, texts)
            probe.record(FINGERPRINT, texts, flags, tuple(0 for _ in flags))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        snapshot = probe.snapshot()
        self.assertEqual(snapshot.hits + snapshot.misses, 50 * 8)
        self.assertEqual(snapshot.entries, 50)

    def test_invalid_inputs_rejected(self) -> None:
        with self.assertRaises(ValueError):
            DetectionCacheProbe(hmac_key=b"short")
        with self.assertRaises(ValueError):
            DetectionCacheProbe(hmac_key=PROBE_KEY, max_entries=0)
        with self.assertRaises(ValueError):
            DetectionCacheProbe(hmac_key=PROBE_KEY, ttl_seconds=0)
        probe = DetectionCacheProbe(hmac_key=PROBE_KEY)
        with self.assertRaises(TypeError):
            probe.classify(b"", ("alpha",))
        with self.assertRaises(TypeError):
            probe.classify(FINGERPRINT, (123,))
        with self.assertRaises(ValueError):
            probe.record(FINGERPRINT, ("a", "b"), (False,), (0,))


class OrchestratorMeasurementTests(unittest.TestCase):
    def _bound(self, probe: DetectionCacheProbe) -> DetectionOrchestrator:
        detector = _orchestrator(
            recognizers=default_recognizers(),
            dictionary=COMPILED,
            ner_package_dir="unused-by-injected-worker",
            ner_worker=_worker_spans,
        )
        detector.configure_cache_probe(probe, FINGERPRINT)
        return detector

    def test_metrics_report_hits_misses_and_timing(self) -> None:
        probe = DetectionCacheProbe(hmac_key=PROBE_KEY)
        detector = self._bound(probe)
        cold: dict[str, float] = {}
        detector.detect_many(("星云科技", "zhangli"), metrics=cold)
        self.assertEqual(cold["cache_hits"], 0)
        self.assertEqual(cold["cache_misses"], 2)
        self.assertEqual(cold["cache_entries"], 2)
        for phase in ("rules_ms", "dictionary_ms", "span_resolve_ms"):
            self.assertIn(phase, cold)
            self.assertGreaterEqual(cold[phase], 0.0)
        warm: dict[str, float] = {}
        detector.detect_many(("星云科技", "zhangli"), metrics=warm)
        self.assertEqual(warm["cache_hits"], 2)
        self.assertEqual(warm["cache_misses"], 0)
        self.assertEqual(warm["cache_avoided_fragments"], 2)
        self.assertGreater(warm["cache_avoided_chars"], 0)
        self.assertGreaterEqual(warm["cache_avoided_spans"], 0)

    def test_secret_block_is_not_recorded(self) -> None:
        probe = DetectionCacheProbe(hmac_key=PROBE_KEY)
        detector = self._bound(probe)
        secret = f"token {SECRET_CANARY} tail"
        with self.assertRaises(SafetyError) as ctx:
            detector.detect(secret)
        self.assertEqual(ctx.exception.code, SafetyCode.SECRET_DETECTED)
        self.assertEqual(probe.snapshot().entries, 0)
        with self.assertRaises(SafetyError):
            detector.detect(secret)

    def test_configure_rejects_partial_binding(self) -> None:
        detector = _orchestrator(
            dictionary=COMPILED,
            ner_package_dir="unused-by-injected-worker",
            ner_worker=_worker_spans,
        )
        detector.configure_cache_probe(None)
        with self.assertRaises(ValueError):
            detector.configure_cache_probe(None, FINGERPRINT)
        with self.assertRaises(TypeError):
            detector.configure_cache_probe(object(), FINGERPRINT)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            detector.configure_cache_probe(DetectionCacheProbe(hmac_key=PROBE_KEY), b"")

    def test_without_probe_no_cache_metrics(self) -> None:
        detector = _orchestrator(
            dictionary=COMPILED,
            ner_package_dir="unused-by-injected-worker",
            ner_worker=_worker_spans,
        )
        metrics: dict[str, float] = {}
        detector.detect_many(("星云科技",), metrics=metrics)
        self.assertNotIn("cache_hits", metrics)


if __name__ == "__main__":
    unittest.main()
