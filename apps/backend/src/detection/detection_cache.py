"""历史消息检测结果缓存 M2：有界、线程安全、带密钥键的进程内结果缓存。

方案 ``docs/plans/history-detection-cache.md`` 的 M2 实现。把多轮对话中
「每轮对全量历史重跑规则/词典/NER」的 O(n²) 检测成本降为 O(n)：同一
``(文本, 检测装配指纹)`` 的片段只完整检测一次，后续请求直接复用其
``DetectionOutcome``。

安全不变量：

* **键为带密钥摘要**：``key = HMAC-SHA256(k_cache, 域 || fingerprint || 0x00
  || text_utf8)``。``k_cache`` 是装配时用 ``secrets.token_bytes(32)`` 生成的
  进程内临时密钥（不落盘、不经运维配置、重启即失效），使缓存键即使内存
  被转储或误入诊断也不能作为「已知明文猜测验证器」。
* **条目不含正文**：只保存 ``DetectionOutcome``（偏移/类型/优先级/来源 +
  词典/NER 溯源），不含任何业务文本；键是摘要。
* **只缓存成功完整结果**：编排器只有在三路检测成功后才 ``put_many``；
  异常、超时、``DETECTION_INCOMPLETE``、``INFERENCE_TIMEOUT``、
  ``SECRET_DETECTED`` 都不会产生可缓存结果。
* **装配/域隔离**：``fingerprint`` 覆盖规则+词典+NER 全量装配，发布切换
  后新指纹永不命中旧条目，旧条目随 TTL/LRU 退出。
* **有界**：条目数、累计跨度数与 TTL 三线上限，超限按 LRU 淘汰；单条
  跨度就超过跨度上限的结果不缓存，避免单条顶掉全部。
* **线程安全**：``process_request`` 经线程并发执行，全部访问在锁内完成。

不引入 Redis/PostgreSQL 等共享或持久缓存：``start_gateway.py`` 单进程
``uvicorn.run`` 下进程内缓存即可覆盖全部在途请求，且与 ADR 0001「共享映射
扩大暴露面」的取向一致。
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Iterable

if TYPE_CHECKING:  # 避免与 detection_orchestrator 形成运行时循环导入。
    from detection.detection_orchestrator import DetectionOutcome

__all__ = ["DetectionResultCache", "DetectionCacheSnapshot", "CACHE_KEY_DOMAIN"]

# 键域分隔：与 M1 影子探测器共用同一前缀，指纹/文本不会与其它用途的 HMAC 混淆。
CACHE_KEY_DOMAIN = b"detection-result-cache-v1\x00"
_MIN_KEY_BYTES = 16


@dataclass(frozen=True, slots=True)
class DetectionCacheSnapshot:
    """累计度量快照；全部为计数，不含任何正文。"""

    hits: int
    misses: int
    entries: int
    spans: int
    evictions: int

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return 0.0 if total == 0 else self.hits / total


@dataclass(frozen=True, slots=True)
class _CacheEntry:
    outcome: "DetectionOutcome"
    expires_at: float
    span_count: int


class DetectionResultCache:
    """按 ``(检测装配指纹, 文本)`` 复用 ``DetectionOutcome`` 的有界内存缓存。"""

    def __init__(
        self,
        *,
        hmac_key: bytes | None = None,
        max_entries: int = 4096,
        ttl_seconds: float = 900.0,
        max_spans: int = 65536,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        key = secrets.token_bytes(32) if hmac_key is None else hmac_key
        if not isinstance(key, (bytes, bytearray)) or len(key) < _MIN_KEY_BYTES:
            raise ValueError(f"hmac_key must be at least {_MIN_KEY_BYTES} bytes")
        for name, value in (("max_entries", max_entries), ("max_spans", max_spans)):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)) \
                or not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a finite positive number")
        self._key = bytes(key)
        self._max_entries = max_entries
        self._ttl_seconds = float(ttl_seconds)
        self._max_spans = max_spans
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: OrderedDict[bytes, _CacheEntry] = OrderedDict()
        self._spans = 0
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def _digest(self, fingerprint: bytes, text: str) -> bytes:
        message = CACHE_KEY_DOMAIN + fingerprint + b"\x00" + text.encode("utf-8")
        return hmac.new(self._key, message, hashlib.sha256).digest()

    @staticmethod
    def _require_fingerprint(fingerprint: bytes | bytearray) -> bytes:
        if not isinstance(fingerprint, (bytes, bytearray)) or not fingerprint:
            raise TypeError("detection fingerprint must be non-empty bytes")
        return bytes(fingerprint)

    def _sweep_expired(self, now: float) -> None:
        # 插入顺序即过期顺序（过期时间随插入单调递增），从最旧端线性清理。
        while self._entries:
            digest, entry = next(iter(self._entries.items()))
            if entry.expires_at > now:
                break
            del self._entries[digest]
            self._spans -= entry.span_count
            self._evictions += 1

    def get_many(self, fingerprint: bytes, texts: Iterable[str]) -> tuple["DetectionOutcome | None", ...]:
        """逐文本返回缓存命中结果；``None`` 表示未命中（调用方需真实检测）。

        不做插入：调用方在三路检测成功后再 ``put_many``，保证失败/超时/
        秘密阻断不会留下可复用结果。
        """
        fingerprint = self._require_fingerprint(fingerprint)
        texts = tuple(texts)
        for text in texts:
            if not isinstance(text, str):
                raise TypeError("cache texts must be strings")
        now = self._clock()
        with self._lock:
            self._sweep_expired(now)
            results: list["DetectionOutcome | None"] = []
            for text in texts:
                digest = self._digest(fingerprint, text)
                entry = self._entries.get(digest)
                if entry is None:
                    self._misses += 1
                    results.append(None)
                else:
                    self._entries.move_to_end(digest)
                    self._hits += 1
                    results.append(entry.outcome)
            return tuple(results)

    def put_many(
        self,
        fingerprint: bytes,
        texts: Iterable[str],
        outcomes: Iterable["DetectionOutcome"],
    ) -> None:
        """缓存一批成功检测结果；超条目/超跨度按 LRU 淘汰。"""
        fingerprint = self._require_fingerprint(fingerprint)
        texts = tuple(texts)
        outcomes = tuple(outcomes)
        if len(texts) != len(outcomes):
            raise ValueError("put_many requires equal-length texts and outcomes")
        now = self._clock()
        expires_at = now + self._ttl_seconds
        with self._lock:
            self._sweep_expired(now)
            for text, outcome in zip(texts, outcomes, strict=True):
                if not isinstance(text, str):
                    raise TypeError("cache texts must be strings")
                span_count = len(getattr(outcome, "spans", ()))
                digest = self._digest(fingerprint, text)
                previous = self._entries.get(digest)
                if previous is not None:
                    self._spans -= previous.span_count
                    self._entries.move_to_end(digest)
                self._entries[digest] = _CacheEntry(outcome, expires_at, span_count)
                self._spans += span_count
                while self._entries and (
                    len(self._entries) > self._max_entries or self._spans > self._max_spans
                ):
                    _, evicted = self._entries.popitem(last=False)
                    self._spans -= evicted.span_count
                    self._evictions += 1

    def snapshot(self) -> DetectionCacheSnapshot:
        """返回累计度量快照；不触发淘汰（过期条目仍计入 entries）。"""
        with self._lock:
            return DetectionCacheSnapshot(
                hits=self._hits,
                misses=self._misses,
                entries=len(self._entries),
                spans=self._spans,
                evictions=self._evictions,
            )

    def clear(self) -> None:
        """装配切换时主动释放全部条目；度量计数一并清零。"""
        with self._lock:
            self._entries.clear()
            self._spans = 0
            self._hits = 0
            self._misses = 0
            self._evictions = 0
