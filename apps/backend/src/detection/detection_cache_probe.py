"""历史消息检测结果缓存 M1：只度量、不缓存结果的影子探测器。

方案 ``docs/plans/history-detection-cache.md`` 分期落地，M1 只做度量：
先把「哪些片段在真实缓存下会命中、能省下多少 NER 片段/字符/跨度、影子表
占多少条目」量出来，再决定 M2 是否实现真实缓存、以及条目/TTL 边界。因此本
模块**不返回任何缓存结果，也不改变检测语义**，只是复用方案 §3 的键构造：

    key = HMAC-SHA256(k_cache, domain || fingerprint || 0x00 || text_utf8)

并观察 ``(文本, 检测装配指纹)`` 在进程内的重复度。影子表只保存带密钥摘要
（32 字节）与插入时刻，**不保存正文、跨度或 DetectionOutcome**：即使内存被
转储或误入诊断，也无法从表内恢复业务正文，也避免键成为已知明文猜测验证器。

命中判定与真实缓存一致：同一次 ``detect_many`` 内先对全部文本查表、批量结束
后才回填，因此同一批次里的重复文本按未命中计（真实缓存也要先算一遍才会命中），
跨请求/跨轮的重复才计入命中。失败、超时、秘密阻断等路径不会走到回填，自然
不入影子表。

M2 将新增 ``detection_cache.DetectionResultCache`` 复用同一键方案与
``DetectionOrchestrator.configure_cache`` 钩子；本模块届时退化为基准与回归
用的对照实现。
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
from typing import Callable, Iterable

from detection.detection_cache import CACHE_KEY_DOMAIN

__all__ = ["DetectionCacheProbe", "DetectionCacheProbeSnapshot", "CACHE_KEY_DOMAIN"]

_MIN_KEY_BYTES = 16


@dataclass(frozen=True, slots=True)
class DetectionCacheProbeSnapshot:
    """累计度量快照；全部为计数，不含任何正文。"""

    hits: int
    misses: int
    entries: int
    evictions: int
    avoided_fragments: int
    avoided_chars: int
    avoided_spans: int

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return 0.0 if total == 0 else self.hits / total


class DetectionCacheProbe:
    """有界、线程安全的影子检测缓存：只记录键摘要与可复用工作量估计。

    ``classify`` 对一批文本按当前影子表给出「真实缓存下是否会命中」的布尔
    序列，并累计 hits/misses；``record`` 在三路检测**成功后**回填本批摘要并
    累计省下的片段/字符/跨度。二者刻意分离，保证失败请求不产生可复用记录，
    与方案 §5「只缓存成功完整结果」一致。
    """

    def __init__(
        self,
        *,
        hmac_key: bytes | None = None,
        max_entries: int = 4096,
        ttl_seconds: float = 900.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        key = secrets.token_bytes(32) if hmac_key is None else hmac_key
        if not isinstance(key, (bytes, bytearray)) or len(key) < _MIN_KEY_BYTES:
            raise ValueError(f"hmac_key must be at least {_MIN_KEY_BYTES} bytes")
        if not isinstance(max_entries, int) or isinstance(max_entries, bool) or max_entries <= 0:
            raise ValueError("max_entries must be a positive integer")
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)) \
                or not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be a finite positive number")
        self._key = bytes(key)
        self._max_entries = max_entries
        self._ttl_seconds = float(ttl_seconds)
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: OrderedDict[bytes, float] = OrderedDict()
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        self._avoided_fragments = 0
        self._avoided_chars = 0
        self._avoided_spans = 0

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
            key, expires_at = next(iter(self._entries.items()))
            if expires_at > now:
                break
            del self._entries[key]
            self._evictions += 1

    def classify(self, fingerprint: bytes, texts: Iterable[str]) -> tuple[bool, ...]:
        """查询一批文本在当前影子表下的命中情况（不插入本批新键）。

        同一批次内重复文本相互不可见，按未命中计，与真实缓存「先整批查询、
        成功后整批回填」的顺序一致。命中项按 LRU 提升到表尾。
        """
        fingerprint = self._require_fingerprint(fingerprint)
        texts = tuple(texts)
        for text in texts:
            if not isinstance(text, str):
                raise TypeError("cache probe texts must be strings")
        now = self._clock()
        with self._lock:
            self._sweep_expired(now)
            flags: list[bool] = []
            for text in texts:
                digest = self._digest(fingerprint, text)
                if digest in self._entries:
                    self._entries.move_to_end(digest)
                    self._hits += 1
                    flags.append(True)
                else:
                    self._misses += 1
                    flags.append(False)
            return tuple(flags)

    def record(
        self,
        fingerprint: bytes,
        texts: Iterable[str],
        hit_flags: Iterable[bool],
        span_counts: Iterable[int],
    ) -> None:
        """成功检测后回填整批摘要，并累计命中片段的可复用工作量估计。"""
        fingerprint = self._require_fingerprint(fingerprint)
        texts = tuple(texts)
        flags = tuple(hit_flags)
        spans = tuple(span_counts)
        if not (len(texts) == len(flags) == len(spans)):
            raise ValueError("record requires equal-length texts/hit_flags/span_counts")
        for text, hit, span_count in zip(texts, flags, spans, strict=True):
            if not isinstance(text, str):
                raise TypeError("cache probe texts must be strings")
            if not isinstance(hit, bool):
                raise TypeError("hit_flags must be booleans")
            if not isinstance(span_count, int) or isinstance(span_count, bool) or span_count < 0:
                raise TypeError("span_counts must be non-negative integers")
        now = self._clock()
        expires_at = now + self._ttl_seconds
        with self._lock:
            self._sweep_expired(now)
            for text, hit, span_count in zip(texts, flags, spans, strict=True):
                digest = self._digest(fingerprint, text)
                if digest in self._entries:
                    self._entries.move_to_end(digest)
                self._entries[digest] = expires_at
                while len(self._entries) > self._max_entries:
                    self._entries.popitem(last=False)
                    self._evictions += 1
                if hit:
                    self._avoided_fragments += 1
                    self._avoided_chars += len(text)
                    self._avoided_spans += span_count

    def snapshot(self) -> DetectionCacheProbeSnapshot:
        """返回累计度量快照；不触发淘汰（过期条目仍计入 entries）。"""
        with self._lock:
            return DetectionCacheProbeSnapshot(
                hits=self._hits,
                misses=self._misses,
                entries=len(self._entries),
                evictions=self._evictions,
                avoided_fragments=self._avoided_fragments,
                avoided_chars=self._avoided_chars,
                avoided_spans=self._avoided_spans,
            )

    def clear(self) -> None:
        """装配切换或基准分段时释放全部摘要；度量计数一并清零。"""
        with self._lock:
            self._entries.clear()
            self._hits = 0
            self._misses = 0
            self._evictions = 0
            self._avoided_fragments = 0
            self._avoided_chars = 0
            self._avoided_spans = 0
