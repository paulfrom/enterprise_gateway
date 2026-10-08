"""Multi-provider and model-based pipeline routing for Enterprise Privacy Gateway.

Enables standalone operation across multiple LLM providers (e.g. DeepSeek,
OpenAI, Claude, vLLM) in BYOK mode without third-party middleware.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

import httpx

from audit.evidence_gate import EvidenceGate
from infra.egress_client import BoundEgressClient, BoundUpstream, Resolver
from infra.errors import SafetyCode, SafetyError
from gateway.pipeline import ProtectedPipeline
from protocol.protocols import CLAUDE_MESSAGES_PROTOCOL, DEEPSEEK_CHAT_PROTOCOL


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    """Definition of one upstream supplier channel and its allowed models."""

    channel_id: str
    protocol: str
    url: str
    models: tuple[str, ...]
    credential_header: str = "authorization"
    timeout_seconds: float = 180.0

    def __post_init__(self) -> None:
        def reject():
            raise SafetyError(SafetyCode.INVALID_UPSTREAM, "provider configuration") from None
        if type(self.channel_id) is not str or not self.channel_id or self.channel_id.strip() != self.channel_id:
            reject()
        if any(ord(c) < 33 or ord(c) > 126 for c in self.channel_id):
            reject()
        if type(self.protocol) is not str or self.protocol not in (DEEPSEEK_CHAT_PROTOCOL, CLAUDE_MESSAGES_PROTOCOL):
            reject()
        if type(self.url) is not str or not self.url or any(c.isspace() or ord(c) < 32 for c in self.url):
            reject()
        try:
            parsed = urlsplit(self.url)
            port = parsed.port
        except ValueError:
            reject()
        expected_path = "/v1/messages" if self.protocol == CLAUDE_MESSAGES_PROTOCOL else "/v1/chat/completions"
        expected_header = "x-api-key" if self.protocol == CLAUDE_MESSAGES_PROTOCOL else "authorization"
        if (parsed.scheme not in ("http", "https") or not parsed.hostname or
                parsed.username is not None or parsed.password is not None or
                parsed.path != expected_path or "?" in self.url or "#" in self.url or
                "\\" in self.url or "%" in parsed.netloc or
                parsed.netloc.endswith(":") or
                (port is not None and not 1 <= port <= 65535) or
                type(self.credential_header) is not str or self.credential_header != expected_header):
            reject()
        if type(self.models) is not tuple or not self.models:
            reject()
        if any(type(model) is not str or not model or model.strip() != model or
               any(c.isspace() or ord(c) < 32 for c in model) for model in self.models):
            reject()
        if len(set(self.models)) != len(self.models):
            reject()
        if (type(self.timeout_seconds) not in (int, float) or
                not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0):
            reject()


def load_provider_configs(path: str | Path) -> tuple[ProviderConfig, ...]:
    """Load one strict JSON route contract; duplicates never select a winner."""
    def reject():
        raise SafetyError(SafetyCode.INVALID_UPSTREAM, "provider configuration") from None

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                reject()
            result[key] = value
        return result

    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"),
                         object_pairs_hook=unique_object, parse_constant=lambda _: reject())
    except (OSError, UnicodeError, ValueError, TypeError):
        reject()
    if type(raw) is not dict or set(raw) != {"providers"}:
        reject()
    entries = raw["providers"]
    if type(entries) is not list or not entries:
        reject()
    required = {"channel_id", "protocol", "url", "models"}
    allowed = required | {"credential_header", "timeout_seconds"}
    configs = []
    channels, models = set(), set()
    for entry in entries:
        if type(entry) is not dict or not required <= entry.keys() or entry.keys() - allowed:
            reject()
        if type(entry["models"]) is not list:
            reject()
        config = ProviderConfig(**{**entry, "models": tuple(entry["models"])})
        if config.channel_id in channels or models.intersection(config.models):
            reject()
        channels.add(config.channel_id)
        models.update(config.models)
        configs.append(config)
    return tuple(configs)


class ProviderRouter:
    """Routes incoming model requests to their bound ProtectedPipeline."""

    def __init__(self, pipelines_by_model: Mapping[str, ProtectedPipeline]) -> None:
        if not pipelines_by_model:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "no provider pipelines configured")
        self._pipelines = dict(pipelines_by_model)

    def get_pipeline(self, model: str) -> ProtectedPipeline:
        pipeline = self._pipelines.get(model)
        if pipeline is None:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, f"model not admitted: {model}")
        return pipeline

    @property
    def supported_models(self) -> tuple[str, ...]:
        return tuple(sorted(self._pipelines.keys()))


def create_provider_pipeline(
    config: ProviderConfig,
    *,
    domain: str,
    policy: Any,
    detector: Any,
    admission_limiter: Any,
    watermark_guard: Any,
    evidence_gate: Any,
    spool_writer: Any,
    evidence_bucket: str,
    package_version: str = "runtime-v1",
    transport: httpx.BaseTransport | None = None,
    resolver: Resolver | None = None,
) -> ProtectedPipeline:
    """Assemble a fail-closed pipeline bound to the specified provider configuration."""
    if not isinstance(config, ProviderConfig):
        raise SafetyError(SafetyCode.INVALID_UPSTREAM, "provider configuration")
    if type(evidence_bucket) is not str or not evidence_bucket.strip() or evidence_bucket.strip() != evidence_bucket:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "evidence bucket required")
    if not isinstance(evidence_gate, EvidenceGate):
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "evidence gate required")
    parsed = urlsplit(config.url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise SafetyError(SafetyCode.INVALID_UPSTREAM, f"invalid scheme: {scheme}")

    port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
    host = parsed.hostname
    path_prefix = parsed.path

    binding = BoundUpstream.resolve(
        channel_id=config.channel_id,
        scheme=scheme,
        host=host,
        port=port,
        path_prefix=path_prefix,
        credential_header=config.credential_header,
        timeout_seconds=config.timeout_seconds,
        resolver=resolver,
    )
    egress = BoundEgressClient(binding, transport=transport, resolver=resolver)

    allowed_models = frozenset(config.models)
    model_mapping = {m: m for m in config.models}

    try:
        return ProtectedPipeline(
            channel_id=config.channel_id,
            protocol=config.protocol,
            domain=domain,
            path=parsed.path,
            policy=policy,
            detector=detector,
            admission_limiter=admission_limiter,
            watermark_guard=watermark_guard,
            evidence_gate=evidence_gate,
            egress_client=egress,
            spool_writer=spool_writer,
            allowed_models=allowed_models,
            model_mapping=model_mapping,
            package_version=package_version,
            request_timeout=config.timeout_seconds,
            evidence_bucket=evidence_bucket,
        )
    except BaseException:
        egress.close()
        raise
