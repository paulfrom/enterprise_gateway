"""Multi-provider and model-based pipeline routing for Enterprise Privacy Gateway.

Enables standalone operation across multiple LLM providers (e.g. DeepSeek,
OpenAI, Claude, vLLM) in BYOK mode without third-party middleware.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from infra.egress_client import BoundEgressClient, BoundUpstream
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
    credential: str | None = None
    credential_header: str = "authorization"
    timeout_seconds: float = 180.0


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
    package_version: str = "runtime-v1",
) -> ProtectedPipeline:
    """Assemble a fail-closed pipeline bound to the specified provider configuration."""
    parsed = urlsplit(config.url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise SafetyError(SafetyCode.INVALID_UPSTREAM, f"invalid scheme: {scheme}")

    port = parsed.port if parsed.port is not None else (443 if scheme == "https" else 80)
    host = parsed.hostname or "127.0.0.1"
    path_prefix = parsed.path if parsed.path.startswith("/") else "/v1"

    # Egress binding (credential is None for BYOK mode)
    binding = BoundUpstream.resolve(
        channel_id=config.channel_id,
        scheme=scheme,
        host=host,
        port=port,
        path_prefix=path_prefix,
        credential=config.credential,
        credential_header=config.credential_header,
        timeout_seconds=config.timeout_seconds,
    )
    egress = BoundEgressClient(binding)

    allowed_models = frozenset(config.models)
    model_mapping = {m: m for m in config.models}

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
    )
