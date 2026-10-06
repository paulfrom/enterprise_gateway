"""Explicit composition root for one admitted Custom Chat Completions route.

The operator supplies identity, governance policy, detector assets and KMS.
This module neither creates production admission nor enables other protocols.
The supplier file is read once at assembly; requests cannot change that route.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
import re
from urllib.parse import urlsplit

import anyio
import httpx
from fastapi import FastAPI

from audit.audit_watermark import AuditWatermarkGuard, WatermarkPolicy
from audit.evidence_gate import EvidenceGate
from detection.detection_orchestrator import DEFAULT_NER_TIMEOUT, DetectionOrchestrator
from detection.dictionary import CompiledDictionary
from gateway.app import create_app
from gateway.pipeline import ProtectedPipeline
from infra.egress_client import BoundEgressClient, BoundUpstream, Resolver
from infra.envelope_crypto import KmsProvider
from infra.errors import SafetyCode, SafetyError
from infra.spool import SpoolWriter
from infra.strict_json import parse_strict_json
from policy.policy import ClassificationPolicy
from protocol.admission import AdmissionLimiter
from protocol.identity import TrustedIdentity
from protocol.protocols import DEEPSEEK_CHAT_PROTOCOL


@dataclass(frozen=True)
class FixedCustomProvider:
    """Server-owned immutable supplier snapshot, with credentials hidden in repr."""

    model_id: str
    host: str
    port: int
    api_key: str = field(repr=False)


def _reject_provider(_kind=None):
    raise SafetyError(SafetyCode.INVALID_UPSTREAM, "fixed supplier configuration")


def load_custom_provider(path: Path) -> FixedCustomProvider:
    """Read exactly one explicit Custom provider from a controlled models file.

    This is a server-side credential reference. No request fields or environment
    URL override are accepted. Client capability flags do not admit capabilities.
    """
    try:
        with Path(path).open("rb") as source:
            raw = source.read(65537)
        if len(raw) > 65536:
            _reject_provider()
        payload = parse_strict_json(raw, reject=_reject_provider)
        if not isinstance(payload, list) or len(payload) != 1:
            _reject_provider()
        entry = payload[0]
        allowed = {"id", "name", "vendor", "url", "apiKey", "supportsToolCall",
                   "supportsImages", "supportsReasoning", "useCustomProtocol"}
        if not isinstance(entry, dict) or set(entry) - allowed:
            _reject_provider()
        if entry.get("vendor") != "Custom" or entry.get("useCustomProtocol") is not False:
            _reject_provider()
        for flag in ("supportsToolCall", "supportsImages", "supportsReasoning"):
            if flag in entry and type(entry[flag]) is not bool:
                _reject_provider()
        model = entry.get("id")
        if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", model):
            _reject_provider()
        key = entry.get("apiKey")
        if not isinstance(key, str) or not key.strip() or any(c.isspace() for c in key):
            _reject_provider()
        url = entry.get("url")
        if not isinstance(url, str) or any(c.isspace() for c in url):
            _reject_provider()
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment
                or parsed.path != "/v1/chat/completions"):
            _reject_provider()
        port = 443 if parsed.port is None else parsed.port
        if not 1 <= port <= 65535:
            _reject_provider()
        return FixedCustomProvider(model, parsed.hostname, port, key)
    except SafetyError:
        raise
    except Exception:
        _reject_provider()


def create_runtime_app(
    *,
    provider_config_path: Path,
    identity: TrustedIdentity,
    enterprise_token: str,
    hmac_key: bytes,
    kms: KmsProvider,
    dictionary: CompiledDictionary,
    ner_package_dir: Path,
    state_directory: Path,
    policy: ClassificationPolicy,
    watermark_policy: WatermarkPolicy,
    evidence_bucket: str,
    channel_id: str = "workbuddy-custom",
    package_version: str = "runtime-v1",
    request_timeout: float = 180.0,
    ner_timeout: float = DEFAULT_NER_TIMEOUT,
    max_body_bytes: int = 1048576,
    transport: httpx.BaseTransport | None = None,
    resolver: Resolver | None = None,
) -> FastAPI:
    """Assemble existing fail-closed components and own their HTTP lifecycle.

    Transport/resolver injection supports controlled protocol tests; normal
    launch uses the existing fixed DNS/TLS egress transport. No fake watermark,
    detector, upstream, KMS or credential is constructed by this factory.
    """
    provider = load_custom_provider(provider_config_path)
    if (not isinstance(identity, TrustedIdentity) or not isinstance(dictionary, CompiledDictionary)
            or dictionary.domain != identity.domain):
        raise SafetyError(SafetyCode.SCOPE_MISMATCH, "runtime assets")
    if (not isinstance(enterprise_token, str) or not enterprise_token
            or any(c.isspace() for c in enterprise_token)
            or enterprise_token == provider.api_key):
        raise SafetyError(SafetyCode.INVALID_IDENTITY, "enterprise credential")
    if not isinstance(hmac_key, bytes) or len(hmac_key) < 32:
        raise SafetyError(SafetyCode.INVALID_HMAC_KEY)
    if not isinstance(policy, ClassificationPolicy) or not isinstance(watermark_policy, WatermarkPolicy):
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "runtime policy")
    if not isinstance(kms, KmsProvider):
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "explicit KMS")
    if not isinstance(evidence_bucket, str) or not evidence_bucket.strip():
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "explicit evidence retention bucket")
    if not Path(ner_package_dir).is_dir():
        raise SafetyError(SafetyCode.DETECTION_INCOMPLETE, "NER package")
    root = Path(state_directory).resolve()
    paths = {name: root / name for name in ("intents", "evidence", "spool")}
    for directory in paths.values():
        directory.mkdir(parents=True, exist_ok=True)
    binding = BoundUpstream.resolve(
        channel_id=channel_id, scheme="https", host=provider.host, port=provider.port,
        path_prefix="/v1", credential="Bearer " + provider.api_key,
        timeout_seconds=request_timeout, resolver=resolver,
    )
    egress = None
    detector = None
    try:
        egress = BoundEgressClient(binding, transport=transport, resolver=resolver)
        detector = DetectionOrchestrator(dictionary=dictionary, ner_package_dir=ner_package_dir,
                                         ner_timeout=ner_timeout)
        pipeline = ProtectedPipeline(
            channel_id=channel_id, protocol=DEEPSEEK_CHAT_PROTOCOL, domain=identity.domain,
            path="/v1/chat/completions", policy=policy,
            admission_limiter=AdmissionLimiter(max_body_bytes=max_body_bytes),
            detector=detector,
            watermark_guard=AuditWatermarkGuard(root, watermark_policy),
            evidence_gate=EvidenceGate(intent_directory=paths["intents"],
                                      evidence_directory=paths["evidence"], kms=kms),
            egress_client=egress, spool_writer=SpoolWriter(directory=paths["spool"], kms=kms),
            allowed_models=frozenset({provider.model_id}),
            model_mapping={provider.model_id: provider.model_id},
            package_version=package_version, request_timeout=request_timeout,
            evidence_bucket=evidence_bucket,
        )
        app = create_app(pipeline=pipeline,
                         enterprise_credentials={enterprise_token: identity}, hmac_key=hmac_key)

        @asynccontextmanager
        async def lifespan(_app):
            try:
                yield
            finally:
                try:
                    await anyio.to_thread.run_sync(detector.close)
                finally:
                    await anyio.to_thread.run_sync(egress.close)

        app.router.lifespan_context = lifespan
        app.state.runtime_spool_directory = paths["spool"]
        app.state.runtime_model_id = provider.model_id
        app.state.runtime_package_hash = pipeline.version_handle.package_hash
        return app
    except BaseException:
        try:
            if detector is not None:
                detector.close()
        finally:
            if egress is not None:
                egress.close()
        raise
