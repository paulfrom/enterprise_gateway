"""Standalone BYOK composition with immutable server-owned supplier routes.

Operator policy, detector assets, storage and KMS are explicit. A trusted server
classifier must be wired; absent classification leaves HTTP refused. Supplier
credentials originate only from the current client request.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable

import anyio
import httpx
from fastapi import FastAPI

from audit.audit_watermark import AuditWatermarkGuard, WatermarkPolicy
from audit.evidence_gate import EvidenceGate
from detection.detection_orchestrator import DEFAULT_NER_TIMEOUT, DetectionOrchestrator
from detection.dictionary import CompiledDictionary
from detection.quick_screen import QuickScreenConfig
from gateway.app import create_app
from gateway.provider_router import ProviderRouter, create_provider_pipeline, load_provider_configs
from infra.egress_client import Resolver
from infra.envelope_crypto import KmsProvider
from infra.errors import SafetyCode, SafetyError
from infra.spool import SpoolWriter
from policy.policy import ClassificationPolicy
from protocol.admission import AdmissionLimiter
from protocol.identity import ByokAuthenticator


def create_runtime_app(
    *, provider_config_path: Path, domain: str, tenant_id: str,
    correlation_key: bytes, hmac_key: bytes, kms: KmsProvider,
    dictionary: CompiledDictionary, ner_package_dir: Path, state_directory: Path,
    policy: ClassificationPolicy, watermark_policy: WatermarkPolicy,
    evidence_bucket: str, classifier: Callable[[bytes], str] | None = None,
    package_version: str = "runtime-v1", ner_timeout: float = DEFAULT_NER_TIMEOUT,
    max_body_bytes: int = 1048576, transport: httpx.BaseTransport | None = None,
    resolver: Resolver | None = None,
    history_store=None, admin_service=None,
    client_profile: str = 'compatible',
    detection_failure_mode: str = 'error',
    quick_screen: QuickScreenConfig | None = None,
) -> FastAPI:
    """Assemble real controls; own all HTTP/detector lifecycle resources.

    Tests can inject HTTP transport/DNS; ordinary startup uses bound DNS/TLS
    clients and the real disk probe. Supplier configuration is read once.
    """
    configs = load_provider_configs(provider_config_path)
    if history_store is not None:
        if history_store.domain != domain or history_store.tenant_id != tenant_id:
            raise SafetyError(SafetyCode.SCOPE_MISMATCH, "history assembly scope")
        history_store.check_ready()
    authenticator = ByokAuthenticator(domain=domain, tenant_id=tenant_id,
                                      correlation_key=correlation_key)
    if not isinstance(dictionary, CompiledDictionary) or dictionary.domain != domain:
        raise SafetyError(SafetyCode.SCOPE_MISMATCH, "runtime assets")
    if not isinstance(hmac_key, bytes) or len(hmac_key) < 32:
        raise SafetyError(SafetyCode.INVALID_HMAC_KEY)
    if not isinstance(policy, ClassificationPolicy) or not isinstance(watermark_policy, WatermarkPolicy):
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "runtime policy")
    if not isinstance(kms, KmsProvider):
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "explicit KMS")
    if not isinstance(evidence_bucket, str) or not evidence_bucket.strip():
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "explicit evidence retention bucket")
    if classifier is not None and not callable(classifier):
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "trusted classifier")
    if not Path(ner_package_dir).is_dir():
        raise SafetyError(SafetyCode.DETECTION_INCOMPLETE, "NER package")
    root = Path(state_directory).resolve()
    paths = {name: root / name for name in ("intents", "evidence", "spool")}
    for directory in paths.values():
        directory.mkdir(parents=True, exist_ok=True)

    detector = None
    pipelines = []
    try:
        detector = DetectionOrchestrator(dictionary=dictionary, ner_package_dir=ner_package_dir,
                                         ner_timeout=ner_timeout, quick_screen=quick_screen)
        guard = AuditWatermarkGuard(root, watermark_policy)
        evidence = EvidenceGate(intent_directory=paths["intents"],
                                evidence_directory=paths["evidence"], kms=kms)
        spool = SpoolWriter(directory=paths["spool"], kms=kms)
        limiter = AdmissionLimiter(max_body_bytes=max_body_bytes)
        by_model = {}
        for config in configs:
            pipeline = create_provider_pipeline(config, domain=domain, policy=policy,
                detector=detector, admission_limiter=limiter, watermark_guard=guard,
                evidence_gate=evidence, spool_writer=spool, evidence_bucket=evidence_bucket,
                package_version=package_version, transport=transport, resolver=resolver,
                detection_failure_mode=detection_failure_mode)
            pipelines.append(pipeline)
            by_model.update({model: pipeline for model in config.models})
        router = ProviderRouter(by_model)
        app = create_app(router=router, authenticator=authenticator,
                         classifier=classifier, hmac_key=hmac_key,
                         history_store=history_store, admin_service=admin_service,
                         client_profile=client_profile)

        def close_resources():
            try:
                detector.close()
            finally:
                failure = None
                for pipeline in pipelines:
                    try:
                        pipeline.egress_client.close()
                    except BaseException as exc:
                        failure = exc
                if failure is not None:
                    raise failure

        @asynccontextmanager
        async def lifespan(_app):
            try:
                yield
            finally:
                app.state.runtime_closed = True
                with anyio.CancelScope(shield=True):
                    await anyio.to_thread.run_sync(close_resources)

        app.router.lifespan_context = lifespan
        app.state.runtime_closed = False
        app.state.runtime_spool_directory = paths["spool"]
        app.state.runtime_evidence_directory = paths["evidence"]
        app.state.runtime_pipelines = tuple(pipelines)
        app.state.runtime_models = router.supported_models
        return app
    except BaseException:
        try:
            if detector is not None:
                detector.close()
        finally:
            for pipeline in pipelines:
                try:
                    pipeline.egress_client.close()
                except Exception:
                    pass
        raise
