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
from detection.detection_cache import DetectionResultCache
from detection.detection_orchestrator import DEFAULT_NER_TIMEOUT, DetectionOrchestrator
from detection.dictionary import CompiledDictionary
from detection.quick_screen import QuickScreenConfig
from document.service import FileRedactor
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
    correlation_key: bytes, kms: KmsProvider, hmac_key: bytes | None = None,
    dictionary: CompiledDictionary, ner_package_dir: Path, state_directory: Path,
    policy: ClassificationPolicy, watermark_policy: WatermarkPolicy,
    evidence_bucket: str, classifier: Callable[[bytes], str] | None = None,
    package_version: str = "runtime-v1", ner_timeout: float = DEFAULT_NER_TIMEOUT,
    max_body_bytes: int = 1048576, transport: httpx.BaseTransport | None = None,
    resolver: Resolver | None = None,
    history_store=None, admin_service=None, dictionary_store=None,
    knowledge_governance=None, audit_reader=None, audit_builder=None,
    detection_failure_mode: str = 'error',
    quick_screen: QuickScreenConfig | None = None,
    ner_max_workers: int = 1, ner_max_pending: int = 4,
    ner_max_tasks_per_worker: int = 8192, ner_intra_op_threads: int | None = None,
    ner_window_length: int = 384, ner_stride: int = 318,
    ner_max_age_seconds: int = 3600, ner_max_rss_kib: int = 2097152,
    ner_batch_wait_ms: int = 0, ner_max_batch_jobs: int = 1,
    ner_max_batch_chars: int = 512, ner_batch_tokens: int = 4096,
    ner_sentence_boundaries: bool = False,
    detection_cache_enabled: bool = False,
    detection_cache_entries: int = 4096,
    detection_cache_ttl_seconds: float = 900.0,
    detection_cache_max_spans: int = 65536,
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
    file_redactor = None
    try:
        detector = DetectionOrchestrator(dictionary=dictionary, ner_package_dir=ner_package_dir,
            ner_timeout=ner_timeout, quick_screen=quick_screen, ner_max_workers=ner_max_workers,
            ner_max_pending=ner_max_pending, ner_max_tasks_per_worker=ner_max_tasks_per_worker,
            ner_intra_op_threads=ner_intra_op_threads,
            window_length=ner_window_length, stride=ner_stride,
            ner_max_age_seconds=ner_max_age_seconds, ner_max_rss_kib=ner_max_rss_kib,
            ner_batch_wait_ms=ner_batch_wait_ms, ner_max_batch_jobs=ner_max_batch_jobs,
            ner_max_batch_chars=ner_max_batch_chars, ner_batch_tokens=ner_batch_tokens,
            ner_sentence_boundaries=ner_sentence_boundaries)
        guard = AuditWatermarkGuard(root, watermark_policy)
        evidence = EvidenceGate(intent_directory=paths["intents"],
                                evidence_directory=paths["evidence"], kms=kms)
        spool = SpoolWriter(directory=paths["spool"], kms=kms)
        limiter = AdmissionLimiter(max_body_bytes=max_body_bytes)
        # M2 检测结果缓存：一个缓存跨全部供应商流水线共享（同一检测器、同一装配指纹）。
        result_cache = DetectionResultCache(
            max_entries=detection_cache_entries,
            ttl_seconds=detection_cache_ttl_seconds,
            max_spans=detection_cache_max_spans,
        ) if detection_cache_enabled else None
        by_model = {}
        for config in configs:
            pipeline = create_provider_pipeline(config, domain=domain, policy=policy,
                detector=detector, admission_limiter=limiter, watermark_guard=guard,
                evidence_gate=evidence, spool_writer=spool, evidence_bucket=evidence_bucket,
                package_version=package_version, transport=transport, resolver=resolver,
                detection_failure_mode=detection_failure_mode,
                detection_result_cache=result_cache)
            pipelines.append(pipeline)
            by_model.update({model: pipeline for model in config.models})
        router = ProviderRouter(by_model)
        def verify_file_assets():
            pipeline = pipelines[0]
            if pipeline.detector is not detector:
                raise SafetyError(SafetyCode.CORRUPTED_PACKAGE)
            handle = pipeline.version_handle
            handle.assert_consistent_hash(pipeline._version_manager.active_package_hash)
            handle.manifest.require_complete()
            handle.manifest.verify_payloads(pipeline._component_payloads())
            return handle.package_hash
        if admin_service is not None:
            file_redactor = FileRedactor(detector=detector, domain=domain,
                scope=f'{tenant_id}/{domain}', verify_assets=verify_file_assets)
        app = create_app(router=router, authenticator=authenticator,
                         classifier=classifier, hmac_key=hmac_key,
                         history_store=history_store, admin_service=admin_service,
                         knowledge_governance=knowledge_governance, audit_reader=audit_reader, audit_builder=audit_builder,
                         file_redactor=file_redactor,
                         )
        if dictionary_store is not None:
            from gateway.dictionary_runtime import DictionaryRuntimeService
            if dictionary_store.scope != f'{tenant_id}/{domain}' or not dictionary.version.startswith('db-'):
                raise SafetyError(SafetyCode.SCOPE_MISMATCH, 'dictionary store assembly')
            app.state.dictionary_service = DictionaryRuntimeService(
                app, dictionary_store, revision=int(dictionary.version[3:]))

        import threading
        builder_stop = threading.Event()
        def build_catalog():
            while not builder_stop.is_set():
                try:
                    audit_builder.build_once()
                    app.state.audit_catalog_error_code = None
                except Exception:
                    app.state.audit_catalog_error_code = 'ADMIN_AUDIT_UNAVAILABLE'  # Directory lag never propagates into model readiness.
                builder_stop.wait(5)
        builder_thread = None

        def close_resources():
            builder_stop.set()
            if file_redactor is not None:
                file_redactor.close()
            if builder_thread is not None:
                builder_thread.join(timeout=5)
            for name in ('admin_audit_executor', 'admin_knowledge_executor'):
                executor = getattr(app.state, name, None)
                if executor is not None:
                    executor.shutdown(wait=False, cancel_futures=True)
            if knowledge_governance is not None:
                close = getattr(getattr(knowledge_governance, '_storage', None), 'close', None)
                if close is not None:
                    close()
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
            nonlocal builder_thread
            if audit_builder is not None:
                builder_thread = threading.Thread(target=build_catalog, name='admin-audit-catalog', daemon=True)
                builder_thread.start()
            try:
                await anyio.to_thread.run_sync(detector.warmup)
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
            if file_redactor is not None:
                file_redactor.close()
            if detector is not None:
                detector.close()
        finally:
            for pipeline in pipelines:
                try:
                    pipeline.egress_client.close()
                except Exception:
                    pass
        raise
