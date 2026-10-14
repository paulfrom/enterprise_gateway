"""Publish complete dictionary assemblies; existing requests keep their objects."""
from __future__ import annotations

from copy import copy
import threading

from detection.detection_orchestrator import DetectionOrchestrator
from detection.ner_worker_pool import NerWorkerPool
from gateway.pipeline import ProtectedPipeline
from gateway.provider_router import ProviderRouter


class DictionaryRuntimeService:
    def __init__(self, app, store, *, revision: int):
        self.app, self.store = app, store
        self.scope = store.scope
        self._revision = revision
        self._lock = threading.RLock()
        self._templates = tuple(dict.fromkeys(app.state.router._pipelines.values()))
        self._file_template = app.state.file_redactor

    def prepare(self, dictionary):
        base = self._templates[0].detector
        kwargs = {} if isinstance(base._executor, NerWorkerPool) else {'ner_worker': base._ner_worker}
        detector = DetectionOrchestrator(
            recognizers=base._recognizers, dictionary=dictionary,
            ner_package_dir=base._ner_package_dir, executor=base._executor,
            ner_timeout=base._ner_timeout, window_length=base._window_length, stride=base._stride,
            ner_intra_op_threads=base._ner_intra_op_threads,
            quick_screen=base._risk_screener.config if base._risk_screener is not None else None,
            **kwargs)
        pipelines = tuple(ProtectedPipeline(
            channel_id=old.channel_id, protocol=old.protocol, domain=old.domain, path=old.path,
            policy=old.policy, admission_limiter=old.admission_limiter, detector=detector,
            watermark_guard=old.watermark_guard, evidence_gate=old.evidence_gate,
            egress_client=old.egress_client, evidence_bucket=old.evidence_bucket,
            spool_writer=old.spool_writer, exemption_registry=old.exemption_registry,
            package_version=old.package_version, allowed_models=old.allowed_models,
            model_mapping=old.model_mapping, request_timeout=old.request_timeout,
            history_adapter=old.history_adapter, detection_failure_mode=old._route.detection_failure_mode,
        ) for old in self._templates)
        router = ProviderRouter({model: pipeline for pipeline in pipelines for model in pipeline.allowed_models})
        redactor = None
        if self._file_template is not None:
            redactor = copy(self._file_template)
            redactor.detector = detector
            pipeline = pipelines[0]
            def verify():
                handle = pipeline.version_handle
                handle.assert_consistent_hash(pipeline._version_manager.active_package_hash)
                handle.manifest.verify_payloads(pipeline._component_payloads())
                return handle.package_hash
            redactor.verify_assets = verify
        return router, pipelines, redactor

    def activate(self, prepared, revision):
        router, pipelines, redactor = prepared
        self.app.state.router = router
        self.app.state.runtime_pipelines = pipelines
        self.app.state.file_redactor = redactor
        self._revision = revision

    def refresh(self):
        with self._lock:
            revision, dictionary = self.store.active(self._revision)
            if dictionary is not None:
                self.activate(self.prepare(dictionary), revision)

    def publish(self, expected_revision, actor):
        with self._lock:
            result, prepared = self.store.publish(expected_revision, actor, self.prepare)
            if prepared is not None:
                self.activate(prepared, result.published_revision)
            else:
                self.refresh()
            return result
