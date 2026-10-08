"""P-18 non-streaming protected roundtrip pipeline.

Integrates all gates and stages of the M2A milestone for a channel:
1. Header & identity verification (C-02) via TrustedIdentity
2. Ingress validation (C-01, C-03, C-04) via IngressValidator
3. Resource admission limiter (P-16) via AdmissionLimiter
4. Three-way detection orchestration (D-12) via DetectionOrchestrator
5. Request redaction and token replacement (P-05) via replace_request
6. Audit watermark capacity guard (A-08) via AuditWatermarkGuard
7. Evidence gate: intent + envelope encryption (A-03) via EvidenceGate
8. Knowledge spooling (K-02) via SpoolWriter
9. Channel-bound outbound client (P-17) via BoundEgressClient
10. Response restoration (P-06) via restore_response

Guarantees:
- Upstream receives ONLY redacted tokens in place of detected entities.
- Upstream egress call count is EXACTLY ZERO if any pre-flight gate fails.
- Upstream usage and metadata fields are strictly preserved.
- Full fail-closed protection on unknown or corrupted tokens in responses.
"""

from __future__ import annotations

import hashlib
import json
import uuid
import time
import math
import pickle
import marshal
from pathlib import Path
from dataclasses import asdict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from types import MappingProxyType

from protocol.admission import AdmissionLimiter
from audit.audit_intent import ReleaseIntent
from audit.audit_watermark import AuditWatermarkGuard, WatermarkAssessment
from detection.detection_orchestrator import DetectionOrchestrator
from infra.egress_client import BoundEgressClient
from infra.errors import SafetyCode, SafetyError
from audit.evidence_gate import EvidenceGate, EvidencePermit, EvidenceSpec
from protocol.identity import (
    FORBIDDEN_CLIENT_IDENTITY_HEADERS,
    TrustedIdentity, UnverifiedSourceContext,
    validate_request_authorization,
)
from gateway.ingress import IngressValidator, ValidatedIngressRequest
from infra.manifest import RequestVersionHandle, PackageManifest, ComponentEntry, VersionManager, _compute_package_hash
from knowledge.knowledge import SourceKind
from knowledge.knowledge_events import ObservationMention
from knowledge.knowledge_events import ObservationEvent, build_gateway_observation
from masking.mapping import MappingContext
from policy.policy import ClassificationPolicy, resolve_egress_policy
from protocol.protocols import (
    CLAUDE_MESSAGES_PROTOCOL,
    DEEPSEEK_CHAT_PROTOCOL,
    ClaudeMessagesRequest,
    DeepSeekChatRequest,
)
from masking.replacer import replace_request
from masking.restorer import (
    ClaudeMessagesResponse,
    DeepSeekChatResponse,
    restore_response,
)
from detection.span_resolver import ResolvedSpan
from infra.spool import CollectionMode, SpoolPermit, SpoolWriter
from protocol.static_exemption import StaticExemptionRegistry

__all__ = ["PipelineResult", "ProtectedPipeline"]


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """Outcome of one end-to-end non-streaming protected pipeline run."""

    response: DeepSeekChatResponse | ClaudeMessagesResponse
    evidence_permit: EvidencePermit
    watermark_assessment: WatermarkAssessment
    spool_permit: SpoolPermit | None
    redacted_request: DeepSeekChatRequest | ClaudeMessagesRequest
    protocol: str
    allowed_tools: Mapping[str, Any]
    state_validator: Any
    state_version: str
    upstream_stream: Any = None
    client_model: str | None = None


@dataclass(frozen=True, slots=True)
class _RouteConfiguration:
    """One assembly's immutable route; replacement requires a new pipeline."""
    channel_id: str
    protocol: str
    domain: str
    path: str
    package_version: str
    allowed_models: frozenset[str]
    model_mapping: Mapping[str, str]
    request_timeout: float

    def __post_init__(self):
        object.__setattr__(self, 'model_mapping', MappingProxyType(dict(self.model_mapping)))


class ProtectedPipeline:
    """End-to-end non-streaming protected roundtrip pipeline for one bound channel."""

    def __init__(
        self,
        *,
        channel_id: str,
        protocol: str,
        domain: str,
        path: str,
        policy: ClassificationPolicy,
        admission_limiter: AdmissionLimiter,
        detector: DetectionOrchestrator,
        watermark_guard: AuditWatermarkGuard,
        evidence_gate: EvidenceGate,
        egress_client: BoundEgressClient,
        evidence_bucket: str,
        spool_writer: SpoolWriter | None = None,
        exemption_registry: StaticExemptionRegistry | None = None,
        package_version: str = "0.1.0",
        allowed_models: frozenset[str] | None = None,
        version_handle: RequestVersionHandle | None = None,
        model_mapping: Mapping[str, str] | None = None,
        request_timeout: float = 60.0,
        history_adapter=None,
    ) -> None:
        if protocol not in (DEEPSEEK_CHAT_PROTOCOL, CLAUDE_MESSAGES_PROTOCOL):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "unsupported protocol")

        self.policy = policy
        self.admission_limiter = admission_limiter
        self.detector = detector
        self.watermark_guard = watermark_guard
        self.evidence_gate = evidence_gate
        self._egress_client = egress_client
        self.spool_writer = spool_writer
        self.exemption_registry = exemption_registry
        if not isinstance(allowed_models, frozenset) or not allowed_models:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, 'bound models required')
        models = dict(model_mapping or {m:m for m in allowed_models})
        if set(models) != set(allowed_models) or any(not isinstance(m,str) or not m for m in models.values()):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, 'model mapping')
        if not isinstance(request_timeout,(int,float)) or isinstance(request_timeout,bool) or not math.isfinite(request_timeout) or request_timeout <= 0:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, 'request deadline')
        self._route = _RouteConfiguration(channel_id, protocol, domain, path,
            package_version, allowed_models, models, float(request_timeout))
        self.body_limit = self.admission_limiter._max_body_bytes
        if self.body_limit is None:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION,'bounded ingress body required')
        self._history_adapter = history_adapter
        if not isinstance(evidence_bucket, str) or not evidence_bucket.strip():
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, 'encrypted request evidence bucket required')
        self.evidence_bucket = evidence_bucket
        if self.egress_client.binding.channel_id != self.channel_id:
            raise SafetyError(SafetyCode.UPSTREAM_BINDING_VIOLATION,'channel binding')
        payloads = self._component_payloads()
        components = {name: ComponentEntry(name=name,version=package_version,sha256=hashlib.sha256(value).hexdigest()) for name,value in payloads.items()}
        manifest = PackageManifest(manifest_id=channel_id,version=package_version,created_at=datetime.now(timezone.utc).isoformat(),components=components,package_hash=_compute_package_hash(channel_id,package_version,components))
        manifest.require_complete()
        self._version_manager = VersionManager(manifest,payloads)
        if version_handle is not None:
            version_handle.manifest.require_complete()
            version_handle.assert_consistent_hash(manifest.package_hash)
        self.version_handle = version_handle or self._version_manager.bind_request('assembly')
        if history_adapter is not None:
            from protocol.history_state import ReasoningStateValidator, HistoricalStateAdapter
            validator=history_adapter.validator
            if validator.scope != domain:
                raise SafetyError(SafetyCode.SCOPE_MISMATCH,'history verifier scope')
            self._history_adapter=HistoricalStateAdapter(ReasoningStateValidator(
                validator._verification_key,scope=domain,version=self.version_handle.package_hash,
                provider_verifier=validator._provider_verifier))

    @property
    def channel_id(self): return self._route.channel_id
    @property
    def protocol(self): return self._route.protocol
    @property
    def domain(self): return self._route.domain
    @property
    def path(self): return self._route.path
    @property
    def package_version(self): return self._route.package_version
    @property
    def allowed_models(self): return self._route.allowed_models
    @property
    def model_mapping(self): return self._route.model_mapping
    @property
    def request_timeout(self): return self._route.request_timeout
    @property
    def egress_client(self): return self._egress_client
    @property
    def history_adapter(self): return self._history_adapter

    def _component_payloads(self, *, route: _RouteConfiguration | None = None) -> dict[str, bytes]:
        route = route or self._route
        root = Path(__file__).resolve().parents[1]
        canonical = lambda value: json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),default=str).encode('utf-8')
        def modules(*directories):
            return canonical({str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
                              for directory in directories for p in sorted((root/directory).rglob('*.py'))})
        dictionary = self.detector._dictionary
        ner_dir = self.detector._ner_package_dir
        if dictionary is None or ner_dir is None:
            raise SafetyError(SafetyCode.DETECTION_INCOMPLETE)
        binding = asdict(self.egress_client.binding)
        binding['allowed_addresses'] = sorted(binding['allowed_addresses'])
        validator=self.history_adapter.validator if self.history_adapter is not None else None
        history_trust=None if validator is None else {
            'scope':validator.scope,'key':hashlib.sha256(validator._verification_key).hexdigest(),
            'provider':validator._provider_verifier.binding_payload}
        return {
            'policy': canonical(self.policy.model_dump(mode='json')),
            'rules': modules('detection')+canonical([{'class':type(r).__module__+'.'+type(r).__qualname__,'definition':r.to_dict(),'policy':vars(r).get('_policy'),'today':vars(r).get('_today'),'strict':vars(r).get('_strict'),'flags':r.global_regex_flags} for r in self.detector._recognizers]),
            'dictionary': (root/'detection/dictionary.py').read_bytes()+canonical({'domain':dictionary.domain,'version':dictionary.version,'entries':[e.model_dump() for e in dictionary.entries]}),
            'ner': canonical({str(p.relative_to(ner_dir)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(ner_dir).rglob('*')) if p.is_file()})+canonical({'timeout':self.detector._ner_timeout,'window':self.detector._window_length,'stride':self.detector._stride,'max_workers':self.detector._executor._max_workers,'max_pending':self.detector._executor._max_pending})+marshal.dumps(self.detector._ner_worker.__code__),
            'mapping': modules('masking'),
            'protocol': modules('protocol','gateway')+canonical({'exemptions':self.exemption_registry.model_dump(mode='json') if self.exemption_registry is not None else None,'history_trust':history_trust}),
            'audit': modules('audit','infra','knowledge','request_history')+canonical({'bucket':self.evidence_bucket,'intent':str(self.evidence_gate._intent_directory),'evidence':str(self.evidence_gate._evidence_directory),'watermark':asdict(self.watermark_guard._policy),'spool':str(self.spool_writer._directory) if self.spool_writer else None}),
            'route': canonical({'binding':binding,'protocol':route.protocol,'path':route.path,'channel':route.channel_id,'domain':route.domain,'models':dict(route.model_mapping),'deadline':route.request_timeout,'admission':{name:getattr(self.admission_limiter,name) for name in ('_max_body_bytes','_max_decompressed_bytes','_max_expansion_ratio','_max_history_messages','_max_text_chars','_max_concurrency','_max_waiters','_wait_timeout')}}),
        }

    def _collect_observations(self, validated, fragment_spans, identity):
        if self.spool_writer is None:
            raise SafetyError(SafetyCode.SPOOL_WRITE_FAILED)
        permit = None
        for fragment in validated.fragments:
            if not fragment.editable:
                continue
            digest = hashlib.sha256(fragment.content.encode('utf-8')).hexdigest()
            mentions = tuple(ObservationMention(name=fragment.content[s.start:s.end],
                entity_type=s.entity_type, start=s.start, end=s.end)
                for s in fragment_spans.get(fragment.json_path, ()) if s.entity_type in {'ORG','PER','LOC'})
            event = build_gateway_observation(tenant=identity.tenant_id, domain=validated.domain,
                request_id=digest, evidence_digest=digest, source_acl=identity.source_acl,
                evidence_text=fragment.content,
                source_kind=SourceKind.MODEL_OUTPUT if fragment.source_kind == 'model-output' else SourceKind.USER_ASSERTION,
                mentions=mentions, source_context=identity if isinstance(identity, UnverifiedSourceContext) else None)
            permit = self.spool_writer.collect(event, mode=CollectionMode.REQUIRED)
        return permit

    def process_request(
        self,
        *,
        raw_body: str | bytes,
        headers: Mapping[str, str],
        identity: TrustedIdentity | UnverifiedSourceContext,
        category: str,
        context: MappingContext,
        observation_event: ObservationEvent | None = None,
        collection_mode: CollectionMode | None = None,
        auto_collect: bool = True,
        deadline_at: float | None = None,
        cancel=None,
        history_recorder=None,
    ) -> PipelineResult:
        """Execute the end-to-end protected pipeline for an incoming request.

        Fails closed before outbound egress if any gate or validation check fails.
        """
        if not isinstance(context, MappingContext):
            raise TypeError("context must be a MappingContext")
        context.require_active()

        # Capture the immutable assembly once. Detection/audit hooks cannot
        # redirect an in-flight request by replacing shared pipeline attributes.
        route = self._route
        version_handle = self.version_handle
        history_adapter = self.history_adapter
        egress_client = self.egress_client
        now = datetime.now(timezone.utc)
        deadline_at = deadline_at if deadline_at is not None else time.monotonic()+route.request_timeout
        def check_deadline():
            if time.monotonic() >= deadline_at or (cancel is not None and cancel.is_set()):
                raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
        check_deadline()

        # Gate 1: Identity validity period and required request intent/purpose (C-02, O-02)
        validate_request_authorization(identity, now=now, required_purpose="model-query")

        # Gate 1a: Untrusted Client Headers Check (C-02)
        for h in headers:
            if h.lower() in FORBIDDEN_CLIENT_IDENTITY_HEADERS:
                raise SafetyError(SafetyCode.UNTRUSTED_HEADER_REJECTED, h)

        # Gate 1b: Domain Scope Consistency Checks (C-02, O-05)
        if identity.domain != route.domain:
            raise SafetyError(SafetyCode.SCOPE_MISMATCH, "domain mismatch")

        if context.domain != route.domain:
            raise SafetyError(SafetyCode.SCOPE_MISMATCH, "context domain mismatch")

        if (
            self.detector._dictionary is not None
            and getattr(self.detector._dictionary, "domain", None) != route.domain
        ):
            raise SafetyError(SafetyCode.SCOPE_MISMATCH, "dictionary domain mismatch")

        # Gate 1c: Version Provenance & RequestVersionHandle Consistency (C-05)
        if version_handle is not None:
            version_handle.assert_consistent_hash(self._version_manager.active_package_hash)
            version_handle.manifest.require_complete()
            version_handle.manifest.verify_payloads(self._component_payloads(route=route))
            if history_adapter is not None and history_adapter.validator.version != version_handle.package_hash:
                raise SafetyError(SafetyCode.CORRUPTED_PACKAGE,'history full-version binding')
            if version_handle.manifest.version != route.package_version:
                raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "package version mismatch")

        # Collection permission is separate from model egress approval.
        # Locally held BYOK observations keep the restricted context even when
        # classification cannot permit any supplier call.
        rule = next((r for r in self.policy.rules if r.category == category), None)
        if rule is not None and rule.scope != route.domain:
            raise SafetyError(SafetyCode.SCOPE_MISMATCH)
        try:
            egress_policy = resolve_egress_policy(self.policy, category)
        except SafetyError:
            if isinstance(identity, UnverifiedSourceContext) and auto_collect:
                if collection_mode is not None and collection_mode is not CollectionMode.REQUIRED:
                    raise SafetyError(SafetyCode.CONTRACT_VIOLATION)
                local = IngressValidator.validate_request(raw_body=raw_body, protocol=route.protocol,
                    domain=route.domain, category=category, policy=self.policy,
                    exemption_registry=self.exemption_registry, allowed_models=route.allowed_models,
                    history_adapter=history_adapter, local_collection_only=True)
                local_bytes = raw_body.encode('utf-8') if isinstance(raw_body, str) else raw_body
                self.admission_limiter.admit(local_bytes, history_messages=len(local.fragments),
                    text_chars=sum(len(f.content) for f in local.fragments))
                with self.admission_limiter.acquire():
                    fragments = tuple(f for f in local.fragments if f.requires_detection)
                    detected = self.detector.detect_many(tuple(f.content for f in fragments),
                        deadline_at=deadline_at, cancel=cancel)
                    spans = dict(zip((f.json_path for f in fragments), (d.spans for d in detected), strict=True))
                    check_deadline()
                    self.watermark_guard.check_egress_permitted()
                    self._collect_observations(local, spans, identity)
                    check_deadline()
            raise
        if egress_policy.scope != route.domain:
            raise SafetyError(SafetyCode.SCOPE_MISMATCH, "policy scope mismatch")

        # Gate 2: Ingress validation (C-01, C-03, C-04, O-01)
        validated = IngressValidator.validate_request(
            raw_body=raw_body,
            protocol=route.protocol,
            domain=identity.domain,
            category=category,
            policy=self.policy,
            exemption_registry=self.exemption_registry,
            allowed_models=route.allowed_models,
            history_adapter=history_adapter,
        )

        raw_bytes = raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body
        text_chars = sum(len(f.content) for f in validated.fragments)
        msg_count = len(validated.fragments)

        # Gate 3: Admission Limiter: Dimension check + Concurrency slot (P-16)
        self.admission_limiter.admit(
            raw_bytes,
            history_messages=msg_count,
            text_chars=text_chars,
        )
        with self.admission_limiter.acquire():
            # Gate 4: Three-way Detection Orchestration (D-12)
            fragment_spans: dict[str, tuple[ResolvedSpan, ...]] = {}
            detection_fragments = tuple(f for f in validated.fragments if f.requires_detection)
            outcomes = self.detector.detect_many(tuple(f.content for f in detection_fragments), deadline_at=deadline_at,cancel=cancel)
            outcome_by_path = dict(zip((f.json_path for f in detection_fragments),outcomes,strict=True))
            for fragment in validated.fragments:
                if fragment.requires_detection:
                    outcome = outcome_by_path[fragment.json_path]
                    fragment_spans[fragment.json_path] = outcome.spans
                else:
                    fragment_spans[fragment.json_path] = ()

            # Gate 5: Request Token Replacement (P-05)
            redacted_request = replace_request(validated, fragment_spans, context)
            provider_model = route.model_mapping[validated.model]
            redacted_request = redacted_request.model_copy(update={'model':provider_model})
            check_deadline()

            # Gate 6: Audit Watermark Pre-flight Check (A-08)
            watermark_assessment = self.watermark_guard.check_egress_permitted()

            # Gate 7: Evidence Gate: Intent + Encryption (A-03, A-01)
            intent = ReleaseIntent(
                intent_id=f"intent-{uuid.uuid4().hex[:12]}",
                recorded_at=now,
                domain=identity.domain,
                category=category,
                policy_version=self.policy.version,
                package_version=route.package_version,
                purpose="model-query",
                route_id=route.channel_id,
                model=validated.model,
                caller_id=identity.source_id if isinstance(identity, UnverifiedSourceContext) else identity.subject_id,
                tenant_id=identity.tenant_id,
                protocol=route.protocol,
                request_model=validated.model,
                upstream_model=provider_model,
                package_hash=version_handle.package_hash,
                channel_version=route.package_version,
            )
            evidence_spec = EvidenceSpec(plaintext=raw_bytes,bucket=self.evidence_bucket,record_id=f'req-{uuid.uuid4().hex}',purpose='model-query')
            evidence_permit = self.evidence_gate.admit(intent, evidence_spec)

            # Gate 8: Knowledge Spooling (K-02, O-03)
            spool_permit: SpoolPermit | None = None
            mode = collection_mode or CollectionMode.REQUIRED
            if auto_collect and mode is not CollectionMode.REQUIRED:
                raise SafetyError(SafetyCode.CONTRACT_VIOLATION, 'automatic collection must be durable')
            if mode == CollectionMode.REQUIRED:
                if self.spool_writer is None:
                    raise SafetyError(SafetyCode.SPOOL_WRITE_FAILED, "spool writer required but missing")
                if observation_event is None:
                    if auto_collect:
                        spool_permit = self._collect_observations(validated, fragment_spans, identity)
                    else:
                        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "required collection missing observation event")
                if observation_event is not None:
                    spool_permit = self.spool_writer.collect(observation_event, mode=mode)
            elif mode == CollectionMode.BEST_EFFORT:
                if self.spool_writer is not None:
                    if observation_event is not None:
                        spool_permit = self.spool_writer.collect(observation_event, mode=mode)

            # Gate 9: Outbound Egress Send (P-17)
            provider_payload=redacted_request.model_dump(exclude_unset=True)
            if route.protocol == CLAUDE_MESSAGES_PROTOCOL:
                for message in provider_payload['messages']:
                    if isinstance(message['content'],list):
                        for block in message['content']:
                            if block['type']=='thinking':
                                # This admission receipt belongs only to the enterprise client.
                                del block['metadata']
            redacted_payload=json.dumps(provider_payload,ensure_ascii=False).encode('utf-8')
            if history_recorder is not None:
                history_recorder.write('redacted', redacted_payload)

            egress_headers = {
                "content-type": "application/json",
                "x-protection-package-version": route.package_version,
            }
            if headers:
                for auth_h in ("authorization", "x-api-key"):
                    for k, v in headers.items():
                        if k.lower() == auth_h and v:
                            egress_headers[auth_h] = str(v)
            check_deadline()
            send = egress_client.open_stream if redacted_request.stream else egress_client.request
            upstream_response = send(
                "POST",
                route.path,
                headers=egress_headers,
                content=redacted_payload,
                timeout=max(0.001,deadline_at-time.monotonic()),
            )
            try:
                # A non-stream response is already fully received here. Retain
                # those bytes even when the send completed after the deadline.
                if history_recorder is not None and not redacted_request.stream:
                    history_recorder.write('upstream', upstream_response.content)
                check_deadline()
            except BaseException:
                upstream_response.close()
                raise

            # Gate 10: Response Verification & Restoration (P-06)
            if upstream_response.status_code != 200:
                from gateway.error_sanitizer import ErrorSanitizer
                sanitized = ErrorSanitizer.sanitize(upstream_response.status_code,upstream_response.headers)
                try:
                    if history_recorder is not None and redacted_request.stream:
                        error_body = bytearray()
                        error_complete = False
                        try:
                            for chunk in upstream_response.iter_bytes():
                                available = history_recorder.max_stage_bytes - len(error_body)
                                if len(chunk) > available:
                                    error_body.extend(chunk[:available])
                                    from request_history.models import HistoryUnavailable
                                    raise HistoryUnavailable()
                                error_body.extend(chunk)
                                check_deadline()
                            error_complete = True
                        finally:
                            if error_body or error_complete:
                                history_recorder.write('upstream', bytes(error_body),
                                    state='complete' if error_complete else 'partial')
                finally:
                    upstream_response.close()
                raise UpstreamFailure(sanitized)

            if redacted_request.stream:
                return PipelineResult(response=None,evidence_permit=evidence_permit,watermark_assessment=watermark_assessment,spool_permit=spool_permit,redacted_request=redacted_request,upstream_stream=upstream_response,client_model=validated.model,
                    protocol=route.protocol,allowed_tools=self.tool_schemas(redacted_request,protocol=route.protocol),
                    state_validator=history_adapter.validator if history_adapter is not None else None,state_version=version_handle.package_hash)

            restored_response = restore_response(
                route.protocol,
                upstream_response.content,
                context,
                allowed_models=frozenset({provider_model}),
                allowed_tools=self.tool_schemas(redacted_request, protocol=route.protocol),
                state_validator=history_adapter.validator if history_adapter is not None else None,
            )
            restored_response = restored_response.model_copy(update={'model':validated.model})
            check_deadline()

            return PipelineResult(
                protocol=route.protocol,allowed_tools=self.tool_schemas(redacted_request,protocol=route.protocol),
                state_validator=history_adapter.validator if history_adapter is not None else None,state_version=version_handle.package_hash,
                response=restored_response,
                evidence_permit=evidence_permit,
                watermark_assessment=watermark_assessment,
                spool_permit=spool_permit,
                redacted_request=redacted_request,
            )

    def tool_schemas(self, request, *, protocol=None):
        if (protocol or self.protocol) == DEEPSEEK_CHAT_PROTOCOL:
            return {t.function.name:t.function.parameters for t in request.tools or []}
        return {t.name:t.input_schema for t in request.tools or []}


class UpstreamFailure(Exception):
    def __init__(self, response):
        self.response = response
        super().__init__('upstream request failed')
