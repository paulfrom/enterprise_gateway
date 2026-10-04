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
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from protocol.admission import AdmissionLimiter
from audit.audit_intent import ReleaseIntent
from audit.audit_watermark import AuditWatermarkGuard, WatermarkAssessment
from detection.detection_orchestrator import DetectionOrchestrator
from infra.egress_client import BoundEgressClient
from infra.errors import SafetyCode, SafetyError
from audit.evidence_gate import EvidenceGate, EvidencePermit, EvidenceSpec
from protocol.identity import (
    FORBIDDEN_CLIENT_IDENTITY_HEADERS,
    TrustedIdentity,
    validate_request_authorization,
)
from gateway.ingress import IngressValidator, ValidatedIngressRequest
from infra.manifest import RequestVersionHandle
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
        spool_writer: SpoolWriter | None = None,
        exemption_registry: StaticExemptionRegistry | None = None,
        package_version: str = "0.1.0",
        allowed_models: frozenset[str] | None = None,
        version_handle: RequestVersionHandle | None = None,
    ) -> None:
        if protocol not in (DEEPSEEK_CHAT_PROTOCOL, CLAUDE_MESSAGES_PROTOCOL):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "unsupported protocol")

        self.channel_id = channel_id
        self.protocol = protocol
        self.domain = domain
        self.path = path
        self.policy = policy
        self.admission_limiter = admission_limiter
        self.detector = detector
        self.watermark_guard = watermark_guard
        self.evidence_gate = evidence_gate
        self.egress_client = egress_client
        self.spool_writer = spool_writer
        self.exemption_registry = exemption_registry
        self.package_version = package_version
        self.allowed_models = allowed_models
        self.version_handle = version_handle

    def process_request(
        self,
        *,
        raw_body: str | bytes,
        headers: Mapping[str, str],
        identity: TrustedIdentity,
        category: str,
        context: MappingContext,
        evidence_spec: EvidenceSpec | None = None,
        observation_event: ObservationEvent | None = None,
        collection_mode: CollectionMode | None = None,
        auto_collect: bool = True,
    ) -> PipelineResult:
        """Execute the end-to-end protected pipeline for an incoming request.

        Fails closed before outbound egress if any gate or validation check fails.
        """
        if not isinstance(context, MappingContext):
            raise TypeError("context must be a MappingContext")
        context.require_active()

        now = datetime.now(timezone.utc)

        # Gate 1: Identity validity period and required request intent/purpose (C-02, O-02)
        validate_request_authorization(identity, now=now, required_purpose="model-query")

        # Gate 1a: Untrusted Client Headers Check (C-02)
        for h in headers:
            if h.lower() in FORBIDDEN_CLIENT_IDENTITY_HEADERS:
                raise SafetyError(SafetyCode.UNTRUSTED_HEADER_REJECTED, h)

        # Gate 1b: Domain Scope Consistency Checks (C-02, O-05)
        if identity.domain != self.domain:
            raise SafetyError(SafetyCode.SCOPE_MISMATCH, "domain mismatch")

        if context.domain != self.domain:
            raise SafetyError(SafetyCode.SCOPE_MISMATCH, "context domain mismatch")

        egress_policy = resolve_egress_policy(self.policy, category)
        if egress_policy.scope != self.domain:
            raise SafetyError(SafetyCode.SCOPE_MISMATCH, "policy scope mismatch")

        if (
            self.detector._dictionary is not None
            and getattr(self.detector._dictionary, "domain", None) != self.domain
        ):
            raise SafetyError(SafetyCode.SCOPE_MISMATCH, "dictionary domain mismatch")

        # Gate 1c: Version Provenance & RequestVersionHandle Consistency (C-05)
        if self.version_handle is not None:
            self.version_handle.assert_consistent_hash()
            if self.version_handle.manifest.version != self.package_version:
                raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "package version mismatch")

        # Gate 2: Ingress validation (C-01, C-03, C-04, O-01)
        validated = IngressValidator.validate_request(
            raw_body=raw_body,
            protocol=self.protocol,
            domain=identity.domain,
            category=category,
            policy=self.policy,
            exemption_registry=self.exemption_registry,
            allowed_models=self.allowed_models,
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
            for fragment in validated.fragments:
                if fragment.requires_detection:
                    outcome = self.detector.detect(fragment.content)
                    fragment_spans[fragment.json_path] = outcome.spans
                else:
                    fragment_spans[fragment.json_path] = ()

            # Gate 5: Request Token Replacement (P-05)
            redacted_request = replace_request(validated, fragment_spans, context)

            # Gate 6: Audit Watermark Pre-flight Check (A-08)
            watermark_assessment = self.watermark_guard.check_egress_permitted()

            # Gate 7: Evidence Gate: Intent + Encryption (A-03, A-01)
            intent = ReleaseIntent(
                intent_id=f"intent-{uuid.uuid4().hex[:12]}",
                recorded_at=now,
                domain=identity.domain,
                category=category,
                policy_version=self.policy.version,
                package_version=self.package_version,
                purpose="model-query",
                route_id=self.channel_id,
                model=validated.model,
            )
            evidence_permit = self.evidence_gate.admit(intent, evidence_spec)

            # Gate 8: Knowledge Spooling (K-02, O-03)
            spool_permit: SpoolPermit | None = None
            mode = collection_mode or (
                CollectionMode.REQUIRED if self.spool_writer is not None else CollectionMode.OFF
            )
            if mode == CollectionMode.REQUIRED:
                if self.spool_writer is None:
                    raise SafetyError(SafetyCode.SPOOL_WRITE_FAILED, "spool writer required but missing")
                if observation_event is None:
                    if auto_collect:
                        digest = (
                            hashlib.sha256(evidence_spec.plaintext).hexdigest()
                            if evidence_spec is not None
                            else hashlib.sha256(raw_bytes).hexdigest()
                        )
                        observation_event = build_gateway_observation(
                            tenant=identity.tenant_id,
                            domain=self.domain,
                            request_id=f"req-{uuid.uuid4().hex[:12]}",
                            evidence_digest=digest,
                            source_acl=identity.source_acl,
                        )
                    else:
                        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "required collection missing observation event")
                spool_permit = self.spool_writer.collect(observation_event, mode=mode)
            elif mode == CollectionMode.BEST_EFFORT:
                if self.spool_writer is not None:
                    if observation_event is None and auto_collect:
                        digest = (
                            hashlib.sha256(evidence_spec.plaintext).hexdigest()
                            if evidence_spec is not None
                            else hashlib.sha256(raw_bytes).hexdigest()
                        )
                        observation_event = build_gateway_observation(
                            tenant=identity.tenant_id,
                            domain=self.domain,
                            request_id=f"req-{uuid.uuid4().hex[:12]}",
                            evidence_digest=digest,
                            source_acl=identity.source_acl,
                        )
                    if observation_event is not None:
                        spool_permit = self.spool_writer.collect(observation_event, mode=mode)

            # Gate 9: Outbound Egress Send (P-17)
            redacted_payload = json.dumps(
                redacted_request.model_dump(), ensure_ascii=False
            ).encode("utf-8")

            egress_headers = {
                "content-type": "application/json",
                "x-protection-package-version": self.package_version,
            }
            upstream_response = self.egress_client.request(
                "POST",
                self.path,
                headers=egress_headers,
                content=redacted_payload,
            )

            # Gate 10: Response Verification & Restoration (P-06)
            if upstream_response.status_code != 200:
                raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "upstream non-200")

            restored_response = restore_response(
                self.protocol,
                upstream_response.content,
                context,
                allowed_models=self.allowed_models,
            )

            return PipelineResult(
                response=restored_response,
                evidence_permit=evidence_permit,
                watermark_assessment=watermark_assessment,
                spool_permit=spool_permit,
                redacted_request=redacted_request,
            )
