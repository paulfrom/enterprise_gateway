"""Exact static-content exemption contract.

Pre-approved, public, deterministic static content (e.g. standard system prompts
or corporate disclaimers) can be evaluated for exemption from the sensitive
detection pipeline ONLY when both the content and its boundaries match the
registered specification exactly (100% character-by-character equality).

Any alteration (single-character edit, whitespace change, casing difference,
dynamic variable interpolation, or unseparable concatenation with user input)
fails exemption and forces full detection. Client self-claims do not grant
exemption.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Callable, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ExemptionErrorCode(StrEnum):
    INVALID_REGISTRY = "invalid_registry"
    INVALID_TEMPLATE = "invalid_template"
    REGISTRY_PARSE_FAILED = "registry_parse_failed"


class ExemptionError(ValueError):
    """Controlled static exemption contract failure."""

    def __init__(self, code: ExemptionErrorCode, detail: str | None = None) -> None:
        self.code = code
        msg = f"static exemption violation: {code.value}"
        if detail:
            msg = f"{msg} ({detail})"
        super().__init__(msg)


class ExemptionStatus(StrEnum):
    EXEMPT = "exempt"
    NOT_EXEMPT = "not_exempt"


@dataclass(frozen=True, slots=True)
class ExemptionDecision:
    status: ExemptionStatus
    matched_template_id: str | None
    reason: str


class StaticTemplate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    template_id: str
    domain: str
    version: str
    text: str
    sha256: str

    @field_validator("template_id", "domain", "version", "text", "sha256")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("fields must not be blank")
        return value

    @model_validator(mode="after")
    def _verify_digest(self) -> StaticTemplate:
        computed = hashlib.sha256(self.text.encode("utf-8")).hexdigest()
        if self.sha256.lower() != computed:
            raise ValueError("sha256 digest does not match text content")
        return self


class StaticExemptionRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: str
    templates: Sequence[StaticTemplate]

    @model_validator(mode="after")
    def _unique_template_ids(self) -> StaticExemptionRegistry:
        keys = [(t.domain, t.template_id) for t in self.templates]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate (domain, template_id) in registry")
        return self

    def find_template(self, domain: str, template_id: str) -> StaticTemplate | None:
        for t in self.templates:
            if t.domain == domain and t.template_id == template_id:
                return t
        return None

    def find_by_exact_text(self, domain: str, text: str) -> StaticTemplate | None:
        for t in self.templates:
            if t.domain == domain and t.text == text:
                return t
        return None


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ExemptionError(ExemptionErrorCode.INVALID_REGISTRY, "duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_val: str) -> None:
    raise ExemptionError(ExemptionErrorCode.REGISTRY_PARSE_FAILED, "non-standard JSON constant")


def load_exemption_registry(source: str | bytes | Mapping[str, Any]) -> StaticExemptionRegistry:
    """Strictly parse trusted static exemption registry document."""
    if isinstance(source, Mapping):
        payload: Any = source
    elif isinstance(source, (str, bytes)):
        try:
            payload = json.loads(source, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant)
        except ExemptionError:
            raise
        except Exception as exc:
            raise ExemptionError(ExemptionErrorCode.REGISTRY_PARSE_FAILED, str(exc)) from None
    else:
        raise ExemptionError(ExemptionErrorCode.INVALID_REGISTRY, "source must be text, bytes, or mapping")

    if not isinstance(payload, dict):
        raise ExemptionError(ExemptionErrorCode.INVALID_REGISTRY, "registry must be a JSON object")

    try:
        return StaticExemptionRegistry.model_validate(payload)
    except Exception as exc:
        raise ExemptionError(ExemptionErrorCode.INVALID_TEMPLATE, str(exc)) from None


def inspect_static_exemption(
    text: str,
    domain: str,
    registry: StaticExemptionRegistry,
    declared_template_id: str | None = None,
) -> ExemptionDecision:
    """Inspect whether a candidate text qualifies for exact static exemption.

    Both content and boundary must match completely. Any mutation or variable
    injection yields NOT_EXEMPT.
    """
    if not isinstance(text, str):
        return ExemptionDecision(ExemptionStatus.NOT_EXEMPT, None, "text_must_be_string")
    if not isinstance(domain, str) or not domain.strip():
        return ExemptionDecision(ExemptionStatus.NOT_EXEMPT, None, "invalid_domain")
    if not isinstance(registry, StaticExemptionRegistry):
        return ExemptionDecision(ExemptionStatus.NOT_EXEMPT, None, "invalid_registry")

    if declared_template_id is not None:
        template = registry.find_template(domain, declared_template_id)
        if template is None:
            return ExemptionDecision(
                ExemptionStatus.NOT_EXEMPT, None, "declared_template_not_found_in_domain"
            )
        # Exact character and boundary equality check
        if text == template.text:
            return ExemptionDecision(
                ExemptionStatus.EXEMPT, template.template_id, "exact_match"
            )
        return ExemptionDecision(
            ExemptionStatus.NOT_EXEMPT, None, "text_mismatch_exact_boundary_required"
        )

    # If no template_id declared, check if text matches any registered template in the domain
    matched = registry.find_by_exact_text(domain, text)
    if matched is not None:
        return ExemptionDecision(ExemptionStatus.EXEMPT, matched.template_id, "exact_match")

    return ExemptionDecision(ExemptionStatus.NOT_EXEMPT, None, "no_matching_registered_template")


def evaluate_and_detect(
    text: str,
    domain: str,
    registry: StaticExemptionRegistry,
    detector_callable: Callable[[str], Any],
    declared_template_id: str | None = None,
) -> tuple[ExemptionDecision, Any | None]:
    """Execute exemption check and invoke detector only when not exempt."""
    decision = inspect_static_exemption(
        text, domain, registry, declared_template_id=declared_template_id
    )
    if decision.status is ExemptionStatus.EXEMPT:
        # Detector is deliberately BYPASSED because exact pre-approved static content matched
        return decision, None

    # Not exempt: detector must be called
    detection_result = detector_callable(text)
    return decision, detection_result
