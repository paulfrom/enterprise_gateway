"""Strict egress-policy contract; trusted sources only, no detection or I/O.

Policy documents must come from trusted configuration or context objects handed
over by caller code (for example a configuration loader or, once C-02 exists,
an identity adapter). Client request bodies, request headers, and self-declared
"classified as approved" claims are never a policy source, and this module
offers no API that reads them.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Mapping, NoReturn

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from policy.egress import DataClassification, DetectorStatus, EgressPolicy, authorize_egress
from infra.errors import SafetyCode, SafetyError
from infra.strict_json import JsonRejectKind, parse_strict_json


class CategoryLabel(StrEnum):
    """Synthetic enterprise classification labels carried by policy documents."""

    SECRET = "secret"
    LOCAL_ONLY = "local_only"
    APPROVED_EXTERNAL = "approved_external"


CLASSIFICATION_BY_LABEL: Mapping[CategoryLabel, DataClassification] = {
    CategoryLabel.SECRET: DataClassification.LOCAL_ONLY,
    CategoryLabel.LOCAL_ONLY: DataClassification.LOCAL_ONLY,
    CategoryLabel.APPROVED_EXTERNAL: DataClassification.APPROVED_EXTERNAL,
}


class CategoryRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    category: str
    label: Annotated[CategoryLabel, Field(strict=False)]
    scope: str

    @field_validator("category", "scope")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("field must be a non-empty string")
        return value


class ClassificationPolicy(BaseModel):
    """Typed policy: a synthetic classification matrix bound to protection domains."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: str
    rules: Annotated[tuple[CategoryRule, ...], Field(strict=False)]

    @model_validator(mode="after")
    def _categories_are_unique(self) -> ClassificationPolicy:
        categories = [rule.category for rule in self.rules]
        if len(set(categories)) != len(categories):
            raise ValueError("duplicate category in classification matrix")
        return self


def _reject_json(kind: JsonRejectKind) -> NoReturn:
    if kind is JsonRejectKind.DUPLICATE_KEY:
        raise SafetyError(SafetyCode.DUPLICATE_POLICY_KEY)
    if kind is JsonRejectKind.NESTING_TOO_DEEP:
        raise SafetyError(SafetyCode.POLICY_NESTING_TOO_DEEP)
    raise SafetyError(SafetyCode.POLICY_NOT_JSON)


def load_policy(source: str | bytes | Mapping[str, Any]) -> ClassificationPolicy:
    """Parse a trusted policy document; anything outside the strict schema is rejected.

    Parser and validator exceptions carry submitted input values, so rejections
    are raised as fresh SafetyError objects after handling ends: no __context__
    or __cause__ chain, and traceback.format_exc() never replays business text.
    """
    if isinstance(source, Mapping):
        payload: Any = source
    elif isinstance(source, (str, bytes)):
        payload = parse_strict_json(source, reject=_reject_json)
    else:
        raise TypeError(
            "policy source must be trusted JSON text or a mapping built by trusted code"
        )
    if not isinstance(payload, dict):
        raise SafetyError(SafetyCode.POLICY_NOT_OBJECT)
    validation_failed = False
    try:
        policy = ClassificationPolicy.model_validate(payload)
    except ValidationError:
        validation_failed = True
    if validation_failed:
        raise SafetyError(SafetyCode.POLICY_VALIDATION_FAILED)
    return policy


def resolve_egress_policy(policy: ClassificationPolicy, category: str) -> EgressPolicy:
    """Bind a trusted content category to the egress contract, or reject it.

    Only categories whose label maps to APPROVED_EXTERNAL yield an EgressPolicy;
    secret/local_only labels, unknown categories, and missing categories are
    rejected here and never reach the detection-eligibility check.
    """
    if not isinstance(policy, ClassificationPolicy):
        raise TypeError("policy must be a parsed ClassificationPolicy")
    if not isinstance(category, str) or not category.strip():
        raise SafetyError(SafetyCode.MISSING_CATEGORY, "category must be a non-empty string")
    rule = next((rule for rule in policy.rules if rule.category == category), None)
    if rule is None:
        raise SafetyError(SafetyCode.UNKNOWN_CATEGORY, "category is not in the classification matrix")
    if CLASSIFICATION_BY_LABEL[rule.label] is not DataClassification.APPROVED_EXTERNAL:
        raise SafetyError(SafetyCode.CATEGORY_NOT_APPROVED, "category label does not permit external egress")
    return EgressPolicy(scope=rule.scope, classification=CLASSIFICATION_BY_LABEL[rule.label])


def authorize_with_policy(
    policy: ClassificationPolicy,
    category: str,
    detector_results: Mapping[str, DetectorStatus],
) -> None:
    """Resolve a trusted category through a trusted policy, then apply the egress contract."""
    authorize_egress(resolve_egress_policy(policy, category), detector_results)
