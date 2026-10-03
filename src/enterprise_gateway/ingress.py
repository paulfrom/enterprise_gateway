"""Unified ingress validator combining policy (C-01), protocol (C-03), and static exemption (C-04).

Enforces fail-closed input admission: unapproved categories, unsupported protocols,
extra/unknown fields, non-text inputs (images/files), streaming, and tool calls
are rejected at the gate. No fields are stripped or quietly bypassed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping, Sequence

from .policy import ClassificationPolicy, PolicyError, resolve_egress_policy
from .protocols import (
    CLAUDE_MESSAGES_PROTOCOL,
    DEEPSEEK_CHAT_PROTOCOL,
    ClaudeMessage,
    ClaudeMessagesRequest,
    ClaudeTextBlock,
    ContractError,
    DeepSeekChatRequest,
    parse_claude_messages,
    parse_deepseek_chat_completion,
)
from .static_exemption import (
    ExemptionDecision,
    ExemptionStatus,
    StaticExemptionRegistry,
    inspect_static_exemption,
)


class IngressErrorCode(StrEnum):
    POLICY_REJECTED = "policy_rejected"
    PROTOCOL_VIOLATION = "protocol_violation"
    UNSUPPORTED_PROTOCOL = "unsupported_protocol"
    INVALID_PAYLOAD = "invalid_payload"


class IngressValidationError(ValueError):
    """Controlled ingress gate failure; never echoes submitted business text."""

    def __init__(self, code: IngressErrorCode, detail: str | None = None) -> None:
        self.code = code
        msg = f"ingress validation failed: {code.value}"
        if detail:
            msg = f"{msg} ({detail})"
        super().__init__(msg)


@dataclass(frozen=True, slots=True)
class BusinessTextFragment:
    """A single logical business text unit targeted for detection or exemption."""

    json_path: str
    content: str
    requires_detection: bool
    matched_template_id: str | None


@dataclass(frozen=True, slots=True)
class ValidatedIngressRequest:
    """A strictly validated request candidate ready for downstream detection & spooling."""

    protocol: str
    model: str
    category: str
    domain: str
    parsed_request: DeepSeekChatRequest | ClaudeMessagesRequest
    fragments: tuple[BusinessTextFragment, ...]


class IngressValidator:
    """Combines policy, protocol, and exemption into a single immutable gateway barrier."""

    @staticmethod
    def validate_request(
        raw_body: str | bytes,
        protocol: str,
        domain: str,
        category: str,
        policy: ClassificationPolicy,
        exemption_registry: StaticExemptionRegistry | None = None,
    ) -> ValidatedIngressRequest:
        # 1. Enforce egress classification policy (C-01)
        try:
            resolve_egress_policy(policy, category)
        except PolicyError as exc:
            raise IngressValidationError(IngressErrorCode.POLICY_REJECTED, str(exc)) from None

        # 2. Strict candidate protocol parse (C-03)
        if protocol == DEEPSEEK_CHAT_PROTOCOL:
            try:
                parsed = parse_deepseek_chat_completion(raw_body)
            except ContractError as exc:
                raise IngressValidationError(IngressErrorCode.PROTOCOL_VIOLATION, exc.reason.value) from None
            model_name = parsed.model
            raw_fragments = [(f"messages[{i}].content", msg.content) for i, msg in enumerate(parsed.messages)]

        elif protocol == CLAUDE_MESSAGES_PROTOCOL:
            try:
                parsed = parse_claude_messages(raw_body)
            except ContractError as exc:
                raise IngressValidationError(IngressErrorCode.PROTOCOL_VIOLATION, exc.reason.value) from None
            model_name = parsed.model
            raw_fragments = []
            if parsed.system is not None:
                raw_fragments.append(("system", parsed.system))
            for i, msg in enumerate(parsed.messages):
                if isinstance(msg.content, str):
                    raw_fragments.append((f"messages[{i}].content", msg.content))
                else:
                    for j, block in enumerate(msg.content):
                        if isinstance(block, ClaudeTextBlock):
                            raw_fragments.append((f"messages[{i}].content[{j}].text", block.text))
        else:
            raise IngressValidationError(
                IngressErrorCode.UNSUPPORTED_PROTOCOL, f"protocol '{protocol}' is not supported"
            )

        # 3. Precise static content exemption evaluation (C-04)
        processed_fragments: list[BusinessTextFragment] = []
        for path, text in raw_fragments:
            if exemption_registry is not None:
                decision = inspect_static_exemption(text, domain, exemption_registry)
                if decision.status is ExemptionStatus.EXEMPT:
                    processed_fragments.append(
                        BusinessTextFragment(
                            json_path=path,
                            content=text,
                            requires_detection=False,
                            matched_template_id=decision.matched_template_id,
                        )
                    )
                    continue

            # Default: requires full detection pipeline
            processed_fragments.append(
                BusinessTextFragment(
                    json_path=path,
                    content=text,
                    requires_detection=True,
                    matched_template_id=None,
                )
            )

        return ValidatedIngressRequest(
            protocol=protocol,
            model=model_name,
            category=category,
            domain=domain,
            parsed_request=parsed,
            fragments=tuple(processed_fragments),
        )
