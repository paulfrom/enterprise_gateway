"""Unified ingress validator combining policy (C-01), protocol (C-03), and static exemption (C-04).

Enforces fail-closed input admission: unapproved categories, unsupported protocols,
extra/unknown fields, non-text inputs (images/files), streaming, and tool calls
are rejected at the gate. No fields are stripped or quietly bypassed.
"""

from __future__ import annotations

from dataclasses import dataclass

from infra.errors import SafetyCode, SafetyError
from policy.policy import ClassificationPolicy, resolve_egress_policy
from protocol.protocols import (
    CLAUDE_MESSAGES_PROTOCOL,
    DEEPSEEK_CHAT_PROTOCOL,
    ClaudeMessagesRequest,
    ClaudeTextBlock,
    DeepSeekChatRequest,
    parse_claude_messages,
    parse_deepseek_chat_completion,
)
from protocol.static_exemption import (
    ExemptionDecision,
    ExemptionStatus,
    StaticExemptionRegistry,
    inspect_static_exemption,
)


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
        except SafetyError as exc:
            raise SafetyError(SafetyCode.POLICY_REJECTED, exc.code.value) from None

        # 2. Strict candidate protocol parse (C-03)
        if protocol == DEEPSEEK_CHAT_PROTOCOL:
            try:
                parsed = parse_deepseek_chat_completion(raw_body)
            except SafetyError as exc:
                raise SafetyError(SafetyCode.PROTOCOL_VIOLATION, exc.code.value) from None
            model_name = parsed.model
            raw_fragments = [(f"messages[{i}].content", msg.content) for i, msg in enumerate(parsed.messages)]

        elif protocol == CLAUDE_MESSAGES_PROTOCOL:
            try:
                parsed = parse_claude_messages(raw_body)
            except SafetyError as exc:
                raise SafetyError(SafetyCode.PROTOCOL_VIOLATION, exc.code.value) from None
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
            raise SafetyError(
                SafetyCode.UNSUPPORTED_PROTOCOL, f"protocol '{protocol}' is not supported"
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
