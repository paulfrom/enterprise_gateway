"""C-07 and P-12 reasoning state admission, verification, and preservation contract.

Enforces:
- Cryptographic verification of historical signed thinking / reasoning blocks.
- Unproven or tampered reasoning blocks fail closed with CONTRACT_VIOLATION.
- Verbatim payload preservation for verified reasoning states across multi-turn exchanges.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
from typing import Any, Mapping

from infra.errors import SafetyCode, SafetyError


@dataclass(frozen=True, slots=True)
class ReasoningBlock:
    """An immutable reasoning/thinking content block with verifiable provenance."""

    block_type: str  # "thinking" | "thought"
    content: str
    signature: str
    metadata: Mapping[str, str]

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()


class ReasoningStateValidator:
    """Verifies provenance and cryptographic signatures of reasoning blocks (C-07, P-12)."""

    def __init__(self, verification_key: bytes) -> None:
        if not verification_key or len(verification_key) < 16:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "invalid verification key for reasoning state")
        self._verification_key = verification_key

    def sign_reasoning_block(
        self,
        block_type: str,
        content: str,
        metadata: Mapping[str, str] | None = None,
    ) -> ReasoningBlock:
        """Create a cryptographically signed reasoning block."""
        meta = dict(metadata or {})
        msg = json.dumps(
            {"type": block_type, "content": content, "meta": meta},
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        sig = hmac.new(self._verification_key, msg, hashlib.sha256).hexdigest()
        return ReasoningBlock(
            block_type=block_type,
            content=content,
            signature=sig,
            metadata=meta,
        )

    def verify_reasoning_block(self, block: ReasoningBlock) -> None:
        """Verify the cryptographic signature of a reasoning block.

        Fails closed with SafetyError(CONTRACT_VIOLATION) if signature is missing,
        invalid, or content has been tampered with.
        """
        if not block.signature or not block.content:
            raise SafetyError(
                SafetyCode.CONTRACT_VIOLATION,
                "reasoning block missing required signature or content",
            )

        msg = json.dumps(
            {"type": block.block_type, "content": block.content, "meta": dict(block.metadata)},
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        expected_sig = hmac.new(self._verification_key, msg, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(block.signature, expected_sig):
            raise SafetyError(
                SafetyCode.CONTRACT_VIOLATION,
                "unverified reasoning state: invalid cryptographic signature",
            )


class HistoricalStateAdapter:
    """Inspects and validates reasoning blocks in conversation history (C-07, P-12)."""

    def __init__(self, validator: ReasoningStateValidator) -> None:
        self.validator = validator

    def validate_message_history(self, messages: list[dict[str, Any]]) -> None:
        """Scan historical messages for thinking/reasoning blocks and enforce signature validity."""
        for msg in messages:
            content = msg.get("content")
            # If content is a list of blocks (Claude messages format)
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") in ("thinking", "thought"):
                        raw_sig = block.get("signature")
                        raw_text = block.get("thinking") or block.get("text") or ""
                        raw_meta = block.get("metadata") or {}
                        if not raw_sig:
                            raise SafetyError(
                                SafetyCode.CONTRACT_VIOLATION,
                                "unproven reasoning block in conversation history",
                            )
                        reasoning_block = ReasoningBlock(
                            block_type=block["type"],
                            content=raw_text,
                            signature=raw_sig,
                            metadata=raw_meta,
                        )
                        self.validator.verify_reasoning_block(reasoning_block)
