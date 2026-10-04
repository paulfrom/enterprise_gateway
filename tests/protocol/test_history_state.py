"""Tests for C-07 and P-12 reasoning state admission, verification, and preservation."""

from __future__ import annotations

import unittest

from infra.errors import SafetyCode, SafetyError
from protocol.history_state import (
    HistoricalStateAdapter,
    ReasoningBlock,
    ReasoningStateValidator,
)

TEST_VERIFICATION_KEY = b"secure-test-reasoning-key-32bytes!!"


class TestHistoryState(unittest.TestCase):
    def setUp(self) -> None:
        self.validator = ReasoningStateValidator(TEST_VERIFICATION_KEY)
        self.adapter = HistoricalStateAdapter(self.validator)

    def test_signed_reasoning_block_passes_and_preserves_content(self) -> None:
        """P-12: Approved immutable payload with valid signature passes verification."""
        content = "Step 1: Compute tax.\nStep 2: Apply discount."
        signed_block = self.validator.sign_reasoning_block(
            block_type="thinking",
            content=content,
            metadata={"model": "claude-sonnet-5-5"},
        )
        self.validator.verify_reasoning_block(signed_block)
        self.assertEqual(content, signed_block.content)
        self.assertTrue(len(signed_block.signature) > 0)

    def test_missing_signature_fails_closed(self) -> None:
        """P-12: Unproven thinking block without signature is rejected."""
        unproven_block = ReasoningBlock(
            block_type="thinking",
            content="Unverified reasoning text",
            signature="",
            metadata={},
        )
        with self.assertRaises(SafetyError) as exc_info:
            self.validator.verify_reasoning_block(unproven_block)
        self.assertEqual(SafetyCode.CONTRACT_VIOLATION, exc_info.exception.code)

    def test_tampered_content_fails_closed(self) -> None:
        """P-12: Tampering with content invalidates signature and fails closed."""
        signed = self.validator.sign_reasoning_block("thinking", "original thought")
        tampered = ReasoningBlock(
            block_type=signed.block_type,
            content="tampered thought text",
            signature=signed.signature,
            metadata=signed.metadata,
        )
        with self.assertRaises(SafetyError) as exc_info:
            self.validator.verify_reasoning_block(tampered)
        self.assertEqual(SafetyCode.CONTRACT_VIOLATION, exc_info.exception.code)

    def test_mock_or_invalid_signature_fails_closed(self) -> None:
        """P-12: Mock signature does not prove authenticity."""
        mock_block = ReasoningBlock(
            block_type="thinking",
            content="Real thought",
            signature="mock-fake-signature-123",
            metadata={},
        )
        with self.assertRaises(SafetyError) as exc_info:
            self.validator.verify_reasoning_block(mock_block)
        self.assertEqual(SafetyCode.CONTRACT_VIOLATION, exc_info.exception.code)

    def test_historical_conversation_adapter_validation(self) -> None:
        """C-07: Historical messages containing invalid thinking blocks are rejected."""
        signed = self.validator.sign_reasoning_block("thinking", "legitimate analysis")
        valid_messages = [
            {"role": "user", "content": "What is the result?"},
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "thinking",
                        "thinking": signed.content,
                        "signature": signed.signature,
                        "metadata": dict(signed.metadata),
                    },
                    {"type": "text", "text": "The result is 42."},
                ],
            },
        ]
        # Valid messages pass
        self.adapter.validate_message_history(valid_messages)

        # Invalid historical thinking block fails closed
        invalid_messages = [
            {"role": "user", "content": "What is the result?"},
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "thinking",
                        "thinking": "unauthorized thinking without signature",
                    }
                ],
            },
        ]
        with self.assertRaises(SafetyError) as exc_info:
            self.adapter.validate_message_history(invalid_messages)
        self.assertEqual(SafetyCode.CONTRACT_VIOLATION, exc_info.exception.code)


if __name__ == "__main__":
    unittest.main()
