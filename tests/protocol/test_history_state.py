"""Tests for C-07 and P-12 reasoning state admission, verification, and preservation."""

from __future__ import annotations

import unittest
import hashlib
import hmac

from infra.errors import SafetyCode, SafetyError
from protocol.history_state import (
    HistoricalStateAdapter,
    ReasoningBlock,
    ReasoningStateValidator,
    ProviderStateVerifier,
)
from tests.protocol.provider_fixtures import verify_hmac_sha256

TEST_VERIFICATION_KEY = b"secure-test-reasoning-key-32bytes!!"

# A module symbol with the same spelling as an attribute is not a global read.
signature = b'unrelated-global-name-collision'
HIDDEN_PROVIDER_KEY=b'hidden-nested-provider-configuration'

def signature_collision_algorithm(block,material):
    return hmac.compare_digest(block.signature,hmac.digest(material,block.content.encode(),'sha256').hex())

def nested_hidden_configuration_algorithm(block,material):
    return all(hmac.compare_digest(block.signature,hmac.digest(HIDDEN_PROVIDER_KEY,block.content.encode(),'sha256').hex()) for _ in (0,))


class TestHistoryState(unittest.TestCase):
    def test_nested_code_cannot_read_hidden_global_trust_material(self):
        with self.assertRaises(SafetyError):
            ProviderStateVerifier(nested_hidden_configuration_algorithm,b'explicit-material')

    def test_pure_verifier_attribute_name_collision_is_allowed(self):
        verifier=ProviderStateVerifier(signature_collision_algorithm,b'explicit-test-key')
        content='public synthetic reasoning'
        proof=hmac.digest(b'explicit-test-key',content.encode(),'sha256').hex()
        self.assertTrue(verifier.verify(ReasoningBlock('thinking',content,proof,{})))
        self.assertIsInstance(verifier.binding_payload,dict)

    def test_verifier_has_explicit_immutable_material_and_rejects_hidden_configuration(self):
        from dataclasses import FrozenInstanceError
        first=ProviderStateVerifier(verify_hmac_sha256,b'first-explicit-key')
        second=ProviderStateVerifier(verify_hmac_sha256,b'second-explicit-key')
        self.assertNotEqual(first.binding_payload,second.binding_payload)
        with self.assertRaises(FrozenInstanceError):
            first.verification_material=b'replacement-key'
        key=b'hidden-key'
        with self.assertRaises(SafetyError):
            ProviderStateVerifier(lambda block,material: hmac.digest(key,block.content.encode(),'sha256').hex()==block.signature,key)
        with self.assertRaises(SafetyError):
            ProviderStateVerifier(lambda block,material=key: True,key)
        with self.assertRaises(SafetyError):
            ReasoningStateValidator(TEST_VERIFICATION_KEY,scope='corp.test',version='v1',provider_verifier=lambda block:True)
        with self.assertRaises(SafetyError):
            ProviderStateVerifier(lambda block,material: block.signature==TEST_VERIFICATION_KEY.decode(),key)

    def setUp(self) -> None:
        self.provider_key = b"provider-fixture-key-32-bytes!!!!"
        self.verifier = ProviderStateVerifier(verify_hmac_sha256, self.provider_key)
        self.validator = ReasoningStateValidator(TEST_VERIFICATION_KEY, scope="corp.test", version="v1", provider_verifier=self.verifier)
        self.adapter = HistoricalStateAdapter(self.validator)

    def admitted(self, content):
        signature = hmac.digest(self.provider_key, content.encode(), "sha256").hex()
        return self.validator.admit_upstream_block(ReasoningBlock("thinking", content, signature, {}))

    def test_signed_reasoning_block_passes_and_preserves_content(self) -> None:
        """P-12: Approved immutable payload with valid signature passes verification."""
        content = "Step 1: Compute tax.\nStep 2: Apply discount."
        signed_block = self.admitted(content)
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
        signed = self.admitted("original thought")
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
        signed = self.admitted("legitimate analysis")
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

    def test_wrong_domain_version_and_gateway_only_signature_rejected(self):
        block = self.admitted("verified state")
        for scope, version in (("another", "v1"), ("corp.test", "v2")):
            validator = ReasoningStateValidator(TEST_VERIFICATION_KEY, scope=scope, version=version, provider_verifier=self.verifier)
            with self.assertRaises(SafetyError):
                validator.verify_reasoning_block(block)
        with self.assertRaises(SafetyError):
            self.validator.admit_upstream_block(ReasoningBlock("thinking", "arbitrary self-signed state", hmac.digest(TEST_VERIFICATION_KEY, b"arbitrary self-signed state", "sha256").hex(), {}))


if __name__ == "__main__":
    unittest.main()
