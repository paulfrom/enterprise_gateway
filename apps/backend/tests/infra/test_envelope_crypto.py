"""Executable envelope-encryption contract tests; synthetic keys and spies only, no KMS/network."""

import traceback
import unittest
from pathlib import Path

from infra.envelope_crypto import (
    FORMAT_VERSION,
    DEK_SIZE_BYTES,
    NONCE_SIZE_BYTES,
    EnvelopeRecord,
    InvalidWrappedKeyError,
    KmsProvider,
    KmsUnavailableError,
    StaticTestKmsProvider,
    build_aad,
    decrypt_payload,
    decrypt_record,
    encrypt_payload,
    encrypt_record,
    parse_record,
    serialize_record,
)
from infra.errors import SafetyCode, SafetyError

FIXTURES = Path(__file__).parent / "fixtures" / "crypto"
CANARY = "CNRY-A02-note-7f3d9c"

DOMAIN = "scope-hr"
PURPOSE = "evidence-retention"
BUCKET = "bucket-180d"
RECORD_ID = "rec-00042"

FIELD_NAMES = (
    "format_version",
    "purpose",
    "domain",
    "bucket",
    "record_id",
    "nonce",
    "wrapped_dek",
    "ciphertext",
)


def fixture_plaintext():
    return (FIXTURES / "plaintext.txt").read_bytes()


def encrypt_canary(kms=None):
    kms = kms or StaticTestKmsProvider()
    record = encrypt_record(
        kms,
        fixture_plaintext(),
        domain=DOMAIN,
        bucket=BUCKET,
        record_id=RECORD_ID,
        purpose=PURPOSE,
    )
    return kms, record


def record_with(record, **overrides):
    payload = record.model_dump()
    payload.update(overrides)
    return EnvelopeRecord.model_validate(payload)


def assert_no_leak(testcase, exc, *, dek=None, kek=None):
    rendered = f"{exc!r} {exc} {''.join(traceback.format_tb(exc.__traceback__))}"
    testcase.assertNotIn(CANARY, rendered)
    testcase.assertNotIn(fixture_plaintext().decode("utf-8")[:20], rendered)
    for material in (dek, kek):
        if material is not None:
            testcase.assertNotIn(material.hex(), rendered)
            testcase.assertNotIn(repr(material), rendered)
    testcase.assertIsNone(exc.__cause__)
    testcase.assertIsNone(exc.__context__)


class FailingKmsProvider(KmsProvider):
    """Test double: signals key-service outage on every operation."""

    def wrap(self, dek, *, purpose, bucket):
        raise KmsUnavailableError("synthetic outage")

    def unwrap(self, wrapped_dek, *, purpose, bucket):
        raise KmsUnavailableError("synthetic outage")


class RejectingShapeKmsProvider(KmsProvider):
    """Test double: refuses wrapped-key shape structurally."""

    def wrap(self, dek, *, purpose, bucket):
        return b"x" * 64

    def unwrap(self, wrapped_dek, *, purpose, bucket):
        raise InvalidWrappedKeyError("synthetic shape rejection")


class RoundTripTests(unittest.TestCase):
    def test_encrypt_serialize_parse_decrypt_restores_plaintext(self):
        kms, record = encrypt_canary()
        serialized = serialize_record(record)
        parsed = parse_record(serialized)
        self.assertEqual(decrypt_record(kms, parsed), fixture_plaintext())

    def test_serialized_record_contains_no_plaintext_no_dek_no_kek(self):
        kms, record = encrypt_canary()
        serialized = serialize_record(record)
        dek = kms.unwrap(record.wrapped_dek, purpose=PURPOSE, bucket=BUCKET)
        kek = kms.kek_for(PURPOSE, BUCKET)
        self.assertEqual(len(dek), DEK_SIZE_BYTES)
        self.assertEqual(len(kek), DEK_SIZE_BYTES)
        for raw in (fixture_plaintext(), dek, kek):
            self.assertNotIn(raw, serialized)
            self.assertNotIn(raw.hex().encode("ascii"), serialized)

    def test_two_records_have_distinct_dek_nonce_ciphertext(self):
        kms = StaticTestKmsProvider()
        first = encrypt_record(
            kms, b"same body", domain=DOMAIN, bucket=BUCKET, record_id=RECORD_ID, purpose=PURPOSE
        )
        second = encrypt_record(
            kms, b"same body", domain=DOMAIN, bucket=BUCKET, record_id=RECORD_ID, purpose=PURPOSE
        )
        self.assertEqual(len(first.nonce), NONCE_SIZE_BYTES)
        self.assertNotEqual(first.nonce, second.nonce)
        self.assertNotEqual(first.ciphertext, second.ciphertext)
        self.assertNotEqual(first.wrapped_dek, second.wrapped_dek)
        dek_first = kms.unwrap(first.wrapped_dek, purpose=PURPOSE, bucket=BUCKET)
        dek_second = kms.unwrap(second.wrapped_dek, purpose=PURPOSE, bucket=BUCKET)
        self.assertNotEqual(dek_first, dek_second)


class AadBindingTests(unittest.TestCase):
    def _dek_aad(self):
        kms, record = encrypt_canary()
        dek = kms.unwrap(record.wrapped_dek, purpose=PURPOSE, bucket=BUCKET)
        return dek, record

    def test_aad_binds_each_component(self):
        dek, record = self._dek_aad()
        good = build_aad(domain=DOMAIN, record_id=RECORD_ID, purpose=PURPOSE)
        tampered = {
            "domain": build_aad(domain="scope-other", record_id=RECORD_ID, purpose=PURPOSE),
            "record_id": build_aad(domain=DOMAIN, record_id="rec-other", purpose=PURPOSE),
            "purpose": build_aad(domain=DOMAIN, record_id=RECORD_ID, purpose="other-purpose"),
            "format_version": build_aad(domain=DOMAIN, record_id=RECORD_ID, purpose=PURPOSE)
            .replace(
                f'"format_version":{FORMAT_VERSION}'.encode("ascii"),
                f'"format_version":{FORMAT_VERSION + 1}'.encode("ascii"),
            ),
        }
        self.assertTrue(any(tampered.values()))
        for name, aad in tampered.items():
            with self.subTest(component=name):
                with self.assertRaises(SafetyError) as caught:
                    decrypt_payload(dek, record.nonce, record.ciphertext, aad)
                self.assertEqual(caught.exception.code, SafetyCode.DECRYPTION_FAILED)
                assert_no_leak(self, caught.exception, dek=dek)
        self.assertEqual(decrypt_payload(dek, record.nonce, record.ciphertext, good), fixture_plaintext())

    def test_record_metadata_tampering_rejected(self):
        kms, record = encrypt_canary()
        variants = {
            "domain": record_with(record, domain="scope-other"),
            "record_id": record_with(record, record_id="rec-other"),
            "purpose": record_with(record, purpose="other-purpose"),
            "bucket": record_with(record, bucket="bucket-365d"),
        }
        for name, tampered in variants.items():
            with self.subTest(component=name):
                with self.assertRaises(SafetyError) as caught:
                    decrypt_record(kms, tampered)
                self.assertEqual(caught.exception.code, SafetyCode.DECRYPTION_FAILED)
                assert_no_leak(self, caught.exception)

    def test_record_version_tamper_rejected_at_parse(self):
        kms, record = encrypt_canary()
        serialized = serialize_record(record)
        bumped = serialized.replace(
            f'"format_version":{FORMAT_VERSION}'.encode("ascii"),
            f'"format_version":{FORMAT_VERSION + 1}'.encode("ascii"),
        )
        self.assertNotEqual(serialized, bumped)
        with self.assertRaises(SafetyError) as caught:
            parse_record(bumped)
        self.assertEqual(caught.exception.code, SafetyCode.INVALID_CIPHERTEXT)
        assert_no_leak(self, caught.exception)


class TamperTests(unittest.TestCase):
    def test_ciphertext_bit_flip_fails_authentication(self):
        kms, record = encrypt_canary()
        flipped = bytes([record.ciphertext[0] ^ 0x01]) + record.ciphertext[1:]
        tampered = record_with(record, ciphertext=flipped)
        with self.assertRaises(SafetyError) as caught:
            decrypt_record(kms, tampered)
        self.assertEqual(caught.exception.code, SafetyCode.DECRYPTION_FAILED)
        assert_no_leak(self, caught.exception)

    def test_nonce_tamper_fails_authentication(self):
        kms, record = encrypt_canary()
        flipped = bytes([record.nonce[0] ^ 0x01]) + record.nonce[1:]
        tampered = record_with(record, nonce=flipped)
        with self.assertRaises(SafetyError) as caught:
            decrypt_record(kms, tampered)
        self.assertEqual(caught.exception.code, SafetyCode.DECRYPTION_FAILED)
        assert_no_leak(self, caught.exception)

    def test_wrong_kek_other_bucket_rejected(self):
        kms, record = encrypt_canary()
        rewrapped_view = record_with(record, bucket="bucket-365d")
        with self.assertRaises(SafetyError) as caught:
            decrypt_record(kms, rewrapped_view)
        self.assertEqual(caught.exception.code, SafetyCode.DECRYPTION_FAILED)
        assert_no_leak(self, caught.exception)

    def test_wrong_kek_cross_provider_rejected(self):
        producer, record = encrypt_canary()
        other = StaticTestKmsProvider()
        with self.assertRaises(SafetyError) as caught:
            decrypt_record(other, record)
        self.assertEqual(caught.exception.code, SafetyCode.DECRYPTION_FAILED)
        assert_no_leak(self, caught.exception, kek=producer.kek_for(PURPOSE, BUCKET))


class KmsFailureTests(unittest.TestCase):
    def test_kms_unavailable_on_wrap(self):
        with self.assertRaises(SafetyError) as caught:
            encrypt_record(
                FailingKmsProvider(),
                b"payload",
                domain=DOMAIN,
                bucket=BUCKET,
                record_id=RECORD_ID,
                purpose=PURPOSE,
            )
        self.assertEqual(caught.exception.code, SafetyCode.KMS_UNAVAILABLE)
        assert_no_leak(self, caught.exception)

    def test_kms_unavailable_on_unwrap(self):
        _, record = encrypt_canary()
        with self.assertRaises(SafetyError) as caught:
            decrypt_record(FailingKmsProvider(), record)
        self.assertEqual(caught.exception.code, SafetyCode.KMS_UNAVAILABLE)
        assert_no_leak(self, caught.exception)

    def test_wrapped_dek_truncated_rejected(self):
        kms, record = encrypt_canary()
        truncated = record.wrapped_dek[: len(record.wrapped_dek) // 2]
        tampered = record_with(record, wrapped_dek=truncated)
        with self.assertRaises(SafetyError) as caught:
            decrypt_record(kms, tampered)
        self.assertEqual(caught.exception.code, SafetyCode.INVALID_WRAPPED_KEY)
        assert_no_leak(self, caught.exception)

    def test_wrapped_dek_padded_rejected(self):
        kms, record = encrypt_canary()
        padded = record.wrapped_dek + b"\x00" * 16
        tampered = record_with(record, wrapped_dek=padded)
        with self.assertRaises(SafetyError) as caught:
            decrypt_record(kms, tampered)
        self.assertEqual(caught.exception.code, SafetyCode.INVALID_WRAPPED_KEY)
        assert_no_leak(self, caught.exception)

    def test_provider_shape_rejection_mapped(self):
        _, record = encrypt_canary()
        with self.assertRaises(SafetyError) as caught:
            decrypt_record(RejectingShapeKmsProvider(), record)
        self.assertEqual(caught.exception.code, SafetyCode.INVALID_WRAPPED_KEY)
        assert_no_leak(self, caught.exception)


class StrictParseTests(unittest.TestCase):
    def _serialized_dict(self):
        _, record = encrypt_canary()
        import json

        return json.loads(serialize_record(record))

    def test_extra_field_rejected(self):
        payload = self._serialized_dict()
        payload["unexpected"] = "value"
        import json

        with self.assertRaises(SafetyError) as caught:
            parse_record(json.dumps(payload))
        self.assertEqual(caught.exception.code, SafetyCode.INVALID_CIPHERTEXT)
        assert_no_leak(self, caught.exception)

    def test_missing_field_rejected(self):
        payload = self._serialized_dict()
        del payload["ciphertext"]
        import json

        with self.assertRaises(SafetyError) as caught:
            parse_record(json.dumps(payload))
        self.assertEqual(caught.exception.code, SafetyCode.INVALID_CIPHERTEXT)
        assert_no_leak(self, caught.exception)

    def test_wrong_type_rejected(self):
        payload = self._serialized_dict()
        payload["nonce"] = 12345
        import json

        with self.assertRaises(SafetyError) as caught:
            parse_record(json.dumps(payload))
        self.assertEqual(caught.exception.code, SafetyCode.INVALID_CIPHERTEXT)
        assert_no_leak(self, caught.exception)

    def test_malformed_json_rejected(self):
        with self.assertRaises(SafetyError) as caught:
            parse_record(b'{"format_version": 1, ')
        self.assertEqual(caught.exception.code, SafetyCode.INVALID_CIPHERTEXT)
        assert_no_leak(self, caught.exception)

    def test_duplicate_key_rejected(self):
        _, record = encrypt_canary()
        serialized = serialize_record(record)
        injected = serialized.replace(
            b'"domain":', b'"domain":"scope-injected-extra","domain":', 1
        )
        with self.assertRaises(SafetyError) as caught:
            parse_record(injected)
        self.assertEqual(caught.exception.code, SafetyCode.INVALID_CIPHERTEXT)
        assert_no_leak(self, caught.exception)

    def test_uppercase_hex_rejected(self):
        _, record = encrypt_canary()
        serialized = serialize_record(record).replace(
            record.ciphertext.hex().encode("ascii"),
            record.ciphertext.hex().upper().encode("ascii"),
        )
        with self.assertRaises(SafetyError) as caught:
            parse_record(serialized)
        self.assertEqual(caught.exception.code, SafetyCode.INVALID_CIPHERTEXT)
        assert_no_leak(self, caught.exception)

    def test_non_object_rejected(self):
        with self.assertRaises(SafetyError) as caught:
            parse_record(b'["not", "an", "object"]')
        self.assertEqual(caught.exception.code, SafetyCode.INVALID_CIPHERTEXT)
        assert_no_leak(self, caught.exception)


class InputContractTests(unittest.TestCase):
    def test_blank_parameters_rejected(self):
        kms = StaticTestKmsProvider()
        for kwargs in (
            {"domain": " ", "bucket": BUCKET, "record_id": RECORD_ID, "purpose": PURPOSE},
            {"domain": DOMAIN, "bucket": "", "record_id": RECORD_ID, "purpose": PURPOSE},
            {"domain": DOMAIN, "bucket": BUCKET, "record_id": "\t", "purpose": PURPOSE},
            {"domain": DOMAIN, "bucket": BUCKET, "record_id": RECORD_ID, "purpose": "\n"},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(SafetyError) as caught:
                    encrypt_record(kms, b"payload", **kwargs)
                self.assertEqual(caught.exception.code, SafetyCode.CONTRACT_VIOLATION)
                assert_no_leak(self, caught.exception)

    def test_non_bytes_plaintext_rejected(self):
        with self.assertRaises(TypeError):
            encrypt_record(
                StaticTestKmsProvider(),
                "text not bytes",
                domain=DOMAIN,
                bucket=BUCKET,
                record_id=RECORD_ID,
                purpose=PURPOSE,
            )

    def test_decrypt_requires_envelope_record(self):
        with self.assertRaises(TypeError):
            decrypt_record(StaticTestKmsProvider(), {"not": "a record"})


class CanaryTests(unittest.TestCase):
    def test_roundtrip_error_messages_leak_nothing(self):
        kms, record = encrypt_canary()
        dek = kms.unwrap(record.wrapped_dek, purpose=PURPOSE, bucket=BUCKET)
        attempts = []
        attempts.append(lambda: decrypt_payload(dek, bytes(12), record.ciphertext, b"aad"))
        bad_record = record_with(record, domain="scope-other")
        attempts.append(lambda: decrypt_record(kms, bad_record))
        attempts.append(lambda: decrypt_record(FailingKmsProvider(), record))
        truncated = record_with(record, wrapped_dek=record.wrapped_dek[:20])
        attempts.append(lambda: decrypt_record(kms, truncated))
        attempts.append(lambda: parse_record(serialize_record(record) + b"garbage"))
        for attempt in attempts:
            with self.assertRaises(SafetyError) as caught:
                attempt()
            assert_no_leak(self, caught.exception, dek=dek, kek=kms.kek_for(PURPOSE, BUCKET))

    def test_encrypt_rejects_reserved_canary_only_via_safetyerror(self):
        # SafetyError messages are code + static detail only, asserted structurally.
        kms = StaticTestKmsProvider()
        try:
            encrypt_record(kms, b"x", domain=DOMAIN, bucket=BUCKET, record_id=RECORD_ID, purpose=" ")
        except SafetyError as exc:
            self.assertEqual(str(exc), f"{exc.code.value} (purpose must be non-empty)")
            self.assertIsNone(exc.__cause__)
            self.assertIsNone(exc.__context__)


class PayloadPrimitiveTests(unittest.TestCase):
    def test_payload_roundtrip_and_nonce_size(self):
        dek = bytes(range(DEK_SIZE_BYTES))
        aad = build_aad(domain=DOMAIN, record_id=RECORD_ID, purpose=PURPOSE)
        nonce, ciphertext = encrypt_payload(dek, b"hello aead", aad)
        self.assertEqual(len(nonce), NONCE_SIZE_BYTES)
        self.assertEqual(decrypt_payload(dek, nonce, ciphertext, aad), b"hello aead")


if __name__ == "__main__":
    unittest.main()
