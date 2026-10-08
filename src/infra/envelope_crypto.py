"""Per-record envelope encryption: random DEK, AES-256-GCM, KMS-wrapped keys.

Capability boundary: this module proves real AEAD encryption/decryption
behavior for individual records — per-record random 256-bit DEK, single-shot
AES-256-GCM with 96-bit random nonces, AAD bound to domain/record/purpose/
format version, and DEK wrapping behind an abstract :class:`KmsProvider`.
Enterprise KMS integration, production storage semantics, and full-copy
destruction belong to R-05/A-05; this module performs no real KMS calls and
offers no configuration switching layer. :class:`StaticTestKmsProvider`
holds explicitly synthetic KEKs for local tests and must never back a
production code path. The controlled local file backend is implemented in
``infra.file_kms``; its durability does not prove enterprise KMS integration
or deletion of filesystem backups.

Serialized record format (canonical JSON object, unique keys, UTF-8)::

    {
      "format_version": 1,
      "purpose": "<non-empty string>",
      "domain": "<non-empty string>",
      "bucket": "<non-empty string>",
      "record_id": "<non-empty string>",
      "nonce": "<24 lowercase hex chars>",
      "wrapped_dek": "<hex>",
      "ciphertext": "<hex>"
    }

Unknown versions, unknown fields, missing fields, wrong value types, malformed
JSON, and duplicate keys are all rejected. KEK and DEK bytes never appear in
the serialized record.

AAD encoding: canonical JSON bytes of exactly
``{"domain":..., "format_version":..., "purpose":..., "record_id":...}``
with sorted keys, ``(","":")`` separators, ``ensure_ascii=False``, UTF-8
encoded — see :func:`build_aad`.

Failure-code mapping (all raised as fresh ``SafetyError`` with no
``__context__``/``__cause__`` chain):

- ``INVALID_CIPHERTEXT`` — serialized record cannot be strictly parsed.
- ``INVALID_WRAPPED_KEY`` — wrapped DEK is structurally malformed (bad magic,
  truncated, padded) or the provider refuses its shape.
- ``DECRYPTION_FAILED`` — any AEAD authentication failure: flipped ciphertext
  bytes, tampered nonce, AAD component mismatch (wrong domain/purpose/record/
  version), or a wrapped DEK that fails authentication under its KEK.
- ``KMS_UNAVAILABLE`` — the provider signals that key service is unavailable.
- ``CONTRACT_VIOLATION`` — caller supplies empty/blank encryption parameters.

Provider contract: ``wrap``/``unwrap`` receive the key selector
``(purpose, bucket)``. Providers signal service outage by raising
:class:`KmsUnavailableError` and structurally malformed wrapped keys by
raising :class:`InvalidWrappedKeyError`. AES-GCM based providers raise
``cryptography.exceptions.InvalidTag`` when a wrapped key fails
authentication; the envelope layer translates all of these without leaking
the original exception.
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from typing import Any, Mapping, NoReturn

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_serializer, field_validator

from infra.errors import SafetyCode, SafetyError
from infra.strict_json import JsonRejectKind, parse_strict_json

FORMAT_VERSION = 1
DEK_SIZE_BYTES = 32
NONCE_SIZE_BYTES = 12
_STATIC_KEK_MAGIC = b"STK1"


class KmsUnavailableError(Exception):
    """Providers raise this to signal the key service is unavailable."""


class InvalidWrappedKeyError(Exception):
    """Providers raise this when wrapped key material is structurally invalid."""


def _reject_json(_kind: JsonRejectKind) -> NoReturn:
    raise SafetyError(SafetyCode.INVALID_CIPHERTEXT)


class KmsProvider(ABC):
    """Abstract KEK wrapping service keyed by (purpose, retention bucket).

    KMS adapters and the controlled local file backend implement this interface.
    The provider below is exclusively synthetic and in-memory for tests.
    """

    @abstractmethod
    def wrap(self, dek: bytes, *, purpose: str, bucket: str) -> bytes:
        """Wrap a DEK under the KEK selected by (purpose, bucket)."""

    @abstractmethod
    def unwrap(self, wrapped_dek: bytes, *, purpose: str, bucket: str) -> bytes:
        """Unwrap a DEK; raise KmsUnavailableError / InvalidWrappedKeyError / InvalidTag."""


class StaticTestKmsProvider(KmsProvider):
    """Synthetic local KEK holder for tests only — never a production backend.

    Each (purpose, bucket) pair gets an independently generated 32-byte KEK
    on first use (or an explicitly supplied one). Wrapping is AES-256-GCM
    over the DEK with a random 96-bit nonce and an AAD binding the key
    selector, so unwrapping under the wrong purpose/bucket fails
    authentication. All KEKs are random test bytes, clearly labeled as
    synthetic; none of them protect real data.
    """

    def __init__(self, seed_keks: Mapping[tuple[str, str], bytes] | None = None) -> None:
        self._keks: dict[tuple[str, str], bytes] = {}
        if seed_keks is not None:
            for selector, kek in seed_keks.items():
                purpose, bucket = selector
                self._set_kek(purpose, bucket, kek)

    def _set_kek(self, purpose: str, bucket: str, kek: bytes) -> None:
        if not isinstance(purpose, str) or not isinstance(bucket, str):
            raise TypeError("purpose and bucket must be strings")
        if not isinstance(kek, bytes) or len(kek) != DEK_SIZE_BYTES:
            raise ValueError("synthetic KEK must be 32 bytes")
        self._keks[(purpose, bucket)] = kek

    def kek_for(self, purpose: str, bucket: str) -> bytes:
        """Return the synthetic KEK for a selector, generating one on first use."""
        selector = (purpose, bucket)
        if selector not in self._keks:
            self._keks[selector] = os.urandom(DEK_SIZE_BYTES)
        return self._keks[selector]

    def wrap(self, dek: bytes, *, purpose: str, bucket: str) -> bytes:
        if not isinstance(dek, bytes) or len(dek) != DEK_SIZE_BYTES:
            raise ValueError("only 256-bit DEKs may be wrapped")
        nonce = os.urandom(NONCE_SIZE_BYTES)
        aad = json.dumps(
            {"bucket": bucket, "purpose": purpose},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        body = AESGCM(self.kek_for(purpose, bucket)).encrypt(nonce, dek, aad)
        return _STATIC_KEK_MAGIC + nonce + body

    def unwrap(self, wrapped_dek: bytes, *, purpose: str, bucket: str) -> bytes:
        if not isinstance(wrapped_dek, bytes):
            raise InvalidWrappedKeyError("wrapped key must be bytes")
        prefix = len(_STATIC_KEK_MAGIC) + NONCE_SIZE_BYTES
        expected = prefix + DEK_SIZE_BYTES + 16
        if len(wrapped_dek) != expected or wrapped_dek[: len(_STATIC_KEK_MAGIC)] != _STATIC_KEK_MAGIC:
            raise InvalidWrappedKeyError("wrapped key shape is invalid")
        nonce = wrapped_dek[len(_STATIC_KEK_MAGIC) : prefix]
        body = wrapped_dek[prefix:]
        aad = json.dumps(
            {"bucket": bucket, "purpose": purpose},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return AESGCM(self.kek_for(purpose, bucket)).decrypt(nonce, body, aad)


def build_aad(*, domain: str, record_id: str, purpose: str, format_version: int = FORMAT_VERSION) -> bytes:
    """Canonical AAD bytes binding domain, record, purpose, and format version.

    Encoding: JSON object with exactly these keys, sorted keys, ``(",",":")``
    separators, ``ensure_ascii=False``, UTF-8 encoded. Any component change
    yields different bytes and therefore AEAD authentication failure.
    """
    return json.dumps(
        {
            "domain": domain,
            "format_version": format_version,
            "purpose": purpose,
            "record_id": record_id,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def encrypt_payload(dek: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Single-shot AES-256-GCM: return (nonce, ciphertext||tag). Random 96-bit nonce."""
    if not isinstance(dek, bytes) or len(dek) != DEK_SIZE_BYTES:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "dek must be 32 bytes")
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    if not isinstance(aad, bytes):
        raise TypeError("aad must be bytes")
    nonce = os.urandom(NONCE_SIZE_BYTES)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt_payload(dek: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """AEAD-decrypt; any authentication failure → DECRYPTION_FAILED with no chain."""
    if not isinstance(dek, bytes) or len(dek) != DEK_SIZE_BYTES:
        raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "dek must be 32 bytes")
    if not isinstance(nonce, bytes) or len(nonce) != NONCE_SIZE_BYTES:
        raise SafetyError(SafetyCode.INVALID_CIPHERTEXT, "nonce must be 12 bytes")
    if not isinstance(ciphertext, bytes) or not isinstance(aad, bytes):
        raise TypeError("ciphertext and aad must be bytes")
    auth_failed = False
    try:
        return AESGCM(dek).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        auth_failed = True
    if auth_failed:
        raise SafetyError(SafetyCode.DECRYPTION_FAILED)


class EnvelopeRecord(BaseModel):
    """Versioned serialized envelope record; strict parse, no extra fields."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    format_version: int
    purpose: str
    domain: str
    bucket: str
    record_id: str
    nonce: bytes = Field(min_length=NONCE_SIZE_BYTES, max_length=NONCE_SIZE_BYTES)
    wrapped_dek: bytes = Field(min_length=1)
    ciphertext: bytes = Field(min_length=1)

    @field_validator("format_version")
    @classmethod
    def _version_supported(cls, value: int) -> int:
        if value != FORMAT_VERSION:
            raise ValueError("unsupported format_version")
        return value

    @field_validator("purpose", "domain", "bucket", "record_id")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("field must be a non-empty string")
        return value

    @field_validator("nonce", "wrapped_dek", "ciphertext", mode="before")
    @classmethod
    def _hex_decode(cls, value: Any) -> Any:
        if isinstance(value, str):
            if value != value.lower():
                raise ValueError("field must be lowercase hex")
            try:
                return bytes.fromhex(value)
            except ValueError:
                raise ValueError("field must be lowercase hex") from None
        return value

    @field_serializer("nonce", "wrapped_dek", "ciphertext")
    def _hex_serialize(self, value: bytes) -> str:
        return value.hex()


def _unwrap_dek(kms: KmsProvider, wrapped_dek: bytes, *, purpose: str, bucket: str) -> bytes:
    unavailable = False
    invalid_wrapped = False
    auth_failed = False
    try:
        dek = kms.unwrap(wrapped_dek, purpose=purpose, bucket=bucket)
    except KmsUnavailableError:
        unavailable = True
    except InvalidWrappedKeyError:
        invalid_wrapped = True
    except InvalidTag:
        auth_failed = True
    if unavailable:
        raise SafetyError(SafetyCode.KMS_UNAVAILABLE)
    if invalid_wrapped:
        raise SafetyError(SafetyCode.INVALID_WRAPPED_KEY)
    if auth_failed:
        raise SafetyError(SafetyCode.DECRYPTION_FAILED)
    if not isinstance(dek, bytes) or len(dek) != DEK_SIZE_BYTES:
        raise SafetyError(SafetyCode.INVALID_WRAPPED_KEY)
    return dek


def encrypt_record(
    kms: KmsProvider,
    plaintext: bytes,
    *,
    domain: str,
    bucket: str,
    record_id: str,
    purpose: str,
) -> EnvelopeRecord:
    """Encrypt one record: fresh random DEK, AES-256-GCM, DEK wrapped via KMS."""
    for name, value in (("domain", domain), ("bucket", bucket), ("record_id", record_id), ("purpose", purpose)):
        if not isinstance(value, str):
            raise TypeError(f"{name} must be a string")
        if not value.strip():
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, f"{name} must be non-empty")
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    dek = os.urandom(DEK_SIZE_BYTES)
    aad = build_aad(domain=domain, record_id=record_id, purpose=purpose)
    nonce, ciphertext = encrypt_payload(dek, plaintext, aad)
    unavailable = False
    try:
        wrapped_dek = kms.wrap(dek, purpose=purpose, bucket=bucket)
    except KmsUnavailableError:
        unavailable = True
    if unavailable:
        raise SafetyError(SafetyCode.KMS_UNAVAILABLE)
    return EnvelopeRecord(
        format_version=FORMAT_VERSION,
        purpose=purpose,
        domain=domain,
        bucket=bucket,
        record_id=record_id,
        nonce=nonce,
        wrapped_dek=wrapped_dek,
        ciphertext=ciphertext,
    )


def decrypt_record(kms: KmsProvider, record: EnvelopeRecord) -> bytes:
    """Unwrap the DEK and AEAD-decrypt; any mismatch rejects, never partial plaintext."""
    if not isinstance(record, EnvelopeRecord):
        raise TypeError("record must be an EnvelopeRecord from parse_record")
    dek = _unwrap_dek(kms, record.wrapped_dek, purpose=record.purpose, bucket=record.bucket)
    aad = build_aad(
        domain=record.domain,
        record_id=record.record_id,
        purpose=record.purpose,
        format_version=record.format_version,
    )
    return decrypt_payload(dek, record.nonce, record.ciphertext, aad)


def serialize_record(record: EnvelopeRecord) -> bytes:
    """Serialize as canonical JSON bytes (sorted keys, compact separators, UTF-8)."""
    if not isinstance(record, EnvelopeRecord):
        raise TypeError("record must be an EnvelopeRecord")
    payload = record.model_dump()
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def parse_record(source: str | bytes) -> EnvelopeRecord:
    """Strict-parse serialized bytes; every deviation → INVALID_CIPHERTEXT."""
    payload = parse_strict_json(source, reject=_reject_json)
    if not isinstance(payload, dict):
        raise SafetyError(SafetyCode.INVALID_CIPHERTEXT)
    validation_failed = False
    try:
        record = EnvelopeRecord.model_validate(payload)
    except ValidationError:
        validation_failed = True
    if validation_failed:
        raise SafetyError(SafetyCode.INVALID_CIPHERTEXT)
    return record
