"""D-08 NER model artifact contract and load-time qualification gate.

A production NER package is a self-contained directory whose integrity,
task head, license attestation, and ONNX payload are all verified before
the package is allowed to load. Loading fails closed with
``SafetyCode.NER_MODEL_INVALID`` on any deviation.

Package layout::

    <package>/
      manifest.json         artifact manifest (schema below)
      config.json           HF token-classification config (id2label, architectures)
      tokenizer.json        tokenizers-library tokenizer with offset mapping
      model.onnx            exported token-classification model
      license-excerpt.json  machine-readable license attestation

``manifest.json`` schema (``manifest_version`` == 1)::

    {
      "manifest_version": 1,
      "artifact": "<artifact name>",
      "created_utc": "<ISO-8601 UTC timestamp>",
      "signature": null,
      "files": {"<relative file name>": {"sha256": "<64 lowercase hex>",
                                         "bytes": <non-negative int>}}
    }

The manifest enumerates every payload file of the package (``manifest.json``
itself is excluded: a manifest cannot hash itself). ``signature`` is
reserved for release signing: version 1 packages ship unsigned (``null``);
a non-null signature is rejected because no release verification key exists
in this release, and an unverifiable signature must not imply trust. When
release signing lands, the signed structure is
``{"alg": <str>, "key_id": <str>, "value": <hex>}`` verified against the
pinned release key before the file hash checks below are trusted.

Load-time checks, in order (first failure wins):

1. Required control files exist: manifest.json, config.json,
   tokenizer.json, model.onnx, license-excerpt.json.
2. Manifest parses as strict JSON (unique keys) and validates against the
   schema above; ``files`` must be non-empty.
3. Package file set equals the manifest file set exactly (no missing, no
   extra payloads); every listed file's SHA-256 and byte count match.
4. config.json carries a token-classification head: ``architectures``
   contains an entry ending with ``ForTokenClassification``; ``id2label``
   is complete (keys exactly ``"0".."N-1"`` for ``N == len(id2label)``,
   consistent with ``num_labels`` when present); every label is BIO
   (``O`` or ``[BI]-TYPE``); entity types include PER, ORG and LOC.
5. license-excerpt.json attests a verified Apache-2.0 license.
6. tokenizer.json loads with the tokenizers library and produces code
   point offset mappings (offsets of a probe encoding cover the probe).
7. model.onnx loads in onnxruntime with the CPU provider and exposes
   inputs ``input_ids``/``attention_mask`` and output ``logits``.

Rejection messages carry only static structural identifiers (file names,
field names); they never contain document text, and rejections are raised
as fresh ``SafetyError`` objects with no exception chaining.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, NoReturn

import onnxruntime as ort
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from tokenizers import Tokenizer

from infra.errors import SafetyCode, SafetyError
from infra.strict_json import JsonRejectKind, parse_strict_json

REQUIRED_FILES = (
    "manifest.json",
    "config.json",
    "tokenizer.json",
    "model.onnx",
    "license-excerpt.json",
)

# Payload files hashed by the manifest: every package file except the
# manifest itself (a manifest cannot list its own digest).
CONTROL_FILES = frozenset({"manifest.json"})

ONNX_INPUT_IDS = "input_ids"
ONNX_ATTENTION_MASK = "attention_mask"
ONNX_LOGITS = "logits"
ONNX_PROVIDERS = ["CPUExecutionProvider"]

REQUIRED_ENTITY_TYPES = frozenset({"PER", "ORG", "LOC"})

_BIO_LABEL_PATTERN = re.compile(r"^(O|[BI]-[A-Z0-9]+)$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ArtifactFileEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    sha256: str
    bytes: int = Field(ge=0)

    @field_validator("sha256")
    @classmethod
    def _digest_format(cls, value: str) -> str:
        if not _SHA256_PATTERN.fullmatch(value):
            raise ValueError("sha256 must be 64 lowercase hexadecimal characters")
        return value


class ArtifactManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    manifest_version: int
    artifact: str
    created_utc: str
    signature: None
    files: dict[str, ArtifactFileEntry]

    @field_validator("manifest_version")
    @classmethod
    def _supported_version(cls, value: int) -> int:
        if value != 1:
            raise ValueError("unsupported manifest_version")
        return value

    @field_validator("artifact", "created_utc")
    @classmethod
    def _non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("manifest metadata must not be blank")
        return value

    @field_validator("files")
    @classmethod
    def _non_empty(cls, value: dict[str, ArtifactFileEntry]) -> dict[str, ArtifactFileEntry]:
        if not value:
            raise ValueError("manifest files must be non-empty")
        return value


class LicenseExcerpt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    license: str
    license_verified: bool
    source: str
    excerpt_date_utc: str

    @field_validator("license")
    @classmethod
    def _verified_license(cls, value: str) -> str:
        if value.strip().lower() != "apache-2.0":
            raise ValueError("license attestation must be apache-2.0")
        return value

    @field_validator("license_verified")
    @classmethod
    def _must_be_verified(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("license attestation must be marked verified")
        return value

    @field_validator("source", "excerpt_date_utc")
    @classmethod
    def _attestation_non_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("license attestation fields must not be blank")
        return value


def _reject_json(kind: JsonRejectKind) -> NoReturn:
    raise SafetyError(SafetyCode.NER_MODEL_INVALID, f"json_rejected:{kind.value}")


def _load_json(path: Path) -> Any:
    try:
        raw = path.read_bytes()
    except OSError:
        raise SafetyError(SafetyCode.NER_MODEL_INVALID, f"unreadable_file:{path.name}") from None
    payload = parse_strict_json(raw, reject=_reject_json)
    if not isinstance(payload, dict):
        raise SafetyError(SafetyCode.NER_MODEL_INVALID, f"json_not_object:{path.name}")
    return payload


def _validate_manifest(payload: Mapping[str, Any]) -> ArtifactManifest:
    validation_failed = False
    try:
        manifest = ArtifactManifest.model_validate(payload)
    except ValidationError:
        validation_failed = True
    if validation_failed:
        raise SafetyError(SafetyCode.NER_MODEL_INVALID, "manifest_failed_validation")
    return manifest


def _verify_file_hashes(package_dir: Path, manifest: ArtifactManifest) -> None:
    actual = {
        path.name
        for path in package_dir.iterdir()
        if path.is_file() and path.name not in CONTROL_FILES
    }
    declared = set(manifest.files)
    missing = declared - actual
    extra = actual - declared
    if missing:
        raise SafetyError(
            SafetyCode.NER_MODEL_INVALID, f"manifest_missing_file:{sorted(missing)[0]}"
        )
    if extra:
        raise SafetyError(
            SafetyCode.NER_MODEL_INVALID, f"manifest_unlisted_file:{sorted(extra)[0]}"
        )
    for name, entry in manifest.files.items():
        path = package_dir / name
        digest = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    digest.update(chunk)
        except OSError:
            raise SafetyError(SafetyCode.NER_MODEL_INVALID, f"unreadable_file:{name}") from None
        if digest.hexdigest() != entry.sha256:
            raise SafetyError(SafetyCode.NER_MODEL_INVALID, f"manifest_hash_mismatch:{name}")
        if path.stat().st_size != entry.bytes:
            raise SafetyError(SafetyCode.NER_MODEL_INVALID, f"manifest_size_mismatch:{name}")


def _validate_config(config: Mapping[str, Any]) -> dict[int, str]:
    architectures = config.get("architectures")
    if (
        not isinstance(architectures, list)
        or not any(isinstance(a, str) and a.endswith("ForTokenClassification") for a in architectures)
    ):
        raise SafetyError(SafetyCode.NER_MODEL_INVALID, "config_not_token_classification")

    id2label = config.get("id2label")
    if not isinstance(id2label, dict) or not id2label:
        raise SafetyError(SafetyCode.NER_MODEL_INVALID, "config_missing_id2label")
    expected_keys = {str(i) for i in range(len(id2label))}
    if set(id2label) != expected_keys or not all(isinstance(v, str) for v in id2label.values()):
        raise SafetyError(SafetyCode.NER_MODEL_INVALID, "config_incomplete_id2label")
    num_labels = config.get("num_labels")
    if num_labels is not None and num_labels != len(id2label):
        raise SafetyError(SafetyCode.NER_MODEL_INVALID, "config_num_labels_mismatch")
    labels = list(id2label.values())
    if not all(_BIO_LABEL_PATTERN.fullmatch(label) for label in labels):
        raise SafetyError(SafetyCode.NER_MODEL_INVALID, "config_non_bio_label")
    entity_types = {label.split("-", 1)[1] for label in labels if "-" in label}
    if not REQUIRED_ENTITY_TYPES.issubset(entity_types):
        raise SafetyError(SafetyCode.NER_MODEL_INVALID, "config_missing_required_entity_type")
    return {int(k): v for k, v in id2label.items()}


def _validate_tokenizer(tokenizer_path: Path) -> Tokenizer:
    load_failed = False
    try:
        tokenizer = Tokenizer.from_file(str(tokenizer_path))
    except Exception:
        load_failed = True
    if load_failed:
        raise SafetyError(SafetyCode.NER_MODEL_INVALID, "tokenizer_load_failed")
    encoding = tokenizer.encode("a b", add_special_tokens=False)
    offsets = encoding.offsets
    if (
        len(encoding.ids) < 2
        or offsets is None
        or any(o is None for o in offsets)
        or offsets[0][0] != 0
        or offsets[-1][1] != 3
    ):
        raise SafetyError(SafetyCode.NER_MODEL_INVALID, "tokenizer_offsets_unavailable")
    return tokenizer


def _validate_onnx(onnx_path: Path) -> ort.InferenceSession:
    load_failed = False
    try:
        session = ort.InferenceSession(str(onnx_path), providers=ONNX_PROVIDERS)
    except Exception:
        load_failed = True
    if load_failed:
        raise SafetyError(SafetyCode.NER_MODEL_INVALID, "onnx_load_failed")
    input_names = {item.name for item in session.get_inputs()}
    output_names = {item.name for item in session.get_outputs()}
    if not {ONNX_INPUT_IDS, ONNX_ATTENTION_MASK}.issubset(input_names):
        raise SafetyError(SafetyCode.NER_MODEL_INVALID, "onnx_input_contract_mismatch")
    if ONNX_LOGITS not in output_names:
        raise SafetyError(SafetyCode.NER_MODEL_INVALID, "onnx_output_contract_mismatch")
    return session


@dataclass(frozen=True, slots=True)
class LoadedNerPackage:
    """A fully verified NER package ready for inference wiring (D-09/D-10)."""

    package_dir: Path
    manifest: ArtifactManifest
    id2label: dict[int, str]
    tokenizer: Tokenizer
    session: ort.InferenceSession

    @property
    def entity_types(self) -> frozenset[str]:
        return frozenset(
            label.split("-", 1)[1] for label in self.id2label.values() if "-" in label
        )


def load_model_package(package_dir: str | Path) -> LoadedNerPackage:
    """Verify and load a NER model package; fail closed on any deviation."""
    directory = Path(package_dir)
    if not directory.is_dir():
        raise SafetyError(SafetyCode.NER_MODEL_INVALID, "package_dir_missing")

    for name in REQUIRED_FILES:
        if not (directory / name).is_file():
            raise SafetyError(SafetyCode.NER_MODEL_INVALID, f"missing_required_file:{name}")

    manifest = _validate_manifest(_load_json(directory / "manifest.json"))
    _verify_file_hashes(directory, manifest)
    id2label = _validate_config(_load_json(directory / "config.json"))

    license_payload = _load_json(directory / "license-excerpt.json")
    license_failed = False
    try:
        LicenseExcerpt.model_validate(license_payload)
    except ValidationError:
        license_failed = True
    if license_failed:
        raise SafetyError(SafetyCode.NER_MODEL_INVALID, "license_attestation_invalid")

    tokenizer = _validate_tokenizer(directory / "tokenizer.json")
    session = _validate_onnx(directory / "model.onnx")
    return LoadedNerPackage(
        package_dir=directory,
        manifest=manifest,
        id2label=id2label,
        tokenizer=tokenizer,
        session=session,
    )
