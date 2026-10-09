"""Provider-verified immutable history with domain/version-bound gateway receipts.

The gateway never manufactures provider signatures. The configured verifier
must validate the actual provider format; test verifiers prove only L1.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import inspect
import marshal
import dis
from pathlib import Path
from types import FunctionType, ModuleType, CodeType
from typing import Any, Callable, Mapping
from types import MappingProxyType

from infra.errors import SafetyCode, SafetyError


@dataclass(frozen=True, slots=True)
class ReasoningBlock:
    block_type: str
    content: str
    signature: str
    metadata: Mapping[str, str]

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, Mapping):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "invalid reasoning metadata")
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ProviderStateVerifier:
    """Bind a reviewed pure algorithm to its actual immutable trust material.

    The algorithm receives (block, verification_material). Hidden closure,
    default-argument or global trust configuration is unsupported. This type
    supplies no vendor algorithm; actual supplier formats require admission.
    """
    algorithm: Callable[[ReasoningBlock, bytes], bool]
    verification_material: bytes

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        algorithm = self.algorithm
        if (not isinstance(algorithm, FunctionType) or algorithm.__closure__ or
                algorithm.__defaults__ or algorithm.__kwdefaults__ or
                not isinstance(self.verification_material, bytes) or not self.verification_material):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "explicit immutable provider verifier required")
        parameters = list(inspect.signature(algorithm).parameters.values())
        if len(parameters) != 2 or any(p.kind not in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD) for p in parameters):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "provider algorithm requires block and trust material")
        if any(not isinstance(value, ModuleType) for value in self._global_dependencies().values()):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "hidden global provider configuration")

    def _global_dependencies(self) -> dict[str, Any]:
        # co_names/inspect.getclosurevars also include LOAD_ATTR names. Only
        # LOAD_GLOBAL can consume hidden module configuration at runtime.
        def code_objects(code):
            yield code
            for value in code.co_consts:
                if isinstance(value, CodeType):
                    yield from code_objects(value)
        names={instruction.argval for code in code_objects(self.algorithm.__code__)
               for instruction in dis.get_instructions(code) if instruction.opname == 'LOAD_GLOBAL'}
        return {name:self.algorithm.__globals__[name] for name in names if name in self.algorithm.__globals__}

    @property
    def binding_payload(self) -> dict[str, Any]:
        self._validate()
        try:
            source_path = Path(inspect.getfile(self.algorithm))
            source_hash = hashlib.sha256(source_path.read_bytes()).hexdigest()
            dependencies = {name: hashlib.sha256(Path(value.__file__).read_bytes()).hexdigest()
                            for name, value in self._global_dependencies().items()}
        except (OSError, TypeError, AttributeError):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "provider algorithm artifact unavailable") from None
        return {"algorithm": hashlib.sha256(marshal.dumps(self.algorithm.__code__)).hexdigest(),
                "source": source_hash, "dependencies": dependencies,
                "verification_material": hashlib.sha256(self.verification_material).hexdigest()}

    def verify(self, block: ReasoningBlock) -> bool:
        self._validate()
        return self.algorithm(block, self.verification_material)


@dataclass(frozen=True, slots=True, init=False)
class ReasoningStateValidator:
    _verification_key: bytes
    scope: str
    version: str
    _provider_verifier: ProviderStateVerifier

    def __init__(self, verification_key: bytes, *, scope: str, version: str,
                 provider_verifier: ProviderStateVerifier) -> None:
        if not isinstance(verification_key, bytes) or len(verification_key) < 32 or not isinstance(scope, str) or not scope or not isinstance(version, str) or not version or not isinstance(provider_verifier, ProviderStateVerifier):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "missing trusted state verifier or binding")
        object.__setattr__(self, '_verification_key', verification_key)
        object.__setattr__(self, 'scope', scope)
        object.__setattr__(self, 'version', version)
        object.__setattr__(self, '_provider_verifier', provider_verifier)

    def _provider_check(self, block: ReasoningBlock) -> None:
        if block.block_type not in ("thinking", "thought") or not isinstance(block.content, str) or not isinstance(block.signature, str) or not block.signature:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "invalid reasoning block")
        try:
            valid = self._provider_verifier.verify(ReasoningBlock(block.block_type, block.content, block.signature, {}))
        except Exception:
            valid = False
        if valid is not True:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "unverified provider reasoning state")

    def _receipt(self, block: ReasoningBlock) -> str:
        message = json.dumps(["gateway-state-receipt-v1", self.scope, self.version, block.block_type,
                              block.content, block.signature], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return hmac.digest(self._verification_key, message, "sha256").hex()

    def admit_upstream_block(self, block: ReasoningBlock) -> ReasoningBlock:
        self._provider_check(block)
        return ReasoningBlock(block.block_type, block.content, block.signature,
                              {"scope": self.scope, "version": self.version, "receipt": self._receipt(block)})

    def verify_reasoning_block(self, block: ReasoningBlock) -> None:
        self._provider_check(block)
        metadata = dict(block.metadata)
        if set(metadata) != {"scope", "version", "receipt"} or metadata.get("scope") != self.scope or metadata.get("version") != self.version:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "reasoning state binding mismatch")
        receipt = metadata.get("receipt")
        if not isinstance(receipt, str) or not hmac.compare_digest(receipt, self._receipt(block)):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "invalid reasoning state receipt")


@dataclass(frozen=True, slots=True)
class HistoricalStateAdapter:
    validator: ReasoningStateValidator

    def validate_message_history(self, messages: list[dict[str, Any]]) -> None:
        for message in messages:
            content = message.get("content")
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") in ("thinking", "thought"):
                        if message.get("role") != "assistant":
                            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "reasoning state in invalid role")
                        self.validator.verify_reasoning_block(ReasoningBlock(block["type"], block.get("thinking", block.get("text", "")),
                                                                           block.get("signature", ""), block.get("metadata", {})))
