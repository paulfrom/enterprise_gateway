"""A-03 evidence gate: durable intent plus encrypted evidence before any egress.

DESIGN §6: before any egress attempt the gateway must durably commit the
minimal release-intent metadata event; when channel policy requires original-
text evidence retention, the encrypted evidence record must be durably
committed first as well. Only when every required step has reached the
persistence boundary is an immutable :class:`EvidencePermit` returned —
"persisted, may attempt send". The gate never fabricates success and never
retries or auto-resends (DESIGN §6): any failure fails the whole gate closed,
and a retry is an explicit new call by the caller.

Gate flow (:meth:`EvidenceGate.admit`):

1. A-01: :func:`enterprise_gateway.audit_intent.commit_release_intent`
   durably commits the intent metadata (temp write + fsync + atomic rename +
   directory fsync). Only after that boundary is an evidence step attempted.
2. When the caller supplies an :class:`EvidenceSpec` (channel policy requires
   original-text evidence): A-02 :func:`enterprise_gateway.envelope_crypto.encrypt_record`
   produces the per-record envelope (random DEK, AES-256-GCM, KMS-wrapped DEK),
   then the serialized record is committed through
   :func:`enterprise_gateway.durable_write.durable_commit` into the evidence
   directory — the persistence boundary for evidence.
3. Only when all required steps succeeded is :class:`EvidencePermit` returned.

Failure-code contract (all raised as fresh ``SafetyError`` with no exception
chain; no permit handle exists on any failure):

- ``AUDIT_WRITE_FAILED`` — intent commit failure (write/fsync/rename/ENOSPC),
  preserved unchanged from A-01.
- ``KMS_UNAVAILABLE`` / ``CONTRACT_VIOLATION`` — evidence encryption failure,
  preserved unchanged from A-02.
- ``EVIDENCE_GATE_FAILED`` — evidence record durable-commit failure after
  encryption (write/fsync/rename/directory fsync). Encryption itself already
  succeeded; only the persistence boundary failed.

Residual state is real, never fabricated: if the intent committed and a later
evidence step failed, the committed intent file stays on disk (A-01 truth) but
no permit is issued and no evidence final name exists. Callers must not infer
"sent" from any partial state; post-crash reconciliation belongs to A-06.

Combination with P-17: :func:`gated_send` runs the gate first and only invokes
the bound client's ``request`` after a permit exists, so any gate failure
leaves upstream egress calls at zero. There is deliberately no retry inside
the gate or :func:`gated_send`; a caller that wants to retry constructs a new
explicit call.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from audit.audit_intent import ReleaseIntent, commit_release_intent
from infra.durable_write import DurableWriteError, durable_commit
from infra.envelope_crypto import KmsProvider, encrypt_record, serialize_record
from infra.errors import SafetyCode, SafetyError

__all__ = [
    "EvidenceGate",
    "EvidencePermit",
    "EvidenceRef",
    "EvidenceSpec",
    "GatedSendResult",
    "gated_send",
]

_RECORD_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


@dataclass(frozen=True, slots=True)
class EvidenceSpec:
    """Original-text evidence the channel policy requires to be retained.

    ``plaintext`` is the evidence body (synthetic canaries in tests; never a
    secret — secrets never enter the evidence path). ``record_id`` doubles as
    the committed file name stem, so it must be a safe token; anything else
    fails closed with ``CONTRACT_VIOLATION`` before any write happens.
    """

    plaintext: bytes
    bucket: str
    record_id: str
    purpose: str

    def __post_init__(self) -> None:
        if not isinstance(self.plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        for name, value in (("bucket", self.bucket), ("record_id", self.record_id), ("purpose", self.purpose)):
            if not isinstance(value, str):
                raise TypeError(f"{name} must be a string")
        if not _RECORD_ID_RE.fullmatch(self.record_id):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "record_id must be a safe token")


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """Reference to one durably committed encrypted evidence record."""

    path: Path
    record_id: str
    sha256: str
    bytes_written: int


@dataclass(frozen=True, slots=True)
class EvidencePermit:
    """Immutable proof handle: every required record reached the boundary.

    ``granted_at`` is the permit time from the gate clock. ``evidence`` is
    ``None`` for channels whose policy requires only the minimal intent event.
    """

    intent_id: str
    intent_path: Path
    intent_sha256: str
    evidence: EvidenceRef | None
    granted_at: datetime


@dataclass(frozen=True, slots=True)
class GatedSendResult:
    """Outcome of one :func:`gated_send`: the permit plus the raw response."""

    permit: EvidencePermit
    response: object


class EvidenceGate:
    """Two-step persistence gate: A-01 intent, then encrypted evidence.

    The gate itself performs no retries (DESIGN §6): a failed step raises the
    contract code and the whole call produces no permit. The caller decides
    whether and when to retry explicitly.
    """

    def __init__(
        self,
        intent_directory: str | Path,
        *,
        evidence_directory: str | Path | None = None,
        kms: KmsProvider | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(intent_directory, (str, Path)):
            raise TypeError("intent_directory must be a str or Path")
        if evidence_directory is not None and not isinstance(evidence_directory, (str, Path)):
            raise TypeError("evidence_directory must be a str or Path")
        if kms is not None and not isinstance(kms, KmsProvider):
            raise TypeError("kms must be a KmsProvider")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self._intent_directory = Path(intent_directory)
        self._evidence_directory = Path(evidence_directory) if evidence_directory is not None else None
        self._kms = kms
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def admit(self, intent: ReleaseIntent, evidence: EvidenceSpec | None = None) -> EvidencePermit:
        """Run the gate; return a permit only after every required boundary.

        Steps, in order: (1) durable intent commit (A-01); (2) when ``evidence``
        is given, envelope-encrypt it (A-02) and durably commit the serialized
        record into the evidence directory. Any failure raises the mapped
        ``SafetyError`` and returns no permit; see the module docstring for the
        code contract. No retry happens here — a retry is a new explicit call.
        """
        if not isinstance(intent, ReleaseIntent):
            raise TypeError("intent must be a ReleaseIntent")
        if evidence is not None and not isinstance(evidence, EvidenceSpec):
            raise TypeError("evidence must be an EvidenceSpec or None")
        # Step 1 — A-01 persistence boundary. AUDIT_WRITE_FAILED propagates.
        intent_permit = commit_release_intent(self._intent_directory, intent)
        evidence_ref: EvidenceRef | None = None
        if evidence is not None:
            if self._kms is None or self._evidence_directory is None:
                raise SafetyError(SafetyCode.CONTRACT_VIOLATION, "evidence requires kms and evidence_directory")
            # Step 2a — A-02 envelope encryption. KMS_UNAVAILABLE /
            # CONTRACT_VIOLATION propagate unchanged.
            record = encrypt_record(
                self._kms,
                evidence.plaintext,
                domain=intent.domain,
                bucket=evidence.bucket,
                record_id=evidence.record_id,
                purpose=evidence.purpose,
            )
            data = serialize_record(record)
            # Step 2b — evidence persistence boundary (write + fsync + rename
            # + directory fsync). Encryption already succeeded; only the
            # durable commit failing maps to EVIDENCE_GATE_FAILED. The raise
            # happens outside the except block (flag pattern, as in A-01) so
            # no exception chain survives at all.
            commit_failed = False
            try:
                committed = durable_commit(
                    self._evidence_directory, f"{evidence.record_id}.evidence.json", data
                )
            except DurableWriteError:
                commit_failed = True
            if commit_failed:
                raise SafetyError(SafetyCode.EVIDENCE_GATE_FAILED) from None
            evidence_ref = EvidenceRef(
                path=committed.path,
                record_id=evidence.record_id,
                sha256=hashlib.sha256(data).hexdigest(),
                bytes_written=committed.bytes_written,
            )
        return EvidencePermit(
            intent_id=intent.intent_id,
            intent_path=intent_permit.path,
            intent_sha256=intent_permit.sha256,
            evidence=evidence_ref,
            granted_at=self._clock(),
        )


def gated_send(
    gate: EvidenceGate,
    client,
    *,
    intent: ReleaseIntent,
    evidence: EvidenceSpec | None = None,
    method: str,
    path: str,
    headers: Mapping[str, str] | None = None,
    content: str | bytes | None = None,
) -> GatedSendResult:
    """Gate first, egress second: one permit, at most one send attempt.

    The gate runs to its persistence boundary before the bound client (P-17)
    is invoked at all, so any gate failure leaves upstream egress calls at
    zero and no partial permit exists. The send itself is attempted exactly
    once — no auto-resend (DESIGN §6); the caller owns explicit retries.
    """
    if not isinstance(gate, EvidenceGate):
        raise TypeError("gate must be an EvidenceGate")
    permit = gate.admit(intent, evidence)
    response = client.request(method, path, headers=headers, content=content)
    return GatedSendResult(permit=permit, response=response)
