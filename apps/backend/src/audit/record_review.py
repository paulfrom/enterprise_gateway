"""Single-record, time-bound, two-person audit review over the existing AEAD chain.

The ledger directory is trusted service storage, not client input. Exclusive
ticket lock directories serialize processes. A crash leaves a fail-closed lock
for controlled recovery; consumed tickets are never reopened automatically.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Callable, Mapping, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from infra.durable_write import DurableWriteError, durable_commit
from infra.envelope_crypto import EnvelopeRecord, KmsProvider, decrypt_record, serialize_record
from infra.errors import SafetyCode, SafetyError
from protocol.identity import (
    EnterpriseAuthenticator, TrustedIdentity, authorize_purpose, authorize_role,
    authorize_scope, resolve_trusted_identity,
)


REVIEW_PURPOSE = "audit-review"
APPROVER_ROLES = frozenset({"audit-security-approver", "audit-data-approver"})


class ReviewTicket(BaseModel):
    """Immutable scope; ticket IDs are handles, never authorization credentials."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    ticket_id: str
    requester_id: str
    tenant_id: str
    domain: str
    record_id: str
    record_sha256: str
    evidence_purpose: str
    purpose: Literal["audit-review"]
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone required")
        return value


class ReviewApproval(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    subject_id: str
    role: Literal["audit-security-approver", "audit-data-approver"]
    approved_at: datetime
    identity_expires_at: datetime


class RecordReviewService:
    """Internal component; callers must obtain encrypted records from trusted storage.

    All public actions authenticate credentials afresh. No raw-record listing,
    export, caller-supplied approval claims, or bulk-decrypt API exists.
    """

    def __init__(self, directory: str | Path, authenticator: EnterpriseAuthenticator,
                 kms: KmsProvider, *, clock: Callable[[], datetime] | None = None) -> None:
        if not isinstance(authenticator, EnterpriseAuthenticator) or not isinstance(kms, KmsProvider):
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION)
        self.directory = Path(directory)
        if not self.directory.is_dir():
            raise SafetyError(SafetyCode.AUDIT_WRITE_FAILED)
        self.authenticator = authenticator
        self.kms = kms
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _write(self, name: str, payload: dict) -> None:
        try:
            durable_commit(self.directory, name, json.dumps(payload, sort_keys=True,
                           separators=(",", ":")).encode("utf-8"))
        except (OSError, DurableWriteError):
            raise SafetyError(SafetyCode.AUDIT_WRITE_FAILED) from None

    def _log(self, action: str, outcome: str, ticket_id: object, actor: TrustedIdentity | None,
             now: datetime, code: str | None = None) -> None:
        # Untrusted handles are hashed, never interpolated as filenames or log text.
        handle = ticket_id if isinstance(ticket_id, str) else type(ticket_id).__name__
        self._write(f"{uuid4()}.review-event.json", {
            "action": action, "outcome": outcome, "handle_sha256":
            hashlib.sha256(handle.encode("utf-8")).hexdigest(),
            "subject_id": actor.subject_id if actor else None,
            "tenant_id": actor.tenant_id if actor else None,
            "domain": actor.domain if actor else None,
            "recorded_at": now.isoformat(), "code": code,
        })

    def _execute(self, headers: Mapping[str, str], action: str, ticket_id: object,
                 operation: Callable[[TrustedIdentity, datetime], object]):
        actor = None
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION)
        try:
            actor = resolve_trusted_identity(self.authenticator.authenticate(headers), now=now)
            authorize_purpose(actor, REVIEW_PURPOSE)
            return operation(actor, now)
        except SafetyError as exc:
            self._log(action, "denied", ticket_id, actor, now, exc.code.value)
            raise
        except Exception:
            self._log(action, "denied", ticket_id, actor, now, SafetyCode.CONTRACT_VIOLATION.value)
            raise SafetyError(SafetyCode.CONTRACT_VIOLATION) from None

    @staticmethod
    def _id(ticket_id: str) -> str:
        if not isinstance(ticket_id, str) or str(UUID(ticket_id)) != ticket_id:
            raise SafetyError(SafetyCode.ACCESS_DENIED)
        return ticket_id

    @contextmanager
    def _locked(self, ticket_id: str):
        lock = self.directory / f"{self._id(ticket_id)}.review-lock"
        try:
            lock.mkdir()
        except FileExistsError:
            raise SafetyError(SafetyCode.ACCESS_DENIED) from None
        try:
            yield
        finally:
            lock.rmdir()

    def _ticket(self, ticket_id: str, actor: TrustedIdentity, now: datetime) -> ReviewTicket:
        try:
            ticket = ReviewTicket.model_validate_json(
                (self.directory / f"{self._id(ticket_id)}.ticket.json").read_bytes())
        except (OSError, ValidationError):
            raise SafetyError(SafetyCode.ACCESS_DENIED) from None
        authorize_scope(actor, ticket.tenant_id, ticket.domain)
        if ticket.ticket_id != ticket_id or not ticket.issued_at <= now < ticket.expires_at:
            raise SafetyError(SafetyCode.ACCESS_DENIED)
        if (self.directory / f"{ticket_id}.consumed.json").exists():
            raise SafetyError(SafetyCode.ACCESS_DENIED)
        return ticket

    def request(self, headers: Mapping[str, str], record: EnvelopeRecord, *,
                tenant_id: str, purpose: str, expires_at: datetime) -> ReviewTicket:
        """Request one exact encrypted record, inside an explicit review interval."""
        ticket_id = str(uuid4())

        def operation(actor: TrustedIdentity, now: datetime) -> ReviewTicket:
            authorize_role(actor, "audit-reader")
            if not isinstance(record, EnvelopeRecord) or purpose != REVIEW_PURPOSE:
                raise SafetyError(SafetyCode.ACCESS_DENIED)
            authorize_scope(actor, tenant_id, record.domain)
            if (not isinstance(expires_at, datetime) or expires_at.tzinfo is None
                    or not now < expires_at <= actor.expires_at):
                raise SafetyError(SafetyCode.ACCESS_DENIED)
            ticket = ReviewTicket(ticket_id=ticket_id, requester_id=actor.subject_id,
                tenant_id=tenant_id, domain=record.domain, record_id=record.record_id,
                record_sha256=hashlib.sha256(serialize_record(record)).hexdigest(),
                evidence_purpose=record.purpose, purpose=purpose,
                issued_at=now, expires_at=expires_at)
            self._write(f"{ticket_id}.ticket.json", ticket.model_dump(mode="json"))
            self._log("request", "requested", ticket_id, actor, now)
            return ticket

        return self._execute(headers, "request", ticket_id, operation)

    def approve(self, headers: Mapping[str, str], ticket_id: str, *, role: str) -> None:
        def operation(actor: TrustedIdentity, now: datetime) -> None:
            with self._locked(ticket_id):
                ticket = self._ticket(ticket_id, actor, now)
                if role not in APPROVER_ROLES or actor.subject_id == ticket.requester_id:
                    raise SafetyError(SafetyCode.ACCESS_DENIED)
                authorize_role(actor, role)
                for existing_role in APPROVER_ROLES:
                    path = self.directory / f"{ticket_id}.{existing_role}.approval.json"
                    if path.exists():
                        existing = ReviewApproval.model_validate_json(path.read_bytes())
                        if existing_role == role or existing.subject_id == actor.subject_id:
                            raise SafetyError(SafetyCode.ACCESS_DENIED)
                approval = ReviewApproval(subject_id=actor.subject_id, role=role,
                                          approved_at=now, identity_expires_at=actor.expires_at)
                self._write(f"{ticket_id}.{role}.approval.json", approval.model_dump(mode="json"))
                self._log("approve", "approved", ticket_id, actor, now)

        self._execute(headers, "approve", ticket_id, operation)

    def read(self, headers: Mapping[str, str], ticket_id: str, record: EnvelopeRecord, *,
             purpose: str) -> bytes:
        """Consume the approved handle durably before real decrypt; log before release."""
        def operation(actor: TrustedIdentity, now: datetime) -> bytes:
            authorize_role(actor, "audit-reader")
            with self._locked(ticket_id):
                ticket = self._ticket(ticket_id, actor, now)
                if (actor.subject_id != ticket.requester_id or purpose != ticket.purpose
                    or not isinstance(record, EnvelopeRecord)
                    or hashlib.sha256(serialize_record(record)).hexdigest() != ticket.record_sha256):
                    raise SafetyError(SafetyCode.ACCESS_DENIED)
                subjects = {actor.subject_id}
                approvals = []
                for role in sorted(APPROVER_ROLES):
                    try:
                        approval = ReviewApproval.model_validate_json(
                            (self.directory / f"{ticket_id}.{role}.approval.json").read_bytes())
                    except (OSError, ValidationError):
                        raise SafetyError(SafetyCode.ACCESS_DENIED) from None
                    if (approval.role != role or approval.subject_id in subjects
                        or not ticket.issued_at <= approval.approved_at <= now
                        or now >= approval.identity_expires_at):
                        raise SafetyError(SafetyCode.ACCESS_DENIED)
                    subjects.add(approval.subject_id)
                    approvals.append(approval)
                self._log("read", "access_attempt", ticket_id, actor, now)
                self._write(f"{ticket_id}.consumed.json", {"consumed_at": now.isoformat()})
                plaintext = decrypt_record(self.kms, record)
                release_actor, release_now = self._validate_release(headers, ticket, approvals)
                self._log("read", "accessed", ticket_id, release_actor, release_now)
            # The KMS, final durable audit and lock release may consume the grant
            # interval. Recheck immediately before returning any plaintext.
            self._validate_release(headers, ticket, approvals)
            return plaintext

        return self._execute(headers, "read", ticket_id, operation)

    def _validate_release(self, headers: Mapping[str, str], ticket: ReviewTicket,
                          approvals: list[ReviewApproval]) -> tuple[TrustedIdentity, datetime]:
        now = self.clock()
        actor = resolve_trusted_identity(self.authenticator.authenticate(headers), now=now)
        authorize_role(actor, "audit-reader")
        authorize_purpose(actor, ticket.purpose)
        authorize_scope(actor, ticket.tenant_id, ticket.domain)
        if (actor.subject_id != ticket.requester_id or not ticket.issued_at <= now < ticket.expires_at
                or any(now >= approval.identity_expires_at for approval in approvals)):
            raise SafetyError(SafetyCode.ACCESS_DENIED)
        return actor, now
