"""Single-admin knowledge governance service (schema v2).

Every successful governance action is one transaction: INSERT into
``knowledge_admin_actions`` -> business change -> necessary outbox event. A
business failure rolls the action record back together with the business
writes and then records a sanitized ``result='failed'`` action in a separate
transaction; a failure of that recording is reported honestly as
``AUDIT_WRITE_FAILED`` instead of fabricating an audit trail.

Schema v2 removed the persisted two-reviewer approval flow completely. The
effective consumer authorization for a publication is the intersection of the
effective governance versions of all contributing sources (design §3.1);
original source ACLs remain untouched evidence and never gate consumption.
The availability contract (design §3.2) is computed from authoritative
outbox/receipt/asset rows, never inferred from candidate state alone.

The frozen method signatures, error codes and Availability fields in this
module are the T2 contract consumed by the admin API layer.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import itertools
import json
from typing import Any, Iterable, Mapping, Sequence, TYPE_CHECKING
from uuid import UUID, uuid4

import psycopg
from psycopg.rows import dict_row

from detection.dictionary import DictionaryEntry, compute_dictionary_hash
from knowledge.knowledge import Evidence, KnowledgeError, TrustedActor

if TYPE_CHECKING:
    from psycopg import Connection

    from knowledge.storage import PostgresKnowledgeStorage

ADMIN_ACTOR_ID = 'admin'

# Fixed governance error codes (the API layer maps these onto 404/409/422/503).
SOURCE_NOT_FOUND = 'KNOWLEDGE_SOURCE_NOT_FOUND'
SOURCE_WITHDRAWN = 'KNOWLEDGE_SOURCE_WITHDRAWN'
SOURCE_EXPIRED = 'KNOWLEDGE_SOURCE_EXPIRED'
GOVERNANCE_VERSION_CONFLICT = 'KNOWLEDGE_GOVERNANCE_VERSION_CONFLICT'
CANDIDATE_NOT_FOUND = 'KNOWLEDGE_CANDIDATE_NOT_FOUND'
CANDIDATE_VERSION_CONFLICT = 'KNOWLEDGE_CANDIDATE_VERSION_CONFLICT'
PUBLISH_REJECTED = 'KNOWLEDGE_PUBLISH_REJECTED'
PUBLICATION_NOT_FOUND = 'KNOWLEDGE_PUBLICATION_NOT_FOUND'
VALIDITY_EXCEEDS_SOURCE = 'KNOWLEDGE_VALIDITY_EXCEEDS_SOURCE'
ADMIN_UNAVAILABLE = 'KNOWLEDGE_ADMIN_UNAVAILABLE'
AUDIT_WRITE_FAILED = 'AUDIT_WRITE_FAILED'

# Fixed blocking reason codes (design §3.1/§3.2); never carry SQL or secrets.
GOVERNANCE_MISSING = 'GOVERNANCE_MISSING'
GOVERNANCE_SUPERSEDED = 'GOVERNANCE_SUPERSEDED'
AUDIENCE_DENIED = 'AUDIENCE_DENIED'
PURPOSE_DENIED = 'PURPOSE_DENIED'
SOURCE_EXPIRED_REASON = 'SOURCE_EXPIRED'
SOURCE_WITHDRAWN_REASON = 'SOURCE_WITHDRAWN'
PUBLICATION_REVOKED = 'PUBLICATION_REVOKED'
EVIDENCE_UNAVAILABLE = 'EVIDENCE_UNAVAILABLE'

# Availability vocabularies (design §3.2).
GOVERNANCE_STATUS_UNCONFIRMED = 'unconfirmed'
GOVERNANCE_STATUS_PUBLISHABLE = 'publishable'
GOVERNANCE_STATUS_REJECTED = 'rejected'
GOVERNANCE_STATUS_SUPERSEDED = 'superseded'
ELIGIBILITY_ELIGIBLE = 'eligible'
ELIGIBILITY_INELIGIBLE = 'ineligible'
ELIGIBILITY_NOT_EVALUATED = 'not_evaluated'
ELIGIBILITY_UNKNOWN = 'unknown'
DELIVERY_NOT_DISPATCHED = 'not_dispatched'
DELIVERY_PENDING = 'pending'
DELIVERY_APPLIED = 'applied'
DELIVERY_FAILED = 'failed'
DELIVERY_INVALIDATION_PENDING = 'invalidation_pending'
EVIDENCE_AVAILABLE = 'available'
EVIDENCE_EXPIRED = 'expired'
EVIDENCE_UNKNOWN = 'unknown'
ASSET_ACTIVE = 'active'
ASSET_INVALIDATED = 'invalidated'
ASSET_INVALIDATION_PENDING = 'invalidation_pending'

_HEX_DIGITS = frozenset('0123456789abcdef')
_BLOCKING_ORDER = (
    SOURCE_WITHDRAWN_REASON,
    SOURCE_EXPIRED_REASON,
    GOVERNANCE_MISSING,
    GOVERNANCE_SUPERSEDED,
    EVIDENCE_UNAVAILABLE,
    PUBLICATION_REVOKED,
    AUDIENCE_DENIED,
    PURPOSE_DENIED,
)


class GovernanceError(Exception):
    """A governance action failed with a fixed, API-mappable error code."""

    def __init__(self, code: str, detail: str = '',
                 *, blocking_reasons: Sequence[str] = ()) -> None:
        self.code = code
        self.blocking_reasons = tuple(blocking_reasons)
        super().__init__(detail or code)


@dataclass(frozen=True)
class AdminActionContext:
    """Server-side admin identity binding for one governance action."""

    actor_id: str            # 服务端固定 'admin'
    session_digest: str      # 会话关联摘要（hex）
    tenant_id: str
    domain: str


@dataclass(frozen=True)
class ReuseAsset:
    """One persisted consumer reuse asset with its application receipt."""

    consumer_id: str
    asset_id: str
    asset_version: int
    asset_kind: str
    receipt_id: str | None
    applied_at: datetime | None
    invalidation_status: str


@dataclass(frozen=True)
class Availability:
    """Design §3.2 availability snapshot computed from authoritative rows."""

    governance_status: str
    blocking_reasons: tuple[str, ...]
    eligibility: str
    evaluated_consumer: str | None
    evaluated_use: str | None
    effective_audiences: tuple[str, ...]
    effective_use: str | None
    valid_until: datetime | None
    delivery_status: str
    pending_event_count: int
    last_attempt_at: datetime | None
    last_error_code: str | None
    reuse_assets: tuple[ReuseAsset, ...]
    evidence_status: str
    evaluated_at: datetime
    state_version: int


def merge_blocking_reasons(reasons: Iterable[str]) -> tuple[str, ...]:
    """Deduplicate blocking codes in their canonical presentation order."""
    merged = [reason for reason in _BLOCKING_ORDER if reason in set(reasons)]
    extras = [reason for reason in dict.fromkeys(reasons) if reason not in _BLOCKING_ORDER]
    return tuple(merged + extras)


def governance_status_label(candidate_state: str, live_publication: bool,
                            tombstoned_publication: bool) -> str:
    """Design §3.2 governance dimension: 未确认/可发布/拒绝/已替代."""
    if candidate_state == 'rejected':
        return GOVERNANCE_STATUS_REJECTED
    if live_publication:
        return GOVERNANCE_STATUS_PUBLISHABLE
    if tombstoned_publication:
        return GOVERNANCE_STATUS_SUPERSEDED
    return GOVERNANCE_STATUS_UNCONFIRMED


def eligibility_verdict(*, consumer: str | None, use: str | None,
                        consumer_audiences: Sequence[str] | None,
                        intended_use: str | None,
                        valid_until: datetime | None, now: datetime,
                        blocking_reasons: Sequence[str],
                        evidence_status: str,
                        candidate_state: str | None = None) -> str:
    """Design §3.2 eligibility dimension over the effective authorization."""
    if candidate_state == 'rejected':
        return ELIGIBILITY_INELIGIBLE
    if consumer is None or use is None:
        return ELIGIBILITY_NOT_EVALUATED
    if evidence_status == EVIDENCE_UNKNOWN:
        return ELIGIBILITY_UNKNOWN
    if blocking_reasons:
        return ELIGIBILITY_INELIGIBLE
    if valid_until is None or valid_until <= now:
        return ELIGIBILITY_INELIGIBLE
    if consumer not in set(consumer_audiences or ()):
        return ELIGIBILITY_INELIGIBLE
    if use != intended_use:
        return ELIGIBILITY_INELIGIBLE
    return ELIGIBILITY_ELIGIBLE


def delivery_snapshot(*, tombstoned: bool, events: Sequence[Mapping[str, Any]],
                      receipts: Sequence[Mapping[str, Any]],
                      asset_consumers: Sequence[str]) -> tuple[str, int, datetime | None, str | None]:
    """Design §3.2 delivery dimension from actual outbox and receipt rows."""
    last_attempt: datetime | None = None
    last_error: str | None = None
    for receipt in receipts:
        received_at = receipt.get('received_at')
        if received_at is not None and (last_attempt is None or received_at > last_attempt):
            last_attempt = received_at
        if receipt.get('last_error_code'):
            last_error = receipt['last_error_code']
    pending = sum(1 for event in events
                  if event.get('status') == 'pending' and event.get('acl'))
    if tombstoned:
        revoked_receipted = {r.get('consumer_id') for r in receipts
                             if r.get('event_type') == 'KNOWLEDGE_REVOKED'}
        if asset_consumers and all(consumer in revoked_receipted
                                   for consumer in asset_consumers):
            status = DELIVERY_APPLIED
        else:
            # Withdrawn without downstream confirmation: never claim deletion.
            status = DELIVERY_INVALIDATION_PENDING
    elif last_error is not None:
        status = DELIVERY_FAILED
    elif not events:
        status = DELIVERY_NOT_DISPATCHED
    elif pending:
        status = DELIVERY_PENDING
    elif receipts:
        status = DELIVERY_APPLIED
    else:
        status = DELIVERY_PENDING
    return status, pending, last_attempt, last_error


def asset_invalidation_verdict(*, active: bool, revoke_receipted: bool) -> str:
    """Asset-level invalidation display; missing receipts stay pending."""
    if active:
        return ASSET_ACTIVE
    if revoke_receipted:
        return ASSET_INVALIDATED
    return ASSET_INVALIDATION_PENDING


def _aware(now: datetime) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise KnowledgeError('timestamps must include a timezone')


def _valid_hex(digest: str) -> bool:
    return bool(digest) and not len(digest) % 2 and all(c in _HEX_DIGITS for c in digest)


class KnowledgeGovernanceService:
    """Single-admin governance over the schema v2 knowledge repository.

    All durable mutations require a real ``PostgresKnowledgeStorage`` with a
    configured admin connection; there is deliberately no in-memory fallback
    for governance actions.
    """

    def __init__(self, *, tenant_id: str, domain: str,
                 storage: PostgresKnowledgeStorage | None = None) -> None:
        if not tenant_id or not domain:
            raise KnowledgeError('governance service requires a tenant and domain scope')
        if storage is not None and (storage.tenant_id not in (None, tenant_id)
                                    or storage.domain not in (None, domain)):
            raise KnowledgeError('storage scope does not match the governance service scope')
        self._tenant_id = tenant_id
        self._domain = domain
        self._storage = storage
        self._state_counter = itertools.count(1)

    # ------------------------------------------------------------------
    # Shared guards and transaction helpers
    # ------------------------------------------------------------------
    def _require_storage(self) -> PostgresKnowledgeStorage:
        storage = self._storage
        if storage is None or not getattr(storage, 'admin_dsn', None):
            raise GovernanceError(ADMIN_UNAVAILABLE,
                                  'knowledge administration requires a configured admin connection')
        return storage

    def _check_context(self, context: AdminActionContext) -> None:
        if not isinstance(context, AdminActionContext):
            raise KnowledgeError('governance actions require an AdminActionContext')
        if context.actor_id != ADMIN_ACTOR_ID:
            raise KnowledgeError('governance actions are bound to the fixed server-side admin actor')
        if (context.tenant_id, context.domain) != (self._tenant_id, self._domain):
            raise KnowledgeError('admin action context scope mismatch')
        if not _valid_hex(context.session_digest or ''):
            raise KnowledgeError('admin action context requires a hex session digest')

    def _admin_tx(self):
        return self._require_storage().admin_transaction(tenant_id=self._tenant_id,
                                                         domain=self._domain)

    def _insert_action(self, conn: Connection, action_id: UUID, *,
                       context: AdminActionContext, action_type: str,
                       object_type: str, object_id: Any, object_version: Any,
                       rationale: str, intended_use: str | None = None,
                       consumer_audiences: Sequence[str] | None = None,
                       result: str = 'succeeded') -> None:
        conn.execute(
            "INSERT INTO knowledge_admin_actions(admin_action_id,tenant_id,domain,actor_id,"
            "session_digest,action_type,object_type,object_id,object_version,rationale,"
            "intended_use,consumer_audiences,result)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (action_id, self._tenant_id, self._domain, context.actor_id,
             context.session_digest, action_type, object_type, str(object_id),
             None if object_version is None else str(object_version), rationale,
             intended_use, None if consumer_audiences is None else list(consumer_audiences),
             result))

    def _record_failed_action(self, *, context: AdminActionContext, action_type: str,
                              object_type: str, object_id: Any, object_version: Any,
                              rationale: str, code: str,
                              blocking_reasons: Sequence[str] = ()) -> None:
        detail = f'{rationale} :: {code}'
        if blocking_reasons:
            detail += ': ' + ','.join(blocking_reasons)
        try:
            with self._admin_tx() as conn:
                with conn.transaction():
                    self._insert_action(conn, uuid4(), context=context,
                                        action_type=action_type, object_type=object_type,
                                        object_id=object_id, object_version=object_version,
                                        rationale=detail, result='failed')
        except GovernanceError:
            raise
        except Exception as exc:
            raise GovernanceError(AUDIT_WRITE_FAILED,
                                  'failed governance action could not be persisted') from exc

    @staticmethod
    def _require_basis(basis: str) -> str:
        if not isinstance(basis, str) or not basis.strip():
            raise KnowledgeError('governance actions require a non-empty basis')
        return basis

    @staticmethod
    def _audience_tuple(audiences: Sequence[str]) -> tuple[str, ...]:
        values = tuple(dict.fromkeys(audiences or ()))
        if not values or any(not isinstance(audience, str) or not audience.strip()
                             for audience in values):
            raise KnowledgeError('governance audiences must be a non-empty sequence of names')
        return values

    @staticmethod
    def _coerce_uuid(value: Any, label: str) -> UUID:
        try:
            return value if isinstance(value, UUID) else UUID(str(value))
        except (ValueError, AttributeError, TypeError):
            raise KnowledgeError(f'{label} must be a uuid') from None

    # ------------------------------------------------------------------
    # Governance reads shared by publish/export/availability
    # ------------------------------------------------------------------
    def _load_governance_rows(self, conn: Connection, source_id: str,
                              source_version: str) -> list[dict[str, Any]]:
        with conn.cursor(row_factory=dict_row) as cur:
            return cur.execute(
                "SELECT g.governance_version_id,g.intended_use,g.consumer_audiences,"
                "g.valid_from,g.valid_until,"
                "EXISTS(SELECT 1 FROM knowledge_governance_versions n"
                " WHERE n.supersedes_version_id=g.governance_version_id) AS superseded"
                " FROM knowledge_governance_versions g"
                " WHERE (g.tenant_id,g.domain,g.source_id,g.source_version)=(%s,%s,%s,%s)"
                " ORDER BY g.created_at DESC, g.governance_version_id",
                (self._tenant_id, self._domain, source_id, source_version)).fetchall()

    @staticmethod
    def _current_governance(rows: Sequence[dict[str, Any]],
                            now: datetime) -> dict[str, Any] | None:
        """The unified effective-version predicate: no successor, valid window."""
        for row in rows:
            if row['superseded']:
                continue
            if row['valid_from'] <= now < row['valid_until']:
                return row
        return None

    def _publication_health(self, conn: Connection, publication_id: UUID,
                            now: datetime) -> tuple[bool, list[dict[str, Any]], list[str]]:
        """Lifecycle blockers for one publication: tombstone, sources, governance."""
        blockers: list[str] = []
        tombstoned = conn.execute(
            "SELECT 1 FROM knowledge_tombstones"
            " WHERE (tenant_id,domain,publication_id)=(%s,%s,%s)",
            (self._tenant_id, self._domain, publication_id)).fetchone() is not None
        bindings = []
        with conn.cursor(row_factory=dict_row) as cur:
            rows = cur.execute(
                "SELECT ps.source_id,ps.source_version,ps.governance_version_id"
                " FROM knowledge_publication_sources ps"
                " WHERE (ps.tenant_id,ps.domain,ps.publication_id)=(%s,%s,%s)"
                " ORDER BY ps.source_id, ps.source_version",
                (self._tenant_id, self._domain, publication_id)).fetchall()
        for binding in rows:
            source = conn.execute(
                "SELECT withdrawn,retention_until FROM knowledge_sources"
                " WHERE (tenant_id,domain,source_id,version)=(%s,%s,%s,%s)",
                (self._tenant_id, self._domain, binding['source_id'],
                 binding['source_version'])).fetchone()
            governance = None
            for row in self._load_governance_rows(conn, binding['source_id'],
                                                  binding['source_version']):
                if row['governance_version_id'] == binding['governance_version_id']:
                    governance = row
                    break
            binding['governance'] = governance
            bindings.append(binding)
            if source is None or source[0]:
                blockers.append(SOURCE_WITHDRAWN_REASON)
            elif source[1] <= now:
                blockers.append(SOURCE_EXPIRED_REASON)
            if governance is None:
                blockers.append(GOVERNANCE_MISSING)
            else:
                if governance['superseded']:
                    blockers.append(GOVERNANCE_SUPERSEDED)
                if not (governance['valid_from'] <= now < governance['valid_until']):
                    blockers.append(GOVERNANCE_MISSING)
        if tombstoned:
            blockers.append(PUBLICATION_REVOKED)
        return tombstoned, bindings, blockers

    def _candidate_evidence_sources(self, conn: Connection,
                                    candidate_id: UUID) -> list[tuple[str, str]]:
        with conn.cursor(row_factory=dict_row) as cur:
            rows = cur.execute(
                "SELECT DISTINCT e.source_id,e.version FROM candidate_evidence_links l"
                " JOIN knowledge_evidence e USING(evidence_id)"
                " WHERE (l.tenant_id,l.domain,l.candidate_id)=(%s,%s,%s)"
                " ORDER BY e.source_id,e.version",
                (self._tenant_id, self._domain, candidate_id)).fetchall()
        return [(row['source_id'], row['version']) for row in rows]

    def _invalidate_publication(self, conn: Connection, publication_id: UUID, *,
                                reason: str, now: datetime,
                                governance_version_ids: Sequence[UUID] = ()) -> None:
        """Conservative invalidation: tombstone + outbox + asset deactivation.

        The original publication ACL and payload stay as evidence on the
        publication row itself; the published outbox event is scrubbed so a
        stale PUBLISHED event can no longer be applied by a lagging consumer.
        """
        publication = conn.execute(
            "SELECT candidate_id,acl,purpose FROM knowledge_publications"
            " WHERE (tenant_id,domain,publication_id)=(%s,%s,%s) FOR UPDATE",
            (self._tenant_id, self._domain, publication_id)).fetchone()
        if publication is None:
            return
        conn.execute(
            "INSERT INTO knowledge_tombstones(tombstone_id,publication_id,candidate_id,tenant_id,"
            "domain,acl,purpose,reason,effective_at)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(publication_id) DO NOTHING",
            (uuid4(), publication_id, publication[0], self._tenant_id, self._domain,
             publication[1], publication[2], reason, now))
        with conn.cursor(row_factory=dict_row) as cur:
            source_bindings = cur.execute(
                "SELECT source_id,source_version,governance_version_id"
                " FROM knowledge_publication_sources WHERE publication_id=%s"
                " ORDER BY source_id,source_version", (publication_id,)).fetchall()
        payload = {
            'publication_id': str(publication_id),
            'candidate_id': str(publication[0]),
            'reason': reason,
            'effective_at': now.isoformat(),
            'governance_version_ids': [str(governance_id)
                                       for governance_id in governance_version_ids],
            'asset_lineage': {'source_bindings': [
                {'source_id': str(binding['source_id']),
                 'source_version': str(binding['source_version']),
                 'governance_version_id': str(binding['governance_version_id'])}
                for binding in source_bindings]},
        }
        conn.execute(
            "INSERT INTO knowledge_outbox(outbox_id,event_type,aggregate_type,aggregate_id,"
            "tenant_id,domain,acl,purpose,payload,status)"
            " VALUES (%s,'KNOWLEDGE_REVOKED','Publication',%s,%s,%s,%s,%s,%s,'pending')"
            " ON CONFLICT(aggregate_id,event_type) DO NOTHING",
            (uuid4(), publication_id, self._tenant_id, self._domain,
             publication[1], publication[2], json.dumps(payload)))
        conn.execute(
            "UPDATE knowledge_outbox SET payload=jsonb_build_object('publication_id',%s::text),"
            "acl=ARRAY[]::text[] WHERE aggregate_id=%s AND event_type='KNOWLEDGE_PUBLISHED'",
            (str(publication_id), publication_id))
        conn.execute(
            "UPDATE knowledge_consumer_assets SET active=false"
            " WHERE (tenant_id,domain,publication_id)=(%s,%s,%s)",
            (self._tenant_id, self._domain, publication_id))

    def _invalidate_publications_bound_to_governance(self, conn: Connection,
                                                     governance_version_id: UUID, *,
                                                     reason: str, now: datetime) -> None:
        with conn.cursor(row_factory=dict_row) as cur:
            rows = cur.execute(
                "SELECT p.publication_id FROM knowledge_publications p"
                " WHERE (p.tenant_id,p.domain)=(%s,%s)"
                " AND EXISTS(SELECT 1 FROM knowledge_publication_sources ps"
                " WHERE ps.publication_id=p.publication_id"
                " AND ps.governance_version_id=%s)"
                " ORDER BY p.publication_id FOR UPDATE OF p",
                (self._tenant_id, self._domain, governance_version_id)).fetchall()
        for row in rows:
            self._invalidate_publication(conn, row['publication_id'], reason=reason,
                                         now=now,
                                         governance_version_ids=(governance_version_id,))

    # ------------------------------------------------------------------
    # Governance actions (each successful action = one admin transaction)
    # ------------------------------------------------------------------
    def confirm_source_governance(self, source_id: str, *, source_version: str,
                                  expected_governance_version: str | None,
                                  ownership: str, use: str, audiences: Sequence[str],
                                  valid_until: datetime, basis: str,
                                  context: AdminActionContext) -> str:
        """Confirm a new governance version for one source version.

        Re-governing supersedes the current effective version and conservatively
        invalidates every publication still bound to it (design §3.1); expanded
        audiences or validity never propagate to prior publications.
        """
        storage = self._require_storage()
        self._check_context(context)
        basis = self._require_basis(basis)
        audience_set = self._audience_tuple(audiences)
        if not isinstance(use, str) or not use.strip():
            raise KnowledgeError('governance use must be a non-empty string')
        if ownership not in ('confirmed', 'unassigned'):
            raise KnowledgeError("ownership must be 'confirmed' or 'unassigned'")
        _aware(valid_until)
        now = datetime.now(timezone.utc)
        if valid_until <= now:
            raise GovernanceError(VALIDITY_EXCEEDS_SOURCE,
                                  'governance validity must end in the future')
        action_type = 'governance_confirm'
        try:
            with storage.admin_transaction(tenant_id=self._tenant_id,
                                           domain=self._domain) as conn:
                with conn.transaction():
                    action_id = uuid4()
                    self._insert_action(conn, action_id, context=context,
                                        action_type=action_type, object_type='source',
                                        object_id=source_id, object_version=source_version,
                                        rationale=basis, intended_use=use,
                                        consumer_audiences=audience_set)
                    source = conn.execute(
                        "SELECT withdrawn,retention_until FROM knowledge_sources"
                        " WHERE (tenant_id,domain,source_id,version)=(%s,%s,%s,%s) FOR UPDATE",
                        (self._tenant_id, self._domain, source_id, source_version)).fetchone()
                    if source is None:
                        raise GovernanceError(SOURCE_NOT_FOUND,
                                              'source does not exist in this scope')
                    if source[0]:
                        raise GovernanceError(SOURCE_WITHDRAWN,
                                              'withdrawn sources cannot be governed')
                    if source[1] <= now:
                        raise GovernanceError(SOURCE_EXPIRED,
                                              'expired sources cannot be governed')
                    if valid_until > source[1]:
                        raise GovernanceError(VALIDITY_EXCEEDS_SOURCE,
                                              'governance validity exceeds source retention')
                    rows = self._load_governance_rows(conn, source_id, source_version)
                    current = self._current_governance(rows, now)
                    current_id = (None if current is None
                                  else str(current['governance_version_id']))
                    if current_id != expected_governance_version:
                        raise GovernanceError(GOVERNANCE_VERSION_CONFLICT,
                                              'effective governance version changed')
                    governance_version_id = uuid4()
                    conn.execute(
                        "INSERT INTO knowledge_governance_versions(governance_version_id,tenant_id,"
                        "domain,source_id,source_version,admin_action_id,ownership_confirmed,"
                        "intended_use,consumer_audiences,valid_until,rationale,supersedes_version_id)"
                        " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (governance_version_id, self._tenant_id, self._domain, source_id,
                         source_version, action_id, ownership == 'confirmed', use,
                         list(audience_set), valid_until, basis,
                         None if current is None else current['governance_version_id']))
                    if current is not None:
                        self._invalidate_publications_bound_to_governance(
                            conn, current['governance_version_id'],
                            reason='governance_version_superseded', now=now)
                    return str(governance_version_id)
        except GovernanceError as exc:
            self._record_failed_action(context=context, action_type=action_type,
                                       object_type='source', object_id=source_id,
                                       object_version=source_version, rationale=basis,
                                       code=exc.code, blocking_reasons=exc.blocking_reasons)
            raise

    def publish_candidate(self, candidate_id: str, *, expected_version: int, use: str,
                          audiences: Sequence[str], valid_until: datetime,
                          idempotency_key: str | None, basis: str,
                          context: AdminActionContext) -> str:
        """Publish one exact candidate version under single-admin governance.

        Admission requires evidence-backed asserted facts and, for every
        contributing source, a currently effective governance version whose
        consumer audiences and intended use permit the publication (design
        §3.1). Retrying with the same idempotency key returns the committed
        publication without duplicate side effects.
        """
        from knowledge.storage import KnowledgeSchemaError

        storage = self._require_storage()
        self._check_context(context)
        basis = self._require_basis(basis)
        candidate_uuid = self._coerce_uuid(candidate_id, 'candidate_id')
        if type(expected_version) is not int or expected_version < 1:
            raise KnowledgeError('expected_version must be a positive integer')
        audience_set = tuple(dict.fromkeys(audiences or ()))
        if any(not isinstance(audience, str) or not audience.strip()
               for audience in audience_set):
            raise KnowledgeError('publication audiences must be non-empty names')
        if not audience_set:
            raise GovernanceError(PUBLISH_REJECTED,
                                  'publication audiences must not be empty',
                                  blocking_reasons=(AUDIENCE_DENIED,))
        if not isinstance(use, str) or not use.strip():
            raise KnowledgeError('publication use must be a non-empty string')
        _aware(valid_until)
        if idempotency_key is not None and (not isinstance(idempotency_key, str)
                                            or not idempotency_key.strip()):
            raise KnowledgeError('idempotency_key must be a non-empty string')
        now = datetime.now(timezone.utc)
        if valid_until <= now:
            raise GovernanceError(VALIDITY_EXCEEDS_SOURCE,
                                  'publication validity must end in the future')
        action_type = 'publish'
        object_id = str(candidate_uuid)
        object_version = str(expected_version)
        action_id = uuid4()
        try:
            with storage.admin_transaction(tenant_id=self._tenant_id,
                                           domain=self._domain) as conn:
                with conn.transaction():
                    # Serialize retries before checking their committed result.
                    conn.execute(
                        "SELECT candidate_id FROM knowledge_candidates"
                        " WHERE (tenant_id,domain,candidate_id)=(%s,%s,%s) FOR UPDATE",
                        (self._tenant_id, self._domain, candidate_uuid)).fetchone()
                    if idempotency_key is not None:
                        row = conn.execute(
                            "SELECT publication_id FROM knowledge_publications"
                            " WHERE (tenant_id,domain,candidate_id,candidate_version,idempotency_key)"
                            "=(%s,%s,%s,%s,%s)",
                            (self._tenant_id, self._domain, candidate_uuid, expected_version,
                             idempotency_key)).fetchone()
                        if row is not None:
                            return str(row[0])
                    self._insert_action(conn, action_id, context=context,
                                        action_type=action_type, object_type='candidate',
                                        object_id=object_id, object_version=object_version,
                                        rationale=basis, intended_use=use,
                                        consumer_audiences=audience_set)
                    bindings = self._admission_check(conn, candidate_uuid,
                                                     expected_version=expected_version,
                                                     use=use, audiences=audience_set,
                                                     valid_until=valid_until, now=now)
                    return storage.publish_in_transaction(
                        conn, candidate_id=candidate_uuid, candidate_version=expected_version,
                        intended_use=use, consumer_audiences=list(audience_set),
                        valid_until=valid_until, admin_action_id=action_id,
                        idempotency_key=idempotency_key,
                        source_bindings=[(binding['source_id'], binding['source_version'],
                                          binding['governance_version_id']) for binding in bindings])
        except GovernanceError as exc:
            self._record_failed_action(context=context, action_type=action_type,
                                       object_type='candidate', object_id=object_id,
                                       object_version=object_version, rationale=basis,
                                       code=exc.code, blocking_reasons=exc.blocking_reasons)
            raise
        except psycopg.errors.Error as exc:
            mapped = self._map_publish_race(exc)
            if mapped is None:
                self._record_failed_action(context=context, action_type=action_type,
                                           object_type='candidate', object_id=object_id,
                                           object_version=object_version, rationale=basis,
                                           code=ADMIN_UNAVAILABLE)
                raise
            self._record_failed_action(context=context, action_type=action_type,
                                       object_type='candidate', object_id=object_id,
                                       object_version=object_version, rationale=basis,
                                       code=mapped.code,
                                       blocking_reasons=mapped.blocking_reasons)
            raise mapped

        except KnowledgeSchemaError:
            # An incompatible repository cannot accept either business or action writes.
            raise
        except Exception:
            self._record_failed_action(context=context, action_type=action_type,
                                       object_type='candidate', object_id=object_id,
                                       object_version=object_version, rationale=basis,
                                       code=ADMIN_UNAVAILABLE)
            raise

    def _admission_check(self, conn: Connection, candidate_uuid: UUID, *,
                         expected_version: int, use: str, audiences: tuple[str, ...],
                         valid_until: datetime, now: datetime) -> list[dict[str, Any]]:
        candidate = conn.execute(
            "SELECT candidate_version,state,claim_id FROM knowledge_candidates"
            " WHERE (tenant_id,domain,candidate_id)=(%s,%s,%s) FOR UPDATE",
            (self._tenant_id, self._domain, candidate_uuid)).fetchone()
        if candidate is None:
            raise GovernanceError(CANDIDATE_NOT_FOUND,
                                  'candidate does not exist in this scope')
        if candidate[0] != expected_version:
            raise GovernanceError(CANDIDATE_VERSION_CONFLICT,
                                  f'candidate version is {candidate[0]}, expected {expected_version}')
        if candidate[1] in ('rejected', 'withdrawn'):
            raise GovernanceError(CANDIDATE_VERSION_CONFLICT,
                                  f'candidate state {candidate[1]} cannot be published')
        claim = conn.execute(
            "SELECT modality,predicate FROM knowledge_claims WHERE claim_id=%s",
            (candidate[2],)).fetchone()
        if claim is None:
            raise GovernanceError(PUBLISH_REJECTED, 'candidate claim is missing',
                                  blocking_reasons=(EVIDENCE_UNAVAILABLE,))
        if claim[0] != 'asserted' or claim[1] == 'co_occurs_with':
            raise GovernanceError(PUBLISH_REJECTED,
                                  'only asserted business facts publish',
                                  blocking_reasons=(EVIDENCE_UNAVAILABLE,))
        with conn.cursor(row_factory=dict_row) as cur:
            sources = cur.execute(
                "SELECT DISTINCT s.source_id,s.version,s.withdrawn,s.retention_until,s.source_kind"
                " FROM candidate_evidence_links l JOIN knowledge_evidence e USING(evidence_id)"
                " JOIN knowledge_sources s"
                " ON (s.tenant_id,s.domain,s.source_id,s.version)=(e.tenant_id,e.domain,e.source_id,e.version)"
                " WHERE (l.tenant_id,l.domain,l.candidate_id)=(%s,%s,%s)"
                " ORDER BY s.source_id,s.version",
                (self._tenant_id, self._domain, candidate_uuid)).fetchall()
        if not sources:
            raise GovernanceError(PUBLISH_REJECTED, 'candidate has no evidence sources',
                                  blocking_reasons=(EVIDENCE_UNAVAILABLE,))
        if all(source['source_kind'] == 'model_output' for source in sources):
            raise GovernanceError(PUBLISH_REJECTED,
                                  'model-only evidence cannot establish facts',
                                  blocking_reasons=(EVIDENCE_UNAVAILABLE,))
        blockers: list[str] = []
        bindings: list[dict[str, Any]] = []
        for source in sources:
            if source['withdrawn']:
                blockers.append(SOURCE_WITHDRAWN_REASON)
                continue
            if source['retention_until'] <= now:
                blockers.append(SOURCE_EXPIRED_REASON)
                continue
            rows = self._load_governance_rows(conn, source['source_id'], source['version'])
            current = self._current_governance(rows, now)
            if current is None:
                blockers.append(GOVERNANCE_SUPERSEDED if any(row['superseded'] for row in rows)
                                else GOVERNANCE_MISSING)
                continue
            bindings.append({'source_id': source['source_id'],
                             'source_version': source['version'],
                             'governance_version_id': current['governance_version_id'],
                             'consumer_audiences': set(current['consumer_audiences']),
                             'intended_use': current['intended_use'],
                             'valid_until': current['valid_until'],
                             'source_retention_until': source['retention_until']})
        if blockers:
            raise GovernanceError(PUBLISH_REJECTED, 'publication admission rejected',
                                  blocking_reasons=merge_blocking_reasons(blockers))
        intersection = set.intersection(*(binding['consumer_audiences']
                                          for binding in bindings))
        if not set(audiences) <= intersection:
            raise GovernanceError(PUBLISH_REJECTED,
                                  'audiences exceed the effective governance intersection',
                                  blocking_reasons=(AUDIENCE_DENIED,))
        if any(binding['intended_use'] != use for binding in bindings):
            raise GovernanceError(PUBLISH_REJECTED,
                                  'use is not permitted by every contributing governance version',
                                  blocking_reasons=(PURPOSE_DENIED,))
        bound = min([binding['valid_until'] for binding in bindings]
                    + [binding['source_retention_until'] for binding in bindings])
        if valid_until > bound:
            raise GovernanceError(VALIDITY_EXCEEDS_SOURCE,
                                  'publication validity exceeds the effective governance bound')
        existing = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM knowledge_tombstones t"
            " WHERE t.publication_id=p.publication_id) AS tombstoned"
            " FROM knowledge_publications p"
            " WHERE (p.tenant_id,p.domain,p.candidate_id,p.candidate_version)=(%s,%s,%s,%s)",
            (self._tenant_id, self._domain, candidate_uuid, expected_version)).fetchone()
        if existing is not None:
            if existing[0]:
                raise GovernanceError(PUBLISH_REJECTED,
                                      'this candidate version was already invalidated;'
                                      ' revise before republishing',
                                      blocking_reasons=(PUBLICATION_REVOKED,))
            raise GovernanceError(CANDIDATE_VERSION_CONFLICT,
                                  'candidate version already published')
        conn.execute(
            "UPDATE knowledge_candidates SET state='published',updated_at=CURRENT_TIMESTAMP"
            " WHERE (tenant_id,domain,candidate_id)=(%s,%s,%s)",
            (self._tenant_id, self._domain, candidate_uuid))
        return bindings

    @staticmethod
    def _map_publish_race(exc: psycopg.errors.Error) -> GovernanceError | None:
        """Map trigger-level concurrent-rejection errors onto fixed codes."""
        message = str(exc)
        if isinstance(exc, psycopg.errors.UniqueViolation):
            return GovernanceError(CANDIDATE_VERSION_CONFLICT,
                                   'candidate version already published')
        if 'KNOWLEDGE_CANDIDATE_VERSION_NOT_FOUND' in message:
            return GovernanceError(CANDIDATE_VERSION_CONFLICT,
                                   'candidate version changed concurrently')
        if 'KNOWLEDGE_SOURCE_WITHDRAWN' in message:
            return GovernanceError(PUBLISH_REJECTED,
                                   'a contributing source was withdrawn concurrently',
                                   blocking_reasons=(SOURCE_WITHDRAWN_REASON,))
        if 'KNOWLEDGE_GOVERNANCE_VERSION_INVALID' in message:
            return GovernanceError(PUBLISH_REJECTED,
                                   'a bound governance version was superseded concurrently',
                                   blocking_reasons=(GOVERNANCE_SUPERSEDED,))
        if 'KNOWLEDGE_PUBLICATION_SOURCE_MISSING' in message:
            return GovernanceError(PUBLISH_REJECTED,
                                   'a contributing source binding is missing',
                                   blocking_reasons=(GOVERNANCE_MISSING,))
        return None

    def reject_candidate(self, candidate_id: str, *, basis: str,
                         context: AdminActionContext) -> None:
        storage = self._require_storage()
        self._check_context(context)
        basis = self._require_basis(basis)
        candidate_uuid = self._coerce_uuid(candidate_id, 'candidate_id')
        action_type = 'reject'
        try:
            with storage.admin_transaction(tenant_id=self._tenant_id,
                                           domain=self._domain) as conn:
                with conn.transaction():
                    self._insert_action(conn, uuid4(), context=context,
                                        action_type=action_type, object_type='candidate',
                                        object_id=candidate_uuid, object_version=None,
                                        rationale=basis)
                    row = conn.execute(
                        "SELECT state FROM knowledge_candidates"
                        " WHERE (tenant_id,domain,candidate_id)=(%s,%s,%s) FOR UPDATE",
                        (self._tenant_id, self._domain, candidate_uuid)).fetchone()
                    if row is None:
                        raise GovernanceError(CANDIDATE_NOT_FOUND,
                                              'candidate does not exist in this scope')
                    if row[0] != 'proposed':
                        raise GovernanceError(CANDIDATE_VERSION_CONFLICT,
                                              f'candidate state {row[0]} cannot be rejected')
                    conn.execute(
                        "UPDATE knowledge_candidates SET state='rejected',rejection_reason=%s,"
                        "updated_at=CURRENT_TIMESTAMP WHERE (tenant_id,domain,candidate_id)=(%s,%s,%s)",
                        (basis, self._tenant_id, self._domain, candidate_uuid))
        except GovernanceError as exc:
            self._record_failed_action(context=context, action_type=action_type,
                                       object_type='candidate', object_id=candidate_uuid,
                                       object_version=None, rationale=basis, code=exc.code,
                                       blocking_reasons=exc.blocking_reasons)
            raise
        return None

    def revise_candidate(self, candidate_id: str, *, modifications: Mapping[str, Any],
                         basis: str, context: AdminActionContext) -> str:
        """Create a new candidate version derived from an existing one.

        The old row and its evidence links stay untouched; the new row starts
        as ``proposed`` with ``candidate_version = old + 1`` so publication
        references remain pinned to exact versions.
        """
        storage = self._require_storage()
        self._check_context(context)
        basis = self._require_basis(basis)
        candidate_uuid = self._coerce_uuid(candidate_id, 'candidate_id')
        if not isinstance(modifications, Mapping):
            raise KnowledgeError('modifications must be a mapping')
        unknown = set(modifications) - {'acl', 'purpose'}
        if unknown:
            raise KnowledgeError(f'unsupported candidate modifications: {sorted(unknown)}')
        action_type = 'revise'
        try:
            with storage.admin_transaction(tenant_id=self._tenant_id,
                                           domain=self._domain) as conn:
                with conn.transaction():
                    self._insert_action(conn, uuid4(), context=context,
                                        action_type=action_type, object_type='candidate',
                                        object_id=candidate_uuid, object_version=None,
                                        rationale=basis)
                    row = conn.execute(
                        "SELECT claim_id,acl,purpose,candidate_version FROM knowledge_candidates"
                        " WHERE (tenant_id,domain,candidate_id)=(%s,%s,%s) FOR UPDATE",
                        (self._tenant_id, self._domain, candidate_uuid)).fetchone()
                    if row is None:
                        raise GovernanceError(CANDIDATE_NOT_FOUND,
                                              'candidate does not exist in this scope')
                    claim_id, old_acl, old_purpose, old_version = row
                    new_acl = list(modifications.get('acl', old_acl))
                    new_purpose = modifications.get('purpose', old_purpose)
                    if (not new_acl or any(not isinstance(token, str) or not token.strip()
                                           for token in new_acl)
                            or not isinstance(new_purpose, str) or not new_purpose.strip()):
                        raise KnowledgeError('revised candidates require a non-empty ACL and purpose')
                    sources = conn.execute(
                        "SELECT DISTINCT s.acl,s.purpose FROM candidate_evidence_links l"
                        " JOIN knowledge_evidence e USING(evidence_id)"
                        " JOIN knowledge_sources s"
                        " ON (s.tenant_id,s.domain,s.source_id,s.version)=(e.tenant_id,e.domain,e.source_id,e.version)"
                        " WHERE (l.tenant_id,l.domain,l.candidate_id)=(%s,%s,%s)",
                        (self._tenant_id, self._domain, candidate_uuid)).fetchall()
                    if sources and (any(source[1] != new_purpose for source in sources)
                                    or any(not set(new_acl) <= set(source[0])
                                           for source in sources)):
                        raise KnowledgeError('revised candidate exceeds its evidence sources')
                    new_candidate_id = uuid4()
                    conn.execute(
                        "INSERT INTO knowledge_candidates(candidate_id,claim_id,tenant_id,domain,"
                        "acl,purpose,state,rejection_reason,candidate_version,derived_from)"
                        " VALUES (%s,%s,%s,%s,%s,%s,'proposed',NULL,%s,%s)",
                        (new_candidate_id, claim_id, self._tenant_id, self._domain,
                         new_acl, new_purpose, old_version + 1, candidate_uuid))
                    conn.execute(
                        "INSERT INTO candidate_evidence_links(candidate_id,evidence_id,tenant_id,"
                        "domain,acl,purpose)"
                        " SELECT %s,evidence_id,tenant_id,domain,acl,purpose"
                        " FROM candidate_evidence_links WHERE candidate_id=%s",
                        (new_candidate_id, candidate_uuid))
                    return str(new_candidate_id)
        except GovernanceError as exc:
            self._record_failed_action(context=context, action_type=action_type,
                                       object_type='candidate', object_id=candidate_uuid,
                                       object_version=None, rationale=basis, code=exc.code,
                                       blocking_reasons=exc.blocking_reasons)
            raise

    def withdraw_source(self, source_id: str, *, source_version: str, basis: str,
                        context: AdminActionContext) -> None:
        """Withdraw a source version, cascading conservative invalidation.

        ``invalidate_knowledge_source`` semantics are preserved (tombstones,
        revocation outbox, asset deactivation, candidate withdrawal) while the
        original source ACL is retained as evidence: consumption is blocked by
        the withdrawn flag and the effective-authorization checks, not by
        erasing the provenance row (design §1.2).
        """
        storage = self._require_storage()
        self._check_context(context)
        basis = self._require_basis(basis)
        action_type = 'withdraw'
        now = datetime.now(timezone.utc)
        try:
            with storage.admin_transaction(tenant_id=self._tenant_id,
                                           domain=self._domain) as conn:
                with conn.transaction():
                    self._insert_action(conn, uuid4(), context=context,
                                        action_type=action_type, object_type='source',
                                        object_id=source_id, object_version=source_version,
                                        rationale=basis)
                    source = conn.execute(
                        "SELECT withdrawn FROM knowledge_sources"
                        " WHERE (tenant_id,domain,source_id,version)=(%s,%s,%s,%s) FOR UPDATE",
                        (self._tenant_id, self._domain, source_id, source_version)).fetchone()
                    if source is None:
                        raise GovernanceError(SOURCE_NOT_FOUND,
                                              'source does not exist in this scope')
                    if source[0]:
                        raise GovernanceError(SOURCE_WITHDRAWN, 'source is already withdrawn')
                    conn.execute(
                        "UPDATE knowledge_sources SET withdrawn=true"
                        " WHERE (tenant_id,domain,source_id,version)=(%s,%s,%s,%s)",
                        (self._tenant_id, self._domain, source_id, source_version))
                    candidate_rows = conn.execute(
                        "SELECT DISTINCT l.candidate_id FROM candidate_evidence_links l"
                        " JOIN knowledge_evidence e USING(evidence_id)"
                        " WHERE (l.tenant_id,l.domain)=(%s,%s) AND (e.source_id,e.version)=(%s,%s)"
                        " ORDER BY l.candidate_id",
                        (self._tenant_id, self._domain, source_id, source_version)).fetchall()
                    candidate_ids = [candidate[0] for candidate in candidate_rows]
                    if candidate_ids:
                        conn.execute(
                            "UPDATE knowledge_candidates SET state='withdrawn',updated_at=CURRENT_TIMESTAMP"
                            " WHERE candidate_id=ANY(%s)", (candidate_ids,))
                        publications = conn.execute(
                            "SELECT publication_id FROM knowledge_publications"
                            " WHERE candidate_id=ANY(%s) ORDER BY publication_id",
                            (candidate_ids,)).fetchall()
                        for publication in publications:
                            self._invalidate_publication(conn, publication[0], reason=basis,
                                                         now=now)
        except GovernanceError as exc:
            self._record_failed_action(context=context, action_type=action_type,
                                       object_type='source', object_id=source_id,
                                       object_version=source_version, rationale=basis,
                                       code=exc.code, blocking_reasons=exc.blocking_reasons)
            raise
        return None

    def revoke_publication(self, publication_id: str, *, basis: str,
                           context: AdminActionContext) -> None:
        """Revoke one publication: candidate withdrawal, tombstone, outbox, assets."""
        storage = self._require_storage()
        self._check_context(context)
        basis = self._require_basis(basis)
        publication_uuid = self._coerce_uuid(publication_id, 'publication_id')
        action_type = 'revoke'
        now = datetime.now(timezone.utc)
        try:
            with storage.admin_transaction(tenant_id=self._tenant_id,
                                           domain=self._domain) as conn:
                with conn.transaction():
                    self._insert_action(conn, uuid4(), context=context,
                                        action_type=action_type, object_type='publication',
                                        object_id=publication_uuid, object_version=None,
                                        rationale=basis)
                    row = conn.execute(
                        "SELECT candidate_id FROM knowledge_publications"
                        " WHERE (tenant_id,domain,publication_id)=(%s,%s,%s) FOR UPDATE",
                        (self._tenant_id, self._domain, publication_uuid)).fetchone()
                    if row is None:
                        raise GovernanceError(PUBLICATION_NOT_FOUND,
                                              'publication does not exist in this scope')
                    already = conn.execute(
                        "SELECT 1 FROM knowledge_tombstones WHERE publication_id=%s",
                        (publication_uuid,)).fetchone() is not None
                    if not already:
                        conn.execute(
                            "UPDATE knowledge_candidates SET state='withdrawn',updated_at=CURRENT_TIMESTAMP"
                            " WHERE (tenant_id,domain,candidate_id)=(%s,%s,%s)",
                            (self._tenant_id, self._domain, row[0]))
                        self._invalidate_publication(conn, publication_uuid, reason=basis,
                                                     now=now)
        except GovernanceError as exc:
            self._record_failed_action(context=context, action_type=action_type,
                                       object_type='publication', object_id=publication_uuid,
                                       object_version=None, rationale=basis, code=exc.code,
                                       blocking_reasons=exc.blocking_reasons)
            raise
        return None

    # ------------------------------------------------------------------
    # Availability (design §3.2)
    # ------------------------------------------------------------------
    def evaluate_availability(self, *, candidate_id: str | None,
                              publication_id: str | None, consumer: str | None,
                              use: str | None, now: datetime) -> Availability:
        _aware(now)
        if candidate_id is None and publication_id is None:
            raise KnowledgeError('candidate_id or publication_id is required')
        if consumer is not None and (not isinstance(consumer, str) or not consumer.strip()):
            raise KnowledgeError('consumer must be a non-empty name or None')
        if use is not None and (not isinstance(use, str) or not use.strip()):
            raise KnowledgeError('use must be a non-empty string or None')
        storage = self._require_storage()
        with storage.admin_transaction(tenant_id=self._tenant_id,
                                       domain=self._domain) as conn:
            publication: dict[str, Any] | None = None
            if publication_id is not None:
                publication_uuid = self._coerce_uuid(publication_id, 'publication_id')
                with conn.cursor(row_factory=dict_row) as cur:
                    publication = cur.execute(
                        "SELECT * FROM knowledge_publications"
                        " WHERE (tenant_id,domain,publication_id)=(%s,%s,%s)",
                        (self._tenant_id, self._domain, publication_uuid)).fetchone()
                if publication is None:
                    raise GovernanceError(PUBLICATION_NOT_FOUND,
                                          'publication does not exist in this scope')
                candidate_uuid = publication['candidate_id']
                if candidate_id is not None and self._coerce_uuid(candidate_id, 'candidate_id') != candidate_uuid:
                    raise KnowledgeError('candidate_id does not match the publication')
            else:
                candidate_uuid = self._coerce_uuid(candidate_id, 'candidate_id')
            with conn.cursor(row_factory=dict_row) as cur:
                candidate = cur.execute(
                    "SELECT * FROM knowledge_candidates"
                    " WHERE (tenant_id,domain,candidate_id)=(%s,%s,%s)",
                    (self._tenant_id, self._domain, candidate_uuid)).fetchone()
            if candidate is None:
                raise GovernanceError(CANDIDATE_NOT_FOUND,
                                      'candidate does not exist in this scope')
            if publication is None:
                with conn.cursor(row_factory=dict_row) as cur:
                    publication = cur.execute(
                        "SELECT * FROM knowledge_publications WHERE candidate_id=%s"
                        " ORDER BY published_at DESC, publication_id DESC LIMIT 1",
                        (candidate_uuid,)).fetchone()
            blockers: list[str] = []
            tombstoned = False
            bindings: list[dict[str, Any]] = []
            if publication is not None:
                tombstoned, bindings, blockers = self._publication_health(
                    conn, publication['publication_id'], now)
            else:
                for source_id, source_version in self._candidate_evidence_sources(conn, candidate_uuid):
                    source = conn.execute(
                        "SELECT withdrawn,retention_until FROM knowledge_sources"
                        " WHERE (tenant_id,domain,source_id,version)=(%s,%s,%s,%s)",
                        (self._tenant_id, self._domain, source_id, source_version)).fetchone()
                    if source is None or source[0]:
                        blockers.append(SOURCE_WITHDRAWN_REASON)
                    elif source[1] <= now:
                        blockers.append(SOURCE_EXPIRED_REASON)
            with conn.cursor(row_factory=dict_row) as cur:
                evidence = cur.execute(
                    "SELECT count(*) AS link_count,count(e.evidence_id) AS evidence_count,"
                    "bool_or(s.retention_until<=%s) AS any_expired"
                    " FROM candidate_evidence_links l"
                    " JOIN knowledge_evidence e USING(evidence_id)"
                    " JOIN knowledge_sources s"
                    " ON (s.tenant_id,s.domain,s.source_id,s.version)=(e.tenant_id,e.domain,e.source_id,e.version)"
                    " WHERE (l.tenant_id,l.domain,l.candidate_id)=(%s,%s,%s)",
                    (now, self._tenant_id, self._domain, candidate_uuid)).fetchone()
            if evidence['link_count'] == 0 or evidence['evidence_count'] != evidence['link_count']:
                evidence_status = EVIDENCE_UNKNOWN
            elif evidence['any_expired']:
                evidence_status = EVIDENCE_EXPIRED
            else:
                evidence_status = EVIDENCE_AVAILABLE
            live = publication is not None and not tombstoned
            governance_status = governance_status_label(candidate['state'], live, tombstoned)
            blocking = list(blockers)
            audiences = tuple(sorted(publication['consumer_audiences'])) if publication else ()
            intended_use = publication['intended_use'] if publication else None
            valid_until = publication['valid_until'] if publication else None
            if consumer is not None and live and not blocking:
                if consumer not in set(audiences):
                    blocking.append(AUDIENCE_DENIED)
                elif use is not None and use != intended_use:
                    blocking.append(PURPOSE_DENIED)
            blocking = list(merge_blocking_reasons(blocking))
            eligibility = eligibility_verdict(
                consumer=consumer, use=use, consumer_audiences=audiences,
                intended_use=intended_use, valid_until=valid_until, now=now,
                blocking_reasons=blocking, evidence_status=evidence_status,
                candidate_state=candidate['state'])
            delivery_status, pending_count, last_attempt, last_error = self._delivery_state(
                conn, publication, tombstoned)
            reuse_assets = self._reuse_assets(conn, publication, tombstoned)
            return Availability(
                governance_status=governance_status,
                blocking_reasons=tuple(blocking),
                eligibility=eligibility,
                evaluated_consumer=consumer,
                evaluated_use=use,
                effective_audiences=audiences,
                effective_use=intended_use,
                valid_until=valid_until,
                delivery_status=delivery_status,
                pending_event_count=pending_count,
                last_attempt_at=last_attempt,
                last_error_code=last_error,
                reuse_assets=reuse_assets,
                evidence_status=evidence_status,
                evaluated_at=now,
                state_version=next(self._state_counter))

    def _delivery_state(self, conn: Connection, publication: Mapping[str, Any] | None,
                        tombstoned: bool):
        if publication is None:
            return DELIVERY_NOT_DISPATCHED, 0, None, None
        with conn.cursor(row_factory=dict_row) as cur:
            events = cur.execute(
                "SELECT event_type,status,created_at,processed_at,acl FROM knowledge_outbox"
                " WHERE (tenant_id,domain,aggregate_id)=(%s,%s,%s) ORDER BY created_at",
                (self._tenant_id, self._domain, publication['publication_id'])).fetchall()
            receipts = cur.execute(
                "SELECT o.event_type,r.consumer_id,r.received_at,r.last_error_code"
                " FROM consumer_receipts r JOIN knowledge_outbox o ON r.event_id=o.outbox_id"
                " WHERE (o.tenant_id,o.domain,o.aggregate_id)=(%s,%s,%s)",
                (self._tenant_id, self._domain, publication['publication_id'])).fetchall()
        asset_consumers = [row['consumer_id'] for row in self._asset_rows(conn, publication)]
        return delivery_snapshot(tombstoned=tombstoned, events=events, receipts=receipts,
                                 asset_consumers=asset_consumers)

    def _asset_rows(self, conn: Connection,
                    publication: Mapping[str, Any]) -> list[dict[str, Any]]:
        with conn.cursor(row_factory=dict_row) as cur:
            return cur.execute(
                "SELECT consumer_id,asset_version,asset_kind,active FROM knowledge_consumer_assets"
                " WHERE (tenant_id,domain,publication_id)=(%s,%s,%s)"
                " ORDER BY consumer_id",
                (self._tenant_id, self._domain, publication['publication_id'])).fetchall()

    def _reuse_assets(self, conn: Connection, publication: Mapping[str, Any] | None,
                      tombstoned: bool) -> tuple[ReuseAsset, ...]:
        if publication is None:
            return ()
        with conn.cursor(row_factory=dict_row) as cur:
            receipts = cur.execute(
                "SELECT o.event_type,r.consumer_id,r.receipt_id,r.received_at"
                " FROM consumer_receipts r JOIN knowledge_outbox o ON r.event_id=o.outbox_id"
                " WHERE (o.tenant_id,o.domain,o.aggregate_id)=(%s,%s,%s)",
                (self._tenant_id, self._domain, publication['publication_id'])).fetchall()
        published = {receipt['consumer_id']: receipt for receipt in receipts
                     if receipt['event_type'] == 'KNOWLEDGE_PUBLISHED'}
        revoked = {receipt['consumer_id'] for receipt in receipts
                   if receipt['event_type'] == 'KNOWLEDGE_REVOKED'}
        assets = []
        for row in self._asset_rows(conn, publication):
            receipt = published.get(row['consumer_id'])
            assets.append(ReuseAsset(
                consumer_id=row['consumer_id'],
                asset_id=str(publication['publication_id']),
                asset_version=row['asset_version'],
                asset_kind=row['asset_kind'],
                receipt_id=None if receipt is None else str(receipt['receipt_id']),
                applied_at=None if receipt is None else receipt['received_at'],
                invalidation_status=asset_invalidation_verdict(
                    active=row['active'], revoke_receipted=row['consumer_id'] in revoked)))
        return tuple(assets)

    # ------------------------------------------------------------------
    # Admin listings (stable keyset pagination, history-API shape)
    # ------------------------------------------------------------------
    def _check_page(self, limit: int, cursor: str | None) -> list[Any] | None:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise KnowledgeError('limit must be an integer between 1 and 100')
        if cursor is None:
            return None
        if not isinstance(cursor, str) or not cursor or not cursor.isascii() or len(cursor) > 512:
            raise KnowledgeError('cursor must be ascii up to 512 characters')
        try:
            values = json.loads(base64.urlsafe_b64decode(cursor + '=' * (-len(cursor) % 4)))
        except Exception:
            raise KnowledgeError('cursor is not decodable') from None
        if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
            raise KnowledgeError('cursor payload is invalid')
        return values

    @staticmethod
    def _next_cursor(values: Sequence[Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(
            list(values), separators=(',', ':')).encode()).decode().rstrip('=')

    def _run_listing(self, *, table: str, columns: str, filters: list[str],
                     params: list[Any], order: str, cursor_values: list[Any] | None,
                     limit: int, cursor_arity: int,
                     key_of) -> tuple[list[dict], str | None]:
        where = ['tenant_id=%s', 'domain=%s'] + filters
        scope = [self._tenant_id, self._domain]
        order_by = ','.join(f'{column} DESC' for column in order.split(','))
        if cursor_values is not None:
            if len(cursor_values) != cursor_arity:
                raise KnowledgeError('cursor payload is invalid')
            where.append(f'({order})<({",".join(["%s"] * cursor_arity)})')
            params = params + cursor_values
        rows = []
        with self._admin_tx() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                found = cur.execute(
                    f"SELECT {columns} FROM {table} WHERE {' AND '.join(where)}"
                    f" ORDER BY {order_by} LIMIT {limit + 1}",
                    scope + params).fetchall()
        for row in found[:limit]:
            rows.append(row)
        next_cursor = None
        if len(found) > limit and rows:
            next_cursor = self._next_cursor(key_of(rows[-1]))
        return rows, next_cursor

    @staticmethod
    def _iso(value: Any) -> str | None:
        return None if value is None else value.isoformat()

    def list_sources(self, *, status=None, use=None, audience=None, limit=50,
                     cursor=None) -> tuple[list[dict], str | None]:
        self._require_storage()
        cursor_values = self._check_page(limit, cursor)
        filters: list[str] = []
        params: list[Any] = []
        if status is not None:
            if status not in ('active', 'withdrawn', 'expired'):
                raise KnowledgeError('status must be active, withdrawn or expired')
            if status == 'active':
                filters.append('NOT withdrawn AND retention_until>clock_timestamp()')
            elif status == 'withdrawn':
                filters.append('withdrawn')
            else:
                filters.append('retention_until<=clock_timestamp()')
        if use is not None:
            if not isinstance(use, str) or not use.strip():
                raise KnowledgeError('use must be a non-empty string')
            filters.append('purpose=%s')
            params.append(use)
        if audience is not None:
            if not isinstance(audience, str) or not audience.strip():
                raise KnowledgeError('audience must be a non-empty string')
            filters.append('acl @> ARRAY[%s]::text[]')
            params.append(audience)
        rows, next_cursor = self._run_listing(
            table='knowledge_sources',
            columns='source_id,version,source_kind,purpose,acl,withdrawn,observed_at,'
                    'retention_until,independence_verified',
            filters=filters, params=params, order='source_id,version',
            cursor_values=cursor_values, limit=limit, cursor_arity=2,
            key_of=lambda row: (row['source_id'], row['version']))
        return [{
            'source_id': row['source_id'],
            'version': row['version'],
            'source_kind': row['source_kind'],
            'purpose': row['purpose'],
            'acl': list(row['acl']),
            'withdrawn': row['withdrawn'],
            'observed_at': self._iso(row['observed_at']),
            'retention_until': self._iso(row['retention_until']),
            'independence_verified': row['independence_verified'],
        } for row in rows], next_cursor

    def list_candidates(self, *, state=None, source_id=None, limit=50,
                        cursor=None) -> tuple[list[dict], str | None]:
        self._require_storage()
        cursor_values = self._check_page(limit, cursor)
        filters: list[str] = []
        params: list[Any] = []
        if state is not None:
            if state not in ('proposed', 'published', 'rejected', 'withdrawn'):
                raise KnowledgeError('state must be a known candidate state')
            filters.append('state=%s')
            params.append(state)
        if source_id is not None:
            if not isinstance(source_id, str) or not source_id.strip():
                raise KnowledgeError('source_id must be a non-empty string')
            filters.append('EXISTS(SELECT 1 FROM candidate_evidence_links l'
                           ' JOIN knowledge_evidence e USING(evidence_id)'
                           ' WHERE l.candidate_id=knowledge_candidates.candidate_id'
                           ' AND e.source_id=%s)')
            params.append(source_id)
        if cursor_values is not None:
            if len(cursor_values) != 1:
                raise KnowledgeError('cursor payload is invalid')
            try:
                cursor_values = [UUID(cursor_values[0])]
            except (ValueError, AttributeError, TypeError):
                raise KnowledgeError('cursor payload is invalid') from None
        rows, next_cursor = self._run_listing(
            table='knowledge_candidates',
            columns='candidate_id,claim_id,acl,purpose,state,rejection_reason,'
                    'candidate_version,derived_from,updated_at',
            filters=filters, params=params, order='candidate_id',
            cursor_values=cursor_values, limit=limit, cursor_arity=1,
            key_of=lambda row: (str(row['candidate_id']),))
        return [{
            'candidate_id': str(row['candidate_id']),
            'claim_id': str(row['claim_id']),
            'acl': list(row['acl']),
            'purpose': row['purpose'],
            'state': row['state'],
            'rejection_reason': row['rejection_reason'],
            'candidate_version': row['candidate_version'],
            'derived_from': None if row['derived_from'] is None else str(row['derived_from']),
            'updated_at': self._iso(row['updated_at']),
        } for row in rows], next_cursor

    def list_publications(self, *, limit=50, cursor=None) -> tuple[list[dict], str | None]:
        self._require_storage()
        cursor_values = self._check_page(limit, cursor)
        if cursor_values is not None:
            if len(cursor_values) != 2:
                raise KnowledgeError('cursor payload is invalid')
            try:
                cursor_values = [datetime.fromisoformat(cursor_values[0]),
                                 UUID(cursor_values[1])]
            except (ValueError, AttributeError, TypeError):
                raise KnowledgeError('cursor payload is invalid') from None
        rows, next_cursor = self._run_listing(
            table='knowledge_publications',
            columns='publication_id,candidate_id,candidate_version,intended_use,'
                    'consumer_audiences,published_at,valid_until,acl,purpose,idempotency_key',
            filters=[], params=[], order='published_at,publication_id',
            cursor_values=cursor_values, limit=limit, cursor_arity=2,
            key_of=lambda row: (row['published_at'].isoformat(),
                                str(row['publication_id'])))
        return [{
            'publication_id': str(row['publication_id']),
            'candidate_id': str(row['candidate_id']),
            'candidate_version': row['candidate_version'],
            'intended_use': row['intended_use'],
            'consumer_audiences': list(row['consumer_audiences']),
            'published_at': self._iso(row['published_at']),
            'valid_until': self._iso(row['valid_until']),
            'acl': list(row['acl']),
            'purpose': row['purpose'],
            'idempotency_key': row['idempotency_key'],
        } for row in rows], next_cursor

    def list_observations(self, *, limit=50, cursor=None) -> tuple[list[dict], str | None]:
        self._require_storage()
        cursor_values = self._check_page(limit, cursor)
        if cursor_values is not None:
            if len(cursor_values) != 2:
                raise KnowledgeError('cursor payload is invalid')
            try:
                cursor_values = [datetime.fromisoformat(cursor_values[0]), cursor_values[1]]
            except (ValueError, AttributeError, TypeError):
                raise KnowledgeError('cursor payload is invalid') from None
        rows, next_cursor = self._run_listing(
            table='knowledge_observations',
            columns='dedup_key,source_id,source_version,candidate_ids,acl,purpose,created_at',
            filters=[], params=[], order='created_at,dedup_key',
            cursor_values=cursor_values, limit=limit, cursor_arity=2,
            key_of=lambda row: (row['created_at'].isoformat(), row['dedup_key']))
        return [{
            'dedup_key': row['dedup_key'],
            'source_id': row['source_id'],
            'source_version': row['source_version'],
            'candidate_ids': [str(candidate_id) for candidate_id in row['candidate_ids']],
            'acl': list(row['acl']),
            'purpose': row['purpose'],
            'created_at': self._iso(row['created_at']),
        } for row in rows], next_cursor

    # ------------------------------------------------------------------
    # K-07: Derivative ACL Calculation
    # ------------------------------------------------------------------
    def compute_derived_acl(self, evidences: Sequence[Evidence]) -> frozenset[str]:
        """K-07: the derived ACL is the INTERSECTION of contributing source ACLs."""
        if not evidences:
            raise KnowledgeError('cannot derive ACL from empty evidence set')
        effective_acl: set[str] | None = None
        tenant = evidences[0].source.tenant_id
        purpose = evidences[0].source.purpose
        for evidence in evidences:
            source = evidence.source
            if source.domain != self._domain or source.tenant_id != tenant \
                    or source.purpose != purpose:
                raise KnowledgeError('cross-domain evidence detected in ACL calculation')
            effective_acl = set(source.acl) if effective_acl is None \
                else effective_acl.intersection(source.acl)
        if not effective_acl:
            raise KnowledgeError('empty ACL intersection: derived knowledge has no authorized audience')
        return frozenset(effective_acl)

    # ------------------------------------------------------------------
    # K-08/K-09: Authorized export and dictionary compilation (v2 model)
    # ------------------------------------------------------------------
    def _export_record(self, conn: Connection, publication_uuid: UUID, *,
                       consumer: TrustedActor, version: str,
                       now: datetime) -> dict[str, Any] | None:
        """One publication's JSONL record, or None when not consumable."""
        if (consumer.tenant_id, consumer.domain) != (self._tenant_id, self._domain):
            raise KnowledgeError('consumer scope mismatch')
        with conn.cursor(row_factory=dict_row) as cur:
            publication = cur.execute(
                "SELECT * FROM knowledge_publications"
                " WHERE (tenant_id,domain,publication_id)=(%s,%s,%s)",
                (self._tenant_id, self._domain, publication_uuid)).fetchone()
            if publication is None:
                return None
            tombstoned, _, blockers = self._publication_health(conn, publication_uuid, now)
            if tombstoned or blockers:
                return None
            if publication['valid_until'] <= now:
                return None
            if consumer.subject_id not in set(publication['consumer_audiences']):
                return None
            if publication['intended_use'] not in consumer.purposes:
                return None
            claim = cur.execute(
                "SELECT k.predicate,k.polarity,k.modality,k.subject_id,k.object_id"
                " FROM knowledge_claims k"
                " JOIN knowledge_candidates c ON c.claim_id=k.claim_id"
                " WHERE c.candidate_id=%s", (publication['candidate_id'],)).fetchone()
            if claim is None:
                return None
            entities = {}
            for entity_id in (claim['subject_id'], claim['object_id']):
                entities[entity_id] = cur.execute(
                    "SELECT entity_id,entity_type,name FROM knowledge_entities"
                    " WHERE entity_id=%s", (entity_id,)).fetchone()
            if any(entities[entity_id] is None for entity_id in entities):
                return None
            subject = entities[claim['subject_id']]
            obj = entities[claim['object_id']]
        return {
            'version': version,
            'domain': self._domain,
            'publication_id': str(publication_uuid),
            'subject': {'entity_id': str(subject['entity_id']),
                        'type': subject['entity_type'], 'name': subject['name']},
            'predicate': claim['predicate'],
            'object': {'entity_id': str(obj['entity_id']),
                       'type': obj['entity_type'], 'name': obj['name']},
            'polarity': claim['polarity'],
            'modality': claim['modality'],
            'acl': sorted(publication['consumer_audiences']),
            'published_at': publication['published_at'].isoformat(),
            'valid_until': publication['valid_until'].isoformat(),
        }

    def export_versioned_jsonl(self, publication_ids: Sequence[Any],
                               consumer: TrustedActor, version: str,
                               now: datetime | None = None) -> str:
        """K-08: versioned JSONL of authorized structured facts only.

        A publication is exported only while its effective governance
        authorization (design §1.2/§3.1) permits the consumer; stale snapshots,
        revoked publications and lapsed governance are excluded.
        """
        storage = self._require_storage()
        if now is None:
            now = datetime.now(timezone.utc)
        _aware(now)
        if not isinstance(version, str) or not version.strip():
            raise KnowledgeError('export version must be a non-empty string')
        lines: list[str] = []
        with storage.admin_transaction(tenant_id=self._tenant_id,
                                       domain=self._domain) as conn:
            for publication_id in publication_ids:
                publication_uuid = self._coerce_uuid(publication_id, 'publication_id')
                record = self._export_record(conn, publication_uuid,
                                             consumer=consumer, version=version,
                                             now=now)
                if record is not None:
                    lines.append(json.dumps(record, ensure_ascii=False))
        return '\n'.join(lines)

    def compile_approved_dictionary_payload(self, dictionary_id: str, version: str,
                                            publication_ids: Sequence[Any],
                                            now: datetime | None = None, *,
                                            consumer: TrustedActor) -> dict:
        """K-09: compile authorized published facts into a dictionary payload."""
        storage = self._require_storage()
        if now is None:
            now = datetime.now(timezone.utc)
        _aware(now)
        if not isinstance(dictionary_id, str) or not dictionary_id.strip() \
                or not isinstance(version, str) or not version.strip():
            raise KnowledgeError('dictionary id and version must be non-empty strings')
        seen_entities: dict[str, str] = {}
        with storage.admin_transaction(tenant_id=self._tenant_id,
                                       domain=self._domain) as conn:
            for publication_id in publication_ids:
                publication_uuid = self._coerce_uuid(publication_id, 'publication_id')
                record = self._export_record(conn, publication_uuid,
                                             consumer=consumer, version=version,
                                             now=now)
                if record is None:
                    continue
                seen_entities[record['subject']['name']] = record['subject']['type']
                seen_entities[record['object']['name']] = record['object']['type']
        entries = [{'text': text, 'entity_type': entity_type}
                   for text, entity_type in sorted(seen_entities.items())]
        dictionary_entries = tuple(DictionaryEntry(text=entry['text'],
                                                   entity_type=entry['entity_type'])
                                   for entry in entries)
        sha256 = compute_dictionary_hash(dictionary_id, version, self._domain,
                                         dictionary_entries)
        return {
            'dictionary_id': dictionary_id,
            'version': version,
            'domain': self._domain,
            'entries': entries,
            'sha256': sha256,
        }
