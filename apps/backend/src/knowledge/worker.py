"""Independent decrypt/extract/PG worker and idempotent outbox consumption.

The input boundary is encrypted spool, never an extra prompt supplied by a test.
The built-in entity recognizer supports explicit Chinese organization suffixes;
it does not claim production NER quality or automatic fact verification.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
import re
from uuid import NAMESPACE_URL, UUID, uuid5

import psycopg

from infra.envelope_crypto import KmsProvider, encrypt_record, serialize_record
from infra.spool_relay import LedgerSink, SpoolRelay
from knowledge.extractor import RelationExtractor
from knowledge.knowledge import Entity, KnowledgeError, Source, TrustedActor
from knowledge.knowledge_events import ObservationEvent, serialize_event
from knowledge.storage import PostgresKnowledgeStorage


def extract_event_candidates(event: ObservationEvent):
    source = Source(event.tenant, event.domain, event.source_id, event.source_version,
                    event.source_kind, event.acl, event.purpose, event.observed_at,
                    event.retention_until, event.source_independence_verified)
    # Explicit supported local grammar, with punctuation/verb boundaries.
    mentions = {(m.name,m.entity_type) for m in event.mentions}
    if not mentions:
        # Only explicit grammar supports local extraction without detector output.
        for match in re.finditer(r'([^\s，。！？：；]{1,32}?(?:公司|集团))\s*(?:不|未|没有|否认|计划)?(?:向|从)\s*([^\s，。！？：；]{1,32}?(?:公司|集团))\s*(?:采购|购买|订购|购入)',event.evidence_text):
            buyer = re.split(r'请查询|请问|查询|报道|传言|核查发现|根据[^，。]*，|关于',match.group(1))[-1]
            mentions.update(((buyer,'ORG'),(match.group(2),'ORG')))
    entities = [Entity(uuid5(NAMESPACE_URL, f'{event.tenant}/{event.domain}/{kind}/{name}'),
                       event.tenant,event.domain,kind,name) for name,kind in sorted(mentions) if name]
    extractor = RelationExtractor(event.domain)
    candidates = extractor.extract_from_text(event.evidence_text, source, entities, event.evidence_ref.digest)
    if not candidates:
        candidates = extractor.extract_co_occurrences(event.evidence_text, source, entities, event.evidence_ref.digest)
    result = []
    for candidate in candidates:
        evidence = tuple(replace(ev, start=ev.start + event.evidence_ref.offset,
                                  end=ev.end + event.evidence_ref.offset) for ev in candidate.evidence)
        key = repr((source.key, event.evidence_ref.digest, candidate.claim.key, tuple((e.start,e.end) for e in evidence)))
        result.append(replace(candidate, candidate_id=uuid5(NAMESPACE_URL,key), evidence=evidence))
    return source, result


class PostgresKnowledgeSink(LedgerSink):
    def __init__(self, storage: PostgresKnowledgeStorage, actor: TrustedActor, kms: KmsProvider,
                 *, processing_acl: tuple[str, ...] = ()):
        if not isinstance(kms, KmsProvider):
            raise TypeError('kms must be a KmsProvider')
        self.storage, self.actor, self.processing_acl = storage, actor, processing_acl
        self.kms = kms

    def _scope(self, conn):
        self.storage.set_session_identity(conn, self.actor, processing_acl=self.processing_acl)

    def has_contributed(self, dedup_key: str) -> bool:
        with psycopg.connect(self.storage.connection_uri) as conn:
            self._scope(conn)
            return conn.execute('SELECT 1 FROM knowledge_observations WHERE dedup_key=%s', (dedup_key,)).fetchone() is not None

    def submit(self, event: ObservationEvent, dedup_key: str) -> None:
        if (event.tenant,event.domain) != (self.actor.tenant_id,self.actor.domain) or event.purpose not in self.actor.purposes:
            raise KnowledgeError('worker scope mismatch')
        if not event.acl.intersection({self.actor.subject_id,*self.processing_acl}):
            raise KnowledgeError('worker lacks source processing access')
        if event.retention_until <= datetime.now(timezone.utc):
            raise KnowledgeError('worker source expired')
        source, candidates = extract_event_candidates(event)
        # Preserve the minimal source fragment after confirmed spool deletion.
        # Reuse its governed key selector, with a fresh DEK and observation-bound AAD.
        encrypted_observation = serialize_record(encrypt_record(
            self.kms, serialize_event(event), domain=event.domain,
            bucket=event.retention_policy, purpose=event.purpose + ':knowledge-spool',
            record_id='obs-' + dedup_key))
        with psycopg.connect(self.storage.connection_uri) as conn:
            self._scope(conn)
            self.storage.save_source(conn, source)
            inserted = conn.execute('''INSERT INTO knowledge_observations
                (dedup_key,tenant_id,domain,acl,purpose,source_id,source_version,candidate_ids,encrypted_observation)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(dedup_key) DO NOTHING RETURNING dedup_key''',
                (dedup_key,event.tenant,event.domain,list(event.acl),event.purpose,event.source_id,event.source_version,
                 [c.candidate_id for c in candidates],encrypted_observation)).fetchone()
            if inserted is None:
                return
            for candidate in candidates:
                evidence_ids = [self.storage.save_evidence(conn, ev) for ev in candidate.evidence]
                self.storage.save_candidate(conn, candidate, evidence_ids)


class KnowledgeWorker:
    def __init__(self, spool_directory, kms: KmsProvider, sink: PostgresKnowledgeSink):
        self.relay = SpoolRelay(spool_directory, kms, sink)

    def run_once(self):
        return self.relay.relay_once()


class GovernedConsumer:
    """Durable, idempotent consumer; receipt follows application in the same PG transaction.

    Applications receive authorized publication IDs. Readable facts are fetched from
    active governed rows, so tombstones/expiry prevent stale snapshot re-use. Consumer
    authorization is the publication-bound effective governance grant (design §1.2):
    outbox rows are visible to a consumer only while the publication's consumer
    audiences and intended use cover the authenticated consumer scope.
    """
    def __init__(self, storage: PostgresKnowledgeStorage, actor: TrustedActor):
        self.storage, self.actor = storage, actor

    def consume_once(self, *, fail_after_apply=False):
        with psycopg.connect(self.storage.connection_uri) as conn:
            self.storage.set_session_identity(conn,self.actor)
            with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                events = cur.execute('''SELECT * FROM knowledge_outbox o WHERE NOT EXISTS
                    (SELECT 1 FROM consumer_receipts r WHERE r.event_id=o.outbox_id AND r.consumer_id=%s)
                    ORDER BY o.created_at,o.outbox_id LIMIT 100''',(self.actor.subject_id,)).fetchall()
            for event in events:
                action = 'tombstone_applied' if event['event_type']=='KNOWLEDGE_REVOKED' else 'publication_applied'
                if action == 'publication_applied':
                    self._apply_publication(conn, event)
                else:
                    self._apply_revocation(conn, event)
                if fail_after_apply:
                    raise RuntimeError('injected consumer crash before receipt')
                self.storage.record_consumer_receipt(conn,self.actor.subject_id,event['outbox_id'],event['domain'],action)
                self.storage.mark_outbox_processed(conn,[event['outbox_id']])
            return len(events)

    def _apply_publication(self, conn, event):
        # Application is durable in consumer_assets and therefore atomic with receipt;
        # the persisted lineage ties the asset to its publication and governance versions.
        payload = event['payload'] if isinstance(event['payload'], dict) else json.loads(event['payload'])
        lineage = {
            'publication_id': str(event['aggregate_id']),
            'source_bindings': payload.get('asset_lineage', {}).get('source_bindings', []),
            'governance_version_ids': payload.get('governance_version_ids', []),
        }
        conn.execute('''INSERT INTO knowledge_consumer_assets
            (consumer_id,publication_id,tenant_id,domain,acl,purpose,active,asset_version,asset_kind,intended_use,lineage)
            SELECT %s,%s,%s,%s,%s,%s,
                   (NOT EXISTS (SELECT 1 FROM knowledge_tombstones t WHERE t.publication_id=%s)
                    AND (SELECT p.valid_until FROM knowledge_publications p WHERE p.publication_id=%s) > clock_timestamp()),
                   1,'knowledge_publication',%s,%s
            ON CONFLICT(consumer_id,publication_id) DO UPDATE SET active=EXCLUDED.active
            WHERE knowledge_consumer_assets.active=true
              AND NOT EXISTS (SELECT 1 FROM knowledge_tombstones t WHERE t.publication_id=EXCLUDED.publication_id)
              AND (SELECT p.valid_until FROM knowledge_publications p WHERE p.publication_id=EXCLUDED.publication_id) > clock_timestamp()''',
            (self.actor.subject_id,event['aggregate_id'],event['tenant_id'],event['domain'],
             [self.actor.subject_id],event['purpose'],event['aggregate_id'],event['aggregate_id'],
             event['purpose'],json.dumps(lineage)))

    def _apply_revocation(self, conn, event):
        # Deactivate this consumer's applied asset; consumers without an applied
        # asset only record the tombstone receipt, never a fabricated asset row.
        conn.execute('UPDATE knowledge_consumer_assets SET active=false'
                     ' WHERE consumer_id=%s AND publication_id=%s',
                     (self.actor.subject_id, event['aggregate_id']))

    def active_publication_ids(self, now: datetime | None = None) -> tuple[UUID, ...]:
        now = now or datetime.now(timezone.utc)
        with psycopg.connect(self.storage.connection_uri) as conn:
            self.storage.set_session_identity(conn,self.actor)
            # v2 semantics: the consumer's own active assets joined to publications
            # that are not revoked (no tombstone) and not expired. Authoritative
            # source and governance invalidations are reflected via tombstones and
            # asset deactivations committed by the governance service.
            rows = conn.execute('''SELECT p.publication_id FROM knowledge_consumer_assets a
                JOIN knowledge_publications p ON (p.tenant_id,p.domain,p.publication_id)=(a.tenant_id,a.domain,a.publication_id)
                WHERE a.consumer_id=%s AND a.active AND p.valid_until>%s
                AND NOT EXISTS (SELECT 1 FROM knowledge_tombstones t WHERE t.publication_id=p.publication_id)
                ORDER BY p.publication_id''',(self.actor.subject_id,now)).fetchall()
            admitted=[]
            for (publication_id,) in rows:
                try:
                    with conn.transaction():
                        # Row lock + savepoint keep per-row inspection independent.
                        locked = conn.execute(
                            'SELECT 1 FROM knowledge_publications WHERE publication_id=%s FOR SHARE',
                            (publication_id,)).fetchone()
                        if locked is not None:
                            admitted.append(publication_id)
                except psycopg.Error:
                    # A failed row must not hide other independent authorized assets.
                    continue
            return tuple(admitted)
