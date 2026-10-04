"""Independent decrypt/extract/PG worker and idempotent outbox consumption.

The input boundary is encrypted spool, never an extra prompt supplied by a test.
The built-in entity recognizer supports explicit Chinese organization suffixes;
it does not claim production NER quality or automatic fact verification.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import re
from uuid import NAMESPACE_URL, UUID, uuid5

import psycopg

from infra.envelope_crypto import KmsProvider
from infra.spool_relay import LedgerSink, SpoolRelay
from knowledge.extractor import RelationExtractor
from knowledge.knowledge import Entity, KnowledgeError, Source, TrustedActor
from knowledge.knowledge_events import ObservationEvent
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
    def __init__(self, storage: PostgresKnowledgeStorage, actor: TrustedActor,
                 *, processing_acl: tuple[str, ...] = ()):
        self.storage, self.actor, self.processing_acl = storage, actor, processing_acl

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
        with psycopg.connect(self.storage.connection_uri) as conn:
            self._scope(conn)
            self.storage.save_source(conn, source)
            inserted = conn.execute('''INSERT INTO knowledge_observations
                (dedup_key,tenant_id,domain,acl,purpose,source_id,source_version,candidate_ids)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(dedup_key) DO NOTHING RETURNING dedup_key''',
                (dedup_key,event.tenant,event.domain,list(event.acl),event.purpose,event.source_id,event.source_version,
                 [c.candidate_id for c in candidates])).fetchone()
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
    active governed rows, so tombstones/expiry prevent stale snapshot re-use.
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
                # Application is durable in consumer_assets and therefore atomic with receipt.
                conn.execute('''INSERT INTO knowledge_consumer_assets
                    (consumer_id,publication_id,tenant_id,domain,acl,purpose,active)
                    VALUES(%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT(consumer_id,publication_id) DO UPDATE SET active=EXCLUDED.active''',
                    (self.actor.subject_id,event['aggregate_id'],event['tenant_id'],event['domain'],
                     [self.actor.subject_id],event['purpose'],action=='publication_applied'))
                if fail_after_apply:
                    raise RuntimeError('injected consumer crash before receipt')
                self.storage.record_consumer_receipt(conn,self.actor.subject_id,event['outbox_id'],event['domain'],action)
                self.storage.mark_outbox_processed(conn,[event['outbox_id']])
            return len(events)

    def active_publication_ids(self, now: datetime | None = None) -> tuple[UUID, ...]:
        now = now or datetime.now(timezone.utc)
        with psycopg.connect(self.storage.connection_uri) as conn:
            self.storage.set_session_identity(conn,self.actor)
            rows = conn.execute('''SELECT a.publication_id,p.candidate_id FROM knowledge_consumer_assets a
                JOIN knowledge_publications p ON (p.tenant_id,p.domain,p.publication_id)=(a.tenant_id,a.domain,a.publication_id)
                JOIN knowledge_candidates c ON c.candidate_id=p.candidate_id
                WHERE a.consumer_id=%s AND a.active AND p.valid_until>%s AND c.state='published'
                AND NOT EXISTS (SELECT 1 FROM knowledge_tombstones t WHERE t.publication_id=p.publication_id)
                AND NOT EXISTS (SELECT 1 FROM candidate_evidence_links l JOIN knowledge_evidence e ON e.evidence_id=l.evidence_id
                    JOIN knowledge_sources s ON (s.tenant_id,s.domain,s.source_id,s.version)=(e.tenant_id,e.domain,e.source_id,e.version)
                    WHERE l.candidate_id=p.candidate_id AND (s.withdrawn OR s.retention_until<=%s))''',
                (self.actor.subject_id,now,now)).fetchall()
            admitted=[]
            for publication_id,candidate_id in rows:
                try:
                    with conn.transaction():
                        self.storage.load_candidate(conn,candidate_id)
                except KnowledgeError:
                    # Read denial aborts the current SQL transaction. A savepoint
                    # keeps subsequent independent authorized assets inspectable.
                    continue
                admitted.append(publication_id)
            return tuple(admitted)
