"""Single-admin governance service v2 contract tests against real PostgreSQL.

Schema v2 removed the persisted two-reviewer approval flow entirely; durable
governance mutations are bound to recorded single-admin actions. These tests
exercise the v2 governance service end to end on an isolated real schema:
admin-direct publish, multi-source authorization intersection, idempotent
publication, supersession/withdrawal cascades, availability against actual
outbox/receipt state, and stable pagination.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import unittest
from uuid import UUID, uuid4

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from detection.dictionary import compile_dictionary
from knowledge.governance import (
    AdminActionContext,
    GovernanceError,
    KnowledgeGovernanceService,
    asset_invalidation_verdict,
    delivery_snapshot,
    eligibility_verdict,
    governance_status_label,
    merge_blocking_reasons,
)
from knowledge.knowledge import TrustedActor
from knowledge.storage import PostgresKnowledgeStorage
from tests.pg_support import prepare_test_database, test_configuration

_HEX = '0123456789abcdef'


class GovernancePgTestCase(unittest.TestCase):
    """Shared real-PG fixture for v2 governance service tests."""

    @classmethod
    def setUpClass(cls):
        prepare_test_database()
        cls.config = test_configuration()

    def setUp(self):
        self.tenant = 'tenant-a'
        self.domain = 'gov-' + uuid4().hex[:12]
        self.now = datetime.now(timezone.utc)
        self.storage = PostgresKnowledgeStorage(
            self.config['app_dsn'], tenant_id=self.tenant, domain=self.domain,
            admin_dsn=self.config['admin_app_dsn'], admin_role=self.config['admin_role'])
        self.service = KnowledgeGovernanceService(
            tenant_id=self.tenant, domain=self.domain, storage=self.storage)
        self.context = AdminActionContext(
            actor_id='admin', session_digest=sha256(b'admin-session').hexdigest(),
            tenant_id=self.tenant, domain=self.domain)

    # ------------------------------------------------------------------
    # Connection and seeding helpers
    # ------------------------------------------------------------------
    @contextmanager
    def admin_conn(self, *, admin_context=True):
        conn = psycopg.connect(self.config['admin_app_dsn'])
        try:
            conn.execute(sql.SQL('SET LOCAL ROLE {}').format(sql.Identifier(self.config['admin_role'])))
            conn.execute("SELECT set_config('app.tenant',%s,true)", (self.tenant,))
            conn.execute("SELECT set_config('app.domain',%s,true)", (self.domain,))
            if admin_context:
                conn.execute("SELECT set_config('app.admin_context','true',true)")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def seed_source(self, conn, source_id, *, version='v1', acl=None, purpose='knowledge',
                    kind='document', verified=True, retention_days=60, withdrawn=False,
                    observed=None):
        acl = list(acl if acl is not None else ('procurement', 'legal'))
        conn.execute(
            "INSERT INTO knowledge_sources(tenant_id,domain,source_id,version,source_kind,acl,purpose,"
            "observed_at,retention_until,independence_verified,withdrawn)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (self.tenant, self.domain, source_id, version, kind, acl, purpose,
             observed or self.now, self.now + timedelta(days=retention_days), verified, withdrawn))

    def seed_candidate(self, conn, *source_keys, subject='甲公司', obj='乙公司', acl=None,
                       purpose='knowledge', predicate='supplies', modality='asserted',
                       state='proposed', candidate_id=None):
        candidate_id = candidate_id or uuid4()
        entities = {}
        for name in (subject, obj):
            row = conn.execute(
                "INSERT INTO knowledge_entities(entity_id,tenant_id,domain,entity_type,name,acl,purpose)"
                " VALUES (%s,%s,%s,'ORG',%s,%s,%s) ON CONFLICT (tenant_id,domain,entity_type,name)"
                " DO NOTHING RETURNING entity_id",
                (uuid4(), self.tenant, self.domain, name,
                 list(acl or ('procurement', 'legal')), purpose)).fetchone()
            if row is None:
                row = conn.execute(
                    "SELECT entity_id FROM knowledge_entities"
                    " WHERE (tenant_id,domain,entity_type,name)=(%s,%s,'ORG',%s)",
                    (self.tenant, self.domain, name)).fetchone()
            entities[name] = row[0]
        claim_id = conn.execute(
            "INSERT INTO knowledge_claims(tenant_id,domain,subject_id,predicate,object_id,polarity,modality,acl,purpose)"
            " VALUES (%s,%s,%s,%s,%s,'positive',%s,%s,%s)"
            " ON CONFLICT (tenant_id,domain,subject_id,predicate,object_id,polarity,modality)"
            " DO NOTHING RETURNING claim_id",
            (self.tenant, self.domain, entities[subject], predicate, entities[obj], modality,
             list(acl or ('procurement', 'legal')), purpose)).fetchone()
        if claim_id is None:
            claim_id = conn.execute(
                "SELECT claim_id FROM knowledge_claims"
                " WHERE (tenant_id,domain,subject_id,predicate,object_id,polarity,modality)"
                "=(%s,%s,%s,%s,%s,'positive',%s)",
                (self.tenant, self.domain, entities[subject], predicate, entities[obj],
                 modality)).fetchone()
        claim_id = claim_id[0]
        conn.execute(
            "INSERT INTO knowledge_candidates(candidate_id,claim_id,tenant_id,domain,acl,purpose,state)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (candidate_id, claim_id, self.tenant, self.domain,
             list(acl or ('procurement', 'legal')), purpose, state))
        for index, key in enumerate(source_keys):
            source_id, version = (key if isinstance(key, tuple) else (key, 'v1'))
            digest = sha256(f'{self.domain}:{source_id}:{version}:{index}'.encode()).hexdigest()
            evidence_id = conn.execute(
                "INSERT INTO knowledge_evidence(tenant_id,domain,source_id,version,content_sha256,char_start,char_end,acl,purpose)"
                " VALUES (%s,%s,%s,%s,%s,0,5,%s,%s) RETURNING evidence_id",
                (self.tenant, self.domain, source_id, version, digest,
                 list(acl or ('procurement', 'legal')), purpose)).fetchone()[0]
            conn.execute(
                "INSERT INTO candidate_evidence_links(candidate_id,evidence_id,tenant_id,domain,acl,purpose)"
                " VALUES (%s,%s,%s,%s,%s,%s)",
                (candidate_id, evidence_id, self.tenant, self.domain,
                 list(acl or ('procurement', 'legal')), purpose))
        return candidate_id

    # ------------------------------------------------------------------
    # Service call helpers
    # ------------------------------------------------------------------
    def confirm(self, source_id, *, version='v1', expected=None, audiences=('legal',),
                use='knowledge', ownership='confirmed', valid_days=30, basis='verified'):
        return self.service.confirm_source_governance(
            source_id, source_version=version, expected_governance_version=expected,
            ownership=ownership, use=use, audiences=audiences,
            valid_until=self.now + timedelta(days=valid_days), basis=basis, context=self.context)

    def publish(self, candidate_id, *, version=1, use='knowledge', audiences=('legal',),
                valid_days=30, key=None, basis='ok'):
        return self.service.publish_candidate(
            candidate_id, expected_version=version, use=use, audiences=audiences,
            valid_until=self.now + timedelta(days=valid_days), idempotency_key=key,
            basis=basis, context=self.context)

    def consumer(self, subject, *purposes):
        return TrustedActor(subject, self.tenant, self.domain, frozenset(),
                            frozenset(purposes or ('knowledge',)))

    @staticmethod
    def fresh_now():
        return datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    # Assertion helpers
    # ------------------------------------------------------------------
    def admin_actions(self, *, action_type=None, result=None, object_id=None):
        query = ("SELECT action_type,object_type,object_id,object_version,rationale,intended_use,"
                 "consumer_audiences,result FROM knowledge_admin_actions"
                 " WHERE tenant_id=%s AND domain=%s")
        params = [self.tenant, self.domain]
        if action_type is not None:
            query += " AND action_type=%s"
            params.append(action_type)
        if result is not None:
            query += " AND result=%s"
            params.append(result)
        if object_id is not None:
            query += " AND object_id=%s"
            params.append(str(object_id))
        query += " ORDER BY created_at,admin_action_id"
        with self.admin_conn() as conn:
            return conn.execute(query, params).fetchall()

    def publication_row(self, publication_id):
        with self.admin_conn() as conn:
            return conn.cursor(row_factory=dict_row).execute(
                "SELECT * FROM knowledge_publications WHERE publication_id=%s",
                (publication_id,)).fetchone()

    def outbox_events(self, publication_id):
        with self.admin_conn() as conn:
            return conn.cursor(row_factory=dict_row).execute(
                "SELECT event_type,status,payload,acl,created_at,processed_at FROM knowledge_outbox"
                " WHERE aggregate_id=%s ORDER BY created_at", (publication_id,)).fetchall()


class TestAvailabilityDecisionFunctions(unittest.TestCase):
    """Design §3.2 verdict columns are pure functions over authoritative state."""

    def test_merge_blocking_reasons_dedupes_in_order(self):
        self.assertEqual(('SOURCE_WITHDRAWN', 'AUDIENCE_DENIED'),
                         merge_blocking_reasons(['SOURCE_WITHDRAWN', 'SOURCE_WITHDRAWN',
                                                 'AUDIENCE_DENIED']))

    def test_governance_status_label(self):
        self.assertEqual('rejected', governance_status_label('rejected', False, False))
        self.assertEqual('unconfirmed', governance_status_label('proposed', False, False))
        self.assertEqual('publishable', governance_status_label('published', True, False))
        self.assertEqual('superseded', governance_status_label('published', False, True))
        self.assertEqual('unconfirmed', governance_status_label('published', False, False))

    def test_eligibility_verdict(self):
        now = datetime.now(timezone.utc)
        future = now + timedelta(days=1)
        base = dict(consumer='reader', use='knowledge', consumer_audiences=('reader',),
                    intended_use='knowledge', valid_until=future, now=now,
                    blocking_reasons=(), evidence_status='available')
        self.assertEqual('not_evaluated', eligibility_verdict(**{**base, 'consumer': None}))
        self.assertEqual('not_evaluated', eligibility_verdict(**{**base, 'use': None}))
        self.assertEqual('eligible', eligibility_verdict(**base))
        self.assertEqual('ineligible',
                         eligibility_verdict(**{**base, 'consumer': 'outsider'}))
        self.assertEqual('ineligible', eligibility_verdict(**{**base, 'use': 'other'}))
        self.assertEqual('ineligible',
                         eligibility_verdict(**{**base, 'valid_until': now - timedelta(seconds=1)}))
        self.assertEqual('ineligible',
                         eligibility_verdict(**{**base, 'blocking_reasons': ('SOURCE_WITHDRAWN',)}))
        self.assertEqual('unknown',
                         eligibility_verdict(**{**base, 'evidence_status': 'unknown'}))

    def test_delivery_snapshot_precedence(self):
        now = datetime.now(timezone.utc)
        events = [{'event_type': 'KNOWLEDGE_PUBLISHED', 'status': 'pending',
                   'created_at': now, 'processed_at': None, 'acl': ('reader',)}]
        status, pending, last_attempt, last_error = delivery_snapshot(
            tombstoned=False, events=events, receipts=[], asset_consumers=[])
        self.assertEqual(('pending', 1, None, None), (status, pending, last_attempt, last_error))
        receipts = [{'event_type': 'KNOWLEDGE_PUBLISHED', 'consumer_id': 'reader',
                     'received_at': now, 'last_error_code': None}]
        status, pending, last_attempt, _ = delivery_snapshot(
            tombstoned=False, events=[{**events[0], 'status': 'processed',
                                       'processed_at': now}], receipts=receipts,
            asset_consumers=['reader'])
        self.assertEqual(('applied', 0, now), (status, pending, last_attempt))
        status, _, _, _ = delivery_snapshot(
            tombstoned=True,
            events=events + [{'event_type': 'KNOWLEDGE_REVOKED', 'status': 'pending',
                              'created_at': now, 'processed_at': None, 'acl': ('reader',)}],
            receipts=receipts, asset_consumers=['reader'])
        self.assertEqual('invalidation_pending', status)
        status, _, _, _ = delivery_snapshot(
            tombstoned=True, events=events, receipts=receipts + [
                {'event_type': 'KNOWLEDGE_REVOKED', 'consumer_id': 'reader',
                 'received_at': now, 'last_error_code': None}], asset_consumers=['reader'])
        self.assertEqual('applied', status)
        status, _, _, error = delivery_snapshot(
            tombstoned=False, events=events,
            receipts=[{'event_type': 'KNOWLEDGE_PUBLISHED', 'consumer_id': 'reader',
                       'received_at': now, 'last_error_code': 'DELIVERY_FAILED'}],
            asset_consumers=['reader'])
        self.assertEqual(('failed', 'DELIVERY_FAILED'), (status, error))

    def test_asset_invalidation_verdict(self):
        self.assertEqual('active', asset_invalidation_verdict(active=True, revoke_receipted=False))
        self.assertEqual('invalidated', asset_invalidation_verdict(active=False, revoke_receipted=True))
        self.assertEqual('invalidation_pending',
                         asset_invalidation_verdict(active=False, revoke_receipted=False))


class TestSingleAdminGovernance(GovernancePgTestCase):
    """Admin-direct governance on real PG: the two-person flow is gone."""

    def test_admin_direct_publish_success_without_second_actor(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
            candidate_id = self.seed_candidate(conn, 'src-a')
        gv = self.confirm('src-a', audiences=('reader',))
        publication_id = self.publish(candidate_id, audiences=('reader',))
        row = self.publication_row(UUID(publication_id))
        self.assertEqual(candidate_id, row['candidate_id'])
        self.assertEqual(1, row['candidate_version'])
        self.assertEqual('knowledge', row['intended_use'])
        self.assertEqual(['reader'], row['consumer_audiences'])
        events = self.outbox_events(UUID(publication_id))
        self.assertEqual(['KNOWLEDGE_PUBLISHED'], [e['event_type'] for e in events])
        self.assertEqual(str(gv), events[0]['payload']['governance_version_ids'][0])
        actions = self.admin_actions(action_type='publish', result='succeeded',
                                     object_id=candidate_id)
        self.assertEqual(1, len(actions))
        self.assertEqual('candidate', actions[0][1])
        self.assertEqual('1', actions[0][3])

    def test_publish_requires_audience_intersection(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a', acl=('procurement', 'legal'))
            self.seed_source(conn, 'src-b', acl=('legal',))
            candidate_id = self.seed_candidate(conn, 'src-a', 'src-b', acl=('legal',))
        self.confirm('src-a', audiences=('procurement', 'legal'))
        self.confirm('src-b', audiences=('legal',))
        publication_id = self.publish(candidate_id, audiences=('legal',))
        self.assertTrue(publication_id)
        with self.assertRaises(GovernanceError) as cm:
            self.publish(candidate_id, audiences=('procurement',), key='k2', basis='x')
        self.assertEqual('KNOWLEDGE_PUBLISH_REJECTED', cm.exception.code)
        self.assertEqual(('AUDIENCE_DENIED',), cm.exception.blocking_reasons)

    def test_publish_rejects_empty_audience_list(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
            candidate_id = self.seed_candidate(conn, 'src-a', acl=('legal',))
        self.confirm('src-a')
        with self.assertRaises(GovernanceError) as cm:
            self.publish(candidate_id, audiences=())
        self.assertEqual(('AUDIENCE_DENIED',), cm.exception.blocking_reasons)

    def test_publish_rejects_when_intersection_empty(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a', acl=('alpha',))
            self.seed_source(conn, 'src-b', acl=('beta',))
            candidate_id = self.seed_candidate(conn, 'src-a', 'src-b', acl=('alpha',))
        self.confirm('src-a', audiences=('alpha',))
        self.confirm('src-b', audiences=('beta',))
        with self.assertRaises(GovernanceError) as cm:
            self.publish(candidate_id, audiences=('alpha',))
        self.assertEqual(('AUDIENCE_DENIED',), cm.exception.blocking_reasons)

    def test_publish_rejects_missing_governance(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
            candidate_id = self.seed_candidate(conn, 'src-a', acl=('legal',))
        self.confirm('src-a')
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-b', acl=('legal',))
            other = str(uuid4())
            conn.execute(
                "INSERT INTO knowledge_evidence(tenant_id,domain,source_id,version,content_sha256,char_start,char_end,acl,purpose)"
                " VALUES (%s,%s,'src-b','v1',%s,0,5,ARRAY['legal'],'knowledge')",
                (self.tenant, self.domain, 'b' * 64))
            evidence_id = conn.execute(
                "SELECT evidence_id FROM knowledge_evidence WHERE source_id='src-b'").fetchone()[0]
            conn.execute(
                "INSERT INTO candidate_evidence_links(candidate_id,evidence_id,tenant_id,domain,acl,purpose)"
                " VALUES (%s,%s,%s,%s,ARRAY['legal'],'knowledge')",
                (candidate_id, evidence_id, self.tenant, self.domain))
        with self.assertRaises(GovernanceError) as cm:
            self.publish(candidate_id, audiences=('legal',))
        self.assertEqual(('GOVERNANCE_MISSING',), cm.exception.blocking_reasons)

    def test_publish_rejects_purpose_mismatch(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
            candidate_id = self.seed_candidate(conn, 'src-a', acl=('legal',))
        self.confirm('src-a', use='knowledge')
        with self.assertRaises(GovernanceError) as cm:
            self.publish(candidate_id, use='marketing', audiences=('legal',))
        self.assertEqual(('PURPOSE_DENIED',), cm.exception.blocking_reasons)

    def test_publish_rejects_expired_source(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a', acl=('legal',))
            candidate_id = self.seed_candidate(conn, 'src-a', acl=('legal',))
        self.confirm('src-a')
        past = self.now - timedelta(days=2)
        with self.admin_conn() as conn:
            conn.execute(
                "UPDATE knowledge_sources SET observed_at=%s, retention_until=%s"
                " WHERE source_id='src-a'", (past - timedelta(days=1), past))
        with self.assertRaises(GovernanceError) as cm:
            self.publish(candidate_id, audiences=('legal',))
        self.assertEqual(('SOURCE_EXPIRED',), cm.exception.blocking_reasons)

    def test_publish_rejects_withdrawn_source(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
            candidate_id = self.seed_candidate(conn, 'src-a', acl=('legal',))
        self.confirm('src-a')
        self.service.withdraw_source('src-a', source_version='v1', basis='compromised',
                                     context=self.context)
        with self.assertRaises(GovernanceError) as cm:
            self.publish(candidate_id, audiences=('legal',))
        self.assertEqual('KNOWLEDGE_CANDIDATE_VERSION_CONFLICT', cm.exception.code)
        # A candidate proposed after its source was withdrawn hits the source blocker;
        # its governance version predates the withdrawal (confirmation of a
        # withdrawn source is refused, which the confirm path above covers).
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-b', acl=('legal',), withdrawn=True)
            late_candidate = self.seed_candidate(conn, 'src-b', acl=('legal',))
            action_id = uuid4()
            conn.execute(
                "INSERT INTO knowledge_admin_actions(admin_action_id,tenant_id,domain,actor_id,"
                "session_digest,action_type,object_type,object_id,object_version,rationale,result)"
                " VALUES (%s,%s,%s,'admin','ab','governance_confirm','source','src-b','v1','pre','succeeded')",
                (action_id, self.tenant, self.domain))
            conn.execute(
                "INSERT INTO knowledge_governance_versions(governance_version_id,tenant_id,domain,"
                "source_id,source_version,admin_action_id,ownership_confirmed,intended_use,"
                "consumer_audiences,valid_until,rationale)"
                " VALUES (%s,%s,%s,'src-b','v1',%s,true,'knowledge',ARRAY['legal'],%s,'pre')",
                (uuid4(), self.tenant, self.domain, action_id,
                 self.now + timedelta(days=1)))
        with self.assertRaises(GovernanceError) as cm:
            self.publish(late_candidate, audiences=('legal',))
        self.assertEqual(('SOURCE_WITHDRAWN',), cm.exception.blocking_reasons)

    def test_publish_rejects_inactive_candidate_state(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
            candidate_id = self.seed_candidate(conn, 'src-a', acl=('legal',),
                                               state='rejected')
        self.confirm('src-a')
        with self.assertRaises(GovernanceError) as cm:
            self.publish(candidate_id, audiences=('legal',))
        self.assertEqual('KNOWLEDGE_CANDIDATE_VERSION_CONFLICT', cm.exception.code)

    def test_publish_version_conflict_returns_fixed_code(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
            candidate_id = self.seed_candidate(conn, 'src-a', acl=('legal',))
        self.confirm('src-a')
        with self.assertRaises(GovernanceError) as cm:
            self.publish(candidate_id, version=7, audiences=('legal',))
        self.assertEqual('KNOWLEDGE_CANDIDATE_VERSION_CONFLICT', cm.exception.code)

    def test_publish_unknown_candidate_returns_fixed_code(self):
        with self.assertRaises(GovernanceError) as cm:
            self.publish(str(uuid4()), audiences=('legal',))
        self.assertEqual('KNOWLEDGE_CANDIDATE_NOT_FOUND', cm.exception.code)

    def test_publish_validity_beyond_governance_bound_rejected(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
            candidate_id = self.seed_candidate(conn, 'src-a', acl=('legal',))
        self.confirm('src-a', valid_days=10)
        with self.assertRaises(GovernanceError) as cm:
            self.publish(candidate_id, audiences=('legal',), valid_days=30)
        self.assertEqual('KNOWLEDGE_VALIDITY_EXCEEDS_SOURCE', cm.exception.code)

    def test_publish_idempotent_retry_returns_same_publication(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
            candidate_id = self.seed_candidate(conn, 'src-a', acl=('legal',))
        self.confirm('src-a')
        first = self.publish(candidate_id, audiences=('legal',), key='req-1')
        retry = self.publish(candidate_id, audiences=('legal',), key='req-1')
        self.assertEqual(first, retry)
        events = self.outbox_events(UUID(first))
        self.assertEqual(1, len(events))
        self.assertEqual([], self.admin_actions(action_type='publish', object_id=candidate_id)[1:])

    def test_publish_same_version_without_key_conflicts(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
            candidate_id = self.seed_candidate(conn, 'src-a', acl=('legal',))
        self.confirm('src-a')
        self.publish(candidate_id, audiences=('legal',), key='req-1')
        with self.assertRaises(GovernanceError) as cm:
            self.publish(candidate_id, audiences=('legal',), key='req-2')
        self.assertEqual('KNOWLEDGE_CANDIDATE_VERSION_CONFLICT', cm.exception.code)

    def test_confirm_first_version_and_conflict_codes(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
        gv1 = self.confirm('src-a', expected=None)
        self.assertTrue(gv1)
        with self.assertRaises(GovernanceError) as cm:
            self.confirm('src-a', expected=None)
        self.assertEqual('KNOWLEDGE_GOVERNANCE_VERSION_CONFLICT', cm.exception.code)
        with self.assertRaises(GovernanceError) as cm:
            self.confirm('src-a', expected=str(uuid4()))
        self.assertEqual('KNOWLEDGE_GOVERNANCE_VERSION_CONFLICT', cm.exception.code)

    def test_confirm_rejects_missing_withdrawn_and_expired_sources(self):
        with self.assertRaises(GovernanceError) as cm:
            self.confirm('missing')
        self.assertEqual('KNOWLEDGE_SOURCE_NOT_FOUND', cm.exception.code)
        past = self.now - timedelta(days=2)
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-w', withdrawn=True)
            self.seed_source(conn, 'src-e', acl=('legal',), observed=past,
                             retention_days=-1)
        with self.assertRaises(GovernanceError) as cm:
            self.confirm('src-w')
        self.assertEqual('KNOWLEDGE_SOURCE_WITHDRAWN', cm.exception.code)
        with self.assertRaises(GovernanceError) as cm:
            self.confirm('src-e')
        self.assertEqual('KNOWLEDGE_SOURCE_EXPIRED', cm.exception.code)

    def test_confirm_validity_exceeds_source_retention(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a', retention_days=7)
        with self.assertRaises(GovernanceError) as cm:
            self.confirm('src-a', valid_days=30)
        self.assertEqual('KNOWLEDGE_VALIDITY_EXCEEDS_SOURCE', cm.exception.code)

    def test_superseding_governance_cascades_invalidation(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
            candidate_id = self.seed_candidate(conn, 'src-a', acl=('legal',))
        gv1 = self.confirm('src-a', audiences=('reader',))
        publication_id = self.publish(candidate_id, audiences=('reader',))
        gv2 = self.confirm('src-a', expected=gv1, audiences=('reader', 'legal'))
        self.assertTrue(gv2)
        row = self.publication_row(UUID(publication_id))
        self.assertIsNotNone(row)
        with self.admin_conn() as conn:
            self.assertIsNotNone(conn.execute(
                "SELECT 1 FROM knowledge_tombstones WHERE publication_id=%s",
                (publication_id,)).fetchone())
            self.assertEqual([], conn.execute(
                "SELECT consumer_id FROM knowledge_consumer_assets WHERE publication_id=%s"
                " AND active", (publication_id,)).fetchall())
        events = self.outbox_events(UUID(publication_id))
        revoked = [e for e in events if e['event_type'] == 'KNOWLEDGE_REVOKED']
        self.assertEqual(1, len(revoked))
        self.assertEqual(str(gv1), revoked[0]['payload']['governance_version_ids'][0])
        self.assertEqual(str(gv1), revoked[0]['payload']['asset_lineage']['source_bindings'][0]['governance_version_id'])
        self.assertEqual('src-a', revoked[0]['payload']['asset_lineage']['source_bindings'][0]['source_id'])
        jsonl = self.service.export_versioned_jsonl(
            [publication_id], self.consumer('reader'), 'v1', self.fresh_now())
        self.assertEqual('', jsonl)

    def test_withdraw_source_cascades_and_retains_original_acl(self):
        restricted = f'{self.domain}:restricted-candidate'
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a', acl=(restricted,), verified=False)
            candidate_id = self.seed_candidate(conn, 'src-a', acl=(restricted,))
        gv = self.confirm('src-a', audiences=('reader',))
        publication_id = self.publish(candidate_id, audiences=('reader',))
        self.service.withdraw_source('src-a', source_version='v1', basis='compromised',
                                     context=self.context)
        with self.admin_conn() as conn:
            source = conn.cursor(row_factory=dict_row).execute(
                "SELECT acl,withdrawn FROM knowledge_sources WHERE source_id='src-a'").fetchone()
            self.assertEqual([restricted], source['acl'])
            self.assertTrue(source['withdrawn'])
            candidate = conn.execute(
                "SELECT state FROM knowledge_candidates WHERE candidate_id=%s",
                (candidate_id,)).fetchone()
            self.assertEqual('withdrawn', candidate[0])
            self.assertIsNotNone(conn.execute(
                "SELECT 1 FROM knowledge_tombstones WHERE publication_id=%s",
                (publication_id,)).fetchone())
        self.assertEqual('', self.service.export_versioned_jsonl(
            [publication_id], self.consumer('reader'), 'v1', self.fresh_now()))
        actions = self.admin_actions(action_type='withdraw', result='succeeded')
        self.assertEqual(1, len(actions))

    def test_withdraw_unknown_and_repeat_withdrawn_codes(self):
        with self.assertRaises(GovernanceError) as cm:
            self.service.withdraw_source('missing', source_version='v1', basis='x',
                                         context=self.context)
        self.assertEqual('KNOWLEDGE_SOURCE_NOT_FOUND', cm.exception.code)
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a', withdrawn=True)
        with self.assertRaises(GovernanceError) as cm:
            self.service.withdraw_source('src-a', source_version='v1', basis='x',
                                         context=self.context)
        self.assertEqual('KNOWLEDGE_SOURCE_WITHDRAWN', cm.exception.code)

    def test_revoke_publication_cascades(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
            candidate_id = self.seed_candidate(conn, 'src-a', acl=('legal',))
        self.confirm('src-a')
        publication_id = self.publish(candidate_id, audiences=('legal',))
        self.service.revoke_publication(publication_id, basis='steward request',
                                        context=self.context)
        with self.admin_conn() as conn:
            self.assertIsNotNone(conn.execute(
                "SELECT 1 FROM knowledge_tombstones WHERE publication_id=%s",
                (publication_id,)).fetchone())
            self.assertEqual('withdrawn', conn.execute(
                "SELECT state FROM knowledge_candidates WHERE candidate_id=%s",
                (candidate_id,)).fetchone()[0])
            self.assertEqual(1, conn.execute(
                "SELECT count(*) FROM knowledge_outbox WHERE aggregate_id=%s"
                " AND event_type='KNOWLEDGE_REVOKED'", (publication_id,)).fetchone()[0])
        # A repeated revoke is an idempotent no-op (no duplicate tombstones/outbox).
        self.service.revoke_publication(publication_id, basis='again',
                                        context=self.context)
        with self.admin_conn() as conn:
            self.assertEqual(1, conn.execute(
                "SELECT count(*) FROM knowledge_outbox WHERE aggregate_id=%s"
                " AND event_type='KNOWLEDGE_REVOKED'", (publication_id,)).fetchone()[0])
        with self.assertRaises(GovernanceError) as cm:
            self.service.revoke_publication(str(uuid4()), basis='x', context=self.context)
        self.assertEqual('KNOWLEDGE_PUBLICATION_NOT_FOUND', cm.exception.code)

    def test_revise_creates_new_version_and_republishes(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
            candidate_id = self.seed_candidate(conn, 'src-a', acl=('legal',))
        self.confirm('src-a')
        self.publish(candidate_id, audiences=('legal',), key='req-1')
        revised_id = self.service.revise_candidate(
            candidate_id, modifications={'acl': ['legal']}, basis='fix scope',
            context=self.context)
        self.assertNotEqual(str(candidate_id), revised_id)
        with self.admin_conn() as conn:
            rows = conn.cursor(row_factory=dict_row).execute(
                "SELECT candidate_id,candidate_version,derived_from,state FROM knowledge_candidates"
                " WHERE claim_id=(SELECT claim_id FROM knowledge_candidates WHERE candidate_id=%s)",
                (candidate_id,)).fetchall()
            self.assertEqual(2, len(rows))
            old = next(r for r in rows if r['candidate_id'] == candidate_id)
            new = next(r for r in rows if str(r['candidate_id']) == revised_id)
            self.assertEqual((1, None, 'published'), (old['candidate_version'], old['derived_from'], old['state']))
            self.assertEqual((2, candidate_id, 'proposed'), (new['candidate_version'], new['derived_from'], new['state']))
        second = self.publish(revised_id, version=2, audiences=('legal',), key='req-2')
        self.assertTrue(second)

    def test_reject_candidate_blocks_publish_and_records_failure(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
            candidate_id = self.seed_candidate(conn, 'src-a', acl=('legal',))
        self.service.reject_candidate(candidate_id, basis='not a business fact',
                                      context=self.context)
        with self.admin_conn() as conn:
            self.assertEqual('rejected', conn.execute(
                "SELECT state FROM knowledge_candidates WHERE candidate_id=%s",
                (candidate_id,)).fetchone()[0])
        self.confirm('src-a')
        with self.assertRaises(GovernanceError) as cm:
            self.publish(candidate_id, audiences=('legal',))
        self.assertEqual('KNOWLEDGE_CANDIDATE_VERSION_CONFLICT', cm.exception.code)
        with self.assertRaises(GovernanceError) as cm:
            self.service.reject_candidate(str(uuid4()), basis='x', context=self.context)
        self.assertEqual('KNOWLEDGE_CANDIDATE_NOT_FOUND', cm.exception.code)
        failed = self.admin_actions(action_type='publish', result='failed',
                                    object_id=candidate_id)
        self.assertEqual(1, len(failed))

    def test_failed_admin_action_is_recorded_sanitized(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
            candidate_id = self.seed_candidate(conn, 'src-a', acl=('legal',))
        with self.assertRaises(GovernanceError):
            self.publish(candidate_id, audiences=('legal',))
        failed = self.admin_actions(action_type='publish', result='failed',
                                    object_id=candidate_id)
        self.assertEqual(1, len(failed))
        self.assertIn('GOVERNANCE_MISSING', failed[0][4])
        self.assertNotIn('SELECT', failed[0][4])
        self.assertEqual(0, len(self.admin_actions(action_type='publish',
                                                   result='succeeded',
                                                   object_id=candidate_id)))

    def test_publication_crash_before_commit_leaves_no_partial_state(self):
        from unittest.mock import patch
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
            candidate_id = self.seed_candidate(conn, 'src-a', acl=('legal',))
        self.confirm('src-a')
        with patch.object(self.storage, 'publish_in_transaction',
                          side_effect=RuntimeError('injected crash before commit')):
            with self.assertRaises(RuntimeError):
                self.publish(candidate_id, audiences=('legal',), key='crash-1')
        with self.admin_conn() as conn:
            self.assertEqual(0, conn.execute(
                "SELECT count(*) FROM knowledge_publications WHERE candidate_id=%s",
                (candidate_id,)).fetchone()[0])
            self.assertEqual(0, conn.execute(
                "SELECT count(*) FROM knowledge_outbox WHERE tenant_id=%s AND domain=%s",
                (self.tenant, self.domain)).fetchone()[0])
        retry = self.publish(candidate_id, audiences=('legal',), key='crash-1')
        self.assertTrue(retry)

    def test_admin_unavailable_without_storage(self):
        service = KnowledgeGovernanceService(tenant_id=self.tenant,
                                             domain=self.domain, storage=None)
        with self.assertRaises(GovernanceError) as cm:
            service.reject_candidate(str(uuid4()), basis='x', context=self.context)
        self.assertEqual('KNOWLEDGE_ADMIN_UNAVAILABLE', cm.exception.code)
        with self.assertRaises(GovernanceError) as cm:
            service.evaluate_availability(candidate_id=str(uuid4()), publication_id=None,
                                          consumer=None, use=None, now=self.fresh_now())
        self.assertEqual('KNOWLEDGE_ADMIN_UNAVAILABLE', cm.exception.code)

    def test_context_is_validated(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
        bad_scope = AdminActionContext(actor_id='admin', session_digest='ab' * 32,
                                       tenant_id='other', domain=self.domain)
        with self.assertRaises(Exception):
            self.service.confirm_source_governance(
                'src-a', source_version='v1', expected_governance_version=None,
                ownership='confirmed', use='knowledge', audiences=('legal',),
                valid_until=self.now + timedelta(days=1), basis='x', context=bad_scope)
        bad_actor = AdminActionContext(actor_id='sec-01', session_digest='ab' * 32,
                                       tenant_id=self.tenant, domain=self.domain)
        with self.assertRaises(Exception):
            self.service.confirm_source_governance(
                'src-a', source_version='v1', expected_governance_version=None,
                ownership='confirmed', use='knowledge', audiences=('legal',),
                valid_until=self.now + timedelta(days=1), basis='x', context=bad_actor)
        with self.admin_conn() as conn:
            self.assertEqual(0, conn.execute(
                "SELECT count(*) FROM knowledge_governance_versions WHERE domain=%s",
                (self.domain,)).fetchone()[0])


class TestGovernanceAuthorizationAndReuse(GovernancePgTestCase):
    """§8.1-1/§8.1-3/§8.1-5: explicit governance grants consumption; reuse is tracked."""

    def _restricted_setup(self):
        restricted = f'{self.domain}:restricted-candidate'
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-byok', acl=(restricted,), verified=False,
                             kind='user_assertion')
            candidate_id = self.seed_candidate(conn, 'src-byok', acl=(restricted,))
        return restricted, candidate_id

    def test_confirmed_consumer_reads_outside_original_acl(self):
        restricted, candidate_id = self._restricted_setup()
        self.confirm('src-byok', audiences=('reader',), use='procurement')
        publication_id = self.publish(candidate_id, audiences=('reader',),
                                      use='procurement')
        jsonl = self.service.export_versioned_jsonl(
            [publication_id], self.consumer('reader', 'procurement'), 'v1', self.fresh_now())
        records = [json.loads(line) for line in jsonl.splitlines() if line.strip()]
        self.assertEqual(1, len(records))
        self.assertEqual('甲公司', records[0]['subject']['name'])
        self.assertEqual('乙公司', records[0]['object']['name'])
        # Other consumers and other purposes are denied.
        self.assertEqual('', self.service.export_versioned_jsonl(
            [publication_id], self.consumer('outsider', 'procurement'), 'v1', self.fresh_now()))
        self.assertEqual('', self.service.export_versioned_jsonl(
            [publication_id], self.consumer('reader', 'knowledge'), 'v1', self.fresh_now()))
        # Original source row is untouched: ACL and trust flags unchanged.
        with self.admin_conn() as conn:
            source = conn.cursor(row_factory=dict_row).execute(
                "SELECT acl,independence_verified,withdrawn FROM knowledge_sources"
                " WHERE source_id='src-byok'").fetchone()
            self.assertEqual([restricted], source['acl'])
            self.assertFalse(source['independence_verified'])
            self.assertFalse(source['withdrawn'])
            candidate = conn.execute(
                "SELECT acl FROM knowledge_candidates WHERE candidate_id=%s",
                (candidate_id,)).fetchone()
            self.assertEqual([restricted], candidate[0])

    def test_availability_lifecycle_matches_outbox_and_receipts(self):
        from knowledge.worker import GovernedConsumer
        restricted, candidate_id = self._restricted_setup()
        self.confirm('src-byok', audiences=('reader',))
        publication_id = self.publish(candidate_id, audiences=('reader',))
        before = self.service.evaluate_availability(
            candidate_id=None, publication_id=publication_id, consumer=None, use=None,
            now=self.fresh_now())
        self.assertEqual('publishable', before.governance_status)
        self.assertEqual((), before.blocking_reasons)
        self.assertEqual('not_evaluated', before.eligibility)
        self.assertEqual('pending', before.delivery_status)
        self.assertEqual(1, before.pending_event_count)
        self.assertEqual((), before.reuse_assets)
        self.assertEqual('available', before.evidence_status)
        self.assertEqual(self.now.date(), before.evaluated_at.date())
        self.assertGreater(before.state_version, 0)

        consumer_storage = PostgresKnowledgeStorage(self.config['app_dsn'])
        consumer = GovernedConsumer(consumer_storage, self.consumer('reader'))
        self.assertEqual(1, consumer.consume_once())
        applied = self.service.evaluate_availability(
            candidate_id=None, publication_id=publication_id, consumer='reader',
            use='knowledge', now=self.fresh_now())
        self.assertEqual('eligible', applied.eligibility)
        self.assertEqual('applied', applied.delivery_status)
        self.assertEqual(0, applied.pending_event_count)
        self.assertEqual(1, len(applied.reuse_assets))
        asset = applied.reuse_assets[0]
        self.assertEqual('reader', asset.consumer_id)
        self.assertEqual(publication_id, asset.asset_id)
        self.assertEqual(1, asset.asset_version)
        self.assertTrue(asset.receipt_id)
        self.assertIsNotNone(asset.applied_at)
        self.assertEqual('active', asset.invalidation_status)
        self.assertIsNotNone(applied.last_attempt_at)

        self.service.withdraw_source('src-byok', source_version='v1', basis='revoked',
                                     context=self.context)
        revoked_view = self.service.evaluate_availability(
            candidate_id=None, publication_id=publication_id, consumer='reader',
            use='knowledge', now=self.fresh_now())
        self.assertEqual('superseded', revoked_view.governance_status)
        self.assertIn('PUBLICATION_REVOKED', revoked_view.blocking_reasons)
        self.assertIn('SOURCE_WITHDRAWN', revoked_view.blocking_reasons)
        self.assertEqual('ineligible', revoked_view.eligibility)
        self.assertEqual('invalidation_pending', revoked_view.delivery_status)
        self.assertEqual('invalidation_pending',
                         revoked_view.reuse_assets[0].invalidation_status)

        self.assertEqual(1, consumer.consume_once())
        invalidated = self.service.evaluate_availability(
            candidate_id=None, publication_id=publication_id, consumer='reader',
            use='knowledge', now=self.fresh_now())
        self.assertEqual('applied', invalidated.delivery_status)
        self.assertEqual('invalidated', invalidated.reuse_assets[0].invalidation_status)

    def test_superseded_availability_reports_blocking_reasons(self):
        _, candidate_id = self._restricted_setup()
        gv1 = self.confirm('src-byok', audiences=('reader',))
        publication_id = self.publish(candidate_id, audiences=('reader',))
        self.confirm('src-byok', expected=gv1, audiences=('reader',))
        view = self.service.evaluate_availability(
            candidate_id=None, publication_id=publication_id, consumer='reader',
            use='knowledge', now=self.fresh_now())
        self.assertEqual('superseded', view.governance_status)
        self.assertIn('GOVERNANCE_SUPERSEDED', view.blocking_reasons)
        self.assertIn('PUBLICATION_REVOKED', view.blocking_reasons)
        self.assertEqual('ineligible', view.eligibility)
        self.assertEqual('invalidation_pending', view.delivery_status)

    def test_unconfirmed_and_rejected_availability(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a')
            candidate_id = self.seed_candidate(conn, 'src-a', acl=('legal',))
        view = self.service.evaluate_availability(
            candidate_id=str(candidate_id), publication_id=None, consumer=None,
            use=None, now=self.fresh_now())
        self.assertEqual('unconfirmed', view.governance_status)
        self.assertEqual('not_evaluated', view.eligibility)
        self.assertEqual('not_dispatched', view.delivery_status)
        self.assertEqual((), view.reuse_assets)
        self.service.reject_candidate(candidate_id, basis='not relevant',
                                      context=self.context)
        rejected = self.service.evaluate_availability(
            candidate_id=str(candidate_id), publication_id=None, consumer=None,
            use=None, now=self.fresh_now())
        self.assertEqual('rejected', rejected.governance_status)
        self.assertEqual('ineligible', rejected.eligibility)

    def test_expired_publication_blocks_new_consumption(self):
        _, candidate_id = self._restricted_setup()
        self.confirm('src-byok', audiences=('reader',))
        publication_id = self.publish(candidate_id, audiences=('reader',),
                                      valid_days=1)
        later = self.fresh_now() + timedelta(days=2)
        self.assertEqual('', self.service.export_versioned_jsonl(
            [publication_id], self.consumer('reader'), 'v1', later))
        view = self.service.evaluate_availability(
            candidate_id=None, publication_id=publication_id, consumer='reader',
            use='knowledge', now=later)
        self.assertEqual('ineligible', view.eligibility)
        # Past the source retention the evidence dimension reports expiry.
        past_retention = self.fresh_now() + timedelta(days=65)
        expired_view = self.service.evaluate_availability(
            candidate_id=None, publication_id=publication_id, consumer='reader',
            use='knowledge', now=past_retention)
        self.assertEqual('expired', expired_view.evidence_status)
        self.assertEqual('ineligible', expired_view.eligibility)
        with self.assertRaises(GovernanceError) as cm:
            self.service.evaluate_availability(
                candidate_id=None, publication_id=str(uuid4()), consumer=None,
                use=None, now=self.fresh_now())
        self.assertEqual('KNOWLEDGE_PUBLICATION_NOT_FOUND', cm.exception.code)
        with self.assertRaises(GovernanceError) as cm:
            self.service.evaluate_availability(
                candidate_id=str(uuid4()), publication_id=None, consumer=None,
                use=None, now=self.fresh_now())
        self.assertEqual('KNOWLEDGE_CANDIDATE_NOT_FOUND', cm.exception.code)

    def test_export_and_dictionary_on_v2_model(self):
        _, candidate_id = self._restricted_setup()
        self.confirm('src-byok', audiences=('reader',))
        publication_id = self.publish(candidate_id, audiences=('reader',))
        jsonl = self.service.export_versioned_jsonl(
            [publication_id], self.consumer('reader'), 'v1', self.fresh_now())
        self.assertTrue(jsonl)
        payload = self.service.compile_approved_dictionary_payload(
            'dict-kb', 'v1.0.0', [publication_id], self.fresh_now(),
            consumer=self.consumer('reader'))
        self.assertEqual('dict-kb', payload['dictionary_id'])
        names = {entry['text'] for entry in payload['entries']}
        self.assertEqual({'甲公司', '乙公司'}, names)
        compiled = compile_dictionary(payload)
        self.assertEqual(2, len(compiled.entries))
        # An unauthorized consumer gets an empty export and empty dictionary.
        self.assertEqual('', self.service.export_versioned_jsonl(
            [publication_id], self.consumer('outsider'), 'v1', self.fresh_now()))
        self.assertEqual([], self.service.compile_approved_dictionary_payload(
            'dict-kb', 'v2', [publication_id], self.fresh_now(),
            consumer=self.consumer('outsider'))['entries'])


class TestGovernanceLists(GovernancePgTestCase):
    """Admin listings: stable pagination matching the history API shape."""

    def _seed_three(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'src-a', acl=('legal',), purpose='procurement')
            self.seed_source(conn, 'src-b', acl=('legal',), purpose='procurement')
            self.seed_source(conn, 'src-c', acl=('reader',), purpose='knowledge',
                             withdrawn=True)
            first = self.seed_candidate(conn, 'src-a', acl=('legal',),
                                        purpose='procurement')
            second = self.seed_candidate(conn, 'src-b', acl=('legal',),
                                         purpose='procurement', predicate='owned_by',
                                         subject='丙公司', obj='丁公司')
        self.confirm('src-a', audiences=('legal',), use='procurement')
        self.confirm('src-b', audiences=('legal',), use='procurement')
        pub1 = self.publish(first, audiences=('legal',), use='procurement')
        pub2 = self.publish(second, audiences=('legal',), use='procurement')
        return first, second, pub1, pub2

    def test_list_sources_filters_and_pagination(self):
        self._seed_three()
        items, cursor = self.service.list_sources()
        self.assertEqual(3, len(items))
        self.assertIsNone(cursor)
        page1, cursor = self.service.list_sources(limit=2)
        self.assertEqual(2, len(page1))
        page2, cursor2 = self.service.list_sources(limit=2, cursor=cursor)
        self.assertEqual(1, len(page2))
        self.assertIsNone(cursor2)
        self.assertEqual({item['source_id'] for item in page1} |
                         {item['source_id'] for item in page2},
                         {'src-a', 'src-b', 'src-c'})
        withdrawn, _ = self.service.list_sources(status='withdrawn')
        self.assertEqual(['src-c'], [item['source_id'] for item in withdrawn])
        active, _ = self.service.list_sources(status='active')
        self.assertEqual({'src-a', 'src-b'}, {item['source_id'] for item in active})
        by_use, _ = self.service.list_sources(use='knowledge')
        self.assertEqual(['src-c'], [item['source_id'] for item in by_use])
        with self.assertRaises(Exception):
            self.service.list_sources(limit=0)
        with self.assertRaises(Exception):
            self.service.list_sources(limit=101)
        with self.assertRaises(Exception):
            self.service.list_sources(cursor='!not-ascii-ü!')
        with self.assertRaises(Exception):
            self.service.list_sources(cursor='x' * 513)
        with self.assertRaises(Exception):
            self.service.list_sources(cursor='a' * 8)

    def test_list_candidates_publications_and_observations(self):
        first, second, pub1, pub2 = self._seed_three()
        candidates, cursor = self.service.list_candidates(limit=1)
        self.assertEqual(1, len(candidates))
        rest, cursor = self.service.list_candidates(limit=1, cursor=cursor)
        self.assertEqual(1, len(rest))
        self.assertIsNone(cursor)
        proposed, _ = self.service.list_candidates(state='published')
        self.assertEqual({str(first), str(second)},
                         {item['candidate_id'] for item in proposed})
        for candidate_id, source_filter in ((first, 'src-a'), (second, 'src-b')):
            matched, _ = self.service.list_candidates(source_id=source_filter)
            self.assertEqual([str(candidate_id)],
                             [item['candidate_id'] for item in matched])
        with self.assertRaises(Exception):
            self.service.list_candidates(state='bogus')
        publications, cursor = self.service.list_publications(limit=1)
        self.assertEqual(1, len(publications))
        self.assertTrue(cursor)
        remaining, cursor = self.service.list_publications(limit=1, cursor=cursor)
        self.assertEqual(1, len(remaining))
        self.assertIsNone(cursor)
        self.assertEqual({pub1, pub2}, {item['publication_id']
                                        for item in publications + remaining})
        observations, cursor = self.service.list_observations()
        self.assertEqual([], observations)
        self.assertIsNone(cursor)


if __name__ == '__main__':
    unittest.main()


class TestPublicationTransactionAtomicity(GovernancePgTestCase):
    def prepare_publication(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'atomic-source', acl=('steward', 'legal'))
            candidate = self.seed_candidate(conn, 'atomic-source', acl=('legal',))
        self.confirm('atomic-source')
        return candidate

    def test_failure_before_outbox_rolls_back_action_candidate_publication_and_bindings(self):
        from unittest.mock import patch
        candidate = self.prepare_publication()
        execute = psycopg.Cursor.execute
        def fail_outbox(cursor, query, *args, **kwargs):
            if isinstance(query, str) and query.startswith('INSERT INTO knowledge_outbox'):
                raise RuntimeError('injected crash before publication outbox')
            return execute(cursor, query, *args, **kwargs)
        with patch.object(psycopg.Cursor, 'execute', fail_outbox):
            with self.assertRaisesRegex(RuntimeError, 'injected crash'):
                self.publish(candidate, key='atomic-retry')
        with self.admin_conn() as conn:
            self.assertEqual('proposed', conn.execute('SELECT state FROM knowledge_candidates WHERE candidate_id=%s', (candidate,)).fetchone()[0])
            for table in ('knowledge_publications', 'knowledge_publication_sources', 'knowledge_outbox'):
                self.assertEqual(0, conn.execute(f'SELECT count(*) FROM {table}').fetchone()[0])
        self.assertEqual(0, len(self.admin_actions(action_type='publish', result='succeeded')))
        self.assertEqual(1, len(self.admin_actions(action_type='publish', result='failed')))
        self.assertTrue(self.publish(candidate, key='atomic-retry'))

    def test_concurrent_same_key_retries_commit_one_action_publication_and_outbox(self):
        from concurrent.futures import ThreadPoolExecutor
        import threading
        candidate = self.prepare_publication()
        ready = threading.Barrier(4)
        def publish():
            ready.wait(10)
            return self.publish(candidate, key='concurrent-retry')
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(lambda _index: publish(), range(4)))
        self.assertEqual(1, len(set(results)))
        self.assertEqual(1, len(self.admin_actions(action_type='publish', result='succeeded')))
        self.assertEqual(0, len(self.admin_actions(action_type='publish', result='failed')))
        self.assertEqual(1, len(self.outbox_events(results[0])))
        with self.admin_conn() as conn:
            self.assertEqual(1, conn.execute('SELECT count(*) FROM knowledge_publications').fetchone()[0])
            self.assertEqual(1, conn.execute('SELECT count(*) FROM knowledge_publication_sources').fetchone()[0])

    def test_source_expiry_preserves_original_acl_and_invalidates_consumption(self):
        from knowledge.knowledge import Role
        from knowledge.worker import GovernedConsumer
        candidate = self.prepare_publication()
        publication = self.publish(candidate)
        actor = self.consumer('legal')
        consumer = GovernedConsumer(self.storage, actor)
        self.assertEqual(1, consumer.consume_once())
        self.assertEqual((UUID(publication),), consumer.active_publication_ids())
        tables = ('knowledge_sources', 'knowledge_entities', 'knowledge_claims',
                  'knowledge_evidence', 'knowledge_candidates', 'candidate_evidence_links')
        with self.admin_conn() as conn:
            before = {table: conn.execute(f'SELECT acl FROM {table} ORDER BY acl::text').fetchall() for table in tables}
        expired_at = self.now + timedelta(days=61)
        self.assertEqual((), consumer.active_publication_ids(expired_at))
        self.assertEqual('', self.service.export_versioned_jsonl([publication], actor, 'expired', expired_at))
        steward = TrustedActor('steward', self.tenant, self.domain, frozenset({Role.DATA_STEWARD}), frozenset({'knowledge'}))
        with psycopg.connect(self.config['app_dsn']) as conn:
            self.storage.set_session_identity(conn, steward)
            self.assertEqual(1, len(self.storage.expire_sources(conn, expired_at)))
        with self.admin_conn() as conn:
            after = {table: conn.execute(f'SELECT acl FROM {table} ORDER BY acl::text').fetchall() for table in tables}
            self.assertFalse(conn.execute('SELECT active FROM knowledge_consumer_assets').fetchone()[0])
            self.assertTrue(conn.execute('SELECT withdrawn FROM knowledge_sources').fetchone()[0])
        self.assertEqual(before, after)
        self.assertEqual((), consumer.active_publication_ids())
        self.assertEqual('', self.service.export_versioned_jsonl([publication], actor, 'revoked'))

    def test_schema_rejection_preserves_fixed_error_without_attempting_action_write(self):
        from unittest.mock import patch
        from knowledge.storage import KnowledgeSchemaError
        candidate = self.prepare_publication()
        with patch.object(self.storage, 'verify_schema', side_effect=KnowledgeSchemaError()), patch.object(self.service, '_record_failed_action') as failed:
            with self.assertRaises(KnowledgeSchemaError):
                self.publish(candidate, key='incompatible')
            failed.assert_not_called()
        self.assertEqual([], self.admin_actions(action_type='publish'))
