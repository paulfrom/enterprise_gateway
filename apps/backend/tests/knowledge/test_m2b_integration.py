"""Real PG worker lifecycle from encrypted spool; HTTP origin is verified by the gateway suite."""
import unittest
from dataclasses import replace
from datetime import datetime,timedelta,timezone
from hashlib import sha256
from pathlib import Path
import tempfile
from unittest.mock import patch
from uuid import UUID, uuid4
import psycopg
from infra.envelope_crypto import StaticTestKmsProvider
from infra.spool import SpoolWriter,CollectionMode
from infra.errors import SafetyError
from infra.spool_relay import compute_dedup_key
from knowledge.knowledge import *
from knowledge.knowledge_events import build_gateway_observation
from knowledge.governance import AdminActionContext, GovernanceError, KnowledgeGovernanceService
from knowledge.storage import PostgresKnowledgeStorage
from knowledge.worker import KnowledgeWorker,PostgresKnowledgeSink,GovernedConsumer
from tests.pg_support import get_test_dsn,prepare_test_database,test_configuration

class TestM2BKnowledgeIntegration(unittest.TestCase):
    def test_same_text_different_trusted_source_acl_does_not_collide(self):
        first=self.observe()
        self.acl=self.acl|{'other-authorized-member'}
        second=self.observe()
        self.writer.collect(first,mode=CollectionMode.REQUIRED)
        self.writer.collect(second,mode=CollectionMode.REQUIRED)
        self.assertEqual(2,self.worker.run_once().submitted)
        self.assertNotEqual(first.source_id,second.source_id)
        self.assertEqual(0,self.load(first).independent_source_count)
        self.assertEqual(0,self.load(second).independent_source_count)

    @classmethod
    def setUpClass(cls):
        prepare_test_database()
        cls.storage=PostgresKnowledgeStorage(get_test_dsn())
        cls.config=test_configuration()

    def setUp(self):
        self.domain='worker-'+uuid4().hex;self.now=datetime.now(timezone.utc)
        self.acl=frozenset({'worker','security','business','publisher','reader','reader2','steward'})
        self.temp=tempfile.TemporaryDirectory();self.spool=Path(self.temp.name)
        self.kms=StaticTestKmsProvider();self.writer=SpoolWriter(self.spool,self.kms)
        self.worker=KnowledgeWorker(self.spool,self.kms,PostgresKnowledgeSink(self.storage,self.actor('worker'),self.kms))

    def tearDown(self):self.temp.cleanup()

    def actor(self,name,*roles):
        return TrustedActor(name,'tenant-a',self.domain,frozenset(roles),frozenset({'knowledge'}))

    def admin_context(self):
        return AdminActionContext(actor_id='admin',session_digest=sha256(b'kb-admin').hexdigest(),
                                  tenant_id='tenant-a',domain=self.domain)

    def governance(self):
        storage=PostgresKnowledgeStorage(get_test_dsn(),tenant_id='tenant-a',domain=self.domain,
                                         admin_dsn=self.config['admin_app_dsn'],
                                         admin_role=self.config['admin_role'])
        return KnowledgeGovernanceService(tenant_id='tenant-a',domain=self.domain,storage=storage)

    def observe(self,text='采购记录显示：甲公司向乙公司采购设备五台。请查询合同编号HT-2026-001。',**extra):
        return build_gateway_observation(tenant='tenant-a',domain=self.domain,request_id='message-1',
            evidence_text=text,evidence_digest=sha256(text.encode()).hexdigest(),observed_at=self.now,
            source_acl=self.acl,purpose='knowledge',retention_until=self.now+timedelta(days=2),**extra)

    def load(self,event):
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,self.actor('worker'))
            ids=conn.execute('SELECT candidate_ids FROM knowledge_observations WHERE dedup_key=%s',(compute_dedup_key(event),)).fetchone()[0]
            self.assertEqual(1,len(ids))
            return self.storage.load_candidate(conn,ids[0])

    def publish(self,c,*,audiences=('reader','reader2'),key=None):
        service=self.governance()
        context=self.admin_context()
        valid_until=self.now+timedelta(hours=12)
        for source_key in {ev.source.key for ev in c.evidence}:
            service.confirm_source_governance(source_key[2],source_version=source_key[3],
                expected_governance_version=None,ownership='confirmed',use='knowledge',
                audiences=audiences,valid_until=valid_until,basis='verified governance',context=context)
        return service.publish_candidate(str(c.candidate_id),expected_version=1,use='knowledge',
            audiences=audiences,valid_until=valid_until,idempotency_key=key,basis='publish',context=context)

    def test_worker_extracts_decrypted_spool_and_lifecycle_is_durable(self):
        event=self.observe();self.writer.collect(event,mode=CollectionMode.REQUIRED)
        self.assertNotIn('甲公司'.encode(),next(self.spool.glob('*.env.json')).read_bytes())
        stats=self.worker.run_once();self.assertEqual(1,stats.submitted)
        c=self.load(event);self.assertEqual('乙公司',c.claim.subject.name);self.assertEqual('甲公司',c.claim.object.name)
        self.assertEqual(0,c.independent_source_count)
        publication_id=self.publish(c)
        service=self.governance()
        self.assertTrue(service.export_versioned_jsonl([publication_id],self.actor('reader'),'v1',datetime.now(timezone.utc)))
        dictionary=service.compile_approved_dictionary_payload('dictionary','v1',[publication_id],datetime.now(timezone.utc),consumer=self.actor('reader'))
        self.assertEqual({'甲公司','乙公司'},{e['text'] for e in dictionary['entries']})
        consumer=GovernedConsumer(self.storage,self.actor('reader'))
        with self.assertRaises(RuntimeError):consumer.consume_once(fail_after_apply=True)
        self.assertEqual((),consumer.active_publication_ids())
        self.assertEqual(1,consumer.consume_once());self.assertEqual(0,consumer.consume_once())
        self.assertEqual((UUID(publication_id),),consumer.active_publication_ids())
        consumer2=GovernedConsumer(self.storage,self.actor('reader2'))
        self.assertEqual(1,consumer2.consume_once())
        service.withdraw_source(c.evidence[0].source.source_id,source_version=c.evidence[0].source.version,
                                basis='permissions withdrawn',context=self.admin_context())
        restart=self.governance()
        self.assertEqual('',restart.export_versioned_jsonl([publication_id],self.actor('reader'),'v2',datetime.now(timezone.utc)))
        self.assertEqual([],restart.compile_approved_dictionary_payload('dictionary','v2',[publication_id],datetime.now(timezone.utc),consumer=self.actor('reader'))['entries'])
        self.assertEqual(1,consumer.consume_once());self.assertEqual(1,consumer2.consume_once())
        self.assertEqual((),consumer.active_publication_ids());self.assertEqual((),consumer2.active_publication_ids())
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,self.actor('reader'))
            self.assertEqual(2,conn.execute("SELECT count(*) FROM consumer_receipts WHERE action='tombstone_applied'").fetchone()[0])

    def test_at_least_once_crash_after_pg_commit_and_history_retry(self):
        event=self.observe();self.writer.collect(event,mode=CollectionMode.REQUIRED)
        with patch('infra.spool_relay._confirm_remove',side_effect=OSError('injected crash after PG commit')):
            with self.assertRaises(SafetyError):self.worker.run_once()
        self.assertEqual(1,self.worker.run_once().skipped)
        retry=self.observe();retry=retry.model_copy(update={'observed_at':self.now+timedelta(seconds=10),'retention_until':self.now+timedelta(days=2,seconds=10)})
        self.writer.collect(retry,mode=CollectionMode.REQUIRED)
        self.assertEqual(1,self.worker.run_once().skipped)
        self.assertEqual(0,self.load(event).independent_source_count)

    def test_publication_crash_before_commit_rolls_back_state_and_outbox(self):
        event=self.observe();self.writer.collect(event,mode=CollectionMode.REQUIRED);self.worker.run_once()
        c=self.load(event)
        context=self.admin_context()
        valid_until=self.now+timedelta(hours=12)
        storage=PostgresKnowledgeStorage(get_test_dsn(),tenant_id='tenant-a',domain=self.domain,
                                         admin_dsn=self.config['admin_app_dsn'],
                                         admin_role=self.config['admin_role'])
        service=KnowledgeGovernanceService(tenant_id='tenant-a',domain=self.domain,storage=storage)
        for source_key in {ev.source.key for ev in c.evidence}:
            service.confirm_source_governance(source_key[2],source_version=source_key[3],
                expected_governance_version=None,ownership='confirmed',use='knowledge',
                audiences=('reader',),valid_until=valid_until,basis='verified governance',context=context)
        with patch.object(storage,'publish_transactional',side_effect=RuntimeError('injected publication crash before commit')):
            with self.assertRaises(RuntimeError):
                service.publish_candidate(str(c.candidate_id),expected_version=1,use='knowledge',
                    audiences=('reader',),valid_until=valid_until,
                    idempotency_key='crash-1',basis='publish',context=context)
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,self.actor('worker'))
            self.assertEqual(0,conn.execute('SELECT count(*) FROM knowledge_publications WHERE candidate_id=%s',(c.candidate_id,)).fetchone()[0])
            self.assertEqual([],self.storage.fetch_pending_outbox(conn))
        publication_id=service.publish_candidate(str(c.candidate_id),expected_version=1,use='knowledge',
            audiences=('reader',),valid_until=valid_until,idempotency_key='crash-1',basis='publish',context=context)
        self.assertTrue(service.export_versioned_jsonl([publication_id],self.actor('reader'),'v1',datetime.now(timezone.utc)))

    def test_source_steward_outside_derived_acl_can_revoke_without_read_expansion(self):
        shared=self.acl-{'steward'}
        first=self.observe().model_copy(update={'source_id':'source-a','acl':shared|{'steward-a'},'source_independence_verified':True})
        second=self.observe().model_copy(update={'source_id':'source-b','acl':shared|{'steward-b'},'source_independence_verified':True})
        self.writer.collect(first,mode=CollectionMode.REQUIRED);self.writer.collect(second,mode=CollectionMode.REQUIRED)
        self.assertEqual(2,self.worker.run_once().submitted)
        a=self.load(first);b=self.load(second)
        merged=Candidate(uuid4(),a.claim,(*a.evidence,*b.evidence),shared,'knowledge')
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,self.actor('worker'))
            evidence_ids=[self.storage.save_evidence(conn,ev) for ev in merged.evidence]
            self.storage.save_candidate(conn,merged,evidence_ids)
        publication_id=self.publish(merged)
        steward=self.actor('steward-a',Role.DATA_STEWARD)
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,steward)
            self.assertIsNone(conn.execute('SELECT publication_id FROM knowledge_publications WHERE publication_id=%s',(UUID(publication_id),)).fetchone())
        consumer=GovernedConsumer(self.storage,self.actor('reader'));consumer.consume_once()
        consumer2=GovernedConsumer(self.storage,self.actor('reader2'));consumer2.consume_once()
        service=self.governance()
        service.withdraw_source(a.evidence[0].source.source_id,source_version=a.evidence[0].source.version,
                                basis='source permission revoked',context=self.admin_context())
        self.assertEqual(1,consumer.consume_once());self.assertEqual(1,consumer2.consume_once())
        self.assertEqual((),consumer.active_publication_ids());self.assertEqual((),consumer2.active_publication_ids())
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,steward)
            self.assertIsNone(conn.execute('SELECT publication_id FROM knowledge_publications WHERE publication_id=%s',(UUID(publication_id),)).fetchone())
        # The independent remaining source's candidate is still readable.
        self.assertEqual(CandidateState.PROPOSED,self.load(second).state)

    def test_source_management_channel_rejects_wrong_scope_role_acl_and_purpose(self):
        event=self.observe();self.writer.collect(event,mode=CollectionMode.REQUIRED);self.worker.run_once()
        source=self.load(event).evidence[0].source
        valid=self.actor('steward',Role.DATA_STEWARD)
        for actor in (replace(valid,tenant_id='other'),replace(valid,domain='other'),
                      replace(valid,subject_id='outsider'),replace(valid,purposes=frozenset({'other'})),
                      replace(valid,roles=frozenset())):
            with self.subTest(actor=actor.subject_id,tenant=actor.tenant_id,purposes=actor.purposes):
                with psycopg.connect(get_test_dsn()) as conn:
                    self.storage.set_session_identity(conn,actor)
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                        self.storage.invalidate_source(conn,source,'withdrawal',self.now)
                    conn.rollback()
        self.assertEqual(CandidateState.PROPOSED,self.load(event).state)

    def test_default_collection_acl_remains_isolated_after_pg_worker_processing(self):
        restricted=f'{self.domain}:restricted-candidate'
        event=self.observe().model_copy(update={'acl':frozenset({restricted})})
        writer=SpoolWriter(self.spool,self.kms);writer.collect(event,mode=CollectionMode.REQUIRED)
        worker=KnowledgeWorker(self.spool,self.kms,PostgresKnowledgeSink(self.storage,self.actor('worker',Role.KNOWLEDGE_PROCESSOR),self.kms,processing_acl=(restricted,)))
        self.assertEqual(1,worker.run_once().submitted)
        for actor in (self.actor('reader'),self.actor('security',Role.SECURITY_REVIEWER)):
            with psycopg.connect(get_test_dsn()) as conn:
                self.storage.set_session_identity(conn,actor)
                self.assertIsNone(conn.execute('SELECT source_id FROM knowledge_sources WHERE domain=%s',(self.domain,)).fetchone())
                self.assertEqual(0,conn.execute('SELECT count(*) FROM knowledge_candidates WHERE domain=%s',(self.domain,)).fetchone()[0])

    def test_rejected_candidate_is_persisted_and_cannot_be_published(self):
        event=self.observe();self.writer.collect(event,mode=CollectionMode.REQUIRED);self.worker.run_once()
        c=self.load(event)
        self.governance().reject_candidate(str(c.candidate_id),basis='verified rejection',context=self.admin_context())
        self.assertEqual(CandidateState.REJECTED,self.load(event).state)
        self.assertEqual('verified rejection',self.load(event).rejection_reason)
        with self.assertRaises(GovernanceError) as cm:
            self.publish(self.load(event))
        self.assertEqual('KNOWLEDGE_CANDIDATE_VERSION_CONFLICT',cm.exception.code)

    def test_distinct_source_acl_consumers_read_context_without_shared_descriptor_expansion(self):
        common=self.acl-{'reader','reader2'}
        first=self.observe().model_copy(update={'source_id':'scope-a','acl':common|{'reader'}})
        second=self.observe().model_copy(update={'source_id':'scope-b','acl':common|{'reader2'}})
        self.writer.collect(first,mode=CollectionMode.REQUIRED);self.worker.run_once()
        self.writer.collect(second,mode=CollectionMode.REQUIRED);self.worker.run_once()
        a=self.load(first);b=self.load(second)
        pa=self.publish(a,audiences=('reader',));pb=self.publish(b,audiences=('reader2',))
        service=self.governance()
        self.assertTrue(service.export_versioned_jsonl([pa],self.actor('reader'),'v1',datetime.now(timezone.utc)))
        self.assertTrue(service.export_versioned_jsonl([pb],self.actor('reader2'),'v1',datetime.now(timezone.utc)))
        self.assertEqual('',service.export_versioned_jsonl([pa],self.actor('reader2'),'v1',datetime.now(timezone.utc)))
        self.assertEqual('',service.export_versioned_jsonl([pb],self.actor('reader'),'v1',datetime.now(timezone.utc)))
        for consumer,pub in ((self.actor('reader'),pa),(self.actor('reader2'),pb)):
            self.assertEqual(2,len(service.compile_approved_dictionary_payload('dictionary','v1',[pub],datetime.now(timezone.utc),consumer=consumer)['entries']))
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,self.actor('reader2'))
            self.assertEqual(0,conn.execute('SELECT count(*) FROM knowledge_entities WHERE entity_id=%s',(b.claim.subject.entity_id,)).fetchone()[0])
            descriptor=self.storage.load_candidate(conn,b.candidate_id)
            self.assertEqual(b.claim,descriptor.claim)
            with self.assertRaises(KnowledgeError):self.storage.load_candidate(conn,a.candidate_id)
            conn.rollback()
        for actor in (replace(self.actor('reader2'),tenant_id='other'),replace(self.actor('reader2'),domain='other'),
                      replace(self.actor('reader2'),purposes=frozenset({'other'})),self.actor('outsider')):
            with psycopg.connect(get_test_dsn()) as conn:
                self.storage.set_session_identity(conn,actor)
                with self.assertRaises(KnowledgeError):self.storage.load_candidate(conn,b.candidate_id)
                conn.rollback()
        with psycopg.connect(get_test_dsn()) as conn:
            with self.assertRaises(KnowledgeError):self.storage.load_candidate(conn,b.candidate_id)
            conn.rollback()
            self.storage.set_session_identity(conn,self.actor('reader'))
            with self.assertRaises(KnowledgeError):self.storage.load_candidate(conn,uuid4())
            conn.rollback()
            self.storage.set_session_identity(conn,self.actor('reader'))
            conn.execute("SELECT set_config('app.subjects',%s::text[]::text,true)",(['reader2'],))
            with self.assertRaises(KnowledgeError):self.storage.load_candidate(conn,b.candidate_id)
            conn.rollback()
        service.withdraw_source(a.evidence[0].source.source_id,source_version=a.evidence[0].source.version,
                                basis='scope a revoked',context=self.admin_context())
        restart=self.governance()
        self.assertEqual('',restart.export_versioned_jsonl([pa],self.actor('reader'),'v2',datetime.now(timezone.utc)))
        self.assertTrue(restart.export_versioned_jsonl([pb],self.actor('reader2'),'v2',datetime.now(timezone.utc)))
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,self.actor('reader2'))
            self.assertEqual(0,conn.execute('SELECT count(*) FROM knowledge_entities WHERE entity_id=%s',(b.claim.subject.entity_id,)).fetchone()[0])

    def test_expiry_rejects_stale_export_and_consumer_snapshot(self):
        event=self.observe();self.writer.collect(event,mode=CollectionMode.REQUIRED);self.worker.run_once()
        c=self.load(event);publication_id=self.publish(c)
        consumer=GovernedConsumer(self.storage,self.actor('reader'));consumer.consume_once()
        service=self.governance()
        stale=self.now+timedelta(days=3)
        self.assertEqual('',service.export_versioned_jsonl([publication_id],self.actor('reader'),'v2',stale))
        self.assertEqual((),consumer.active_publication_ids(stale))
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,self.actor('steward',Role.DATA_STEWARD))
            self.assertEqual(1,len(self.storage.expire_sources(conn,stale)))
        self.assertEqual(1,consumer.consume_once())
        self.assertEqual((),consumer.active_publication_ids())
        self.assertEqual('',self.governance().export_versioned_jsonl([publication_id],self.actor('reader'),'v2',datetime.now(timezone.utc)))
        # A separate active asset tests policy-shortened retention snapshots.
        event2=self.observe('丙公司向丁公司采购设备')
        self.writer.collect(event2,mode=CollectionMode.REQUIRED);self.worker.run_once()
        c=self.load(event2);publication_id2=self.publish(c)
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,self.actor('steward',Role.DATA_STEWARD))
            conn.execute('UPDATE knowledge_sources SET observed_at=%s, retention_until=%s WHERE source_id=%s',
                         (self.now-timedelta(hours=2),self.now-timedelta(hours=1),c.evidence[0].source.source_id))
        # Authoritative metadata changes invalidate old snapshots immediately.
        self.assertEqual('',self.governance().export_versioned_jsonl([publication_id2],self.actor('reader'),'v2',datetime.now(timezone.utc)))
