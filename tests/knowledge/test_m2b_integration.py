"""Real PG worker lifecycle from encrypted spool; HTTP origin is verified by the gateway suite."""
import unittest
from dataclasses import replace
from datetime import datetime,timedelta,timezone
from hashlib import sha256
from pathlib import Path
import tempfile
from unittest.mock import patch
from uuid import uuid4
import psycopg
from infra.envelope_crypto import StaticTestKmsProvider
from infra.spool import SpoolWriter,CollectionMode
from infra.errors import SafetyError
from infra.spool_relay import compute_dedup_key
from knowledge.knowledge import *
from knowledge.knowledge_events import build_gateway_observation
from knowledge.governance import KnowledgeGovernanceService
from knowledge.storage import PostgresKnowledgeStorage
from knowledge.worker import KnowledgeWorker,PostgresKnowledgeSink,GovernedConsumer
from tests.pg_support import get_test_dsn,prepare_test_database

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

    def setUp(self):
        self.domain='worker-'+uuid4().hex;self.now=datetime.now(timezone.utc)
        self.acl=frozenset({'worker','security','business','publisher','reader','reader2','steward'})
        self.temp=tempfile.TemporaryDirectory();self.spool=Path(self.temp.name)
        self.kms=StaticTestKmsProvider();self.writer=SpoolWriter(self.spool,self.kms)
        self.worker=KnowledgeWorker(self.spool,self.kms,PostgresKnowledgeSink(self.storage,self.actor('worker')))

    def tearDown(self):self.temp.cleanup()

    def actor(self,name,*roles):
        return TrustedActor(name,'tenant-a',self.domain,frozenset(roles),frozenset({'knowledge'}))

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

    def publish(self,c):
        service=KnowledgeGovernanceService(self.domain,self.storage)
        c=service.approve_candidate(c,self.actor('security',Role.SECURITY_REVIEWER),Role.SECURITY_REVIEWER,'verified/security',self.now)
        # Recreate service to prove persisted approvals survive worker/process lifecycle.
        service=KnowledgeGovernanceService(self.domain,self.storage)
        c=service.approve_candidate(c,self.actor('business',Role.BUSINESS_REVIEWER),Role.BUSINESS_REVIEWER,'verified/business',self.now)
        service=KnowledgeGovernanceService(self.domain,self.storage)
        pub,_=service.publish_candidate(c,self.actor('publisher',Role.PUBLISHER),self.now+timedelta(days=30),self.now)
        return pub

    def test_worker_extracts_decrypted_spool_and_lifecycle_is_durable(self):
        event=self.observe();self.writer.collect(event,mode=CollectionMode.REQUIRED)
        self.assertNotIn('甲公司'.encode(),next(self.spool.glob('*.env.json')).read_bytes())
        stats=self.worker.run_once();self.assertEqual(1,stats.submitted)
        c=self.load(event);self.assertEqual('乙公司',c.claim.subject.name);self.assertEqual('甲公司',c.claim.object.name)
        self.assertEqual(0,c.independent_source_count)
        pub=self.publish(c)
        service=KnowledgeGovernanceService(self.domain,self.storage)
        self.assertTrue(service.export_versioned_jsonl([pub],self.actor('reader'),'v1',self.now))
        dictionary=service.compile_approved_dictionary_payload('dictionary','v1',[pub],self.now,consumer=self.actor('reader'))
        self.assertEqual({'甲公司','乙公司'},{e['text'] for e in dictionary['entries']})
        consumer=GovernedConsumer(self.storage,self.actor('reader'))
        with self.assertRaises(RuntimeError):consumer.consume_once(fail_after_apply=True)
        self.assertEqual((),consumer.active_publication_ids())
        self.assertEqual(1,consumer.consume_once());self.assertEqual(0,consumer.consume_once())
        self.assertEqual((pub.publication_id,),consumer.active_publication_ids())
        consumer2=GovernedConsumer(self.storage,self.actor('reader2'))
        self.assertEqual(1,consumer2.consume_once())
        service.withdraw_source(c.evidence[0].source,self.actor('steward',Role.DATA_STEWARD),'permissions withdrawn',self.now)
        restart=KnowledgeGovernanceService(self.domain,self.storage)
        self.assertEqual('',restart.export_versioned_jsonl([pub],self.actor('reader'),'v2',self.now))
        self.assertEqual([],restart.compile_approved_dictionary_payload('dictionary','v2',[pub],self.now,consumer=self.actor('reader'))['entries'])
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
        service=KnowledgeGovernanceService(self.domain,self.storage)
        c=service.approve_candidate(c,self.actor('security',Role.SECURITY_REVIEWER),Role.SECURITY_REVIEWER,'verified/security',self.now)
        c=service.approve_candidate(c,self.actor('business',Role.BUSINESS_REVIEWER),Role.BUSINESS_REVIEWER,'verified/business',self.now)
        original=self.storage.publish_transactional
        def fail_after_insert(*args,**kwargs):
            original(*args,**kwargs)
            raise RuntimeError('injected publication crash before commit')
        with patch.object(self.storage,'publish_transactional',side_effect=fail_after_insert):
            with self.assertRaises(RuntimeError):
                service.publish_candidate(c,self.actor('publisher',Role.PUBLISHER),self.now+timedelta(days=1),self.now)
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,self.actor('publisher',Role.PUBLISHER))
            stored=self.storage.load_candidate(conn,c.candidate_id)
            self.assertEqual(CandidateState.APPROVED,stored.state)
            self.assertEqual(0,conn.execute('SELECT count(*) FROM knowledge_publications WHERE candidate_id=%s',(c.candidate_id,)).fetchone()[0])
            self.assertEqual([],self.storage.fetch_pending_outbox(conn))
        pub,_=KnowledgeGovernanceService(self.domain,self.storage).publish_candidate(c,self.actor('publisher',Role.PUBLISHER),self.now+timedelta(days=1),self.now)
        self.assertTrue(KnowledgeGovernanceService(self.domain,self.storage).export_versioned_jsonl([pub],self.actor('reader'),'v1',self.now))

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
        pub=self.publish(merged)
        steward=self.actor('steward-a',Role.DATA_STEWARD)
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,steward)
            self.assertIsNone(conn.execute('SELECT publication_id FROM knowledge_publications WHERE publication_id=%s',(pub.publication_id,)).fetchone())
        consumer=GovernedConsumer(self.storage,self.actor('reader'));consumer.consume_once()
        consumer2=GovernedConsumer(self.storage,self.actor('reader2'));consumer2.consume_once()
        service=KnowledgeGovernanceService(self.domain,self.storage)
        self.assertEqual(1,len(service.withdraw_source(a.evidence[0].source,steward,'source permission revoked',self.now)))
        self.assertEqual(1,consumer.consume_once());self.assertEqual(1,consumer2.consume_once())
        self.assertEqual((),consumer.active_publication_ids());self.assertEqual((),consumer2.active_publication_ids())
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,steward)
            self.assertIsNone(conn.execute('SELECT publication_id FROM knowledge_publications WHERE publication_id=%s',(pub.publication_id,)).fetchone())
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
        worker=KnowledgeWorker(self.spool,self.kms,PostgresKnowledgeSink(self.storage,self.actor('worker',Role.KNOWLEDGE_PROCESSOR),processing_acl=(restricted,)))
        self.assertEqual(1,worker.run_once().submitted)
        for actor in (self.actor('reader'),self.actor('security',Role.SECURITY_REVIEWER)):
            with psycopg.connect(get_test_dsn()) as conn:
                self.storage.set_session_identity(conn,actor)
                self.assertIsNone(conn.execute('SELECT source_id FROM knowledge_sources WHERE domain=%s',(self.domain,)).fetchone())
                self.assertEqual(0,conn.execute('SELECT count(*) FROM knowledge_candidates WHERE domain=%s',(self.domain,)).fetchone()[0])

    def test_rejected_candidate_is_persisted_and_stale_object_cannot_approve(self):
        event=self.observe();self.writer.collect(event,mode=CollectionMode.REQUIRED);self.worker.run_once()
        c=self.load(event)
        rejected=KnowledgeGovernanceService(self.domain,self.storage).reject_candidate(c,self.actor('business',Role.BUSINESS_REVIEWER),'verified rejection')
        self.assertEqual(CandidateState.REJECTED,rejected.state)
        self.assertEqual(CandidateState.REJECTED,self.load(event).state)
        self.assertEqual('verified rejection',self.load(event).rejection_reason)
        with self.assertRaises(KnowledgeError):
            KnowledgeGovernanceService(self.domain,self.storage).approve_candidate(c,self.actor('security',Role.SECURITY_REVIEWER),Role.SECURITY_REVIEWER,'external/verification',self.now)

    def test_distinct_source_acl_consumers_read_context_without_shared_descriptor_expansion(self):
        common=self.acl-{'reader','reader2'}
        first=self.observe().model_copy(update={'source_id':'scope-a','acl':common|{'reader'}})
        second=self.observe().model_copy(update={'source_id':'scope-b','acl':common|{'reader2'}})
        self.writer.collect(first,mode=CollectionMode.REQUIRED);self.worker.run_once()
        self.writer.collect(second,mode=CollectionMode.REQUIRED);self.worker.run_once()
        a=self.load(first);b=self.load(second);pa=self.publish(a);pb=self.publish(b)
        service=KnowledgeGovernanceService(self.domain,self.storage)
        self.assertTrue(service.export_versioned_jsonl([pa],self.actor('reader'),'v1',self.now))
        self.assertTrue(service.export_versioned_jsonl([pb],self.actor('reader2'),'v1',self.now))
        self.assertEqual('',service.export_versioned_jsonl([pa],self.actor('reader2'),'v1',self.now))
        self.assertEqual('',service.export_versioned_jsonl([pb],self.actor('reader'),'v1',self.now))
        for consumer,pub in ((self.actor('reader'),pa),(self.actor('reader2'),pb)):
            self.assertEqual(2,len(service.compile_approved_dictionary_payload('dictionary','v1',[pub],self.now,consumer=consumer)['entries']))
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
        service.withdraw_source(a.evidence[0].source,self.actor('steward',Role.DATA_STEWARD),'scope a revoked',self.now)
        restart=KnowledgeGovernanceService(self.domain,self.storage)
        self.assertEqual('',restart.export_versioned_jsonl([pa],self.actor('reader'),'v2',self.now))
        self.assertTrue(restart.export_versioned_jsonl([pb],self.actor('reader2'),'v2',self.now))
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,self.actor('reader2'))
            self.assertEqual(0,conn.execute('SELECT count(*) FROM knowledge_entities WHERE entity_id=%s',(b.claim.subject.entity_id,)).fetchone()[0])

    def test_expiry_rejects_stale_export_and_consumer_snapshot(self):
        event=self.observe();self.writer.collect(event,mode=CollectionMode.REQUIRED);self.worker.run_once()
        c=self.load(event);pub=self.publish(c)
        consumer=GovernedConsumer(self.storage,self.actor('reader'));consumer.consume_once()
        service=KnowledgeGovernanceService(self.domain,self.storage)
        self.assertEqual('',service.export_versioned_jsonl([pub],self.actor('reader'),'v2',self.now+timedelta(days=3)))
        self.assertEqual((),consumer.active_publication_ids(self.now+timedelta(days=3)))
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,self.actor('steward',Role.DATA_STEWARD))
            self.assertEqual(1,len(self.storage.expire_sources(conn,self.now+timedelta(days=3))))
        self.assertEqual(1,consumer.consume_once())
        self.assertEqual((),consumer.active_publication_ids())
        self.assertEqual('',KnowledgeGovernanceService(self.domain,self.storage).export_versioned_jsonl([pub],self.actor('reader'),'v2',self.now))
        # A separate active asset tests policy-shortened retention snapshots.
        event2=self.observe('丙公司向丁公司采购设备')
        self.writer.collect(event2,mode=CollectionMode.REQUIRED);self.worker.run_once()
        c=self.load(event2);pub=self.publish(c)
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,self.actor('steward',Role.DATA_STEWARD))
            conn.execute('UPDATE knowledge_sources SET retention_until=%s WHERE source_id=%s',(self.now+timedelta(seconds=1),c.evidence[0].source.source_id))
        # Authoritative metadata changes invalidate old snapshots immediately.
        self.assertEqual('',KnowledgeGovernanceService(self.domain,self.storage).export_versioned_jsonl([pub],self.actor('reader'),'v2',self.now))
