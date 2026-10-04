"""Real PostgreSQL constrained-role contract tests; configuration is injected."""
import unittest
import threading
import time
from dataclasses import replace
from datetime import datetime,timedelta,timezone
from uuid import uuid4
import psycopg
from psycopg.errors import ForeignKeyViolation,InsufficientPrivilege,CheckViolation
from knowledge.storage import PostgresKnowledgeStorage,_ASSET_TABLES
from knowledge.knowledge import *
from tests.pg_support import get_test_dsn,get_admin_dsn,prepare_test_database

class TestPostgresKnowledgeStorage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        prepare_test_database()
        cls.storage=PostgresKnowledgeStorage(get_test_dsn())

    def setUp(self):
        self.domain='storage-'+uuid4().hex
        self.actor=TrustedActor('security','tenant-a',self.domain,frozenset({Role.SECURITY_REVIEWER}),frozenset({'knowledge'}))
        self.conn=psycopg.connect(get_test_dsn())
        self.storage.set_session_identity(self.conn,self.actor)
        now=datetime.now(timezone.utc)
        self.source=Source('tenant-a',self.domain,'source','v1',SourceKind.DOCUMENT,
                           frozenset({'security','business','publisher','reader','steward'}),'knowledge',now,now+timedelta(days=2),True)

    def tearDown(self):
        self.conn.rollback(); self.conn.close()

    def test_k14_nonowner_no_bypass_and_every_asset_rls(self):
        row=self.conn.execute('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user').fetchone()
        self.assertEqual((False,False),row)
        rows=self.conn.execute("SELECT relname,relrowsecurity,relforcerowsecurity,pg_get_userbyid(relowner)=current_user FROM pg_class WHERE relnamespace=current_schema()::regnamespace AND relname=ANY(%s)",(list(_ASSET_TABLES),)).fetchall()
        self.assertEqual(len(_ASSET_TABLES),len(rows))
        for name,enabled,forced,owner in rows:
            self.assertTrue(enabled and forced); self.assertFalse(owner)

    def test_k14_tenant_domain_purpose_and_source_acl(self):
        self.storage.save_source(self.conn,self.source)
        self.conn.commit()
        for actor in (replace(self.actor,tenant_id='tenant-b'),replace(self.actor,domain='other'),
                      replace(self.actor,purposes=frozenset({'other'})),replace(self.actor,subject_id='outsider')):
            with psycopg.connect(get_test_dsn()) as conn:
                self.storage.set_session_identity(conn,actor)
                self.assertIsNone(conn.execute('SELECT source_id FROM knowledge_sources WHERE domain=%s',(self.domain,)).fetchone())
        with psycopg.connect(get_test_dsn()) as conn:
            self.storage.set_session_identity(conn,self.actor)
            self.assertIsNotNone(conn.execute('SELECT source_id FROM knowledge_sources WHERE domain=%s',(self.domain,)).fetchone())

    def test_k04_cross_domain_entity_foreign_key(self):
        a=Entity(uuid4(),'tenant-a',self.domain,'ORG','甲公司')
        other_domain='other-'+uuid4().hex
        b=Entity(uuid4(),'tenant-a',other_domain,'ORG','乙公司')
        self.storage.save_entity(self.conn,a,self.source.acl,'knowledge')
        self.storage.set_session_identity(self.conn,replace(self.actor,domain=other_domain))
        self.storage.save_entity(self.conn,b,self.source.acl,'knowledge')
        self.storage.set_session_identity(self.conn,self.actor)
        with self.assertRaises(ForeignKeyViolation):
            self.conn.execute("INSERT INTO knowledge_claims(tenant_id,domain,subject_id,predicate,object_id,polarity,modality,acl,purpose) VALUES(%s,%s,%s,'supplies',%s,'positive','asserted',%s,'knowledge')",('tenant-a',self.domain,a.entity_id,b.entity_id,list(self.source.acl)))

    def test_k04_evidence_constraints_and_missing_source(self):
        with self.assertRaises(ForeignKeyViolation):
            self.conn.execute("INSERT INTO knowledge_evidence(tenant_id,domain,source_id,version,content_sha256,char_start,char_end,acl,purpose) VALUES(%s,%s,'missing','v1',%s,0,5,%s,'knowledge')",('tenant-a',self.domain,'a'*64,list(self.source.acl)))

    def test_k06_raw_forged_approval_actor_rejected(self):
        self.storage.save_source(self.conn,self.source)
        a=Entity(uuid4(),'tenant-a',self.domain,'ORG','甲公司');b=Entity(uuid4(),'tenant-a',self.domain,'ORG','乙公司')
        ev=Evidence(self.source,'a'*64,0,5)
        c=Candidate(uuid4(),Claim(a,Predicate.SUPPLIES,b),(ev,),self.source.acl,'knowledge')
        eid=self.storage.save_evidence(self.conn,ev);self.storage.save_candidate(self.conn,c,[eid])
        with self.assertRaises(KnowledgeError):
            self.storage.save_approval(self.conn,c.candidate_id,Approval('other',Role.SECURITY_REVIEWER,'ref',self.source.observed_at))

    def test_source_metadata_cannot_broaden_or_revive_same_version(self):
        self.storage.save_source(self.conn,self.source)
        with self.assertRaises(KnowledgeError):
            self.storage.save_source(self.conn,replace(self.source,acl=self.source.acl|{'outsider'}))
        with self.assertRaises(KnowledgeError):
            self.storage.save_source(self.conn,replace(self.source,retention_until=self.source.retention_until+timedelta(days=1)))
        self.conn.execute('UPDATE knowledge_sources SET withdrawn=true WHERE source_id=%s',(self.source.source_id,))
        with self.assertRaises(KnowledgeError):
            self.storage.save_source(self.conn,self.source)

    def test_fixed_descriptor_function_owner_and_public_execute_boundary(self):
        row=self.conn.execute("""SELECT r.rolsuper,r.rolbypassrls,p.prosecdef,p.proconfig,
            EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
                   WHERE a.grantee=0 AND a.privilege_type='EXECUTE')
            FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid='read_authorized_knowledge_candidate(uuid)'::regprocedure""").fetchone()
        self.assertTrue(row[0] or row[1],'FORCE RLS bypass must be explicit for the governed definer')
        self.assertTrue(row[2]);self.assertFalse(row[4]);self.assertTrue(any('search_path=' in setting and 'pg_catalog' in setting for setting in row[3]))
        with psycopg.connect(get_admin_dsn()) as conn:
            schema=conn.execute('SELECT current_schema()').fetchone()[0]
            conn.execute('SET LOCAL ROLE pg_read_all_data')
            from psycopg import sql
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                conn.execute(sql.SQL('SELECT {}.read_authorized_knowledge_candidate(%s)').format(sql.Identifier(schema)),(uuid4(),))
            conn.rollback()

    def test_processing_subjects_cannot_mint_reader_or_other_domain_access(self):
        for actor,tokens in ((self.actor,(f'{self.domain}:restricted-candidate',)),
                            (replace(self.actor,roles=frozenset({Role.KNOWLEDGE_PROCESSOR})),('reader',)),
                            (replace(self.actor,roles=frozenset({Role.KNOWLEDGE_PROCESSOR})),('other:restricted-candidate',))):
            with self.assertRaises(KnowledgeError):self.storage.set_session_identity(self.conn,actor,processing_acl=tokens)

    def test_candidate_read_holds_every_source_until_commit_before_withdrawal(self):
        self._assert_candidate_read_source_serialization()

    def test_candidate_read_holds_every_source_until_commit_before_expiry_batch(self):
        self._assert_candidate_read_source_serialization(expire=True)

    def _assert_candidate_read_source_serialization(self, *, expire=False):
        # Reverse insertion order makes the read acquire both contributing rows,
        # in source identity order rather than the evidence input order.
        sources=(replace(self.source,source_id='z-source'),replace(self.source,source_id='a-source'))
        evidence=tuple(Evidence(source,'a'*64,0,5) for source in sources)
        candidate=Candidate(uuid4(),Claim(Entity(uuid4(),'tenant-a',self.domain,'ORG','甲公司'),
                            Predicate.SUPPLIES,Entity(uuid4(),'tenant-a',self.domain,'ORG','乙公司')),
                            evidence,self.source.acl,'knowledge')
        for source in sources:self.storage.save_source(self.conn,source)
        self.storage.save_candidate(self.conn,candidate,[self.storage.save_evidence(self.conn,ev) for ev in evidence])
        self.conn.commit()
        reader_ready=threading.Event();reader_returned=threading.Event();reader_commit=threading.Event()
        writer_ready=threading.Event();writer_committed=threading.Event();results={}
        blocker=psycopg.connect(get_admin_dsn())
        blocker.execute('LOCK TABLE knowledge_claims IN ACCESS EXCLUSIVE MODE')

        def read():
            try:
                with psycopg.connect(get_test_dsn()) as conn:
                    self.storage.set_session_identity(conn,replace(self.actor,subject_id='reader'))
                    results['reader_pid']=conn.info.backend_pid;reader_ready.set()
                    results['candidate']=self.storage.load_candidate(conn,candidate.candidate_id)
                    reader_returned.set()
                    if not reader_commit.wait(10):raise AssertionError('reader commit barrier timed out')
                results['reader_committed']=True
            except BaseException as exc:results['reader_error']=repr(exc)

        def withdraw():
            try:
                with psycopg.connect(get_test_dsn()) as conn:
                    self.storage.set_session_identity(conn,replace(self.actor,subject_id='steward',roles=frozenset({Role.DATA_STEWARD})))
                    results['writer_pid']=conn.info.backend_pid;writer_ready.set()
                    if expire:self.storage.expire_sources(conn,self.source.retention_until+timedelta(seconds=1))
                    else:self.storage.invalidate_source(conn,sources[0],'concurrent withdrawal',datetime.now(timezone.utc))
                writer_committed.set()
            except BaseException as exc:results['writer_error']=repr(exc)

        def wait_for_blocker(pid,blocking_pid):
            with psycopg.connect(get_admin_dsn(),autocommit=True) as monitor:
                deadline=time.monotonic()+5
                while time.monotonic()<deadline:
                    if blocking_pid in monitor.execute('SELECT pg_blocking_pids(%s)',(pid,)).fetchone()[0]:return True
                    if writer_committed.is_set():return False
                    time.sleep(.02)
            return False

        reader=threading.Thread(target=read,daemon=True);writer=threading.Thread(target=withdraw,daemon=True)
        reader.start()
        try:
            self.assertTrue(reader_ready.wait(5),'reader did not start')
            self.assertTrue(wait_for_blocker(results['reader_pid'],blocker.info.backend_pid),'reader must pause after source admission')
            for source in sources:
                with psycopg.connect(get_test_dsn()) as probe:
                    self.storage.set_session_identity(probe,self.actor)
                    with self.assertRaises(psycopg.errors.LockNotAvailable,msg=f'{source.source_id} must be locked'):
                        probe.execute('SELECT source_id FROM knowledge_sources WHERE source_id=%s FOR UPDATE NOWAIT',
                                      (source.source_id,))
                    probe.rollback()
            writer.start();self.assertTrue(writer_ready.wait(5),'withdrawal did not start')
            self.assertTrue(wait_for_blocker(results['writer_pid'],results['reader_pid']),
                            'withdrawal must wait on the reader source locks, not commit during descriptor read')
            self.assertFalse(writer_committed.is_set())
            blocker.commit()
            self.assertTrue(reader_returned.wait(5),results)
            self.assertEqual(CandidateState.PROPOSED,results['candidate'].state)
            self.assertEqual({'a-source','z-source'},{ev.source.source_id for ev in results['candidate'].evidence})
            self.assertFalse(writer_committed.is_set(),'source locks must remain after function return until reader commit')
            reader_commit.set();reader.join(10);writer.join(10)
            self.assertFalse(reader.is_alive());self.assertFalse(writer.is_alive())
            self.assertNotIn('reader_error',results);self.assertNotIn('writer_error',results)
            self.assertTrue(results.get('reader_committed'));self.assertTrue(writer_committed.is_set())
            with psycopg.connect(get_test_dsn()) as conn:
                self.storage.set_session_identity(conn,replace(self.actor,subject_id='reader'))
                with self.assertRaises(KnowledgeError):self.storage.load_candidate(conn,candidate.candidate_id)
        finally:
            blocker.rollback();blocker.close();reader_commit.set()
            reader.join(10)
            if writer.ident is not None:writer.join(10)
