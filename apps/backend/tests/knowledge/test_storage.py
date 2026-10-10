"""Real PostgreSQL constrained-role contract tests; configuration is injected."""
import unittest
import threading
import time
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime,timedelta,timezone
from uuid import uuid4
import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
from psycopg.errors import ForeignKeyViolation,InsufficientPrivilege,CheckViolation
from knowledge.storage import PostgresKnowledgeStorage,_ASSET_TABLES
from knowledge.knowledge import *
from tests.pg_support import get_test_dsn,get_admin_dsn,prepare_test_database,test_configuration

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


class AdminGovernanceTestCase(unittest.TestCase):
    """Shared fixtures for the v2 single-admin governance schema."""

    @classmethod
    def setUpClass(cls):
        prepare_test_database()
        cls.config = test_configuration()

    def setUp(self):
        self.tenant = 'tenant-a'
        self.domain = 'admin-' + uuid4().hex

    def admin_storage(self, *, domain=None) -> PostgresKnowledgeStorage:
        return PostgresKnowledgeStorage(self.config['admin_app_dsn'], tenant_id=self.tenant,
                                        domain=domain or self.domain,
                                        admin_dsn=self.config['admin_app_dsn'],
                                        admin_role=self.config['admin_role'])

    @contextmanager
    def admin_scope(self, *, domain=None, admin_context=True):
        conn = psycopg.connect(self.config['admin_app_dsn'])
        try:
            conn.execute(sql.SQL('SET LOCAL ROLE {}').format(sql.Identifier(self.config['admin_role'])))
            conn.execute("SELECT set_config('app.tenant',%s,true)", (self.tenant,))
            conn.execute("SELECT set_config('app.domain',%s,true)", (domain or self.domain,))
            if admin_context:
                conn.execute("SELECT set_config('app.admin_context','true',true)")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextmanager
    def app_scope(self, *, subjects=('reader',), purposes=('procurement',), admin_context=False, domain=None):
        conn = psycopg.connect(self.config['app_dsn'])
        try:
            conn.execute("SELECT set_config('app.tenant',%s,true)", (self.tenant,))
            conn.execute("SELECT set_config('app.domain',%s,true)", (domain or self.domain,))
            conn.execute("SELECT set_config('app.subjects',%s::text[]::text,true)", (list(subjects),))
            conn.execute("SELECT set_config('app.purposes',%s::text[]::text,true)", (list(purposes),))
            if admin_context:
                conn.execute("SELECT set_config('app.admin_context','true',true)")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def seed_source(self, conn, *, domain=None, source_id='source', version='v1', withdrawn=False):
        domain = domain or self.domain
        conn.execute(
            "INSERT INTO knowledge_sources(tenant_id,domain,source_id,version,source_kind,acl,purpose,"
            "observed_at,retention_until,independence_verified,withdrawn)"
            " VALUES(%s,%s,%s,%s,'document',ARRAY['legal'],'procurement',now(),now()+interval '7 days',true,%s)",
            (self.tenant, domain, source_id, version, withdrawn))
        conn.execute(
            "INSERT INTO knowledge_evidence(tenant_id,domain,source_id,version,content_sha256,char_start,char_end,acl,purpose)"
            " VALUES(%s,%s,%s,%s,%s,0,5,ARRAY['legal'],'procurement')",
            (self.tenant, domain, source_id, version, 'a' * 64))

    def seed_candidate(self, conn, *, domain=None, source_id='source', version='v1', candidate_id=None):
        domain = domain or self.domain
        candidate_id = candidate_id or uuid4()
        self.seed_source(conn, domain=domain, source_id=source_id, version=version)
        subject = uuid4()
        obj = uuid4()
        conn.execute(
            "INSERT INTO knowledge_entities(entity_id,tenant_id,domain,entity_type,name,acl,purpose)"
            " VALUES(%s,%s,%s,'ORG','甲公司',ARRAY['legal'],'procurement')", (subject, self.tenant, domain))
        conn.execute(
            "INSERT INTO knowledge_entities(entity_id,tenant_id,domain,entity_type,name,acl,purpose)"
            " VALUES(%s,%s,%s,'ORG','乙公司',ARRAY['legal'],'procurement')", (obj, self.tenant, domain))
        claim_id = conn.execute(
            "INSERT INTO knowledge_claims(tenant_id,domain,subject_id,predicate,object_id,polarity,modality,acl,purpose)"
            " VALUES(%s,%s,%s,'supplies',%s,'positive','asserted',ARRAY['legal'],'procurement') RETURNING claim_id",
            (self.tenant, domain, subject, obj)).fetchone()[0]
        conn.execute(
            "INSERT INTO knowledge_candidates(candidate_id,claim_id,tenant_id,domain,acl,purpose,state)"
            " VALUES(%s,%s,%s,%s,ARRAY['legal'],'procurement','proposed')",
            (candidate_id, claim_id, self.tenant, domain))
        evidence_id = conn.execute(
            "SELECT evidence_id FROM knowledge_evidence WHERE (tenant_id,domain,source_id,version)=(%s,%s,%s,%s)",
            (self.tenant, domain, source_id, version)).fetchone()[0]
        conn.execute(
            "INSERT INTO candidate_evidence_links(candidate_id,evidence_id,tenant_id,domain,acl,purpose)"
            " VALUES(%s,%s,%s,%s,ARRAY['legal'],'procurement')",
            (candidate_id, evidence_id, self.tenant, domain))
        return candidate_id

    def bind_governance(self, conn, *, domain=None, source_id='source', version='v1',
                        candidate_id=None, consumer_audiences=('legal',), valid_days=7,
                        object_version='1'):
        domain = domain or self.domain
        admin_action_id = uuid4()
        governance_version_id = uuid4()
        conn.execute(
            "INSERT INTO knowledge_admin_actions(admin_action_id,tenant_id,domain,actor_id,session_digest,action_type,"
            "object_type,object_id,object_version,rationale,intended_use,consumer_audiences,result)"
            " VALUES(%s,%s,%s,'admin','session-digest','publish','candidate',%s,%s,'verified basis',"
            "'procurement',%s,'succeeded')",
            (admin_action_id, self.tenant, domain, str(candidate_id), object_version,
             list(consumer_audiences)))
        conn.execute(
            "INSERT INTO knowledge_governance_versions(governance_version_id,tenant_id,domain,source_id,source_version,"
            "admin_action_id,ownership_confirmed,intended_use,consumer_audiences,valid_until,rationale)"
            " VALUES(%s,%s,%s,%s,%s,%s,true,'procurement',%s,now()+interval '%s days','verified basis')",
            (governance_version_id, self.tenant, domain, source_id, version, admin_action_id,
             list(consumer_audiences), valid_days))
        return admin_action_id, governance_version_id


class TestKnowledgeSchemaV2(AdminGovernanceTestCase):
    def test_v2_schema_objects(self):
        with self.admin_scope() as conn:
            names = {r[0] for r in conn.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema()")}
            self.assertNotIn('knowledge_approvals', names)
            self.assertLessEqual({'knowledge_admin_actions', 'knowledge_governance_versions',
                                  'knowledge_publication_sources'}, names)
            triggers = {r[0] for r in conn.execute(
                "SELECT trigger_name FROM information_schema.triggers WHERE trigger_schema=current_schema()")}
            self.assertNotIn('enforce_reviewer_identity', triggers)
            self.assertIn('enforce_publication_admission', triggers)
            columns = {(r[0], r[1]) for r in conn.execute(
                "SELECT table_name,column_name FROM information_schema.columns"
                " WHERE table_schema=current_schema()")}
            for expected in (('knowledge_candidates', 'candidate_version'),
                             ('knowledge_candidates', 'derived_from'),
                             ('knowledge_publications', 'candidate_version'),
                             ('knowledge_publications', 'intended_use'),
                             ('knowledge_publications', 'consumer_audiences'),
                             ('knowledge_publications', 'admin_action_id'),
                             ('knowledge_publications', 'idempotency_key'),
                             ('knowledge_consumer_assets', 'asset_version'),
                             ('knowledge_consumer_assets', 'asset_kind'),
                             ('knowledge_consumer_assets', 'intended_use'),
                             ('knowledge_consumer_assets', 'lineage'),
                             ('consumer_receipts', 'delivery_result'),
                             ('consumer_receipts', 'last_error_code')):
                self.assertIn(expected, columns)

    def test_publication_requires_bound_admin_action(self):
        # Direct publication insert (no bound publish admin action) is rejected.
        with self.admin_scope() as conn:
            candidate_id = self.seed_candidate(conn)
            with self.assertRaisesRegex(Exception, 'KNOWLEDGE_ADMIN_ACTION_REQUIRED'):
                conn.execute(
                    "INSERT INTO knowledge_publications(publication_id,tenant_id,domain,candidate_id,"
                    "candidate_version,intended_use,consumer_audiences,valid_until,admin_action_id,acl,purpose)"
                    " VALUES (%s,'t1','d1',%s,1,'procurement',ARRAY['legal'],now()+interval '1 day',%s,"
                    "ARRAY['legal'],'procurement')",
                    (uuid4(), uuid4(), uuid4()))

    def test_publication_requires_admin_role(self):
        with self.app_scope(admin_context=True) as conn:
            with self.assertRaisesRegex(Exception, 'KNOWLEDGE_PUBLISHER_REQUIRED'):
                conn.execute(
                    "INSERT INTO knowledge_publications(publication_id,tenant_id,domain,candidate_id,"
                    "candidate_version,intended_use,consumer_audiences,valid_until,admin_action_id,acl,purpose)"
                    " VALUES (%s,%s,%s,%s,1,'procurement',ARRAY['legal'],now()+interval '1 day',%s,"
                    "ARRAY['legal'],'procurement')",
                    (uuid4(), self.tenant, self.domain, uuid4(), uuid4()))

    def test_publication_requires_admin_context_guc(self):
        with self.admin_scope() as conn:
            candidate_id = self.seed_candidate(conn)
            admin_action_id, governance_version_id = self.bind_governance(conn, candidate_id=candidate_id)
            publication_id = uuid4()
            conn.execute(
                "INSERT INTO knowledge_publication_sources(publication_id,tenant_id,domain,source_id,source_version,"
                "governance_version_id) VALUES(%s,%s,%s,'source','v1',%s)",
                (publication_id, self.tenant, self.domain, governance_version_id))
            conn.execute("SELECT set_config('app.admin_context','false',true)")
            with self.assertRaisesRegex(Exception, 'KNOWLEDGE_ADMIN_CONTEXT_REQUIRED'):
                conn.execute(
                    "INSERT INTO knowledge_publications(publication_id,tenant_id,domain,candidate_id,"
                    "candidate_version,intended_use,consumer_audiences,valid_until,admin_action_id,acl,purpose)"
                    " VALUES (%s,%s,%s,%s,1,'procurement',ARRAY['legal'],now()+interval '1 day',%s,"
                    "ARRAY['legal'],'procurement')",
                    (uuid4(), self.tenant, self.domain, candidate_id, admin_action_id))

    def test_publication_rejects_unknown_candidate_version(self):
        with self.admin_scope() as conn:
            candidate_id = self.seed_candidate(conn)
            admin_action_id, governance_version_id = self.bind_governance(
                conn, candidate_id=candidate_id, object_version=None)
            publication_id = uuid4()
            conn.execute(
                "INSERT INTO knowledge_publication_sources(publication_id,tenant_id,domain,source_id,source_version,"
                "governance_version_id) VALUES(%s,%s,%s,'source','v1',%s)",
                (publication_id, self.tenant, self.domain, governance_version_id))
            with self.assertRaisesRegex(Exception, 'KNOWLEDGE_CANDIDATE_VERSION_NOT_FOUND'):
                conn.execute(
                    "INSERT INTO knowledge_publications(publication_id,tenant_id,domain,candidate_id,"
                    "candidate_version,intended_use,consumer_audiences,valid_until,admin_action_id,acl,purpose)"
                    " VALUES (%s,%s,%s,%s,9,'procurement',ARRAY['legal'],now()+interval '1 day',%s,"
                    "ARRAY['legal'],'procurement')",
                    (publication_id, self.tenant, self.domain, candidate_id, admin_action_id))

    def test_publication_rejects_unbound_contributing_source(self):
        with self.admin_scope() as conn:
            candidate_id = self.seed_candidate(conn)
            admin_action_id, _ = self.bind_governance(conn, candidate_id=candidate_id)
            with self.assertRaisesRegex(Exception, 'KNOWLEDGE_PUBLICATION_SOURCE_MISSING'):
                conn.execute(
                    "INSERT INTO knowledge_publications(publication_id,tenant_id,domain,candidate_id,"
                    "candidate_version,intended_use,consumer_audiences,valid_until,admin_action_id,acl,purpose)"
                    " VALUES (%s,%s,%s,%s,1,'procurement',ARRAY['legal'],now()+interval '1 day',%s,"
                    "ARRAY['legal'],'procurement')",
                    (uuid4(), self.tenant, self.domain, candidate_id, admin_action_id))

    def test_publication_rejects_superseded_governance_version(self):
        with self.admin_scope() as conn:
            candidate_id = self.seed_candidate(conn)
            admin_action_id, governance_version_id = self.bind_governance(conn, candidate_id=candidate_id)
            replacement_id = uuid4()
            conn.execute(
                "INSERT INTO knowledge_governance_versions(governance_version_id,tenant_id,domain,source_id,source_version,"
                "admin_action_id,ownership_confirmed,intended_use,consumer_audiences,valid_until,rationale,"
                "supersedes_version_id) VALUES(%s,%s,%s,'source','v1',%s,true,'procurement',ARRAY['legal'],"
                "now()+interval '7 days','replacement basis',%s)",
                (replacement_id, self.tenant, self.domain, admin_action_id, governance_version_id))
            publication_id = uuid4()
            conn.execute(
                "INSERT INTO knowledge_publication_sources(publication_id,tenant_id,domain,source_id,source_version,"
                "governance_version_id) VALUES(%s,%s,%s,'source','v1',%s)",
                (publication_id, self.tenant, self.domain, governance_version_id))
            with self.assertRaisesRegex(Exception, 'KNOWLEDGE_GOVERNANCE_VERSION_INVALID'):
                conn.execute(
                    "INSERT INTO knowledge_publications(publication_id,tenant_id,domain,candidate_id,"
                    "candidate_version,intended_use,consumer_audiences,valid_until,admin_action_id,acl,purpose)"
                    " VALUES (%s,%s,%s,%s,1,'procurement',ARRAY['legal'],now()+interval '1 day',%s,"
                    "ARRAY['legal'],'procurement')",
                    (publication_id, self.tenant, self.domain, candidate_id, admin_action_id))

    def test_publication_rejects_withdrawn_source(self):
        with self.admin_scope() as conn:
            candidate_id = self.seed_candidate(conn)
            admin_action_id, governance_version_id = self.bind_governance(conn, candidate_id=candidate_id)
            conn.execute(
                "UPDATE knowledge_sources SET withdrawn=true WHERE (tenant_id,domain,source_id,version)=(%s,%s,'source','v1')",
                (self.tenant, self.domain))
            publication_id = uuid4()
            conn.execute(
                "INSERT INTO knowledge_publication_sources(publication_id,tenant_id,domain,source_id,source_version,"
                "governance_version_id) VALUES(%s,%s,%s,'source','v1',%s)",
                (publication_id, self.tenant, self.domain, governance_version_id))
            with self.assertRaisesRegex(Exception, 'KNOWLEDGE_SOURCE_WITHDRAWN'):
                conn.execute(
                    "INSERT INTO knowledge_publications(publication_id,tenant_id,domain,candidate_id,"
                    "candidate_version,intended_use,consumer_audiences,valid_until,admin_action_id,acl,purpose)"
                    " VALUES (%s,%s,%s,%s,1,'procurement',ARRAY['legal'],now()+interval '1 day',%s,"
                    "ARRAY['legal'],'procurement')",
                    (publication_id, self.tenant, self.domain, candidate_id, admin_action_id))


class TestAdminPublishTransactional(AdminGovernanceTestCase):
    def test_publish_transactional_binds_sources_and_is_idempotent(self):
        storage = self.admin_storage()
        with self.admin_scope() as conn:
            candidate_id = self.seed_candidate(conn)
            admin_action_id, governance_version_id = self.bind_governance(conn, candidate_id=candidate_id)
        valid_until = datetime.now(timezone.utc) + timedelta(days=1)
        publication_id = storage.publish_transactional(
            candidate_id=candidate_id, candidate_version=1, intended_use='procurement',
            consumer_audiences=['legal'], valid_until=valid_until, admin_action_id=admin_action_id,
            idempotency_key='publish-req-1', source_bindings=[('source', 'v1', governance_version_id)])
        retry_id = storage.publish_transactional(
            candidate_id=candidate_id, candidate_version=1, intended_use='procurement',
            consumer_audiences=['legal'], valid_until=valid_until, admin_action_id=admin_action_id,
            idempotency_key='publish-req-1', source_bindings=[('source', 'v1', governance_version_id)])
        self.assertEqual(publication_id, retry_id)
        with self.admin_scope() as conn:
            row = conn.execute(
                "SELECT candidate_version,intended_use,consumer_audiences,admin_action_id,idempotency_key"
                " FROM knowledge_publications WHERE publication_id=%s", (publication_id,)).fetchone()
            self.assertEqual((1, 'procurement', ['legal'], admin_action_id, 'publish-req-1'), row)
            self.assertEqual(1, conn.execute(
                "SELECT count(*) FROM knowledge_publication_sources WHERE publication_id=%s",
                (publication_id,)).fetchone()[0])
            self.assertEqual(1, conn.execute(
                "SELECT count(*) FROM knowledge_outbox WHERE aggregate_id=%s AND event_type='KNOWLEDGE_PUBLISHED'",
                (publication_id,)).fetchone()[0])
            payload = conn.execute(
                "SELECT payload FROM knowledge_outbox WHERE aggregate_id=%s", (publication_id,)).fetchone()[0]
            self.assertEqual(publication_id, payload['publication_id'])
            self.assertEqual(str(governance_version_id), payload['governance_version_ids'][0])

    def test_publish_transactional_requires_admin_binding(self):
        storage = self.admin_storage()
        with self.admin_scope() as conn:
            candidate_id = self.seed_candidate(conn)
        with self.assertRaisesRegex(Exception, 'KNOWLEDGE_ADMIN_ACTION_REQUIRED'):
            storage.publish_transactional(
                candidate_id=candidate_id, candidate_version=1, intended_use='procurement',
                consumer_audiences=['legal'], valid_until=datetime.now(timezone.utc) + timedelta(days=1),
                admin_action_id=uuid4(), idempotency_key='publish-req-2',
                source_bindings=[])

    def test_admin_transaction_sets_scope_and_commits(self):
        storage = self.admin_storage()
        with storage.admin_transaction(tenant_id=self.tenant, domain=self.domain) as conn:
            conn.execute(
                "INSERT INTO knowledge_admin_actions(admin_action_id,tenant_id,domain,actor_id,session_digest,"
                "action_type,object_type,object_id,rationale,result) VALUES(%s,%s,%s,'admin','digest',"
                "'reject','candidate',%s,'basis','succeeded')",
                (uuid4(), self.tenant, self.domain, str(uuid4())))
        with self.admin_scope() as conn:
            self.assertEqual(1, conn.execute(
                "SELECT count(*) FROM knowledge_admin_actions WHERE tenant_id=%s AND domain=%s",
                (self.tenant, self.domain)).fetchone()[0])

    def test_admin_transaction_requires_admin_dsn(self):
        storage = PostgresKnowledgeStorage(self.config['admin_app_dsn'], tenant_id=self.tenant, domain=self.domain)
        with self.assertRaises(KnowledgeError):
            with storage.admin_transaction(tenant_id=self.tenant, domain=self.domain):
                pass


class TestSchemaFingerprint(AdminGovernanceTestCase):
    def test_fingerprint_constant_matches_computed(self):
        from knowledge.storage import SCHEMA_FINGERPRINT_V2, compute_schema_fingerprint
        with psycopg.connect(self.config['admin_app_dsn']) as conn:
            self.assertEqual(compute_schema_fingerprint(conn, admin_role=self.config['admin_role']),
                             SCHEMA_FINGERPRINT_V2)

    def test_fingerprint_stable_across_random_deployments(self):
        from knowledge.storage import SCHEMA_FINGERPRINT_V2, compute_schema_fingerprint
        fingerprints = []
        for _ in range(2):
            token = uuid4().hex[:12]
            schema = f'gw_test_fp_{token}'
            admin_role = f'{schema}_admin'
            dsn = make_conninfo(self.config['admin_dsn'], options='-c search_path=' + schema)
            try:
                with psycopg.connect(self.config['admin_dsn']) as conn:
                    conn.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
                PostgresKnowledgeStorage(dsn).init_database(enable_rls=True, admin_role=admin_role)
                with psycopg.connect(dsn) as conn:
                    fingerprints.append(compute_schema_fingerprint(conn, admin_role=admin_role))
            finally:
                with psycopg.connect(self.config['admin_dsn'], autocommit=True) as conn:
                    conn.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(schema)))
        self.assertEqual(fingerprints[0], fingerprints[1])
        self.assertEqual(SCHEMA_FINGERPRINT_V2, fingerprints[0])

    def test_fingerprint_rejects_tampered_schema(self):
        from knowledge.storage import KnowledgeSchemaError
        storage = self.admin_storage()
        with psycopg.connect(self.config['admin_app_dsn']) as conn:
            conn.execute('CREATE TABLE knowledge_extra_drift (id INTEGER)')
            conn.commit()
            try:
                with self.assertRaisesRegex(KnowledgeSchemaError, 'KNOWLEDGE_SCHEMA_INCOMPATIBLE'):
                    storage.verify_schema(conn)
            finally:
                conn.execute('DROP TABLE knowledge_extra_drift')
                conn.commit()


class TestAdminRls(AdminGovernanceTestCase):
    def test_admin_policy_reads_without_consumer_acl(self):
        with self.admin_scope() as conn:
            self.seed_source(conn, source_id='hidden-source')
            conn.execute(
                "UPDATE knowledge_sources SET acl=ARRAY['hidden-subject'], withdrawn=true"
                " WHERE (tenant_id,domain,source_id)=(%s,%s,'hidden-source')", (self.tenant, self.domain))
        with self.admin_scope() as conn:
            self.assertIsNotNone(conn.execute(
                "SELECT source_id FROM knowledge_sources WHERE source_id='hidden-source'").fetchone())
        with self.app_scope(subjects=('reader',)) as conn:
            self.assertEqual(0, conn.execute(
                "SELECT count(*) FROM knowledge_sources WHERE source_id='hidden-source'").fetchone()[0])

    def test_app_role_cannot_use_admin_context(self):
        with self.admin_scope() as conn:
            conn.execute(
                "INSERT INTO knowledge_admin_actions(admin_action_id,tenant_id,domain,actor_id,session_digest,"
                "action_type,object_type,object_id,rationale,result) VALUES(%s,%s,%s,'admin','digest',"
                "'reject','candidate',%s,'basis','succeeded')",
                (uuid4(), self.tenant, self.domain, str(uuid4())))
        with self.app_scope(admin_context=True) as conn:
            self.assertEqual(0, conn.execute(
                "SELECT count(*) FROM knowledge_admin_actions WHERE domain=%s", (self.domain,)).fetchone()[0])
            with self.assertRaises(InsufficientPrivilege):
                conn.execute(
                    "INSERT INTO knowledge_admin_actions(admin_action_id,tenant_id,domain,actor_id,session_digest,"
                    "action_type,object_type,object_id,rationale,result) VALUES(%s,%s,%s,'admin','digest',"
                    "'reject','candidate',%s,'basis','succeeded')",
                    (uuid4(), self.tenant, self.domain, str(uuid4())))

    def test_app_role_cannot_set_role_admin(self):
        with psycopg.connect(self.config['app_dsn']) as conn:
            with self.assertRaises(InsufficientPrivilege):
                conn.execute(sql.SQL('SET ROLE {}').format(sql.Identifier(self.config['admin_role'])))
