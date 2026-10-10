"""Observable four-stage behavior and fail-closed plaintext retrieval."""
import json
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

import psycopg

from infra.envelope_crypto import KmsUnavailableError, StaticTestKmsProvider
from infra.file_kms import FileKmsProvider
from request_history import HistoryNotFound, HistoryUnavailable, PostgresHistoryStore
from request_history.models import PURPOSE
from tests.request_history.pg_support import configuration

PROTOCOL = 'deepseek-chat-completions'


class HistoryLocalTests(unittest.TestCase):
    def test_purge_commit_failure_audits_attempt_without_false_success(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.store(directory)
            from unittest.mock import Mock
            connection = Mock()
            connection.execute.return_value.rowcount = 1
            @contextmanager
            def fail_commit(_mode):
                yield connection
                raise OSError('synthetic commit failure')
            with patch.object(store, '_connection', fail_commit), self.assertRaises(HistoryUnavailable):
                store.purge_expired()
            events = [json.loads(path.read_text()) for path in Path(directory).glob('*.json')]
            self.assertEqual([('purge', 'attempted')], [(event['operation'], event['outcome']) for event in events])

    def store(self, directory, **kwargs):
        options = dict(tenant_id='synthetic-tenant',domain='synthetic-domain',retention_days=7,
                       bucket='synthetic-test',audit_directory=directory)
        options.update(kwargs)
        return PostgresHistoryStore('host=unused',StaticTestKmsProvider(),**options)

    def test_retention_and_stage_bound_are_strict_positive_integers(self):
        with tempfile.TemporaryDirectory() as directory:
            for key in ('retention_days','max_stage_bytes'):
                for value in (None,0,-1,True,1.5,'7'):
                    with self.subTest(key=key,value=value),self.assertRaises(HistoryUnavailable):
                        self.store(directory,**{key:value})

    def test_envelope_binding_rejects_uuid_stage_scope_and_metadata_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.store(directory)
            identifier = str(uuid4())
            encrypted = store._encrypt(identifier,'input',b'synthetic-secret','complete','application/json')
            self.assertNotIn(b'synthetic-secret',encrypted)
            self.assertEqual(b'synthetic-secret',store._decrypt(identifier,'input',encrypted,'complete','application/json'))
            for changed_id,stage,state,media in (
                (str(uuid4()),'input','complete','application/json'),
                (identifier,'redacted','complete','application/json'),
                (identifier,'input','partial','application/json'),
                (identifier,'input','complete','text/event-stream'),
            ):
                with self.assertRaises(HistoryUnavailable):
                    store._decrypt(changed_id,stage,encrypted,state,media)
            for options in (dict(tenant_id='other-tenant'),dict(domain='other-domain'),dict(bucket='other-bucket')):
                foreign = self.store(directory,**options)
                foreign.kms = store.kms
                with self.assertRaises(HistoryUnavailable):
                    foreign._decrypt(identifier,'input',encrypted,'complete','application/json')

    def test_durable_audit_contains_only_whitelisted_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.store(directory)
            store.audit_access(operation='get',request_id=str(uuid4()),outcome='success',
                               actor='admin',session_reference='ab'*8)
            document = json.loads(next(Path(directory).glob('*.json')).read_text(encoding='utf-8'))
            self.assertEqual({'audit_id','operation','outcome','request_id','tenant_id','domain',
                              'actor','session_reference','created_at'},set(document))
            self.assertEqual('admin',document['actor'])
            self.assertEqual('ab'*8,document['session_reference'])
            for options in (dict(operation='body-secret',outcome='success'),
                            dict(operation='get',outcome='secret'),
                            dict(operation='get',outcome='success',actor='root'),
                            dict(operation='get',outcome='success',session_reference='not-hex-ref')):
                with self.assertRaises(HistoryUnavailable):
                    store.audit_access(**options)

    def test_audit_failure_has_no_sensitive_exception_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.store(directory)
            with patch('request_history.storage.durable_commit',side_effect=OSError('synthetic-body-password-dsn')):
                with self.assertRaises(HistoryUnavailable) as raised:
                    store.audit_access(operation='list',outcome='success')
            self.assertEqual('Request history unavailable',str(raised.exception))
            self.assertIsNone(raised.exception.__context__)
            self.assertEqual([],list(Path(directory).glob('*.json')))

    def test_missing_audit_directory_does_not_get_created(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory)/'missing'
            store = self.store(missing)
            with self.assertRaises(HistoryUnavailable):
                store.audit_access(operation='get',outcome='denied')
            self.assertFalse(missing.exists())

    def test_read_failure_has_no_sensitive_exception_context(self):
        with tempfile.TemporaryDirectory() as directory:
            store = self.store(directory)
            with patch.object(store,'_connection') as connection:
                connection.return_value.__enter__.side_effect = RuntimeError('synthetic-secret-dsn-body')
                with self.assertRaises(HistoryUnavailable) as raised:
                    store.get_request(str(uuid4()))
            self.assertEqual('Request history unavailable',str(raised.exception))
            self.assertIsNone(raised.exception.__context__)


class HistoryPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.environ.get('GATEWAY_HISTORY_PG_CONFIG'):
            raise unittest.SkipTest('Explicit isolated history PostgreSQL configuration required')
        cls.config = configuration()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.scope = 'synthetic-'+uuid4().hex
        self.kms = StaticTestKmsProvider()
        self.store = PostgresHistoryStore(self.config['app_dsn'],self.kms,tenant_id=self.scope,
                                         domain='synthetic-domain',retention_days=7,bucket='test-seven-days',
                                         audit_directory=self.directory.name,max_stage_bytes=2048)

    def begin(self, body=b'{"messages":[{"content":"synthetic-sensitive-text"}]}',model='synthetic-model'):
        return self.store.begin(protocol=PROTOCOL,model=model,raw_body=body)

    def admin(self):
        return psycopg.connect(self.config['admin_dsn'],connect_timeout=10)

    def expire(self, identifier):
        with self.admin() as conn:
            conn.execute("UPDATE request_records SET created_at=clock_timestamp()-INTERVAL '2 day',"
                         "expires_at=clock_timestamp()-INTERVAL '1 day' WHERE request_id=%s", (identifier,))

    def test_four_exact_stages_and_missing_stage_state(self):
        self.store.check_ready()
        recorder = self.begin()
        initial = self.store.get_request(recorder.request_id)
        self.assertEqual(['complete','not_produced','not_produced','not_produced'],[s['state'] for s in initial['stages']])
        values = {'redacted':b'{"messages":[{"content":"[PERSON_1]"}]}',
                  'upstream':b'{"content":"Hello [PERSON_1]"}','restored':b'{"content":"Hello synthetic-sensitive-text"}'}
        recorder.write_many([dict(stage=stage,body=body) for stage,body in values.items()])
        recorder.finish('completed')
        result = self.store.get_request(recorder.request_id)
        self.assertEqual('completed',result['status'])
        for stage in result['stages'][1:]:
            self.assertEqual(values[stage['stage']].decode(),stage['body'])
        with self.admin() as conn:
            envelopes = conn.execute('SELECT envelope FROM request_stage_contents WHERE request_id=%s',
                                     (recorder.request_id,)).fetchall()
        self.assertEqual(4,len(envelopes))
        self.assertTrue(all(b'synthetic-sensitive-text' not in bytes(row[0]) for row in envelopes))

    def test_write_many_failure_rolls_back_preceding_stage(self):
        recorder = self.begin()
        original = self.store._encrypt
        def encrypt(identifier,stage,*args):
            if stage=='restored':
                raise KmsUnavailableError('synthetic-sensitive-error')
            return original(identifier,stage,*args)
        with patch.object(self.store,'_encrypt',side_effect=encrypt):
            with self.assertRaises(HistoryUnavailable):
                recorder.write_many([dict(stage='redacted',body=b'synthetic-one'),dict(stage='restored',body=b'synthetic-two')])
        states = [stage['state'] for stage in self.store.get_request(recorder.request_id)['stages']]
        self.assertEqual(['complete','not_produced','not_produced','not_produced'],states)

    def test_append_cumulative_bound_and_terminal_immutability(self):
        recorder = self.begin()
        recorder.write('upstream',b'a'*1024,media_type='text/event-stream',state='partial',append=True)
        recorder.write('upstream',b'b'*1024,media_type='text/event-stream',state='partial',append=True)
        with self.assertRaises(HistoryUnavailable):
            recorder.write('upstream',b'c',media_type='text/event-stream',state='partial',append=True)
        recorder.finish('partial','STREAM_INTERRUPTED')
        recorder.finish('partial','STREAM_INTERRUPTED')
        for action in (lambda:recorder.finish('completed'),lambda:recorder.write('restored',b'fake-complete')):
            with self.assertRaises(HistoryUnavailable):
                action()
        detail = self.store.get_request(recorder.request_id)
        self.assertEqual('partial',detail['status'])
        self.assertEqual('a'*1024+'b'*1024,detail['stages'][2]['body'])
        self.assertIsNone(detail['stages'][3]['body'])

    def test_cursor_status_and_metadata_filters_cover_all_domain_records(self):
        first = self.begin(model='synthetic-alpha')
        first.finish('blocked','SECRET_DETECTED')
        second = self.begin(model='synthetic-beta')
        second.finish('completed')
        page = self.store.list_requests(limit=1)
        self.assertEqual(second.request_id,page['items'][0]['request_id'])
        self.assertIsNotNone(page['next_cursor'])
        following = self.store.list_requests(limit=1,cursor=page['next_cursor'])
        self.assertEqual(first.request_id,following['items'][0]['request_id'])
        self.assertIsNone(following['next_cursor'])
        self.assertEqual([first.request_id],[r['request_id'] for r in self.store.list_requests(status='blocked')['items']])
        self.assertEqual([second.request_id],[r['request_id'] for r in self.store.list_requests(model='synthetic-beta')['items']])
        self.assertEqual([first.request_id],[r['request_id'] for r in self.store.list_requests(error_code='SECRET_DETECTED')['items']])
        self.assertEqual(sorted([first.request_id,second.request_id]),
                         sorted(r['request_id'] for r in self.store.list_requests(protocol=PROTOCOL)['items']))
        # Body content is never a filter input; only recorded metadata matches.
        self.assertEqual([],self.store.list_requests(model='synthetic-sensitive-text')['items'])
        future = datetime.now(timezone.utc)+timedelta(days=1)
        past = datetime.now(timezone.utc)-timedelta(days=1)
        self.assertEqual(2,len(self.store.list_requests(created_after=past)['items']))
        self.assertEqual([],self.store.list_requests(created_after=future)['items'])
        self.assertEqual(2,len(self.store.list_requests(created_before=future)['items']))
        self.assertEqual([],self.store.list_requests(created_after=past,created_before=past)['items'])
        for options in (dict(cursor='malformed'),dict(limit=True),dict(status='synthetic-body'),
                        dict(model=''),dict(protocol='unknown'),dict(error_code='NOPE'),
                        dict(created_after='not-a-moment'),dict(created_after=datetime.now()),
                        dict(created_after=future,created_before=past)):
            with self.assertRaises(HistoryUnavailable):
                self.store.list_requests(**options)

    def test_expiry_hides_immediately_and_domain_scoped_purge_cascades(self):
        mine = self.begin()
        other = PostgresHistoryStore(self.config['app_dsn'],self.kms,tenant_id='other-'+self.scope,
                                     domain='synthetic-domain',retention_days=7,bucket=self.store.bucket,
                                     audit_directory=self.directory.name)
        foreign = other.begin(protocol=PROTOCOL,model='synthetic',raw_body=b'synthetic-other')
        with self.assertRaises(HistoryNotFound):
            self.store.get_request(foreign.request_id)
        self.expire(mine.request_id)
        self.expire(foreign.request_id)
        self.assertTrue(self.store.has_records())
        self.assertEqual([],self.store.list_requests()['items'])
        with self.assertRaises(HistoryNotFound):
            self.store.get_request(mine.request_id)
        self.assertEqual(1,self.store.purge_expired())
        self.assertFalse(self.store.has_records())
        with self.admin() as conn:
            self.assertEqual(0,conn.execute('SELECT count(*) FROM request_stage_contents WHERE request_id=%s',(mine.request_id,)).fetchone()[0])
            self.assertEqual(1,conn.execute('SELECT count(*) FROM request_records WHERE request_id=%s',(foreign.request_id,)).fetchone()[0])

    def test_envelope_swap_rejected_and_audit_failure_releases_no_plaintext(self):
        one,two = self.begin(b'synthetic-one'),self.begin(b'synthetic-two')
        with self.admin() as conn:
            conn.execute("UPDATE request_stage_contents SET envelope=(SELECT envelope FROM request_stage_contents WHERE request_id=%s AND stage='input') WHERE request_id=%s AND stage='input'",(one.request_id,two.request_id))
        with self.assertRaises(HistoryUnavailable):
            self.store.get_request(two.request_id)
        with patch.object(self.store,'audit_access',side_effect=HistoryUnavailable()):
            with self.assertRaises(HistoryUnavailable):
                self.store.get_request(one.request_id)

    def test_expiry_is_rechecked_after_audit_commit(self):
        recorder = self.begin()
        audit = self.store.audit_access
        def audit_and_expire(**options):
            audit(**options)
            if options['operation']=='get' and options['outcome']=='success':
                self.expire(recorder.request_id)
        with patch.object(self.store,'audit_access',side_effect=audit_and_expire):
            with self.assertRaises(HistoryNotFound):
                self.store.get_request(recorder.request_id)

    def test_file_kms_restart_and_destroy_fail_closed_without_reprovision(self):
        directory = Path(self.directory.name)/'keys'
        master = os.urandom(32)
        first = FileKmsProvider(directory,master)
        missing = PostgresHistoryStore(self.config['app_dsn'],first,tenant_id=self.scope,domain=self.store.domain,
                                       retention_days=7,bucket=self.store.bucket,audit_directory=self.directory.name)
        with self.assertRaises(HistoryUnavailable):
            missing.check_ready()
        first.provision(purpose=PURPOSE,bucket=self.store.bucket)
        self.store.kms = first
        recorder = self.begin()
        self.store.kms = FileKmsProvider(directory,master)
        self.assertEqual('complete',self.store.get_request(recorder.request_id)['stages'][0]['state'])
        first.destroy(purpose=PURPOSE,bucket=self.store.bucket)
        self.assertTrue(self.store.has_records())
        with self.assertRaises(HistoryUnavailable):
            self.store.get_request(recorder.request_id)
        with self.assertRaises(HistoryUnavailable):
            self.store.check_ready()
