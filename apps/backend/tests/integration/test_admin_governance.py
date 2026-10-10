"""Synthetic BYOK requests, real FileKMS/spool/PG and single-admin lifecycle."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
import unittest
from uuid import UUID, uuid4

import httpx
import psycopg
from starlette.testclient import TestClient

from audit.admin_reader import AdminReviewService
from audit.catalog import AuditCatalogBuilder
from gateway.admin_audit_api import revalidate_audit_session
from gateway.admin_auth import AdminAuthService, initialize_admin_state
from gateway.admin_storage import AdminStateStore
from infra.envelope_crypto import decrypt_record, parse_record
from knowledge.governance import KnowledgeGovernanceService
from knowledge.knowledge import Candidate, Role, TrustedActor
from knowledge.knowledge_events import ObservationEvent
from knowledge.storage import PostgresKnowledgeStorage
from knowledge.worker import GovernedConsumer, KnowledgeWorker, PostgresKnowledgeSink
from tests.gateway import test_runtime
from tests.pg_support import prepare_test_database, test_configuration
from tests.request_history.test_local_e2e import admin_login, synthetic_requests


@contextmanager
def synthetic_governance_runtime(*, enable_management=True):
    prepare_test_database()
    config = test_configuration()
    fixture = test_runtime.RuntimeAssemblyTests(methodName='runTest')
    app = None
    try:
        fixture.setUp()
        tenant, domain = 'governance-' + uuid4().hex, fixture.domain
        storage = PostgresKnowledgeStorage(config['app_dsn'], tenant_id=tenant, domain=domain,
            admin_dsn=config['admin_app_dsn'], admin_role=config['admin_role'])
        service = KnowledgeGovernanceService(tenant_id=tenant, domain=domain, storage=storage)
        admin_store = AdminStateStore(fixture.root/'state'/'admin')
        from scripts.prepare_admin_state import INITIAL_ADMIN_PASSWORD
        initialize_admin_state(admin_store, INITIAL_ADMIN_PASSWORD)
        admin_service = AdminAuthService(admin_store, scope=f'{tenant}/{domain}')
        root = fixture.root/'state'
        # Runtime owns these exact directories; the assembler supplies lifecycle.
        builder = AuditCatalogBuilder(intent_root=root/'intents', evidence_root=root/'evidence',
            catalog_directory=root/'catalog', lifecycle=lambda _id: (datetime.now(timezone.utc)+timedelta(days=1), 'synthetic-retention-v1'))
        reader = AdminReviewService(catalog_directory=root/'catalog', evidence_root=root/'evidence',
            kms=fixture.kms, revalidate=revalidate_audit_session, review_purpose='model-query',
            access_log_directory=root/'access-events')
        def supplier(request):
            response = fixture.upstream(request)
            payload = json.loads(request.content)
            if not payload.get('stream'):
                return response
            from tests.protocol.test_stream_events import chat, choice, claude
            if request.url.path == '/v1/messages':
                message = response.json()
                text = ''.join(block['text'] for block in message['content'] if block['type']=='text')
                message.update(content=[], stop_reason=None, usage={'input_tokens':1,'output_tokens':0})
                body = (claude('message_start', message=message)
                    + claude('content_block_start',index=0,content_block={'type':'text','text':''})
                    + claude('content_block_delta',index=0,delta={'type':'text_delta','text':text})
                    + claude('content_block_stop',index=0)
                    + claude('message_delta',delta={'stop_reason':'end_turn','stop_sequence':None},usage={'output_tokens':1})
                    + claude('message_stop'))
            else:
                text = response.json()['choices'][0]['message']['content']
                body = chat([choice(delta={'role':'assistant','content':text})],model=payload['model']) + chat([choice(finish='stop')],model=payload['model']) + b'data: [DONE]\n\n'
            return httpx.Response(200,content=body,headers={'content-type':'text/event-stream'})
        fixture.transport = httpx.MockTransport(supplier)
        app = fixture.app(tenant_id=tenant, admin_service=admin_service,
            knowledge_governance=service if enable_management else None,
            audit_reader=reader if enable_management else None,
            audit_builder=builder if enable_management else None)
        yield SimpleNamespace(app=app,fixture=fixture,storage=storage,service=service,config=config,
            tenant=tenant,domain=domain,kms=fixture.kms,builder=builder,reader=reader,admin_service=admin_service)
    finally:
        if app is not None and not app.state.runtime_closed:
            pipelines = app.state.runtime_pipelines
            try:
                if pipelines: pipelines[0].detector.close()
            finally:
                for pipeline in pipelines: pipeline.egress_client.close()
                app.state.runtime_closed=True
        fixture.doCleanups()


class AdminGovernanceWholeFlowTests(unittest.TestCase):
    def test_encrypted_worker_governance_consumption_and_actual_audit(self):
        with synthetic_governance_runtime() as runtime, TestClient(runtime.app) as client:
            csrf = admin_login(client)
            headers = {'Origin':'http://testserver','x-admin-csrf':csrf}
            now = datetime.now(timezone.utc)
            until = now+timedelta(hours=12)
            restricted = runtime.domain+':restricted-candidate'
            actor = TrustedActor('worker',runtime.tenant,runtime.domain,
                frozenset({Role.KNOWLEDGE_PROCESSOR}),frozenset({'knowledge-accumulation'}))
            text='甲公司向乙公司采购设备。'
            path, request_headers, request_body = synthetic_requests()[0]
            for suffix in ('采购记录A。', '采购记录B。'):
                body = dict(request_body, messages=[{'role':'user','content':text+suffix}])
                response = client.post(path, headers=request_headers, json=body)
                self.assertEqual(200,response.status_code,response.text)
                self.assertIn(text,response.text)
            files=list(runtime.app.state.runtime_spool_directory.glob('*.env.json'))
            self.assertEqual(2,len(files))
            self.assertTrue(all(text.encode() not in file.read_bytes() for file in files))
            events=[ObservationEvent.model_validate_json(decrypt_record(runtime.kms,parse_record(file.read_bytes()))) for file in files]
            sources=dict(zip(('A','B'),events))
            self.assertTrue(all(event.acl==frozenset({restricted}) and not event.source_independence_verified
                and event.source_provenance=='unverified' and event.ownership_status=='unassigned' for event in events))
            sink=PostgresKnowledgeSink(runtime.storage,actor,runtime.kms,processing_acl=(restricted,))
            self.assertEqual(2,KnowledgeWorker(runtime.app.state.runtime_spool_directory,runtime.kms,sink).run_once().submitted)
            with psycopg.connect(runtime.config['app_dsn']) as conn:
                runtime.storage.set_session_identity(conn,actor,processing_acl=(restricted,))
                ids=conn.execute('SELECT candidate_id FROM knowledge_candidates ORDER BY candidate_id').fetchall()
                candidates=[runtime.storage.load_candidate(conn,row[0]) for row in ids]
                self.assertEqual(2,len(candidates))
                merged=Candidate(uuid4(),candidates[0].claim,tuple(ev for c in candidates for ev in c.evidence),frozenset({restricted}),'knowledge-accumulation')
                runtime.storage.save_candidate(conn,merged,[runtime.storage.save_evidence(conn,ev) for ev in merged.evidence])
                self.assertEqual(0,merged.independent_source_count)
            for source,audiences in (('A',['procurement','legal']),('B',['legal'])):
                response=client.post(f'/api/admin/sources/{sources[source].source_id}/governance',headers=headers,json={
                    'source_version':sources[source].source_version,'expected_governance_version':None,'ownership':'confirmed',
                    'use':'knowledge-accumulation','audiences':audiences,'valid_until':until.isoformat(),'basis':'synthetic source review'})
                self.assertEqual(200,response.status_code,response.text)
            payload={'expected_version':1,'use':'knowledge-accumulation','audiences':['procurement'],
                'valid_until':until.isoformat(),'idempotency_key':'wholeflow','basis':'synthetic publish'}
            rejected=client.post(f'/api/admin/candidates/{merged.candidate_id}/publish',headers=headers,json=payload)
            self.assertEqual(422,rejected.status_code,rejected.text)
            self.assertIn('AUDIENCE_DENIED',rejected.text)
            payload['audiences']=['legal']
            published=client.post(f'/api/admin/candidates/{merged.candidate_id}/publish',headers=headers,json=payload)
            self.assertEqual(200,published.status_code,published.text)
            publication=published.json()['publication_id']
            legal=TrustedActor('legal',runtime.tenant,runtime.domain,frozenset(),frozenset({'knowledge-accumulation'}))
            consumer=GovernedConsumer(runtime.storage,legal)
            availability=lambda: runtime.service.evaluate_availability(candidate_id=None,publication_id=publication,consumer='legal',use='knowledge-accumulation',now=datetime.now(timezone.utc))
            self.assertEqual('pending',availability().delivery_status)
            with self.assertRaises(RuntimeError): consumer.consume_once(fail_after_apply=True)
            self.assertEqual((),consumer.active_publication_ids())
            self.assertEqual(1,consumer.consume_once())
            applied=availability()
            self.assertEqual('applied',applied.delivery_status)
            self.assertEqual(1,applied.reuse_assets[0].asset_version)
            self.assertIsNotNone(applied.reuse_assets[0].receipt_id)
            self.assertEqual((UUID(publication),),consumer.active_publication_ids())
            self.assertEqual((),consumer.active_publication_ids(until+timedelta(seconds=1)))
            self.assertTrue(runtime.service.export_versioned_jsonl([publication],legal,'v1'))
            self.assertEqual({'甲公司','乙公司'},{entry['text'] for entry in runtime.service.compile_approved_dictionary_payload('synthetic','v1',[publication],consumer=legal)['entries']})
            for name,purpose in (('procurement','knowledge-accumulation'),('legal','other-use')):
                denied=TrustedActor(name,runtime.tenant,runtime.domain,frozenset(),frozenset({purpose}))
                self.assertEqual(0,GovernedConsumer(runtime.storage,denied).consume_once())
                self.assertEqual('',runtime.service.export_versioned_jsonl([publication],denied,'v1'))
            withdrawn=client.post(f'/api/admin/sources/{sources["A"].source_id}/withdraw',headers=headers,json={'source_version':sources['A'].source_version,'basis':'synthetic withdrawal'})
            self.assertEqual(200,withdrawn.status_code,withdrawn.text)
            self.assertEqual('invalidation_pending',availability().delivery_status)
            self.assertEqual((),consumer.active_publication_ids())
            self.assertEqual('',runtime.service.export_versioned_jsonl([publication],legal,'v2'))
            self.assertEqual(1,consumer.consume_once())
            self.assertEqual('invalidated',availability().reuse_assets[0].invalidation_status)
            with runtime.storage.admin_transaction(tenant_id=runtime.tenant,domain=runtime.domain) as conn:
                self.assertEqual([([restricted],False),([restricted],False)],conn.execute('SELECT acl,independence_verified FROM knowledge_sources ORDER BY source_id').fetchall())
            path,request_headers,body=synthetic_requests()[0]
            response=client.post(path,headers=request_headers,json=body)
            self.assertEqual(200,response.status_code,response.text)
            runtime.builder.build_once()
            records=client.get('/api/admin/audit/records').json()['items']
            self.assertTrue(records)
            record_id=records[0]['record_id']
            detail=client.get('/api/admin/audit/records/'+record_id)
            self.assertEqual(200,detail.status_code,detail.text)
            self.assertIn('甲公司',detail.json()['plaintext'])
            envelope=parse_record((runtime.app.state.runtime_evidence_directory/(record_id+'.evidence.json')).read_bytes())
            self.assertEqual(decrypt_record(runtime.kms,envelope).decode(),detail.json()['plaintext'])
            audit_events=client.get('/api/admin/audit/events').json()['items']
            self.assertEqual({'AUDIT_READ_ATTEMPTED','AUDIT_READ_RELEASED'},{item['event'] for item in audit_events})
