"""Real HTTP protection matrix with real detector/audit/spool and controlled upstream."""
import asyncio
import json
import unittest
import time
import hmac
import httpx
from pathlib import Path
from gateway.app import create_app
from gateway.provider_router import ProviderRouter
from protocol.identity import ByokAuthenticator
from tests.integration import test_integration_roundtrip as fixture_module
from tests.integration.test_integration_roundtrip import UpstreamSpyTransport, TEST_HMAC_KEY
from protocol.protocols import DEEPSEEK_CHAT_PROTOCOL, CLAUDE_MESSAGES_PROTOCOL
from protocol.history_state import HistoricalStateAdapter, ReasoningStateValidator, ProviderStateVerifier
from tests.protocol.provider_fixtures import verify_hmac_sha256

def hanging_ner(*args):
    time.sleep(30)

class ProtocolHttpMatrix(unittest.IsolatedAsyncioTestCase):
    async def test_inflight_stream_uses_bound_protocol_and_history_snapshot(self):
        from dataclasses import replace
        for protocol in (DEEPSEEK_CHAT_PROTOCOL,CLAUDE_MESSAGES_PROTOCOL):
            with self.subTest(protocol=protocol):
                spy=UpstreamSpyTransport(lambda req:self.response(req,protocol,True,False))
                pipeline=self.fixture._create_pipeline(protocol,spy)
                original=self.fixture.detector.detect_many
                def replace_live_assembly(*args,**kwargs):
                    outcomes=original(*args,**kwargs)
                    other=CLAUDE_MESSAGES_PROTOCOL if protocol==DEEPSEEK_CHAT_PROTOCOL else DEEPSEEK_CHAT_PROTOCOL
                    pipeline._route=replace(pipeline._route,protocol=other,path='/unadmitted-path')
                    pipeline._history_adapter=object()
                    return outcomes
                self.fixture.detector.detect_many=replace_live_assembly
                try:
                    app=create_app(router=ProviderRouter({model: pipeline for model in pipeline.allowed_models}), authenticator=ByokAuthenticator(domain=self.fixture.identity.domain, tenant_id=self.fixture.identity.tenant_id, correlation_key=TEST_HMAC_KEY), classifier=lambda raw: "STANDARD", hmac_key=TEST_HMAC_KEY)
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://gateway') as client:
                        path='/v1/messages' if protocol==CLAUDE_MESSAGES_PROTOCOL else '/v1/chat/completions'
                        response=await client.post(path,json=self.request(protocol,True),headers={'authorization':'Bearer enterprise-token'})
                    self.assertEqual(200,response.status_code,response.text)
                    self.assertIn('阿尔法科技',response.text)
                    self.assertNotIn('STREAM_PROTECTION_FAILED',response.text)
                    self.assertNotIn('STREAM_TRANSPORT_FAILED',response.text)
                    self.assertEqual(1,len(spy.calls))
                    self.assertNotIn('/unadmitted-path',str(spy.calls[0].url))
                finally:
                    self.fixture.detector.detect_many=original

    async def test_verified_history_receipt_is_private_and_full_version_bound(self):
        provider_key=b'synthetic-provider-signature-key-32'
        thinking='public synthetic reasoning'
        signature=hmac.digest(provider_key,thinking.encode(),'sha256').hex()
        trust=HistoricalStateAdapter(ReasoningStateValidator(TEST_HMAC_KEY,scope=self.fixture.domain,
            version='assembly-input',provider_verifier=ProviderStateVerifier(verify_hmac_sha256,provider_key)))
        def respond(req):
            body=json.loads(req.content)
            for message in body['messages']:
                if isinstance(message['content'],list):
                    for block in message['content']:
                        if block['type']=='thinking':
                            self.assertNotIn('metadata',block)
                            self.assertEqual(thinking,block['thinking'])
                            self.assertEqual(signature,block['signature'])
            return httpx.Response(200,json={'id':'history','type':'message','role':'assistant',
                'model':body['model'],'content':[{'type':'thinking','thinking':thinking,'signature':signature},
                {'type':'text','text':body['messages'][-1]['content']}],'stop_reason':'end_turn',
                'usage':{'input_tokens':1,'output_tokens':2}})
        spy=UpstreamSpyTransport(respond)
        p=self.fixture._create_pipeline(CLAUDE_MESSAGES_PROTOCOL,spy,history_adapter=trust)
        app=create_app(router=ProviderRouter({model: p for model in p.allowed_models}), authenticator=ByokAuthenticator(domain=self.fixture.identity.domain, tenant_id=self.fixture.identity.tenant_id, correlation_key=TEST_HMAC_KEY), classifier=lambda raw: "STANDARD", hmac_key=TEST_HMAC_KEY)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://gateway') as client:
            body=self.request(CLAUDE_MESSAGES_PROTOCOL)
            first=await client.post('/v1/messages',json=body,headers={'authorization':'Bearer enterprise-token'})
            self.assertEqual(200,first.status_code,first.text)
            proof=first.json()['content'][0]
            self.assertEqual(p.version_handle.package_hash,proof['metadata']['version'])
            body['messages']=[*body['messages'],{'role':'assistant','content':first.json()['content']},
                              {'role':'user','content':'请核对阿尔法科技。'}]
            second=await client.post('/v1/messages',json=body,headers={'authorization':'Bearer enterprise-token'})
            self.assertEqual(200,second.status_code,second.text)
            self.assertEqual(2,len(spy.calls))
            proof['metadata']['version']='different-complete-package'
            body['messages'][1]['content'][0]=proof
            rejected=await client.post('/v1/messages',json=body,headers={'authorization':'Bearer enterprise-token'})
            self.assertEqual(400,rejected.status_code,rejected.text)
            self.assertEqual(2,len(spy.calls))

    def setUp(self):
        self.fixture = fixture_module.IntegrationRoundtripTests()
        self.fixture.setUp()
        self.fixture.detector._ner_package_dir=str(Path(__file__).resolve().parents[2]/"models"/"bert4ner-base-chinese-onnx")
    def tearDown(self):
        self.fixture.tearDown()
    def request(self,protocol,stream=False,tools=False):
        body={'model':'deepseek-flash' if protocol==DEEPSEEK_CHAT_PROTOCOL else 'claude-sonnet-5-5','messages':[{'role':'user','content':'请查询阿尔法科技的张三。'}],'stream':stream}
        schema={'type':'object','properties':{'org':{'type':'string'}},'required':['org'],'additionalProperties':False}
        if protocol==CLAUDE_MESSAGES_PROTOCOL: body['max_tokens']=64
        if tools:
            body['tools']=[{'type':'function','function':{'name':'lookup','description':'查询企业','parameters':schema}}] if protocol==DEEPSEEK_CHAT_PROTOCOL else [{'name':'lookup','description':'查询企业','input_schema':schema}]
        return body
    def response(self,req,protocol,stream,tools,bad=False):
        body=json.loads(req.content)
        self.assertNotIn('阿尔法科技',req.content.decode())
        self.assertNotIn('张三',req.content.decode())
        text=body['messages'][0]['content']
        model=body['model']
        args={'org':text} if not bad else {'org':32,'unknown':True}
        if not stream:
            if protocol==DEEPSEEK_CHAT_PROTOCOL:
                message={'role':'assistant','content':None,'tool_calls':[{'id':'call-1','type':'function','function':{'name':'lookup','arguments':json.dumps(args)}}]} if tools else {'role':'assistant','content':text}
                result={'id':'test','object':'chat.completion','created':1,'model':model,'choices':[{'index':0,'message':message,'finish_reason':'tool_calls' if tools else 'stop'}],'usage':{'prompt_tokens':1,'completion_tokens':2,'total_tokens':3}}
            else:
                result={'id':'test','type':'message','role':'assistant','model':model,'content':[{'type':'tool_use','id':'call-1','name':'lookup','input':args}] if tools else [{'type':'text','text':text}],'stop_reason':'tool_use' if tools else 'end_turn','stop_sequence':None,'usage':{'input_tokens':1,'output_tokens':2}}
            return httpx.Response(200,json=result)
        def frame(v,event=None):
            return ((f'event: {event}\n' if event else '')+'data: '+json.dumps(v,ensure_ascii=False)+'\n\n').encode()
        frames=[]
        if protocol==DEEPSEEK_CHAT_PROTOCOL:
            base={'id':'test','object':'chat.completion.chunk','created':1,'model':model}
            def chat(delta,finish=None,usage=None):
                return frame({**base,'choices':[{'index':0,'delta':delta,'finish_reason':finish}],**({'usage':usage} if usage else {})})
            frames.append(chat({'role':'assistant'}))
            if tools:
                args_text=json.dumps(args,ensure_ascii=False)
                frames.append(chat({'tool_calls':[{'index':0,'id':'call-1','type':'function','function':{'name':'lookup','arguments':args_text}}]}))
            else:
                for c in text: frames.append(chat({'content':c}))
            frames.append(chat({},'tool_calls' if tools else 'stop',{'prompt_tokens':1,'completion_tokens':2,'total_tokens':3}))
            frames.append(b'data: [DONE]\n\n')
        else:
            events=[{'type':'message_start','message':{'id':'test','type':'message','role':'assistant','model':model,'content':[],'stop_reason':None,'stop_sequence':None,'usage':{'input_tokens':1,'output_tokens':0}}}]
            events.append({'type':'content_block_start','index':0,'content_block':{'type':'tool_use','id':'call-1','name':'lookup','input':{}} if tools else {'type':'text','text':''}})
            if tools: events.append({'type':'content_block_delta','index':0,'delta':{'type':'input_json_delta','partial_json':json.dumps(args,ensure_ascii=False)}})
            else:
                for c in text: events.append({'type':'content_block_delta','index':0,'delta':{'type':'text_delta','text':c}})
            events += [{'type':'content_block_stop','index':0},{'type':'message_delta','delta':{'stop_reason':'tool_use' if tools else 'end_turn','stop_sequence':None},'usage':{'output_tokens':2}},{'type':'message_stop'}]
            frames=[frame(e,e['type']) for e in events]
        return httpx.Response(200,headers={'content-type':'text/event-stream'},content=b''.join(frames))
    async def call(self,protocol,body,handler,**options):
        spy=UpstreamSpyTransport(handler)
        pipeline=self.fixture._create_pipeline(protocol,spy,**options)
        app=create_app(router=ProviderRouter({model: pipeline for model in pipeline.allowed_models}), authenticator=ByokAuthenticator(domain=self.fixture.identity.domain, tenant_id=self.fixture.identity.tenant_id, correlation_key=TEST_HMAC_KEY), classifier=lambda raw: "STANDARD", hmac_key=TEST_HMAC_KEY)
        path='/v1/chat/completions' if protocol==DEEPSEEK_CHAT_PROTOCOL else '/v1/messages'
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://gateway') as client:
            response=await client.post(path,json=body,headers={'authorization':'Bearer enterprise-token'})
        return response,spy
    async def test_two_protocols_text_tool_and_stream_complete_http_chain(self):
        for protocol in (DEEPSEEK_CHAT_PROTOCOL,CLAUDE_MESSAGES_PROTOCOL):
            for stream,tools in ((False,False),(False,True),(True,False),(True,True)):
                with self.subTest(protocol=protocol,stream=stream,tools=tools):
                    response,spy=await self.call(protocol,self.request(protocol,stream,tools),lambda req:self.response(req,protocol,stream,tools))
                    self.assertEqual(response.status_code,200,response.text)
                    self.assertIn('阿尔法科技',response.text)
                    self.assertNotIn('<<ENT',response.text)
                    self.assertNotIn('STREAM_PROTECTION_FAILED',response.text)
                    self.assertEqual(len(spy.calls),1)
                    self.assertTrue(list(self.fixture.spool_dir.glob('*.json')))
    async def test_unknown_model_field_history_and_sensitive_structure_zero_egress(self):
        for protocol in (DEEPSEEK_CHAT_PROTOCOL,CLAUDE_MESSAGES_PROTOCOL):
            for change in ({'model':'unadmitted'},{'unknown':'canary'},{'messages':[{'role':'user','content':'hi','compression':'unproved'}]},{'stop':'阿尔法科技'} if protocol==DEEPSEEK_CHAT_PROTOCOL else {'stop_sequences':['阿尔法科技']}):
                response,spy=await self.call(protocol,{**self.request(protocol),**change},lambda req:self.fail('must not leave gateway'))
                self.assertEqual(response.status_code,400,response.text)
                self.assertEqual(len(spy.calls),0)
    async def test_bad_tools_are_not_released_in_http_json_or_stream(self):
        for protocol in (DEEPSEEK_CHAT_PROTOCOL,CLAUDE_MESSAGES_PROTOCOL):
            for stream in (False,True):
                response,spy=await self.call(protocol,self.request(protocol,stream,True),lambda req:self.response(req,protocol,stream,True,bad=True))
                self.assertNotIn('unexpected_admin',response.text)
                self.assertNotIn('tool_calls',response.text)
                self.assertNotIn('"input":',response.text)
                self.assertEqual(len(spy.calls),1)
                self.assertEqual(response.status_code,200 if stream else 400)
    async def test_upstream_status_retry_after_and_error_body_are_sanitized_once(self):
        response,spy=await self.call(DEEPSEEK_CHAT_PROTOCOL,self.request(DEEPSEEK_CHAT_PROTOCOL),lambda req:httpx.Response(429,headers={'retry-after':'12'},content=b'CANARY_RAW_ERROR'))
        self.assertEqual(response.status_code,429)
        self.assertEqual(response.headers['retry-after'],'12')
        self.assertNotIn('CANARY_RAW_ERROR',response.text)
        self.assertEqual(len(spy.calls),1)

    async def test_alias_route_and_response_model_are_bound_in_complete_package(self):
        for stream in (False,True):
            body=self.request(DEEPSEEK_CHAT_PROTOCOL,stream)
            body['model']='client-alias'
            response,spy=await self.call(DEEPSEEK_CHAT_PROTOCOL,body,lambda req:self.response(req,DEEPSEEK_CHAT_PROTOCOL,stream,False),allowed_models=frozenset({'client-alias'}),model_mapping={'client-alias':'provider-model'})
            self.assertEqual(response.status_code,200,response.text)
            self.assertIn('client-alias',response.text)
            self.assertNotIn('provider-model',response.text)
            self.assertEqual(json.loads(spy.calls[0].content)['model'],'provider-model')

    async def test_tampered_package_and_missing_required_spool_have_zero_egress(self):
        for failure in ('route','spool'):
            spy=UpstreamSpyTransport(lambda _:self.fail('preflight failure may not leave'))
            if failure=='spool':self.fixture.spool_writer=None
            p=self.fixture._create_pipeline(DEEPSEEK_CHAT_PROTOCOL,spy)
            if failure=='route':
                from dataclasses import replace
                # Deliberate private package corruption, not a supported live
                # configuration update; public bound routes are immutable.
                p._route=replace(p._route,model_mapping={'deepseek-flash':'other-provider'})
            app=create_app(router=ProviderRouter({model: p for model in p.allowed_models}), authenticator=ByokAuthenticator(domain=self.fixture.identity.domain, tenant_id=self.fixture.identity.tenant_id, correlation_key=TEST_HMAC_KEY), classifier=lambda raw: "STANDARD", hmac_key=TEST_HMAC_KEY)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://gateway') as client:
                r=await client.post('/v1/chat/completions',json=self.request(DEEPSEEK_CHAT_PROTOCOL),headers={'authorization':'Bearer enterprise-token'})
            self.assertEqual(r.status_code,500 if failure=='route' else 503,r.text)
            self.assertEqual(len(spy.calls),0)

    async def test_deadline_reclaims_inference_and_http_loop_remains_responsive(self):
        spy=UpstreamSpyTransport(lambda _:self.fail('deadline must prevent egress'))
        self.fixture.detector._ner_worker=hanging_ner
        p=self.fixture._create_pipeline(DEEPSEEK_CHAT_PROTOCOL,spy,request_timeout=1.0)
        app=create_app(router=ProviderRouter({model: p for model in p.allowed_models}), authenticator=ByokAuthenticator(domain=self.fixture.identity.domain, tenant_id=self.fixture.identity.tenant_id, correlation_key=TEST_HMAC_KEY), classifier=lambda raw: "STANDARD", hmac_key=TEST_HMAC_KEY)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://gateway') as client:
            started=time.monotonic()
            pending=asyncio.create_task(client.post('/v1/chat/completions',json=self.request(DEEPSEEK_CHAT_PROTOCOL),headers={'authorization':'Bearer enterprise-token'}))
            await asyncio.sleep(0.05)
            health_started=time.monotonic()
            health=await client.get('/healthz')
            self.assertEqual(health.status_code,200)
            self.assertLess(time.monotonic()-health_started,0.5)
            r=await pending
            self.assertEqual(r.status_code,504,r.text)
            self.assertLess(time.monotonic()-started,5)
        self.assertEqual(len(spy.calls),0)
        deadline=time.monotonic()+2
        while self.fixture.executor.snapshot()!=(0,0) and time.monotonic()<deadline: await asyncio.sleep(0.02)
        self.assertEqual(self.fixture.executor.snapshot(),(0,0))
