import json
import unittest
from protocol.identity import ByokAuthenticator
from protocol.protocols import DEEPSEEK_CHAT_PROTOCOL
from infra.errors import SafetyError
from infra.envelope_crypto import parse_record, decrypt_record
from knowledge.knowledge_events import ObservationEvent
from masking.mapping import MappingContext
from tests.integration import test_integration_roundtrip as fixtures
from tests.integration.test_integration_roundtrip import UpstreamSpyTransport, TEST_HMAC_KEY


class LocalSedimentTests(unittest.TestCase):
    def test_local_only_and_unknown_classification_persist_restricted_candidates_without_egress(self):
        for category in ('FORBIDDEN', 'UNKNOWN'):
            with self.subTest(category=category):
                fixture = fixtures.IntegrationRoundtripTests()
                fixture.setUp()
                try:
                    spy = UpstreamSpyTransport(lambda _: self.fail('local content was sent'))
                    pipeline = fixture._create_pipeline(DEEPSEEK_CHAT_PROTOCOL, spy)
                    source = ByokAuthenticator(domain=fixture.domain, tenant_id='tenant-corp', correlation_key=b'c'*32).authenticate({'authorization':'Bearer synthetic-local-key'})
                    with MappingContext(fixture.domain, 'v1', TEST_HMAC_KEY) as context:
                        with self.assertRaises(SafetyError):
                            pipeline.process_request(raw_body=json.dumps({'model':'deepseek-flash','messages':[{'role':'user','content':'阿尔法科技雇佣张三。'}]}),
                                headers={'authorization':'Bearer synthetic-local-key'}, identity=source, category=category, context=context)
                    self.assertEqual(spy.calls, [])
                    self.assertEqual(list(fixture.intent_dir.glob('*.json')), [])
                    records = list(fixture.spool_dir.glob('*.env.json'))
                    self.assertEqual(len(records), 1)
                    event = ObservationEvent.model_validate_json(decrypt_record(fixture.kms, parse_record(records[0].read_bytes())))
                    self.assertEqual(event.acl, source.source_acl)
                    self.assertEqual(event.source_provenance, 'unverified')
                    self.assertEqual(event.ownership_status, 'unassigned')
                    self.assertFalse(event.source_independence_verified)
                finally:
                    fixture.tearDown()
