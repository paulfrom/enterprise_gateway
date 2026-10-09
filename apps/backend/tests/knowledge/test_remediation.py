import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import uuid4

from knowledge.extractor import RelationExtractor
from knowledge.governance import KnowledgeGovernanceService
from knowledge.knowledge import *


class KnowledgeSafetyRegression(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.acl = frozenset({'security', 'business', 'publisher', 'reader', 'steward'})
        self.source = Source('tenant-a', 'domain-a', 'source-a', 'v1', SourceKind.USER_ASSERTION,
                             self.acl, 'knowledge', self.now, self.now + timedelta(days=1))
        self.a = Entity(uuid4(), 'tenant-a', 'domain-a', 'ORG', '甲公司')
        self.b = Entity(uuid4(), 'tenant-a', 'domain-a', 'ORG', '乙公司')
        self.service = KnowledgeGovernanceService('domain-a')
        self.candidate = Candidate(uuid4(), Claim(self.b, Predicate.SUPPLIES, self.a),
            (Evidence(self.source, 'a'*64, 0, 5),), self.acl, 'knowledge')

    def actor(self, subject, *roles):
        return TrustedActor(subject, 'tenant-a', 'domain-a', frozenset(roles), frozenset({'knowledge'}))

    def publish(self):
        c = self.service.approve_candidate(self.candidate, self.actor('security', Role.SECURITY_REVIEWER),
             Role.SECURITY_REVIEWER, 'verification/security', self.now)
        c = self.service.approve_candidate(c, self.actor('business', Role.BUSINESS_REVIEWER),
             Role.BUSINESS_REVIEWER, 'verification/business', self.now)
        return self.service.publish_candidate(c, self.actor('publisher', Role.PUBLISHER),
               self.now + timedelta(days=30), self.now)[0]

    def test_cross_tenant_empty_verification_and_forged_approved_rejected(self):
        with self.assertRaises(KnowledgeError):
            self.service.approve_candidate(self.candidate,
                replace(self.actor('security', Role.SECURITY_REVIEWER), tenant_id='tenant-b'),
                Role.SECURITY_REVIEWER, '', self.now)
        with self.assertRaises(KnowledgeError):
            self.service.publish_candidate(replace(self.candidate, state=CandidateState.APPROVED),
                self.actor('publisher', Role.PUBLISHER), self.now + timedelta(days=1), self.now)

    def test_revoke_and_source_expiry_invalidate_output_and_dictionary(self):
        pub = self.publish()
        self.assertTrue(self.service.export_versioned_jsonl([pub], self.actor('reader'), 'v1', self.now))
        self.assertEqual('', self.service.export_versioned_jsonl([pub], self.actor('reader'), 'v1',
                                                                  self.now + timedelta(days=2)))
        self.service.revoke_publication(pub, self.actor('steward', Role.DATA_STEWARD), 'withdrawn', self.now)
        self.assertEqual('', self.service.export_versioned_jsonl([pub], self.actor('reader'), 'v1', self.now))
        self.assertEqual([], self.service.compile_approved_dictionary_payload('dict', 'v1', [pub], self.now,consumer=self.actor('reader'))['entries'])

    def test_same_domain_wrong_tenant_and_purpose_cannot_read(self):
        pub = self.publish()
        for actor in (replace(self.actor('reader'), tenant_id='tenant-b'),
                      replace(self.actor('reader'), purposes=frozenset()), self.actor('outsider')):
            self.assertEqual('', self.service.export_versioned_jsonl([pub], actor, 'v1', self.now))

    def test_common_negation_quotes_and_digest(self):
        extractor = RelationExtractor('domain-a')
        for text in ('甲公司不向乙公司采购设备', '甲公司否认向乙公司采购设备',
                     '甲公司向乙公司采购设备的说法不实'):
            with self.subTest(text=text):
                c = extractor.extract_from_text(text, self.source, [self.a,self.b], sha256(text.encode()).hexdigest())
                self.assertEqual(Polarity.NEGATIVE, c[0].claim.polarity)
        text = '报道引用传言：甲公司向乙公司采购设备'
        c = extractor.extract_from_text(text,self.source,[self.a,self.b],sha256(text.encode()).hexdigest())
        self.assertNotEqual(Modality.ASSERTED,c[0].claim.modality)
        with self.assertRaises(KnowledgeError):
            extractor.extract_from_text(text,self.source,[self.a,self.b],'a'*64)
