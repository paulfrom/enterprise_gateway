"""Safety regressions for single-admin governance on the v2 model (real PG).

Cross-scope consumers, rejected candidates, revocation and expiry must keep
blocking export and dictionary compilation; the extractor contract tests stay
pure in-memory.
"""
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from uuid import uuid4

from knowledge.extractor import RelationExtractor
from knowledge.governance import AdminActionContext, GovernanceError
from knowledge.knowledge import *
from tests.knowledge.test_governance import GovernancePgTestCase


class KnowledgeSafetyRegression(GovernancePgTestCase):
    def setUp(self):
        super().setUp()
        self.seed()

    def seed(self):
        with self.admin_conn() as conn:
            self.seed_source(conn, 'source-a', acl=('security', 'reader', 'steward'))
            self.candidate_id = self.seed_candidate(conn, 'source-a', acl=('security', 'reader', 'steward'))

    def confirm_and_publish(self):
        self.confirm('source-a', audiences=('reader',))
        return self.publish(self.candidate_id, audiences=('reader',))

    def test_cross_scope_context_and_rejected_candidate_cannot_publish(self):
        foreign = AdminActionContext(actor_id='admin', session_digest='ab' * 32,
                                     tenant_id='tenant-b', domain=self.domain)
        with self.assertRaises(Exception):
            self.service.reject_candidate(str(self.candidate_id), basis='x', context=foreign)
        self.service.reject_candidate(str(self.candidate_id), basis='forged claim',
                                      context=self.context)
        with self.assertRaises(GovernanceError) as cm:
            self.publish(self.candidate_id, audiences=('reader',))
        self.assertEqual('KNOWLEDGE_CANDIDATE_VERSION_CONFLICT', cm.exception.code)
        with self.admin_conn() as conn:
            self.assertEqual(0, conn.execute(
                "SELECT count(*) FROM knowledge_publications WHERE candidate_id=%s",
                (self.candidate_id,)).fetchone()[0])

    def test_revoke_and_source_expiry_invalidate_output_and_dictionary(self):
        publication_id = self.confirm_and_publish()
        now = self.fresh_now()
        self.assertTrue(self.service.export_versioned_jsonl(
            [publication_id], self.consumer('reader'), 'v1', now))
        self.service.revoke_publication(publication_id, basis='withdrawn', context=self.context)
        self.assertEqual('', self.service.export_versioned_jsonl(
            [publication_id], self.consumer('reader'), 'v1', self.fresh_now()))
        self.assertEqual([], self.service.compile_approved_dictionary_payload(
            'dict', 'v1', [publication_id], self.fresh_now(), consumer=self.consumer('reader'))['entries'])

    def test_same_domain_wrong_tenant_and_purpose_cannot_read(self):
        publication_id = self.confirm_and_publish()
        foreign_tenant = replace(self.consumer('reader'), tenant_id='tenant-b')
        with self.assertRaises(Exception):
            self.service.export_versioned_jsonl([publication_id], foreign_tenant, 'v1', self.fresh_now())
        for consumer in (replace(self.consumer('reader'), purposes=frozenset()),
                         self.consumer('outsider')):
            self.assertEqual('', self.service.export_versioned_jsonl(
                [publication_id], consumer, 'v1', self.fresh_now()))
            self.assertEqual([], self.service.compile_approved_dictionary_payload(
                'dict', 'v1', [publication_id], self.fresh_now(), consumer=consumer)['entries'])

    def test_common_negation_quotes_and_digest(self):
        extractor = RelationExtractor('domain-a')
        source = Source('tenant-a', 'domain-a', 'source-a', 'v1', SourceKind.USER_ASSERTION,
                        frozenset({'security'}), 'knowledge', self.now, self.now + timedelta(days=1))
        a = Entity(uuid4(), 'tenant-a', 'domain-a', 'ORG', '甲公司')
        b = Entity(uuid4(), 'tenant-a', 'domain-a', 'ORG', '乙公司')
        for text in ('甲公司不向乙公司采购设备', '甲公司否认向乙公司采购设备',
                     '甲公司向乙公司采购设备的说法不实'):
            with self.subTest(text=text):
                c = extractor.extract_from_text(text, source, [a, b], sha256(text.encode()).hexdigest())
                self.assertEqual(Polarity.NEGATIVE, c[0].claim.polarity)
        text = '报道引用传言：甲公司向乙公司采购设备'
        c = extractor.extract_from_text(text, source, [a, b], sha256(text.encode()).hexdigest())
        self.assertNotEqual(Modality.ASSERTED, c[0].claim.modality)
        with self.assertRaises(KnowledgeError):
            extractor.extract_from_text(text, source, [a, b], 'a' * 64)


if __name__ == '__main__':
    unittest.main()
