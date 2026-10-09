import unittest
from datetime import datetime,timedelta,timezone
from hashlib import sha256
from dataclasses import replace
from knowledge.knowledge_events import build_gateway_observation,ObservationMention
from knowledge.knowledge import Modality,Polarity,SourceKind
from knowledge.worker import extract_event_candidates
from infra.spool_relay import compute_dedup_key

class WorkerExtractionContract(unittest.TestCase):
    def event(self,text,**kw):
        now=datetime.now(timezone.utc)
        return build_gateway_observation(tenant='tenant',domain='domain',request_id='request',
          evidence_text=text,evidence_digest=sha256(text.encode()).hexdigest(),observed_at=now,
          retention_until=now+timedelta(days=30),**kw)

    def test_full_prompt_preserves_entities_and_direction(self):
        event=self.event('请查询甲公司向乙公司采购设备五台，合同编号HT-2026-001。')
        source,c=extract_event_candidates(event)
        self.assertEqual('乙公司',c[0].claim.subject.name)
        self.assertEqual('甲公司',c[0].claim.object.name)
        self.assertEqual(Modality.QUESTION,c[0].claim.modality)
        self.assertEqual(0,c[0].independent_source_count)

    def test_detected_mentions_preserve_source_offsets(self):
        text='报道引用传言：甲公司向乙公司采购设备'
        start=text.index('甲公司');other=text.index('乙公司')
        event=self.event(text,evidence_offset=100,mentions=(ObservationMention(name='甲公司',entity_type='ORG',start=start,end=start+3),
                     ObservationMention(name='乙公司',entity_type='ORG',start=other,end=other+3)))
        source,c=extract_event_candidates(event)
        self.assertEqual('甲公司',c[0].claim.object.name)
        self.assertEqual(100+start,c[0].evidence[0].start)
        self.assertNotEqual(Modality.ASSERTED,c[0].claim.modality)

    def test_negative_and_model_outputs_remain_unverified(self):
        source,c=extract_event_candidates(self.event('甲公司不向乙公司采购设备'))
        self.assertEqual(Polarity.NEGATIVE,c[0].claim.polarity)
        source,c=extract_event_candidates(self.event('甲公司向乙公司采购设备',source_kind=SourceKind.MODEL_OUTPUT))
        self.assertNotEqual(Modality.ASSERTED,c[0].claim.modality)
        self.assertEqual(0,c[0].independent_source_count)

    def test_retry_clocks_do_not_change_contribution_identity(self):
        first=self.event('甲公司向乙公司采购设备')
        other=self.event('甲公司向乙公司采购设备')
        self.assertEqual(first.source_id,other.source_id)
        self.assertEqual(compute_dedup_key(first),compute_dedup_key(other))
        verified=self.event('甲公司向乙公司采购设备',source_independence_verified=True)
        source,c=extract_event_candidates(verified)
        self.assertEqual(1,c[0].independent_source_count)
        self.assertNotEqual(compute_dedup_key(first),compute_dedup_key(verified))

    def test_no_entity_or_explicit_business_grammar_no_invented_candidates(self):
        self.assertEqual([],extract_event_candidates(self.event('请查询今天的天气'))[1])
