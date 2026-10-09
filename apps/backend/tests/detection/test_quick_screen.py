"""Risk routing and bounded scanning using synthetic text, without loading NER."""
import unittest
from unittest.mock import patch

from detection.dictionary import DictionaryEntry, compile_dictionary, compute_dictionary_hash
from detection.quick_screen import QuickRiskScreen, QuickScreenConfig


def dictionary(*names):
    entries = tuple(DictionaryEntry(text=name, entity_type='PER') for name in names)
    return compile_dictionary({'dictionary_id': 'synthetic-screen', 'version': 'v1', 'domain': 'synthetic',
        'entries': [e.model_dump() for e in entries],
        'sha256': compute_dictionary_hash('synthetic-screen', 'v1', 'synthetic', entries)})


class QuickScreenTests(unittest.TestCase):
    def screen(self, *names, **options):
        return QuickRiskScreen(dictionary(*(names or ('synthetic-person',))), QuickScreenConfig(**options))

    def test_clean_text_skips_and_entity_formats_and_dictionary_require_detection(self):
        screen = self.screen('synthetic-person')
        for text in ('你好，请解释递归。', 'please explain recursion', ''):
            with self.subTest(text=text):
                self.assertFalse(screen.assess_many((text,))[0].requires_detection)
        for text in ('synthetic-person', '刘洋', '张三', 'Alice Smith', '赵氏有限公司',
                     'someone@example.test', '13800138000', 'password=syntheticvalue',
                     '口令=合成密码', 'ak-abcdefghijklmnop', '-----BEGIN PRIVATE KEY-----'):
            with self.subTest(text=text):
                self.assertTrue(screen.assess_many((text,))[0].requires_detection)

    def test_dictionary_at_chunk_boundary_and_end_is_not_skipped(self):
        screen = self.screen('opaque-sensitive')
        for padding in (510, 1500):
            self.assertTrue(screen.assess_many(('a' * padding + 'opaque-sensitive',))[0].requires_detection)

    def test_shared_budget_expiry_routes_unscanned_tail_to_detection(self):
        screen = self.screen()
        with patch('detection.quick_screen.time.perf_counter_ns', side_effect=[0, 0, 0, 0, 3_000_000]):
            first, second = screen.assess_many(('hello', 'clean tail'))
        self.assertFalse(first.requires_detection)
        self.assertEqual(second.reason, 'budget_exhausted')
        with patch('detection.quick_screen.time.perf_counter_ns', side_effect=[0, 0, 3_000_000]):
            result = screen.assess_many(('a' * 2000,))[0]
        self.assertTrue(result.requires_detection)
        self.assertEqual(result.reason, 'budget_exhausted')

    def test_threshold_disabled_and_custom_policy_cues(self):
        self.assertTrue(self.screen(threshold=0.01).assess_many(('hello',))[0].requires_detection)
        self.assertFalse(self.screen(threshold=0.9).assess_many(('Alice',))[0].requires_detection)
        self.assertTrue(self.screen(enabled=False).assess_many(('hello',))[0].requires_detection)
        screen = QuickRiskScreen(dictionary('synthetic-person'), QuickScreenConfig(threshold=1),
                                 policy_cues=('credentialword',))
        self.assertTrue(screen.assess_many(('credentialword=opaquevalue',))[0].requires_detection)
        self.assertTrue(screen.assess_many(('口令=合成密码',))[0].requires_detection)
        self.assertTrue(QuickRiskScreen(dictionary('x' * 513), QuickScreenConfig()).assess_many(('hello',))[0].requires_detection)
        self.assertTrue(QuickRiskScreen(dictionary('x'), QuickScreenConfig(), custom_rules=True).assess_many(('hello',))[0].requires_detection)

    def test_orchestrator_carries_operator_secret_policy_cues(self):
        from detection.detection_orchestrator import DetectionOrchestrator
        from detection.recognizers import SecretRecognizer, SecretPolicy
        secret = SecretRecognizer(policy=SecretPolicy(api_key_prefixes=('credential-',),
                                                       password_contexts=('passphrase',)))
        with DetectionOrchestrator(dictionary=dictionary('opaque-sensitive'), recognizers=(secret,),
                                  quick_screen=QuickScreenConfig(threshold=1)) as detector:
            for text in ('credential-abcdefghijklmnop', 'passphrase=opaqueword'):
                self.assertTrue(detector._risk_screener.assess_many((text,))[0].requires_detection)

    def test_invalid_configuration_is_rejected(self):
        for options in ({'threshold': 0}, {'threshold': 1.1}, {'threshold': float('nan')},
                        {'budget_ms': 0}, {'budget_ms': 11}, {'enabled': 'true'}, {'threshold': True}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                QuickScreenConfig(**options)
