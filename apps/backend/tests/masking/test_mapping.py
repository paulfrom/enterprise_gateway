"""Readable request-local mappings, role consistency and namespace guards."""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import unittest

from detection.spans import Span
from infra.errors import SafetyCode, SafetyError
from masking.mapping import MappingContext, reject_reserved_literals


class MappingTests(unittest.TestCase):
    def assert_code(self, code, operation):
        with self.assertRaises(SafetyError) as failure:
            operation()
        self.assertEqual(code, failure.exception.code)

    def test_exact_spellings_and_types_keep_independent_mappings(self):
        originals = ('企业甲', '企业甲 ', '企业 甲', '企業甲', '企业甲\n')
        with MappingContext('synthetic-domain') as context:
            tokens = [context.token_for('ORG', original) for original in originals]
            self.assertEqual(len(originals), len(set(tokens)))
            self.assertEqual('<ORG_001>', tokens[0])
            self.assertEqual(tokens[0], context.token_for('ORG', originals[0]))
            self.assertEqual('<PER_001>', context.token_for('PER', originals[0]))
            for token, original in zip(tokens, originals, strict=True):
                self.assertEqual(original, context.restore(token))

    def test_counters_do_not_stop_at_999(self):
        with MappingContext('synthetic-domain') as context:
            for number in range(1, 1002):
                token = context.token_for('ORG', f'合成企业{number}')
            self.assertEqual('<ORG_1001>', token)
            self.assertEqual('合成企业1001', context.restore(token))

    def test_subset_repetition_and_no_entity_reference(self):
        with MappingContext('synthetic-domain') as context:
            token = context.token_for('ORG', '合成企业甲')
            context.token_for('ORG', '合成企业乙')
            self.assertEqual('合成企业甲 / 合成企业甲', context.restore(token + ' / ' + token))
            self.assertEqual('无实体的结论', context.restore('无实体的结论'))

    def test_same_placeholder_in_other_requests_has_no_shared_original(self):
        with MappingContext('scope-a') as one, MappingContext('scope-b') as two:
            token = one.token_for('ORG', '合成企业甲')
            self.assert_code(SafetyCode.UNKNOWN_TOKEN, lambda: two.restore(token))
            self.assertEqual(token, two.token_for('ORG', '合成企业乙'))
            self.assertEqual('合成企业甲', one.restore(token))
            self.assertEqual('合成企业乙', two.restore(token))

    def test_legacy_arguments_are_not_needed_or_retained(self):
        context = MappingContext('synthetic-domain', 'legacy', b'synthetic-key')
        with context:
            self.assertIsNone(context.key)
            self.assertEqual('<ORG_001>', context.token_for('ORG', '合成企业'))

    def test_unknown_malformed_and_bare_placeholders_fail_without_originals(self):
        with MappingContext('synthetic-domain') as context:
            context.token_for('ORG', 'PRIVATE_CANARY')
            self.assert_code(SafetyCode.UNKNOWN_TOKEN, lambda: context.restore('<ORG_002>'))
            for text in ('<ORG_01>', '<org_001>', '<ORG-001>', '<ORG_0X1>', '<ORG_001', 'ORG_001', '<<ENT_old>>'):
                with self.subTest(text=text), self.assertRaises(SafetyError) as failure:
                    context.restore(text)
                self.assertEqual(SafetyCode.MALFORMED_TOKEN, failure.exception.code)
                self.assertNotIn('PRIVATE_CANARY', str(failure.exception))

    def test_originals_cannot_impersonate_current_or_retired_tokens(self):
        for text in ('<ORG_001>', '<PARTYA_1000>', '<org_001>', '<ORG_01>', '<ORG_001', '<<ENT', '<<EN'):
            with self.subTest(text=text):
                self.assert_code(SafetyCode.RESERVED_TOKEN_LITERAL, lambda: reject_reserved_literals(text))

    def test_html_and_non_placeholder_angle_text_are_preserved(self):
        text = '<h1>标题</h1> a < b <custom-element>内容</custom-element>'
        reject_reserved_literals(text)
        with MappingContext('synthetic-domain') as context:
            self.assertEqual(text, context.restore(text))

    def test_overlong_and_truncated_markers_never_pass_as_plain_text(self):
        with MappingContext('synthetic-domain') as context:
            context.token_for('ORG', 'PRIVATE_CANARY')
            for text in ('<ORG_' + 'X' * 10000 + '>', '<OR', '<ORG'):
                self.assert_code(SafetyCode.MALFORMED_TOKEN, lambda: context.restore(text))

    def test_lifecycle_clears_all_original_references_on_exception(self):
        context = MappingContext('synthetic-domain')
        with self.assertRaises(RuntimeError), context:
            context.token_for('ORG', 'PRIVATE_CANARY')
            raise RuntimeError('synthetic')
        self.assertEqual(0, context.entry_count)
        self.assertEqual({}, context._tokens)
        self.assertEqual({}, context._roles)
        self.assert_code(SafetyCode.MAPPING_LIFECYCLE, context.__enter__)
        self.assert_code(SafetyCode.MAPPING_NOT_ACTIVE, lambda: context.restore('<ORG_001>'))

    def test_cancelled_and_base_exceptions_clear_references(self):
        for exception in (asyncio.CancelledError, KeyboardInterrupt):
            context = MappingContext('synthetic-domain')
            with self.assertRaises(exception), context:
                context.token_for('ORG', 'PRIVATE_CANARY')
                raise exception()
            self.assertEqual(0, context.entry_count)

    def test_parallel_requests_restore_their_own_original(self):
        def request(number):
            original = f'合成企业{number}'
            with MappingContext('synthetic-domain') as context:
                return context.restore(context.token_for('ORG', original))
        with ThreadPoolExecutor(max_workers=4) as executor:
            self.assertEqual([f'合成企业{i}' for i in range(40)], list(executor.map(request, range(40))))

    def test_invalid_scope_type_text_and_unicode_are_controlled(self):
        for scope in ('', ' ', None, 123):
            self.assert_code(SafetyCode.INVALID_SCOPE, lambda: MappingContext(scope))
        with MappingContext('synthetic-domain') as context:
            for entity_type in ('', 'org', 'O' * 33, None):
                self.assert_code(SafetyCode.INVALID_ENTITY_TYPE, lambda: context.token_for(entity_type, '原值'))
            self.assert_code(SafetyCode.EMPTY_ENTITY, lambda: context.token_for('ORG', ''))
            self.assert_code(SafetyCode.INVALID_UNICODE, lambda: context.token_for('ORG', '\ud800'))
            self.assert_code(SafetyCode.INVALID_TEXT, lambda: context.restore(None))

    def test_counter_collision_never_overwrites_original(self):
        with MappingContext('synthetic-domain') as context:
            token = context.token_for('ORG', '合成企业甲')
            context._counters['ORG'] = 0
            self.assert_code(SafetyCode.TOKEN_COLLISION, lambda: context.token_for('ORG', '合成企业乙'))
            self.assertEqual('合成企业甲', context.restore(token))


class RoleMappingTests(unittest.TestCase):
    @staticmethod
    def fragment(text, value, entity_type='ORG'):
        start = text.index(value)
        return text, (Span(start, start + len(value), entity_type),)

    def test_later_role_declaration_applies_to_earlier_fragments(self):
        fragments = [self.fragment('合成公司甲负责付款。', '合成公司甲'),
                     self.fragment('甲方：合成公司甲', '合成公司甲')]
        with MappingContext('synthetic-domain') as context:
            context.assign_roles(fragments)
            self.assertEqual('<PARTYA_001>', context.token_for('ORG', '合成公司甲'))

    def test_contract_and_investment_roles_follow_explicit_cues(self):
        for cue, prefix in (('乙方', 'PARTYB'), ('总承包', 'GENCON'), ('分包', 'SUBCON'),
                            ('担保人', 'GUARANTOR'), ('牵头投资方', 'LEAD'), ('标的公司', 'TARGET')):
            with self.subTest(cue=cue), MappingContext('synthetic-domain') as context:
                context.assign_roles([self.fragment(cue + '：合成企业', '合成企业')])
                self.assertEqual(f'<{prefix}_001>', context.token_for('ORG', '合成企业'))

    def test_conflicting_roles_fall_back_to_type_for_all_mentions(self):
        with MappingContext('synthetic-domain') as context:
            context.assign_roles([self.fragment('甲方：合成企业', '合成企业'),
                                  self.fragment('乙方：合成企业', '合成企业')])
            self.assertEqual('<ORG_001>', context.token_for('ORG', '合成企业'))

    def test_persons_are_not_assigned_organization_roles(self):
        with MappingContext('synthetic-domain') as context:
            context.assign_roles([self.fragment('甲方：合成人员', '合成人员', 'PER')])
            self.assertEqual('<PER_001>', context.token_for('PER', '合成人员'))

    def test_roles_cannot_be_changed_after_token_allocation(self):
        with MappingContext('synthetic-domain') as context:
            context.token_for('ORG', '合成企业')
            with self.assertRaises(SafetyError) as failure:
                context.assign_roles([self.fragment('甲方：合成企业', '合成企业')])
            self.assertEqual(SafetyCode.MAPPING_LIFECYCLE, failure.exception.code)
