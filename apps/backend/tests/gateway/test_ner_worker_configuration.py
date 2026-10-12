"""Operator worker bounds are parsed without exposing supplied values."""

import os
import unittest
from unittest.mock import patch

import start_gateway
from infra.errors import SafetyCode, SafetyError


class NerWorkerConfigurationTests(unittest.TestCase):
    def test_absent_options_keep_runtime_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(start_gateway._ner_worker_options(), {})
        with patch.dict(os.environ, {'GATEWAY_NER_INTRA_OP_THREADS': ''}, clear=True):
            self.assertEqual(start_gateway._ner_worker_options(), {})

    def test_all_explicit_options_and_zero_waiting_queue(self):
        with patch.dict(os.environ, {'GATEWAY_NER_MAX_WORKERS': '2', 'GATEWAY_NER_MAX_PENDING': '0',
                         'GATEWAY_NER_MAX_TASKS_PER_WORKER': '100', 'GATEWAY_NER_INTRA_OP_THREADS': '3'}, clear=True):
            self.assertEqual(start_gateway._ner_worker_options(), {'ner_max_workers': 2, 'ner_max_pending': 0,
                              'ner_max_tasks_per_worker': 100, 'ner_intra_op_threads': 3})

    def test_invalid_operator_values_are_controlled(self):
        for name, value in (('GATEWAY_NER_MAX_WORKERS', '0'), ('GATEWAY_NER_MAX_PENDING', '-1'),
                            ('GATEWAY_NER_MAX_TASKS_PER_WORKER', '0'), ('GATEWAY_NER_INTRA_OP_THREADS', '0'),
                            ('GATEWAY_NER_MAX_WORKERS', 'private-configuration-canary'),
                            ('GATEWAY_NER_MAX_WORKERS', '1.5')):
            with self.subTest(name=name, value=value), patch.dict(os.environ, {name: value}, clear=True):
                with self.assertRaises(SafetyError) as caught:
                    start_gateway._ner_worker_options()
                self.assertEqual(caught.exception.code, SafetyCode.CONTRACT_VIOLATION)
                self.assertNotIn(value, str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assertIsNone(caught.exception.__context__)


if __name__ == '__main__':
    unittest.main()
