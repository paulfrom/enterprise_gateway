"""Quality metrics must expose boundary errors, screening misses and failures."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.ner.benchmark_business import (DEFAULT_DATASET, coverage_counts, distribution,
    evaluate_request, exact_counts, finish_counts, load_dataset, run_group, summarize)
from scripts.ner.evaluate import per_type_metrics

MINI = Path(__file__).parent / 'fixtures/ner/mini-valid-package'
CANARY = 'private-synthetic-business-text-never-in-report'


class BusinessEvaluationTests(unittest.TestCase):
    def test_exact_metrics_require_type_start_and_end(self):
        gold = {('PER', 0, 4)}
        partial = {('PER', 0, 2)}
        counts = exact_counts(gold, partial)
        self.assertEqual(counts['PER'], {'tp': 0, 'fp': 1, 'fn': 1})
        self.assertEqual(per_type_metrics({'sample': gold}, {'sample': partial})['PER']['tp'], 0)
        self.assertEqual(exact_counts(gold, {('ORG', 0, 4)})['PER']['fn'], 1)
        self.assertEqual(finish_counts(counts)['micro']['recall'], 0)

    def test_coverage_accepts_union_of_masks_and_ignores_label(self):
        gold = {('PER', 1, 5)}
        masks = {('ORG', 1, 3), ('PHONE_NUMBER', 3, 5)}
        self.assertEqual(coverage_counts(gold, masks), {'entities': 1, 'fully_covered_entities': 1,
                            'sensitive_codepoints': 4, 'covered_codepoints': 4})
        self.assertEqual(coverage_counts(gold, {('PER', 1, 4)})['fully_covered_entities'], 0)

    def test_undefined_ratios_and_empty_distributions_are_explicit(self):
        self.assertIsNone(finish_counts({})['micro']['recall'])
        self.assertIsNone(distribution([])['p95'])
        self.assertEqual(distribution([10, 20, 30])['p50'], 20)
        json.dumps(finish_counts({}), allow_nan=False)

    def test_dataset_rejects_duplicates_bad_offsets_unknown_fields_and_secret_mismatch(self):
        data, digest = load_dataset(DEFAULT_DATASET)
        self.assertEqual(len(digest), 64)
        cases = []
        duplicate = copy.deepcopy(data)
        duplicate['samples'].append(duplicate['samples'][0])
        cases.append(duplicate)
        offset = copy.deepcopy(data)
        offset['samples'][0]['fragments'][0]['entities'][0]['end'] = 999999
        cases.append(offset)
        extra = copy.deepcopy(data)
        extra['unknown'] = CANARY
        cases.append(extra)
        secret = copy.deepcopy(data)
        secret['samples'][0]['expect_secret_block'] = True
        cases.append(secret)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'dataset.json')
            for case in cases:
                path.write_text(json.dumps(case))
                with self.assertRaises(ValueError) as caught:
                    load_dataset(path)
                self.assertNotIn(CANARY, str(caught.exception))

    def test_failed_request_and_screening_miss_count_as_uncovered_not_success(self):
        sample = {'id': 'sample', 'scenario': 'contract', 'tags': [],
                  'expect_secret_block': False,
                  'fragments': [{'text': CANARY, 'entities': [{'type': 'PER', 'start': 0, 'end': 4}]}]}
        detector = SimpleNamespace(_risk_screener=None)
        with patch('scripts.ner.benchmark_business._infer', side_effect=ValueError(CANARY)):
            failed = evaluate_request(detector, sample, 10)
        skipped = {**failed, 'error': None, 'selected': []}
        report = summarize([failed, skipped], 1)
        self.assertEqual(report['protection_coverage']['entity_coverage'], 0)
        self.assertEqual(report['ner_exact']['micro']['fn'], 2)
        self.assertEqual(report['screening']['gold_positive_skipped_fragments'], 1)
        self.assertEqual(report['failures'], {'DETECTION_FAILED': 1})
        self.assertNotIn(CANARY, json.dumps(report))

    def test_smoke_baseline_uses_production_window_decoder_in_both_modes(self):
        data, _ = load_dataset(DEFAULT_DATASET)
        data['samples'] = [{'id': 'mini', 'scenario': 'low_risk', 'tags': [],
                            'expect_secret_block': False,
                            'fragments': [{'text': 'aa bb cc dd', 'entities': []}]}]
        signatures = []
        for mode in ('oneshot', 'persistent'):
            result, prediction = run_group(data, MINI, mode=mode, screening='full', concurrency=1,
                workers=1, pending=4, repeats=2, timeout=20, ort_threads=1, recycle=256)
            self.assertEqual(result['requests'], 2)
            self.assertEqual(result['failures'], {})
            self.assertEqual(result['nondeterministic_samples'], 0)
            self.assertIn('onnx_ms', result['phases_ms'])
            self.assertGreater(result['cold_probe_ms']['session_load_ms'], 0)
            if mode == 'persistent':
                self.assertEqual(result['worker_processes_observed'], 1)
                self.assertEqual(result['phases_ms']['worker_startup_ms']['max'], 0)
            else:
                self.assertEqual(result['worker_processes_observed'], 2)
            signatures.append(prediction)
        self.assertEqual(signatures[0], signatures[1])


if __name__ == '__main__':
    unittest.main()
