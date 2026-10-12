"""Business-quality evaluation and offline NER performance baselines.

Runs the production sliding-window decoder and full rule/dictionary/span
resolution path. Reports contain aggregate metrics and artifact digests,
never text, entity surfaces, raw predictions or exception messages. Real
business datasets and generated reports belong outside the repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import statistics
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / 'src') not in sys.path:
    sys.path.insert(0, str(ROOT / 'src'))

from detection.detection_orchestrator import DetectionOrchestrator, _ner_batch_worker
from detection.dictionary import DictionaryEntry, compile_dictionary, compute_dictionary_hash
from detection.inference_executor import InferenceExecutor
from detection.ner_model import model_manifest_digest
from detection.ner_worker_pool import NerWorkerPool
from detection.quick_screen import QuickScreenConfig
from infra.errors import SafetyCode, SafetyError
from infra.strict_json import parse_strict_json

DEFAULT_DATASET = ROOT / 'tests/detection/fixtures/ner/business-samples.json'
DEFAULT_PACKAGE = ROOT / 'models/bert4ner-base-chinese-onnx'
NER_TYPES = frozenset({'PER', 'ORG', 'LOC'})
GOLD_TYPES = NER_TYPES | {'PHONE_NUMBER', 'CN_ID_NUMBER', 'CN_USCC', 'MONEY_AMOUNT',
                         'ACCOUNT_NUMBER', 'CONTRACT_NUMBER', 'SECRET'}
SCENARIOS = {'customer_service', 'contract', 'finance', 'human_resources', 'rule_format',
             'secret', 'low_risk'}


def _reject_json(_kind):
    raise ValueError('invalid dataset JSON')


def load_dataset(path: Path) -> tuple[dict, str]:
    raw = path.read_bytes()
    data = parse_strict_json(raw, reject=_reject_json)
    if (not isinstance(data, dict)
            or set(data) != {'schema_version', 'synthetic_only', 'span_convention', 'dictionary_entries', 'samples'}
            or type(data.get('schema_version')) is not int or data.get('schema_version') != 1
            or type(data.get('synthetic_only')) is not bool
            or data.get('span_convention') != 'unicode-codepoint-half-open'
            or not isinstance(data.get('dictionary_entries'), list)
            or not isinstance(data.get('samples'), list) or not data['samples']):
        raise ValueError('invalid dataset schema')
    identifiers = set()
    for entry in data['dictionary_entries']:
        if (not isinstance(entry, dict) or set(entry) != {'text', 'entity_type'}
                or not isinstance(entry['text'], str) or not entry['text']
                or entry['entity_type'] not in GOLD_TYPES - {'SECRET'}):
            raise ValueError('invalid dataset dictionary entry')
    for sample in data['samples']:
        if (not isinstance(sample, dict)
                or set(sample) != {'id', 'scenario', 'tags', 'fragments', 'expect_secret_block'}
                or not isinstance(sample['id'], str) or not sample['id']
                or sample['id'] in identifiers or sample['scenario'] not in SCENARIOS
                or not isinstance(sample['tags'], list)
                or any(not isinstance(tag, str) for tag in sample['tags'])
                or type(sample['expect_secret_block']) is not bool
                or not isinstance(sample['fragments'], list) or not sample['fragments']):
            raise ValueError('invalid dataset sample')
        identifiers.add(sample['id'])
        secret_found = False
        for fragment in sample['fragments']:
            if (not isinstance(fragment, dict) or set(fragment) != {'text', 'entities'}
                    or not isinstance(fragment['text'], str)
                    or not isinstance(fragment['entities'], list)):
                raise ValueError('invalid dataset fragment')
            seen = set()
            for entity in fragment['entities']:
                if (not isinstance(entity, dict) or set(entity) != {'type', 'start', 'end'}
                        or entity['type'] not in GOLD_TYPES
                        or type(entity['start']) is not int or type(entity['end']) is not int
                        or not 0 <= entity['start'] < entity['end'] <= len(fragment['text'])):
                    raise ValueError('invalid dataset entity')
                span = (entity['type'], entity['start'], entity['end'])
                if span in seen:
                    raise ValueError('duplicate dataset entity')
                seen.add(span)
                secret_found |= entity['type'] == 'SECRET'
        if secret_found != sample['expect_secret_block']:
            raise ValueError('inconsistent secret expectation')
    return data, hashlib.sha256(raw).hexdigest()


def make_dictionary(data):
    entries = tuple(DictionaryEntry(**entry) for entry in data['dictionary_entries'])
    name, version, domain = 'business-evaluation', '1', 'synthetic-evaluation'
    return compile_dictionary({'dictionary_id': name, 'version': version, 'domain': domain,
                              'entries': [entry.model_dump() for entry in entries],
                              'sha256': compute_dictionary_hash(name, version, domain, entries)})


def exact_counts(gold, predictions, types=None):
    """Count type AND both boundaries; same-start partial spans are errors."""
    gold, predictions = set(gold), set(predictions)
    labels = set(types) if types is not None else {span[0] for span in gold | predictions}
    return {label: {'tp': len({span for span in gold & predictions if span[0] == label}),
                    'fp': len({span for span in predictions - gold if span[0] == label}),
                    'fn': len({span for span in gold - predictions if span[0] == label})}
            for label in sorted(labels)}


def finish_counts(counts):
    def scores(values):
        tp, fp, fn = (values[name] for name in ('tp', 'fp', 'fn'))
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        return {**values, 'precision': precision, 'recall': recall,
                'f1': 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None}
    total = {name: sum(values[name] for values in counts.values()) for name in ('tp', 'fp', 'fn')}
    return {'per_type': {label: scores(values) for label, values in counts.items()}, 'micro': scores(total)}


def coverage_counts(gold, predictions):
    """Measure actual masked coverage independently of the predicted label."""
    sensitive = {position for _, start, end in gold for position in range(start, end)}
    covered = {position for _, start, end in predictions for position in range(start, end)}
    return {'entities': len(gold),
            'fully_covered_entities': sum(set(range(start, end)) <= covered for _, start, end in gold),
            'sensitive_codepoints': len(sensitive), 'covered_codepoints': len(sensitive & covered)}


def distribution(values):
    values = sorted(values)
    if not values:
        return {'count': 0, 'mean': None, 'p50': None, 'p95': None, 'p99': None, 'max': None}
    def percentile(fraction):
        index = (len(values) - 1) * fraction
        low, high = math.floor(index), math.ceil(index)
        return values[low] + (values[high] - values[low]) * (index - low)
    return {'count': len(values), 'mean': statistics.mean(values), 'p50': percentile(.50),
            'p95': percentile(.95), 'p99': percentile(.99), 'max': values[-1]}


def _infer(detector, texts, timeout):
    started = time.monotonic()
    executor = detector._executor
    if isinstance(executor, NerWorkerPool):
        return executor.infer_profiled(texts, timeout=timeout)
    result = executor.submit(_ner_batch_worker, detector._ner_package_dir, texts,
                 detector._window_length, detector._stride, timeout=timeout,
                 profile=True, intra_op_threads=detector._ner_intra_op_threads)
    elapsed_ms = (time.monotonic() - started) * 1000
    result.metrics['queue_and_worker_startup_ms'] = (result.metrics.pop('worker_entry_at') - started) * 1000
    result.metrics['ipc_and_reclaim_ms'] = max(0.0, elapsed_ms - result.metrics['queue_and_worker_startup_ms']
                 - result.metrics['worker_initialization_ms'] - result.metrics['worker_task_ms'])
    result.metrics['total_ms'] = elapsed_ms
    return result


def evaluate_request(detector, sample, timeout):
    started = time.monotonic()
    deadline = started + timeout
    fragments = sample['fragments']
    texts = tuple(fragment['text'] for fragment in fragments)
    metrics = {}
    selected = list(range(len(texts)))
    ner = [set() for _ in texts]
    final = [set() for _ in texts]
    pid, error = None, None
    try:
        screening_started = time.perf_counter()
        if detector._risk_screener is not None:
            assessments = detector._risk_screener.assess_many(texts)
            selected = [index for index, assessment in enumerate(assessments) if assessment.requires_detection]
        metrics['screening_ms'] = (time.perf_counter() - screening_started) * 1000
        if selected:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
            result = _infer(detector, tuple(texts[index] for index in selected), remaining)
            metrics.update(result.metrics)
            pid = result.worker_pid
            for index, (spans, _) in zip(selected, result.results, strict=True):
                ner[index] = {(span.entity_type, span.start, span.end) for span in spans}
            for index, ner_result in zip(selected, result.results, strict=True):
                outcome = detector._detect_with_ner(texts[index], ner_result, metrics=metrics)
                final[index] = {(span.entity_type, span.start, span.end) for span in outcome.spans}
        if time.monotonic() >= deadline:
            raise SafetyError(SafetyCode.INFERENCE_TIMEOUT)
    except SafetyError as exc:
        error = exc.code.value
        final = [set() for _ in texts]  # no partial detections after a failed request
    except Exception:
        error = SafetyCode.DETECTION_FAILED.value
        final = [set() for _ in texts]
    metrics['request_latency_ms'] = (time.monotonic() - started) * 1000
    signature = hashlib.sha256(json.dumps({'ner': [sorted(spans) for spans in ner],
                      'final': [sorted(spans) for spans in final], 'error': error}, sort_keys=True).encode()).hexdigest()
    return {'sample': sample, 'ner': ner, 'final': final, 'selected': selected,
            'error': error, 'metrics': metrics, 'pid': pid, 'signature': signature}


def summarize(records, elapsed):
    ner_counts, full_counts = {}, {}
    coverage = Counter()
    failures = Counter()
    screening = Counter()
    expected_secret = correct_secret = false_secret = negative_requests = false_positive_requests = 0
    signatures, inconsistent = {}, set()
    for record in records:
        sample = record['sample']
        signatures.setdefault(sample['id'], record['signature'])
        if signatures[sample['id']] != record['signature']:
            inconsistent.add(sample['id'])
        expected_secret += sample['expect_secret_block']
        actual_secret = record['error'] == SafetyCode.SECRET_DETECTED.value
        correct_secret += actual_secret and sample['expect_secret_block']
        false_secret += actual_secret and not sample['expect_secret_block']
        if record['error'] and not actual_secret:
            failures[record['error']] += 1
        negative = not any(fragment['entities'] for fragment in sample['fragments'])
        negative_requests += negative
        false_positive_requests += negative and any(record['final'])
        for index, fragment in enumerate(sample['fragments']):
            gold = {(entity['type'], entity['start'], entity['end']) for entity in fragment['entities']}
            ner_gold = {span for span in gold if span[0] in NER_TYPES}
            for label, values in exact_counts(ner_gold, record['ner'][index], NER_TYPES).items():
                target = ner_counts.setdefault(label, Counter())
                target.update(values)
            if not sample['expect_secret_block']:
                full_gold = {span for span in gold if span[0] != 'SECRET'}
                for label, values in exact_counts(full_gold, record['final'][index]).items():
                    full_counts.setdefault(label, Counter()).update(values)
                coverage.update(coverage_counts(full_gold, record['final'][index]))
            screening['fragments'] += 1
            if index not in record['selected']:
                screening['skipped_fragments'] += 1
                screening['gold_positive_skipped_fragments'] += bool(gold)
                screening['gold_entities_skipped'] += len(gold)
    entities = coverage['entities']
    sensitive = coverage['sensitive_codepoints']
    coverage_result = {**coverage, 'entity_coverage': coverage['fully_covered_entities'] / entities if entities else None,
                       'codepoint_coverage': coverage['covered_codepoints'] / sensitive if sensitive else None}
    phase_names = {name for record in records for name in record['metrics'] if name.endswith('_ms')}
    # Missing cold initialization stages on successful warm calls are zero.
    # Failed calls only contribute to their observed phases and end-to-end latency.
    phases = {name: distribution([record['metrics'].get(name, 0.0) for record in records
                       if record['error'] in (None, SafetyCode.SECRET_DETECTED.value) or name in record['metrics']])
              for name in sorted(phase_names)}
    return {'requests': len(records), 'elapsed_seconds': elapsed,
            'throughput_requests_per_second': len(records) / elapsed if elapsed else None,
            'completed_requests_per_second': sum(record['error'] is None for record in records) / elapsed if elapsed else None,
            'phases_ms': phases, 'ner_exact': finish_counts(ner_counts), 'full_detection_exact': finish_counts(full_counts),
            'protection_coverage': coverage_result,
            'secret_blocking': {'expected': expected_secret, 'correct': correct_secret, 'false_blocks': false_secret},
            'negative_requests': negative_requests, 'false_positive_requests': false_positive_requests,
            'screening': dict(screening), 'failures': dict(failures), 'nondeterministic_samples': len(inconsistent),
            'worker_processes_observed': len({record['pid'] for record in records if record['pid'] is not None}),
            'worker_peak_rss_kib': max((record['metrics'].get('worker_peak_rss_kib', 0) for record in records), default=0)}


def run_group(data, package, *, mode, screening, concurrency, workers, pending,
              repeats, timeout, ort_threads, recycle, window_length=128, stride=32):
    dictionary = make_dictionary(data)
    executor = (NerWorkerPool(str(package), max_workers=workers, max_pending=pending,
                    intra_op_threads=ort_threads, max_tasks_per_worker=recycle,
                    window_length=window_length, stride=stride)
                if mode == 'persistent' else InferenceExecutor(max_workers=workers, max_pending=pending))
    try:
        detector = DetectionOrchestrator(dictionary=dictionary, ner_package_dir=package,
            executor=executor, ner_timeout=timeout, ner_intra_op_threads=ort_threads,
            window_length=window_length, stride=stride,
            quick_screen=QuickScreenConfig() if screening == 'screened' else None)
        probe_started = time.monotonic()
        probe = _infer(detector, ('',), timeout)
        cold = {name: value for name, value in probe.metrics.items() if name.endswith('_ms')}
        cold['request_latency_ms'] = (time.monotonic() - probe_started) * 1000
        # Use fresh processes for each group, a separate cold probe, and the
        # same deterministic request order and model/thread options in both modes.
        started = time.monotonic()
        driver = ThreadPoolExecutor(max_workers=concurrency)
        try:
            futures = [driver.submit(evaluate_request, detector, sample, timeout)
                       for _ in range(repeats) for sample in data['samples']]
            records = [future.result() for future in futures]
        except BaseException:
            executor.close()
            driver.shutdown(wait=True, cancel_futures=True)
            raise
        else:
            driver.shutdown(wait=True)
        result = summarize(records, time.monotonic() - started)
        result['cold_probe_ms'] = cold
        result['configuration'] = {'mode': mode, 'screening': screening, 'concurrency': concurrency,
            'workers': workers, 'pending': pending, 'repeats': repeats, 'ort_threads': ort_threads,
            'max_tasks_per_worker': recycle, 'window_length': window_length, 'stride': stride}
        result['by_scenario'] = {scenario: summarize([record for record in records if record['sample']['scenario'] == scenario], 0)
                                 for scenario in sorted({sample['scenario'] for sample in data['samples']})}
        return result, {record['sample']['id']: record['signature'] for record in records}
    finally:
        executor.close()


def hardware_metadata():
    import onnxruntime
    import tokenizers
    cpu_model = platform.processor()
    if Path('/proc/cpuinfo').exists():
        for line in Path('/proc/cpuinfo').read_text().splitlines():
            if line.startswith('model name'):
                cpu_model = line.split(':', 1)[1].strip()
                break
    return {'platform': platform.platform(), 'python': platform.python_version(), 'cpu_model': cpu_model,
            'logical_cpu_count': os.cpu_count(),
            'cpu_affinity_count': len(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else None,
            'onnxruntime': onnxruntime.__version__, 'tokenizers': tokenizers.__version__}


def build_report(data, dataset_digest, package, *, modes, screening_modes, concurrencies,
                 progress_callback=None, **options):
    source_digest = hashlib.sha256()
    for source in [Path(__file__), *sorted((ROOT / 'src/detection').rglob('*.py'))]:
        source_digest.update(str(source.relative_to(ROOT)).encode())
        source_digest.update(hashlib.sha256(source.read_bytes()).digest())
    report = {'schema_version': 1, 'task': 'business-ner-baseline', 'hardware': hardware_metadata(),
        'dataset': {'sha256': dataset_digest, 'synthetic_only': data['synthetic_only'],
                    'requests': len(data['samples']), 'fragments': sum(len(sample['fragments']) for sample in data['samples'])},
        'model_manifest_sha256': model_manifest_digest(package), 'implementation_sha256': source_digest.hexdigest(),
        'groups': {}, 'comparisons': {}}
    comparisons = {}
    for screening in screening_modes:
        for concurrency in concurrencies:
            signatures = {}
            for mode in modes:
                key = f'{mode}:{screening}:concurrency={concurrency}'
                print(f'Running {key}', file=sys.stderr, flush=True)
                group, signatures[mode] = run_group(data, package, mode=mode, screening=screening,
                                                   concurrency=concurrency, **options)
                if model_manifest_digest(package) != report['model_manifest_sha256']:
                    raise SafetyError(SafetyCode.NER_MODEL_INVALID, 'model changed during evaluation')
                report['groups'][key] = group
                if progress_callback is not None:
                    progress_callback(report)
            if {'oneshot', 'persistent'} <= signatures.keys():
                mismatches = sum(signatures['oneshot'][key] != signatures['persistent'][key] for key in signatures['oneshot'])
                comparisons[f'{screening}:concurrency={concurrency}'] = {'prediction_mismatches': mismatches}
    report['comparisons'] = comparisons
    return report


def _positive(value):
    result = int(value)
    if result < 1:
        raise argparse.ArgumentTypeError('must be positive')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', type=Path, default=DEFAULT_DATASET)
    parser.add_argument('--package', type=Path, default=DEFAULT_PACKAGE)
    parser.add_argument('--output', type=Path, required=True, help='aggregate JSON report outside the repository')
    parser.add_argument('--modes', choices=['both', 'oneshot', 'persistent'], default='both')
    parser.add_argument('--screening', choices=['both', 'full', 'screened'], default='both')
    parser.add_argument('--concurrency', default='1', help='comma-separated driver concurrency values')
    parser.add_argument('--workers', type=_positive, default=1)
    parser.add_argument('--pending', type=int, default=4)
    parser.add_argument('--repeats', type=_positive, default=3)
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--ort-threads', default='1', help='positive thread count or auto; identical in both modes')
    parser.add_argument('--recycle', type=_positive, default=256)
    parser.add_argument('--window-length', type=_positive, default=128)
    parser.add_argument('--stride', type=_positive, default=32)
    parser.add_argument('--min-coverage', type=float, help='optional acceptance threshold for full entity coverage')
    args = parser.parse_args(argv)
    output = args.output.resolve()
    repository = ROOT.parent.parent
    if output.is_relative_to(repository):
        parser.error('--output must be outside the repository')
    if args.pending < 1 and args.modes in ('both', 'oneshot'):
        parser.error('oneshot baseline requires pending >= 1')
    if args.pending < 0 or not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error('invalid queue/deadline settings')
    if args.min_coverage is not None and not 0 <= args.min_coverage <= 1:
        parser.error('--min-coverage must be between 0 and 1')
    try:
        concurrencies = [_positive(value) for value in args.concurrency.split(',')]
        ort_threads = None if args.ort_threads == 'auto' else _positive(args.ort_threads)
        data, digest = load_dataset(args.dataset)
        def checkpoint(report):
            output.parent.mkdir(parents=True, exist_ok=True)
            output.with_suffix('.partial.json').write_text(json.dumps(
                {**report, 'status': 'running'}, ensure_ascii=False, indent=2, allow_nan=False) + '\n')
        report = build_report(data, digest, args.package,
            modes=['oneshot', 'persistent'] if args.modes == 'both' else [args.modes],
            screening_modes=['full', 'screened'] if args.screening == 'both' else [args.screening],
            concurrencies=concurrencies, workers=args.workers, pending=args.pending,
            repeats=args.repeats, timeout=args.timeout, ort_threads=ort_threads,
            recycle=args.recycle, window_length=args.window_length, stride=args.stride,
            progress_callback=checkpoint)
    except KeyboardInterrupt:
        print('Business evaluation interrupted; inference workers have been closed.', file=sys.stderr)
        return 130
    except Exception:
        # Neither private dataset contents nor arbitrary loader messages print.
        print('Business evaluation failed; check dataset and model contracts.', file=sys.stderr)
        return 2
    failed = any(value['prediction_mismatches'] for value in report['comparisons'].values())
    failed |= any(group['nondeterministic_samples'] or group['failures'] or group['secret_blocking']['false_blocks']
                  or group['secret_blocking']['expected'] != group['secret_blocking']['correct']
                  for group in report['groups'].values())
    if args.min_coverage is not None:
        failed |= any(group['protection_coverage']['entity_coverage'] is None
                      or group['protection_coverage']['entity_coverage'] < args.min_coverage
                      for group in report['groups'].values())
    report['acceptance'] = {'passed': not failed, 'min_entity_coverage': args.min_coverage,
                            'coverage_gate_passed': args.min_coverage is not None and not failed}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False) + '\n')
    output.with_suffix('.partial.json').unlink(missing_ok=True)
    print(f'Report: {output}')
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
