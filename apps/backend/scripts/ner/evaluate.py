"""Evaluate the qualified ONNX package on the synthetic independent validation set.

Two engines, identical gold set and identical span-extraction logic:

- onnxruntime: inference through the production contract path
  (enterprise_gateway.ner_model.load_model_package) — the artifact gate.
- torch (dev dependency): transformers inference on the archived snapshot,
  as the reference pipeline for the same weights.

Both produce entity-level (span exact match) per-label precision/recall/F1
with code point half-open spans. Assertions: PER/ORG/LOC each have TP > 0
in both engines (proves the package is not an empty or constant-zero
predictor). Fixed hardware (CPU identifier, thread counts, engine
versions) and wall-clock duration are recorded.

The validation set is self-built synthetic data (tests/fixtures/D-08/
validation-set.json); it shares no source with the model's training corpus
(People's Daily NER), so this is an independent local re-test.

Writes tests/fixtures/D-08/eval-report.json.

Usage:
    python scripts/ner/evaluate.py
"""

from __future__ import annotations

import json
import os
import platform
import sys
import time
from pathlib import Path

import numpy as np

GATEWAY_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = GATEWAY_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from infra.errors import SafetyCode, SafetyError  # noqa: E402
from detection.ner_model import load_model_package  # noqa: E402

FIXTURES_DIR = GATEWAY_ROOT / "tests" / "detection" / "fixtures" / "ner"
PACKAGE_DIR = GATEWAY_ROOT / "models" / "bert4ner-base-chinese-onnx"
SNAPSHOT_DIR = GATEWAY_ROOT / "models" / "bert4ner-base-chinese"
REPORT_PATH = FIXTURES_DIR / "eval-report.json"

MAX_SEQUENCE = 128
REQUIRED_TYPES = ("PER", "ORG", "LOC")


# ---------------------------------------------------------------------------
# Span extraction (identical logic for both engines)
# ---------------------------------------------------------------------------

def tokens_to_spans(tokens: list[tuple[int, int]], labels: list[str]) -> set[tuple[str, int, int]]:
    """Convert (offset, BIO label) pairs to exact code point spans.

    ``tokens`` holds half-open (start, end) offsets; special tokens carry
    empty offsets and act as boundaries. ``I-X`` after ``O`` or a different
    type opens a new entity (lenient continuation), matching seqeval-style
    default BIO decoding.
    """
    spans: set[tuple[str, int, int]] = set()
    open_span: tuple[str, int] | None = None
    span_end = 0

    def close() -> None:
        nonlocal open_span
        if open_span is not None:
            spans.add((open_span[0], open_span[1], span_end))
            open_span = None

    for (start, end), label in zip(tokens, labels):
        if start == end:
            close()  # boundary token (e.g. [CLS]/[SEP]); span keeps last entity end
            continue
        if label == "O" or "-" not in label:
            close()
            continue
        prefix, etype = label.split("-", 1)
        if prefix == "B" or open_span is None or open_span[0] != etype:
            close()
            open_span = (etype, start)
        span_end = end
    close()
    return spans


def per_type_metrics(
    gold: dict[str, set[tuple[str, int, int]]],
    pred: dict[str, set[tuple[str, int, int]]],
) -> dict[str, dict[str, float]]:
    types = sorted({t for spans in gold.values() for t, _, _ in spans} |
                   {t for spans in pred.values() for t, _, _ in spans})
    metrics: dict[str, dict[str, float]] = {}
    for etype in types:
        tp = fp = fn = 0
        for sample_id in gold:
            g = {s for t, s, e in gold[sample_id] if t == etype}
            p = {s for t, s, e in pred[sample_id] if t == etype}
            tp += len(g & p)
            fp += len(p - g)
            fn += len(g - p)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        metrics[etype] = {
            "tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }
    return metrics


# ---------------------------------------------------------------------------
# onnxruntime engine (production contract path)
# ---------------------------------------------------------------------------

def run_onnx(samples: list[dict], package_dir: Path) -> tuple[dict, dict]:
    import onnxruntime as ort

    loaded = load_model_package(package_dir)
    tokenizer = loaded.tokenizer
    tokenizer.enable_truncation(max_length=MAX_SEQUENCE)
    id2label = loaded.id2label
    session = loaded.session

    gold: dict[str, set] = {}
    pred: dict[str, set] = {}
    logits_runs: list[np.ndarray] = []
    for run in range(2):  # second pass feeds the determinism check
        run_logits: list[np.ndarray] = []
        for sample in samples:
            encoding = tokenizer.encode(sample["text"], add_special_tokens=True)
            input_ids = np.array([encoding.ids], dtype=np.int64)
            attention_mask = np.array([encoding.attention_mask], dtype=np.int64)
            logits = session.run(
                ["logits"], {"input_ids": input_ids, "attention_mask": attention_mask}
            )[0][0]
            run_logits.append(logits)
            if run == 0:
                label_ids = np.argmax(logits, axis=-1)
                labels = [id2label[int(i)] for i in label_ids]
                valid = [
                    ((s, e), lab)
                    for (s, e), lab in zip(encoding.offsets, labels)
                    if s != e
                ]
                pred[sample["id"]] = tokens_to_spans(
                    [o for o, _ in valid], [l for _, l in valid]
                )
                gold[sample["id"]] = {
                    (e["type"], e["start"], e["end"]) for e in sample["entities"]
                }
        logits_runs.append(np.concatenate(run_logits, axis=0))
    determinism_max_abs_diff = float(
        np.max(np.abs(logits_runs[0] - logits_runs[1]))
    )
    return gold, pred, {
        "engine": "onnxruntime",
        "onnxruntime_version": ort.__version__,
        "determinism_max_abs_diff": determinism_max_abs_diff,
    }


# ---------------------------------------------------------------------------
# torch engine (dev reference, transformers on the archived snapshot)
# ---------------------------------------------------------------------------

def run_torch(samples: list[dict], snapshot_dir: Path) -> tuple[dict, dict]:
    import torch
    from transformers import AutoModelForTokenClassification, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(str(snapshot_dir), use_fast=True)
    model = AutoModelForTokenClassification.from_pretrained(str(snapshot_dir))
    model.eval()
    id2label = {int(k): v for k, v in model.config.id2label.items()}

    gold: dict[str, set] = {}
    pred: dict[str, set] = {}
    with torch.no_grad():
        for sample in samples:
            encoded = tokenizer(
                sample["text"],
                return_offsets_mapping=True,
                add_special_tokens=True,
                truncation=True,
                max_length=MAX_SEQUENCE,
                return_tensors="pt",
            )
            offsets = encoded.pop("offset_mapping")[0].tolist()
            logits = model(**encoded).logits[0].numpy()
            label_ids = np.argmax(logits, axis=-1)
            labels = [id2label[int(i)] for i in label_ids]
            valid = [((s, e), lab) for (s, e), lab in zip(offsets, labels) if s != e]
            pred[sample["id"]] = tokens_to_spans(
                [o for o, _ in valid], [l for _, l in valid]
            )
            gold[sample["id"]] = {
                (e["type"], e["start"], e["end"]) for e in sample["entities"]
            }
    return gold, pred, {"engine": "torch", "torch_version": torch.__version__}


def assert_required_types(metrics: dict[str, dict[str, float]], engine: str) -> None:
    for etype in REQUIRED_TYPES:
        stats = metrics.get(etype)
        if stats is None or stats["tp"] <= 0:
            raise SafetyError(
                SafetyCode.NER_EVALUATION_FAILED, f"{engine}:{etype}_zero_true_positives"
            )


def main() -> None:
    dataset = json.loads((FIXTURES_DIR / "validation-set.json").read_text(encoding="utf-8"))
    samples = dataset["samples"]

    report: dict = {
        "task": "ner-eval",
        "dataset": {
            "path": "tests/detection/fixtures/ner/validation-set.json",
            "sample_count": len(samples),
            "span_convention": dataset["span_convention"],
            "synthetic_only": dataset["synthetic_only"],
            "independence": dataset["no_overlap_with_training_corpus"],
        },
        "hardware": {
            "platform": platform.platform(),
            "processor_identifier": os.environ.get("PROCESSOR_IDENTIFIER", "unavailable"),
            "cpu_count": os.cpu_count(),
            "python_version": platform.python_version(),
        },
        "engines": {},
    }

    gold_onnx, pred_onnx, onnx_meta = None, None, None
    timings: dict[str, float] = {}

    start = time.perf_counter()
    gold_onnx, pred_onnx, onnx_meta = run_onnx(samples, PACKAGE_DIR)
    timings["onnxruntime_seconds"] = round(time.perf_counter() - start, 3)

    start = time.perf_counter()
    gold_torch, pred_torch, torch_meta = run_torch(samples, SNAPSHOT_DIR)
    timings["torch_seconds"] = round(time.perf_counter() - start, 3)

    onnx_metrics = per_type_metrics(gold_onnx, pred_onnx)
    torch_metrics = per_type_metrics(gold_torch, pred_torch)
    assert_required_types(onnx_metrics, "onnxruntime")
    assert_required_types(torch_metrics, "torch")

    report["engines"]["onnxruntime"] = {
        **onnx_meta,
        "threads": os.cpu_count(),
        "duration_seconds": timings["onnxruntime_seconds"],
        "per_type_metrics": onnx_metrics,
    }
    report["engines"]["torch"] = {
        **torch_meta,
        "threads": os.cpu_count(),
        "duration_seconds": timings["torch_seconds"],
        "per_type_metrics": torch_metrics,
    }

    export_report_path = GATEWAY_ROOT / "models" / "export-report.json"
    if export_report_path.is_file():
        report["export"] = json.loads(export_report_path.read_text(encoding="utf-8"))

    report["assertions"] = {
        "per_type_tp_positive": list(REQUIRED_TYPES),
        "engines": ["onnxruntime", "torch"],
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(json.dumps(report["engines"], indent=2, ensure_ascii=False))
    print(f"report -> {REPORT_PATH}")


if __name__ == "__main__":
    main()
