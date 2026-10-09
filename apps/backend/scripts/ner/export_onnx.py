"""Export bert4ner-base-chinese to ONNX and assemble the D-08 model package.

Loads the archived snapshot (models/bert4ner-base-chinese) with
transformers, exports BertForTokenClassification via torch.onnx.export
(CPU, fixed opset 17, dynamic batch/sequence axes, inputs
input_ids/attention_mask, output logits), then assembles the contract
package in models/bert4ner-base-chinese-onnx/:

    model.onnx            exported graph
    tokenizer.json        tokenizers-library tokenizer (offset mapping)
    config.json           HF token-classification config
    license-excerpt.json  machine-readable Apache-2.0 attestation
    manifest.json         per-file SHA-256 + byte count

After export, an onnxruntime smoke check compares ONNX logits against
PyTorch logits on identical inputs; the max absolute difference must be
within 1e-3. The full qualified package is then loaded through
enterprise_gateway.ner_model.load_model_package as the final gate.

Usage:
    python scripts/ner/export_onnx.py
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort
import torch
from transformers import AutoModelForTokenClassification, AutoTokenizer

GATEWAY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from package_utils import write_license_excerpt, write_manifest  # noqa: E402

SNAPSHOT_DIR = GATEWAY_ROOT / "models" / "bert4ner-base-chinese"
PACKAGE_DIR = GATEWAY_ROOT / "models" / "bert4ner-base-chinese-onnx"

OPSET_VERSION = 17
LOGITS_TOLERANCE = 1e-3

ARTIFACT_NAME = "bert4ner-base-chinese-onnx"
LICENSE_SOURCE = (
    "https://huggingface.co/shibing624/bert4ner-base-chinese "
    "(cardData.license=apache-2.0; nerpy framework repo Apache-2.0)"
)


def export() -> dict:
    if not (SNAPSHOT_DIR / "model.safetensors").is_file():
        raise SystemExit(f"snapshot missing: {SNAPSHOT_DIR}; run fetch_model.py first")

    tokenizer = AutoTokenizer.from_pretrained(str(SNAPSHOT_DIR), use_fast=True)
    if tokenizer.backend_tokenizer is None:
        raise SystemExit("fast tokenizer with offset mapping is required")

    model = AutoModelForTokenClassification.from_pretrained(str(SNAPSHOT_DIR))
    model.eval()

    batch, seq = 2, 8
    input_ids = torch.randint(0, model.config.vocab_size, (batch, seq))
    attention_mask = torch.ones((batch, seq), dtype=torch.long)
    attention_mask[1, 6:] = 0  # exercise padding in the traced mask path

    PACKAGE_DIR.mkdir(parents=True, exist_ok=True)
    onnx_path = PACKAGE_DIR / "model.onnx"
    with torch.no_grad():
        torch.onnx.export(
            model,
            (input_ids, attention_mask),
            str(onnx_path),
            input_names=["input_ids", "attention_mask"],
            output_names=["logits"],
            dynamic_axes={
                "input_ids": {0: "batch", 1: "sequence"},
                "attention_mask": {0: "batch", 1: "sequence"},
                "logits": {0: "batch", 1: "sequence"},
            },
            opset_version=OPSET_VERSION,
            do_constant_folding=True,
            # torch 2.14 defaults to the dynamo exporter, which needs
            # onnxscript (not a project dependency); the TorchScript
            # exporter is the deterministic, dependency-stable path.
            dynamo=False,
        )

    tokenizer.backend_tokenizer.save(str(PACKAGE_DIR / "tokenizer.json"))
    shutil.copyfile(SNAPSHOT_DIR / "config.json", PACKAGE_DIR / "config.json")
    write_license_excerpt(PACKAGE_DIR, LICENSE_SOURCE)
    manifest = write_manifest(PACKAGE_DIR, ARTIFACT_NAME)

    # Smoke: identical inputs through ONNX Runtime and PyTorch.
    check_ids = input_ids
    check_mask = attention_mask
    with torch.no_grad():
        torch_logits = model(input_ids=check_ids, attention_mask=check_mask).logits.numpy()
    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    onnx_logits = session.run(
        ["logits"],
        {
            "input_ids": check_ids.numpy().astype(np.int64),
            "attention_mask": check_mask.numpy().astype(np.int64),
        },
    )[0]
    max_abs_diff = float(np.max(np.abs(torch_logits - onnx_logits)))
    if max_abs_diff >= LOGITS_TOLERANCE:
        raise SystemExit(
            f"onnx smoke check failed: max_abs_diff={max_abs_diff} >= {LOGITS_TOLERANCE}"
        )

    return {
        "opset_version": OPSET_VERSION,
        "dynamic_axes": ["batch", "sequence"],
        "torch_version": torch.__version__,
        "onnxruntime_version": ort.__version__,
        "smoke_max_abs_diff": max_abs_diff,
        "smoke_tolerance": LOGITS_TOLERANCE,
        "package_files": {k: v["sha256"] for k, v in manifest["files"].items()},
    }


def main() -> None:
    report = export()
    # Final gate: the assembled package must pass the production contract
    # (enterprise_gateway is the installed package; reinstall after src edits).
    from detection.ner_model import load_model_package

    loaded = load_model_package(PACKAGE_DIR)
    report["contract_load"] = "ok"
    report["entity_types"] = sorted(loaded.entity_types)
    out = GATEWAY_ROOT / "models" / "export-report.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
