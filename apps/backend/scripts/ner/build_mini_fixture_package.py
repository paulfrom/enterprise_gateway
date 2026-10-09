"""Build the hermetic mini NER package used by contract tests.

Generates a tiny, deterministically-initialized BertForTokenClassification
(vocab 48, hidden 16, one layer) plus a small wordpiece tokenizer, exports
the model to ONNX (same I/O contract as the real package), and assembles a
fully contract-valid package at tests/fixtures/D-08/mini-valid-package/.

The fixture is committed to git so tests load it directly (onnxruntime
only, fast). Re-run this script to regenerate after intentional fixture
changes; the seed is fixed, so regenerated artifacts are byte-stable apart
from manifest timestamps.

Usage:
    python scripts/ner/build_mini_fixture_package.py
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import torch
from tokenizers import Tokenizer
from tokenizers.models import WordPiece
from tokenizers.pre_tokenizers import BertPreTokenizer
from transformers import BertConfig, BertForTokenClassification

GATEWAY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from package_utils import write_license_excerpt, write_manifest  # noqa: E402

FIXTURE_PACKAGE = GATEWAY_ROOT / "tests" / "detection" / "fixtures" / "ner" / "mini-valid-package"

SEED = 20261003
OPSET_VERSION = 17

# Same BIO shape as the real bert4ner package (9 labels).
ID2LABEL = {
    "0": "O",
    "1": "B-PER",
    "2": "I-PER",
    "3": "B-ORG",
    "4": "I-ORG",
    "5": "B-LOC",
    "6": "I-LOC",
    "7": "B-TIME",
    "8": "I-TIME",
}

VOCAB = {
    "[PAD]": 0,
    "[UNK]": 1,
    "[CLS]": 2,
    "[SEP]": 3,
    "[MASK]": 4,
    "a": 5,
    "b": 6,
    "c": 7,
    "d": 8,
    "e": 9,
    "f": 10,
    "g": 11,
    "h": 12,
    "i": 13,
    "j": 14,
    "k": 15,
    "l": 16,
    "m": 17,
    "n": 18,
    "o": 19,
    "p": 20,
    "q": 21,
    "r": 22,
    "s": 23,
    "t": 24,
    "u": 25,
    "v": 26,
    "w": 27,
    "x": 28,
    "y": 29,
    "z": 30,
    "##a": 31,
    "##b": 32,
    "##c": 33,
    "##d": 34,
    "##e": 35,
    "##f": 36,
    "##g": 37,
    "##h": 38,
}


def build_tokenizer() -> Tokenizer:
    tokenizer = Tokenizer(WordPiece(vocab=VOCAB, unk_token="[UNK]"))
    tokenizer.pre_tokenizer = BertPreTokenizer()
    return tokenizer


def build_model() -> BertForTokenClassification:
    torch.manual_seed(SEED)
    config = BertConfig(
        vocab_size=len(VOCAB),
        hidden_size=16,
        num_hidden_layers=1,
        num_attention_heads=2,
        intermediate_size=32,
        max_position_embeddings=64,
        num_labels=len(ID2LABEL),
        id2label={int(k): v for k, v in ID2LABEL.items()},
        label2id={v: int(k) for k, v in ID2LABEL.items()},
        architectures=["BertForTokenClassification"],
    )
    model = BertForTokenClassification(config)
    model.eval()
    return model


def main() -> None:
    if FIXTURE_PACKAGE.exists():
        shutil.rmtree(FIXTURE_PACKAGE)
    FIXTURE_PACKAGE.mkdir(parents=True)

    tokenizer = build_tokenizer()
    tokenizer.save(str(FIXTURE_PACKAGE / "tokenizer.json"))

    config = {
        "architectures": ["BertForTokenClassification"],
        "model_type": "bert",
        "vocab_size": len(VOCAB),
        "hidden_size": 16,
        "num_hidden_layers": 1,
        "num_attention_heads": 2,
        "num_labels": len(ID2LABEL),
        "id2label": ID2LABEL,
        "label2id": {v: int(k) for k, v in ID2LABEL.items()},
    }
    with open(FIXTURE_PACKAGE / "config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
        f.write("\n")

    model = build_model()
    input_ids = torch.randint(0, len(VOCAB), (2, 6))
    attention_mask = torch.ones((2, 6), dtype=torch.long)
    with torch.no_grad():
        torch.onnx.export(
            model,
            (input_ids, attention_mask),
            str(FIXTURE_PACKAGE / "model.onnx"),
            input_names=["input_ids", "attention_mask"],
            output_names=["logits"],
            dynamic_axes={
                "input_ids": {0: "batch", 1: "sequence"},
                "attention_mask": {0: "batch", 1: "sequence"},
                "logits": {0: "batch", 1: "sequence"},
            },
            opset_version=OPSET_VERSION,
            do_constant_folding=True,
            dynamo=False,
        )

    write_license_excerpt(FIXTURE_PACKAGE, "synthetic mini fixture (Apache-2.0 attestation template)")
    write_manifest(FIXTURE_PACKAGE, "mini-valid-package")
    print(f"mini fixture package written: {FIXTURE_PACKAGE}")


if __name__ == "__main__":
    main()
