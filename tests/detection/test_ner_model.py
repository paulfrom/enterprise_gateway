"""NER model artifact contract tests for the load-time qualification gate.

Positive path runs against the frozen mini-valid-package fixture; every
rejection path mutates a fresh copy in a temp directory and asserts the
frozen SafetyError code plus the static detail prefix. Payload mutations that
must reach a check downstream of the manifest hash verification recompute the
manifest digests first; manifest-text mutations skip that step because the
manifest cannot hash itself.
"""

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from infra.errors import SafetyCode, SafetyError
from detection.ner_model import LoadedNerPackage, load_model_package

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "ner"
MINI_PACKAGE = FIXTURES_DIR / "mini-valid-package"


def rewrite_manifest_hashes(package_dir: Path) -> None:
    """Recompute sha256/bytes for every declared payload file still present."""
    manifest_path = package_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for name, entry in manifest["files"].items():
        path = package_dir / name
        if path.is_file():
            data = path.read_bytes()
            entry["sha256"] = hashlib.sha256(data).hexdigest()
            entry["bytes"] = len(data)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def rewrite_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_config(package_dir: Path) -> dict:
    return json.loads((package_dir / "config.json").read_text(encoding="utf-8"))


def load_license(package_dir: Path) -> dict:
    return json.loads((package_dir / "license-excerpt.json").read_text(encoding="utf-8"))


class NerModelGateTests(unittest.TestCase):
    def make_package(
        self, tmp_dir: str, mutate=None, *, sync_manifest: bool = True
    ) -> Path:
        package_dir = Path(tmp_dir) / "package"
        shutil.copytree(MINI_PACKAGE, package_dir)
        if mutate is not None:
            mutate(package_dir)
        if sync_manifest:
            rewrite_manifest_hashes(package_dir)
        return package_dir

    def assert_rejected(self, package_dir: Path, detail_prefix: str) -> SafetyError:
        with self.assertRaises(SafetyError) as raised:
            load_model_package(package_dir)
        exc = raised.exception
        self.assertEqual(exc.code, SafetyCode.NER_MODEL_INVALID)
        self.assertTrue(
            str(exc).startswith(f"NER_MODEL_INVALID ({detail_prefix}"),
            f"unexpected rejection message: {exc}",
        )
        self.assertIsNone(exc.__cause__)
        self.assertIsNone(exc.__context__)
        return exc

    def test_mini_valid_package_loads_and_is_usable(self):
        loaded = load_model_package(str(MINI_PACKAGE))
        self.assertIsInstance(loaded, LoadedNerPackage)
        self.assertEqual(loaded.package_dir, Path(str(MINI_PACKAGE)))
        self.assertEqual(loaded.manifest.artifact, "mini-valid-package")
        self.assertTrue({"PER", "ORG", "LOC"}.issubset(loaded.entity_types))
        self.assertEqual(set(loaded.id2label), set(range(len(loaded.id2label))))
        self.assertEqual(
            set(loaded.id2label.values()),
            {"O", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-LOC", "I-LOC", "B-TIME", "I-TIME"},
        )
        probe = "探针文本"
        encoding = loaded.tokenizer.encode(probe, add_special_tokens=False)
        self.assertEqual(encoding.offsets[0][0], 0)
        self.assertEqual(encoding.offsets[-1][1], len(probe))
        logits = loaded.session.run(
            ["logits"],
            {"input_ids": [[1, 2, 3]], "attention_mask": [[1, 1, 1]]},
        )[0]
        self.assertEqual(logits.shape, (1, 3, len(loaded.id2label)))

    def test_missing_package_dir_rejected(self):
        self.assert_rejected(FIXTURES_DIR / "no-such-package", "package_dir_missing")

    def test_missing_required_file_rejected(self):
        def delete_model(package_dir: Path) -> None:
            (package_dir / "model.onnx").unlink()

        with tempfile.TemporaryDirectory() as tmp:
            package_dir = self.make_package(tmp, mutate=delete_model)
            self.assert_rejected(package_dir, "missing_required_file:model.onnx")

    def test_tampered_file_rejected_with_hash_mismatch(self):
        def tamper_config(package_dir: Path) -> None:
            config = load_config(package_dir)
            config["model_type"] = "tamper-marker-ner"
            rewrite_json(package_dir / "config.json", config)

        with tempfile.TemporaryDirectory() as tmp:
            package_dir = self.make_package(tmp, mutate=tamper_config, sync_manifest=False)
            exc = self.assert_rejected(package_dir, "manifest_hash_mismatch:config.json")
            self.assertNotIn("tamper-marker-ner", str(exc))

    def test_unlisted_extra_file_rejected(self):
        def add_note(package_dir: Path) -> None:
            (package_dir / "notes.txt").write_text("unlisted", encoding="utf-8")

        with tempfile.TemporaryDirectory() as tmp:
            package_dir = self.make_package(tmp, mutate=add_note)
            self.assert_rejected(package_dir, "manifest_unlisted_file:notes.txt")

    def test_manifest_with_duplicate_key_rejected(self):
        def duplicate_key(package_dir: Path) -> None:
            text = (package_dir / "manifest.json").read_text(encoding="utf-8")
            text = text.replace(
                '"artifact": "mini-valid-package",',
                '"artifact": "mini-valid-package", "artifact": "mini-valid-package",',
                1,
            )
            (package_dir / "manifest.json").write_text(text, encoding="utf-8")

        with tempfile.TemporaryDirectory() as tmp:
            package_dir = self.make_package(tmp, mutate=duplicate_key, sync_manifest=False)
            self.assert_rejected(package_dir, "json_rejected:DUPLICATE_KEY")

    def test_manifest_with_non_null_signature_rejected(self):
        def sign_manifest(package_dir: Path) -> None:
            manifest = json.loads(
                (package_dir / "manifest.json").read_text(encoding="utf-8")
            )
            manifest["signature"] = {"alg": "ed25519", "key_id": "release", "value": "ab12"}
            rewrite_json(package_dir / "manifest.json", manifest)

        with tempfile.TemporaryDirectory() as tmp:
            package_dir = self.make_package(tmp, mutate=sign_manifest, sync_manifest=False)
            self.assert_rejected(package_dir, "manifest_failed_validation")

    def test_non_token_classification_config_rejected(self):
        def swap_head(package_dir: Path) -> None:
            config = load_config(package_dir)
            config["architectures"] = ["BertForSequenceClassification"]
            rewrite_json(package_dir / "config.json", config)

        with tempfile.TemporaryDirectory() as tmp:
            package_dir = self.make_package(tmp, mutate=swap_head)
            self.assert_rejected(package_dir, "config_not_token_classification")

    def test_config_missing_id2label_rejected(self):
        def drop_id2label(package_dir: Path) -> None:
            config = load_config(package_dir)
            del config["id2label"]
            config.pop("label2id", None)
            rewrite_json(package_dir / "config.json", config)

        with tempfile.TemporaryDirectory() as tmp:
            package_dir = self.make_package(tmp, mutate=drop_id2label)
            self.assert_rejected(package_dir, "config_missing_id2label")

    def test_config_incomplete_id2label_rejected(self):
        def gap_id2label(package_dir: Path) -> None:
            config = load_config(package_dir)
            # Drop key "3" without renumbering: keys no longer "0".."N-1".
            config["id2label"].pop("3")
            config["label2id"] = {v: int(k) for k, v in config["id2label"].items()}
            rewrite_json(package_dir / "config.json", config)

        with tempfile.TemporaryDirectory() as tmp:
            package_dir = self.make_package(tmp, mutate=gap_id2label)
            self.assert_rejected(package_dir, "config_incomplete_id2label")

    def test_config_num_labels_mismatch_rejected(self):
        def bump_num_labels(package_dir: Path) -> None:
            config = load_config(package_dir)
            config["num_labels"] = len(config["id2label"]) + 1
            rewrite_json(package_dir / "config.json", config)

        with tempfile.TemporaryDirectory() as tmp:
            package_dir = self.make_package(tmp, mutate=bump_num_labels)
            self.assert_rejected(package_dir, "config_num_labels_mismatch")

    def test_non_bio_label_config_rejected(self):
        def non_bio_label(package_dir: Path) -> None:
            config = load_config(package_dir)
            config["id2label"]["1"] = "X-PER"
            config["label2id"].pop("B-PER")
            config["label2id"]["X-PER"] = 1
            rewrite_json(package_dir / "config.json", config)

        with tempfile.TemporaryDirectory() as tmp:
            package_dir = self.make_package(tmp, mutate=non_bio_label)
            self.assert_rejected(package_dir, "config_non_bio_label")

    def test_missing_required_entity_type_rejected(self):
        def drop_loc(package_dir: Path) -> None:
            config = load_config(package_dir)
            # Renumber so id2label keys stay exactly "0".."N-1"; the head
            # loses the LOC type while remaining a well-formed token head.
            labels = ["O", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-TIME", "I-TIME"]
            config["id2label"] = {str(i): label for i, label in enumerate(labels)}
            config["label2id"] = {label: i for i, label in enumerate(labels)}
            config["num_labels"] = len(labels)
            rewrite_json(package_dir / "config.json", config)

        with tempfile.TemporaryDirectory() as tmp:
            package_dir = self.make_package(tmp, mutate=drop_loc)
            self.assert_rejected(package_dir, "config_missing_required_entity_type")

    def test_non_apache_license_rejected(self):
        def relicence(package_dir: Path) -> None:
            license_excerpt = load_license(package_dir)
            license_excerpt["license"] = "mit"
            rewrite_json(package_dir / "license-excerpt.json", license_excerpt)

        with tempfile.TemporaryDirectory() as tmp:
            package_dir = self.make_package(tmp, mutate=relicence)
            self.assert_rejected(package_dir, "license_attestation_invalid")

    def test_unverified_license_rejected(self):
        def unverify(package_dir: Path) -> None:
            license_excerpt = load_license(package_dir)
            license_excerpt["license_verified"] = False
            rewrite_json(package_dir / "license-excerpt.json", license_excerpt)

        with tempfile.TemporaryDirectory() as tmp:
            package_dir = self.make_package(tmp, mutate=unverify)
            self.assert_rejected(package_dir, "license_attestation_invalid")

    def test_corrupt_tokenizer_rejected(self):
        def corrupt(package_dir: Path) -> None:
            (package_dir / "tokenizer.json").write_bytes(b"not a json tokenizer {")

        with tempfile.TemporaryDirectory() as tmp:
            package_dir = self.make_package(tmp, mutate=corrupt)
            self.assert_rejected(package_dir, "tokenizer_load_failed")

    def test_corrupt_onnx_rejected(self):
        def corrupt(package_dir: Path) -> None:
            (package_dir / "model.onnx").write_bytes(os.urandom(128))

        with tempfile.TemporaryDirectory() as tmp:
            package_dir = self.make_package(tmp, mutate=corrupt)
            self.assert_rejected(package_dir, "onnx_load_failed")


if __name__ == "__main__":
    unittest.main()
