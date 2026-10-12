"""Kernel-enforced immutability and verified-copy failure boundaries."""

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from detection.ner_snapshot import SealedNerSnapshot, load_snapshot
from infra.errors import SafetyCode, SafetyError

MINI = Path(__file__).parent / 'fixtures/ner/mini-valid-package'


class SnapshotTests(unittest.TestCase):
    def test_kernel_blocks_writes_resizing_and_reopening_for_write(self):
        snapshot = SealedNerSnapshot.create(MINI)
        self.addCleanup(snapshot.close)
        fd = snapshot._fds['model.onnx']
        for operation in (lambda: os.write(fd, b'x'), lambda: os.ftruncate(fd, 0),
                          lambda: snapshot.path('model.onnx').write_bytes(b'x')):
            with self.assertRaises(OSError):
                operation()
        snapshot.validate()
        package = load_snapshot(snapshot, intra_op_threads=1)
        self.assertIs(package.snapshot, snapshot)

    def test_source_disappearance_does_not_change_pinned_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            shutil.copytree(MINI, directory, dirs_exist_ok=True)
            snapshot = SealedNerSnapshot.create(directory)
            self.addCleanup(snapshot.close)
            fingerprint = snapshot.fingerprint()
            shutil.rmtree(directory)
            self.assertEqual(fingerprint, snapshot.fingerprint())
            load_snapshot(snapshot, intra_op_threads=1)

    def test_corruption_and_unverified_license_rejected_before_use(self):
        for invalid_license in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                shutil.copytree(MINI, directory, dirs_exist_ok=True)
                if invalid_license:
                    path = Path(directory, 'license-excerpt.json')
                    payload = json.loads(path.read_text())
                    payload['license_verified'] = False
                    path.write_text(json.dumps(payload))
                    manifest_path = Path(directory, 'manifest.json')
                    manifest = json.loads(manifest_path.read_text())
                    manifest['files'][path.name] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                                                  'bytes': path.stat().st_size}
                    manifest_path.write_text(json.dumps(manifest))
                else:
                    path = Path(directory, 'model.onnx')
                    before = path.stat()
                    path.write_bytes(b'x' * before.st_size)
                    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
                with self.assertRaises(SafetyError) as caught:
                    SealedNerSnapshot.create(directory)
                self.assertEqual(caught.exception.code, SafetyCode.NER_MODEL_INVALID)

    def test_closed_and_unsealed_descriptors_cannot_pass_verification(self):
        snapshot = SealedNerSnapshot.create(MINI)
        self.addCleanup(snapshot.close)
        original = snapshot._fds['model.onnx']
        with tempfile.TemporaryFile() as replacement:
            snapshot._fds['model.onnx'] = replacement.fileno()
            with self.assertRaises(SafetyError):
                snapshot.validate()
            snapshot._fds['model.onnx'] = original
        snapshot.close()
        with self.assertRaises(SafetyError):
            snapshot.validate()


if __name__ == '__main__':
    unittest.main()
