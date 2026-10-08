"""Local controlled file KMS: real crypto, separate processes, no supplier calls."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from infra.envelope_crypto import (
    decrypt_record, encrypt_record, InvalidWrappedKeyError, KmsUnavailableError,
)
from infra.errors import SafetyError


class FileKmsTests(unittest.TestCase):
    def setUp(self):
        from infra.file_kms import FileKmsProvider
        self.provider_type = FileKmsProvider
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "keys"
        self.master = bytes(range(32))  # explicitly synthetic fixture
        self.kms = FileKmsProvider(self.directory, self.master)

    def provision(self, purpose="model-query", bucket="restricted-retention"):
        self.kms.provision(purpose=purpose, bucket=bucket)

    def record(self, purpose="model-query", bucket="restricted-retention"):
        return encrypt_record(self.kms, b"synthetic confidential fixture", domain="restricted",
                              record_id="record-1", purpose=purpose, bucket=bucket)

    def child(self, script, *args):
        return subprocess.run([sys.executable, "-c", script, *map(str, args)],
                              capture_output=True, text=True, timeout=30)

    def test_restart_and_separate_process_decrypt(self):
        from infra.envelope_crypto import serialize_record
        self.provision()
        record = self.record()
        self.assertEqual(decrypt_record(self.provider_type(self.directory, self.master), record),
                         b"synthetic confidential fixture")
        envelope = Path(self.temp.name) / "record.json"
        envelope.write_bytes(serialize_record(record))
        result = self.child(
            "from pathlib import Path; import sys; from infra.file_kms import FileKmsProvider; "
            "from infra.envelope_crypto import decrypt_record,parse_record; "
            "assert decrypt_record(FileKmsProvider(Path(sys.argv[1]),bytes(range(32))), "
            "parse_record(Path(sys.argv[2]).read_bytes())) == b'synthetic confidential fixture'",
            self.directory, envelope)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unknown_selector_and_missing_key_never_generate(self):
        with self.assertRaises(KmsUnavailableError):
            self.kms.wrap(bytes(32), purpose="model-query", bucket="restricted-retention")
        self.assertEqual(list(self.directory.glob("*.key.json")), [])
        self.provision()
        record = self.record()
        next(self.directory.glob("*.key.json")).unlink()
        with self.assertRaises(SafetyError):
            decrypt_record(self.kms, record)
        self.assertEqual(list(self.directory.glob("*.key.json")), [])
        self.provision()  # newly provisioned random key cannot recover old ciphertext
        with self.assertRaises(SafetyError):
            decrypt_record(self.kms, record)

    def test_independent_selectors_have_distinct_keys(self):
        self.provision()
        self.provision("model-query:knowledge-spool")
        first = self.kms.wrap(bytes(32), purpose="model-query", bucket="restricted-retention")
        second = self.kms.wrap(bytes(32), purpose="model-query:knowledge-spool", bucket="restricted-retention")
        self.assertNotEqual(first[4:20], second[4:20])
        files = list(self.directory.glob("*.key.json"))
        self.assertEqual(len(files), 2)
        self.assertNotEqual(json.loads(files[0].read_bytes())["ciphertext"],
                            json.loads(files[1].read_bytes())["ciphertext"])
        for path in files:
            self.assertNotIn(self.master.hex().encode(), path.read_bytes())

    def test_wrong_master_purpose_bucket_and_ciphertext_reject(self):
        self.provision()
        record = self.record()
        with self.assertRaises(SafetyError):
            decrypt_record(self.provider_type(self.directory, bytes([77]) * 32), record)
        for purpose, bucket in (("other", "restricted-retention"), ("model-query", "other")):
            self.provision(purpose, bucket)
            with self.assertRaises(SafetyError):
                decrypt_record(self.kms, record.model_copy(update={"purpose": purpose, "bucket": bucket}))
        altered = record.wrapped_dek[:-1] + bytes([record.wrapped_dek[-1] ^ 1])
        with self.assertRaises(SafetyError):
            decrypt_record(self.kms, record.model_copy(update={"wrapped_dek": altered}))
        path = next(self.directory.glob("*.key.json"))
        body = json.loads(path.read_bytes())
        body["ciphertext"] = "00" * (len(body["ciphertext"]) // 2)
        path.write_text(json.dumps(body))
        # Select the envelope corresponding to the altered file.
        with self.assertRaises((SafetyError, KmsUnavailableError)):
            self.kms.wrap(bytes(32), purpose=body["purpose"], bucket=body["bucket"])

    def test_wrapped_shape_and_unknown_version_reject(self):
        self.provision()
        wrapped = self.kms.wrap(bytes(32), purpose="model-query", bucket="restricted-retention")
        for bad in (wrapped[:-1], wrapped + b"0", b"BAD!" + wrapped[4:],
                    wrapped[:20] + (2).to_bytes(4, "big") + wrapped[24:]):
            with self.assertRaises(InvalidWrappedKeyError):
                self.kms.unwrap(bad, purpose="model-query", bucket="restricted-retention")

    def test_destroy_blocks_other_instances_and_reprovision(self):
        self.provision()
        record = self.record()
        other = self.provider_type(self.directory, self.master)
        self.assertEqual(decrypt_record(other, record), b"synthetic confidential fixture")
        self.kms.destroy(purpose="model-query", bucket="restricted-retention")
        body = json.loads(next(self.directory.glob("*.key.json")).read_bytes())
        self.assertEqual(body["state"], "destroyed")
        self.assertEqual(len(bytes.fromhex(body["ciphertext"])), 16)
        for kms in (self.kms, other, self.provider_type(self.directory, self.master)):
            with self.assertRaises(SafetyError):
                decrypt_record(kms, record)
            with self.assertRaises(KmsUnavailableError):
                kms.provision(purpose="model-query", bucket="restricted-retention")
        self.kms.destroy(purpose="model-query", bucket="restricted-retention")  # idempotent

    def test_separate_process_destroy_invalidates_already_live_instance(self):
        self.provision()
        record = self.record()
        result = self.child(
            "from pathlib import Path; import sys; from infra.file_kms import FileKmsProvider; "
            "FileKmsProvider(Path(sys.argv[1]),bytes(range(32))).destroy("
            "purpose='model-query',bucket='restricted-retention')", self.directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        with self.assertRaises(SafetyError):
            decrypt_record(self.kms, record)

    def test_threads_serialize_provision_and_do_not_replace_keys(self):
        def provision_wrap(_):
            self.provision()
            return self.kms.wrap(bytes(32), purpose="model-query", bucket="restricted-retention")
        with ThreadPoolExecutor(max_workers=8) as pool:
            wrapped = list(pool.map(provision_wrap, range(16)))
        self.assertEqual(len({value[4:20] for value in wrapped}), 1)
        for value in wrapped:
            self.assertEqual(self.kms.unwrap(value, purpose="model-query", bucket="restricted-retention"), bytes(32))

    def test_empty_lock_held_by_other_process_waits_without_prelock_write(self):
        # Windows byte locks may cover EOF; writing a sentinel before owning
        # that byte fails with EACCES when another process owns the empty file.
        script = """
import os,sys
from pathlib import Path
path=Path(sys.argv[1])/'.kms.lock'
fd=os.open(path,os.O_RDWR|os.O_CREAT,0o600)
if os.name=='nt':
 import msvcrt
 msvcrt.locking(fd,msvcrt.LK_NBLCK,1)
else:
 import fcntl
 fcntl.flock(fd,fcntl.LOCK_EX)
print('owned',flush=True)
sys.stdin.readline()
if os.name=='nt':
 msvcrt.locking(fd,msvcrt.LK_UNLCK,1)
else:
 fcntl.flock(fd,fcntl.LOCK_UN)
os.close(fd)
"""
        child = subprocess.Popen([sys.executable, "-c", script, str(self.directory)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), "owned")
            self.assertEqual((self.directory / ".kms.lock").stat().st_size, 0)
            with ThreadPoolExecutor(max_workers=1) as pool:
                result = pool.submit(self.provision)
                try:
                    with self.assertRaises(FutureTimeoutError):
                        result.result(timeout=.2)
                finally:
                    child.stdin.write("release\n")
                    child.stdin.flush()
                result.result(timeout=10)
            _, stderr = child.communicate(timeout=10)
            self.assertEqual(child.returncode, 0, stderr)
            self.assertEqual((self.directory / ".kms.lock").stat().st_size, 0)
            self.assertEqual(decrypt_record(self.kms, self.record()), b"synthetic confidential fixture")
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)

    def test_threads_from_distinct_instances_keep_one_selector_key(self):
        def provision_wrap(_):
            provider = self.provider_type(self.directory, self.master)
            provider.provision(purpose="model-query", bucket="restricted-retention")
            return provider.wrap(bytes(32), purpose="model-query", bucket="restricted-retention")
        with ThreadPoolExecutor(max_workers=8) as pool:
            wrapped = list(pool.map(provision_wrap, range(32)))
        self.assertEqual(len({value[4:20] for value in wrapped}), 1)
        for value in wrapped:
            self.assertEqual(self.kms.unwrap(value, purpose="model-query", bucket="restricted-retention"), bytes(32))

    def test_body_exception_releases_lock_for_next_operation(self):
        with self.assertRaisesRegex(RuntimeError, "synthetic caller failure"):
            with self.kms._locked():
                raise RuntimeError("synthetic caller failure")
        other = self.provider_type(self.directory, self.master)
        other.provision(purpose="model-query", bucket="restricted-retention")
        self.assertEqual(decrypt_record(other, self.record()), b"synthetic confidential fixture")

    def test_key_state_duplicate_fields_wrong_version_and_tombstone_tamper_reject(self):
        self.provision()
        path = next(self.directory.glob("*.key.json"))
        valid = path.read_bytes()
        malformed = [b'{"version":1,' + valid[1:]]
        for update in ({"version": 2}, {"format_version": True}, {"nonce": "zz" * 12},
                       {"key_id": "not-hex"}, {"unknown": 1}):
            body = json.loads(valid)
            body.update(update)
            malformed.append(json.dumps(body).encode())
        for value in malformed:
            path.write_bytes(value)
            with self.assertRaises(KmsUnavailableError):
                self.kms.wrap(bytes(32), purpose="model-query", bucket="restricted-retention")
        path.write_bytes(valid)
        self.kms.destroy(purpose="model-query", bucket="restricted-retention")
        body = json.loads(path.read_bytes())
        body["state"] = "active"
        path.write_text(json.dumps(body))
        with self.assertRaises(KmsUnavailableError):
            self.provision()

    def test_symlink_directory_key_record_and_lock_reject(self):
        # Windows hosts without symlink privileges report this specific limit.
        target = Path(self.temp.name) / "real"
        target.mkdir()
        link = Path(self.temp.name) / "linked"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {type(exc).__name__}")
        with self.assertRaises(KmsUnavailableError):
            self.provider_type(link, self.master)
        self.provision()
        key_path = next(self.directory.glob("*.key.json"))
        outside = Path(self.temp.name) / "copied-key"
        outside.write_bytes(key_path.read_bytes())
        key_path.unlink()
        key_path.symlink_to(outside)
        with self.assertRaises(KmsUnavailableError):
            self.provision()
        key_path.unlink()
        lock = self.directory / ".kms.lock"
        lock.unlink()
        lock.symlink_to(outside)
        with self.assertRaises(KmsUnavailableError):
            self.provision()

    def test_master_key_not_in_provider_representation(self):
        self.assertNotIn(self.master.hex(), repr(self.kms))
        self.assertNotIn(repr(self.master), repr(self.kms))

    def test_symlink_guard_rejects_without_requiring_host_symlink_privileges(self):
        with patch.object(Path, "is_symlink", return_value=True):
            with self.assertRaises(KmsUnavailableError):
                self.provider_type(self.directory, self.master)
        self.provision()
        key_path = next(self.directory.glob("*.key.json"))
        with patch.object(Path, "is_symlink", lambda path: path == key_path):
            with self.assertRaises(KmsUnavailableError):
                self.provision()
        lock_path = self.directory / ".kms.lock"
        with patch.object(Path, "is_symlink", lambda path: path == lock_path):
            with self.assertRaises(KmsUnavailableError):
                self.provision()

    def test_destroy_write_failure_keeps_previous_key_and_cannot_claim_destroyed(self):
        self.provision()
        record = self.record()
        with patch("infra.file_kms.durable_commit", side_effect=OSError("synthetic failure")):
            with self.assertRaises(KmsUnavailableError):
                self.kms.destroy(purpose="model-query", bucket="restricted-retention")
        self.assertEqual(decrypt_record(self.kms, record), b"synthetic confidential fixture")

    def test_concurrent_process_provision_preserves_all_wrapped_keys(self):
        script = (
            "from pathlib import Path; import sys; from infra.file_kms import FileKmsProvider; "
            "k=FileKmsProvider(Path(sys.argv[1]),bytes(range(32))); "
            "k.provision(purpose='model-query',bucket='restricted-retention'); "
            "Path(sys.argv[2]).write_bytes(k.wrap(bytes(32),purpose='model-query',bucket='restricted-retention'))"
        )
        files = [Path(self.temp.name) / f"wrapped-{i}" for i in range(5)]
        children = [subprocess.Popen([sys.executable, "-c", script, str(self.directory), str(path)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    for path in files]
        for child in children:
            _, stderr = child.communicate(timeout=30)
            self.assertEqual(child.returncode, 0, stderr)
        wrapped = [path.read_bytes() for path in files]
        self.assertEqual(len({value[4:20] for value in wrapped}), 1)
        for value in wrapped:
            self.assertEqual(self.kms.unwrap(value, purpose="model-query", bucket="restricted-retention"), bytes(32))

    def test_storage_failure_does_not_report_success_or_emit_key(self):
        with patch("infra.file_kms.durable_commit", side_effect=OSError("synthetic private detail")):
            with self.assertRaises(KmsUnavailableError) as caught:
                self.provision()
        self.assertNotIn("synthetic private detail", str(caught.exception))
        self.assertEqual(list(self.directory.glob("*.key.json")), [])

    def test_invalid_master_and_selector_rejected(self):
        for value in (b"short", "x" * 32, bytes(33)):
            with self.assertRaises((ValueError, TypeError)):
                self.provider_type(self.directory, value)
        for purpose, bucket in (("", "x"), ("x", " "), (None, "x")):
            with self.assertRaises((ValueError, TypeError)):
                self.kms.provision(purpose=purpose, bucket=bucket)


if __name__ == "__main__":
    unittest.main()
