"""Durable-commit primitive tests: real fsync/rename on the happy path, injected failures elsewhere."""

import errno
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from infra.durable_write import (
    CommittedDocument,
    DurableWriteError,
    durable_commit,
)

DW = "infra.durable_write"


def tmpdir():
    return tempfile.TemporaryDirectory()


def contents(directory):
    return sorted(p.name for p in Path(directory).iterdir())


class DurableCommitSuccessTests(unittest.TestCase):
    def test_commit_persists_complete_content(self):
        with tmpdir() as d:
            data = b"release-intent canonical bytes \xe2\x88\x9e"
            doc = durable_commit(d, "rec-1.intent.json", data)
            self.assertIsInstance(doc, CommittedDocument)
            self.assertEqual(doc.bytes_written, len(data))
            target = Path(d) / "rec-1.intent.json"
            self.assertEqual(doc.path, target)
            self.assertEqual(target.read_bytes(), data)  # full content on disk

    def test_commit_overwrites_via_atomic_rename(self):
        with tmpdir() as d:
            durable_commit(d, "rec-1.json", b"v1")
            durable_commit(d, "rec-1.json", b"v2")
            self.assertEqual((Path(d) / "rec-1.json").read_bytes(), b"v2")
            self.assertEqual(contents(d), ["rec-1.json"])  # no tmp leftovers

    def test_capacity_hook_runs_before_anything_is_created(self):
        with tmpdir() as d:

            def hook(directory, incoming):
                self.assertEqual(Path(directory), Path(d))
                self.assertEqual(incoming, 5)
                raise RuntimeError("water-mark tripped")

            with self.assertRaises(RuntimeError):
                durable_commit(d, "rec-1.json", b"12345", capacity_check=hook)
            self.assertEqual(contents(d), [])  # hook fired before tmp creation

    def test_rejects_bad_inputs(self):
        with tmpdir() as d:
            with self.assertRaises(ValueError):
                durable_commit(d, "../escape.json", b"x")
            with self.assertRaises(ValueError):
                durable_commit(d, "a/b.json", b"x")
            with self.assertRaises(TypeError):
                durable_commit(d, "rec.json", "not bytes")  # type: ignore[arg-type]
            with self.assertRaises(DurableWriteError):
                durable_commit(Path(d) / "missing-sub", "rec.json", b"x")


class DurableCommitFailureTests(unittest.TestCase):
    def test_write_failure_enospc_leaves_no_committed_file(self):
        with tmpdir() as d:
            def boom(fileobj, data):
                raise OSError(errno.ENOSPC, "No space left on device")
            with mock.patch(f"{DW}._write_all", side_effect=boom):
                with self.assertRaises(DurableWriteError):
                    durable_commit(d, "rec.json", b"payload")
            self.assertEqual(contents(d), [])  # tmp cleaned, no final name

    def test_fsync_failure_leaves_no_committed_file(self):
        with tmpdir() as d:
            with mock.patch(f"{DW}._flush_and_fsync", side_effect=OSError(errno.EIO, "fsync failed")):
                with self.assertRaises(DurableWriteError):
                    durable_commit(d, "rec.json", b"payload")
            self.assertEqual(contents(d), [])

    def test_rename_failure_leaves_no_committed_file(self):
        with tmpdir() as d:
            with mock.patch(f"{DW}._replace", side_effect=OSError(errno.EPERM, "rename denied")):
                with self.assertRaises(DurableWriteError):
                    durable_commit(d, "rec.json", b"payload")
            self.assertEqual(contents(d), [])  # tmp removed, final never created

    def test_dir_fsync_failure_raises_but_file_is_complete(self):
        # Residual semantics: rename already landed and the body was fsynced
        # before it, so the file is complete; the commit still reports failure
        # (no permit) and a retry replaces the name idempotently.
        with tmpdir() as d:
            with mock.patch(f"{DW}._fsync_directory", side_effect=OSError(errno.EIO, "dir fsync")):
                with self.assertRaises(DurableWriteError):
                    durable_commit(d, "rec.json", b"payload")
            self.assertEqual((Path(d) / "rec.json").read_bytes(), b"payload")
            doc = durable_commit(d, "rec.json", b"payload")  # retry commits cleanly
            self.assertEqual(doc.bytes_written, 7)

    def test_residual_tmp_survives_only_with_tmp_suffix_when_cleanup_fails(self):
        with tmpdir() as d:
            with mock.patch(f"{DW}._write_all", side_effect=OSError(errno.ENOSPC, "full")), \
                 mock.patch(f"{DW}.os.remove", side_effect=OSError(errno.EPERM, "locked")):
                with self.assertRaises(DurableWriteError):
                    durable_commit(d, "rec.json", b"payload")
            leftover = contents(d)
            self.assertEqual(len(leftover), 1)
            self.assertTrue(leftover[0].endswith(".tmp"))  # documented residual, never "rec.json"
            self.assertFalse((Path(d) / "rec.json").exists())

    def test_durable_write_error_carries_static_detail_only(self):
        with tmpdir() as d:
            with mock.patch(f"{DW}._replace", side_effect=OSError(errno.EPERM, "rename denied")):
                with self.assertRaises(DurableWriteError) as ctx:
                    durable_commit(d, "rec.json", b"secret-payload-bytes")
            self.assertNotIn("secret-payload-bytes", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
