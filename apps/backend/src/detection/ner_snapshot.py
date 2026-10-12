"""Verified Linux memfd snapshots, shared with spawn workers by descriptor.

Every payload is hashed while copying, then sealed against writes, resizing
and removal of seals. Requests never depend on mutable source paths. A new
model release requires a new snapshot/pool; chmod/mtime caches are not used.
"""

from __future__ import annotations

import ctypes
import fcntl
import hashlib
import os
import sys
from pathlib import Path
from multiprocessing.reduction import recv_handle, send_handle

from detection.ner_model import (
    REQUIRED_FILES, ArtifactManifest, LicenseExcerpt, LoadedNerPackage,
    _load_json, _validate_config, _validate_manifest, _validate_onnx,
    _validate_tokenizer, _reject_json,
)
from infra.errors import SafetyCode, SafetyError
from infra.strict_json import parse_strict_json

# Linux UAPI values; some CPython builds omit the otherwise supported wrappers.
_ADD_SEALS = getattr(fcntl, 'F_ADD_SEALS', 1033)
_GET_SEALS = getattr(fcntl, 'F_GET_SEALS', 1034)
_SEALS = 1 | 2 | 4 | 8  # SEAL_SEAL, SEAL_SHRINK, SEAL_GROW, SEAL_WRITE


def _invalid(detail):
    raise SafetyError(SafetyCode.NER_MODEL_INVALID, detail)


def _memfd():
    if sys.platform != 'linux':
        _invalid('sealed_snapshot_requires_linux')
    if hasattr(os, 'memfd_create'):
        return os.memfd_create('gateway-ner-artifact', flags=3)
    fn = ctypes.CDLL(None, use_errno=True).memfd_create
    fn.argtypes = (ctypes.c_char_p, ctypes.c_uint)
    fn.restype = ctypes.c_int
    fd = fn(b'gateway-ner-artifact', 3)
    if fd < 0:
        _invalid('sealed_snapshot_unavailable')
    return fd


class SealedNerSnapshot:
    """Own immutable descriptors, not request data or writable model copies."""

    def __init__(self, source_dir, digest, manifest, descriptors):
        self.source_dir = Path(source_dir)
        self.digest = digest
        self.manifest = manifest
        self._fds = descriptors
        self._closed = False

    @classmethod
    def create(cls, directory, *, expected_digest=None, check=lambda: None):
        directory = Path(directory)
        descriptors = {}
        failed = False
        try:
            check()
            if not directory.is_dir() or any(not (directory / name).is_file() for name in REQUIRED_FILES):
                _invalid('snapshot_required_file_missing')
            raw = (directory / 'manifest.json').read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            if expected_digest is not None and digest != expected_digest:
                _invalid('manifest_version_changed')
            payload = parse_strict_json(raw, reject=_reject_json)
            if not isinstance(payload, dict):
                _invalid('manifest_not_object')
            manifest = _validate_manifest(payload)
            names = {'manifest.json', *manifest.files}
            actual = {p.name for p in directory.iterdir() if p.is_file()}
            if actual != names:
                _invalid('snapshot_file_set_mismatch')
            for name in sorted(names):
                check()
                fd = _memfd()
                descriptors[name] = fd
                hasher = hashlib.sha256()
                size = 0
                with (directory / name).open('rb') as source:
                    for chunk in iter(lambda: source.read(1 << 20), b''):
                        check()
                        hasher.update(chunk)
                        size += len(chunk)
                        remaining = memoryview(chunk)
                        while remaining:
                            written = os.write(fd, remaining)
                            if written <= 0:
                                _invalid('snapshot_copy_failed')
                            remaining = remaining[written:]
                entry = manifest.files.get(name)
                expected_hash = digest if name == 'manifest.json' else entry.sha256
                expected_size = len(raw) if name == 'manifest.json' else entry.bytes
                if hasher.hexdigest() != expected_hash or size != expected_size:
                    _invalid('snapshot_hash_mismatch')
                fcntl.fcntl(fd, _ADD_SEALS, _SEALS)
            check()
            if hashlib.sha256((directory / 'manifest.json').read_bytes()).hexdigest() != digest:
                _invalid('manifest_version_changed')
            snapshot = cls(directory, digest, manifest, descriptors)
            snapshot.validate()
            _validate_config(_load_json(snapshot.path('config.json')))
            try:
                LicenseExcerpt.model_validate(_load_json(snapshot.path('license-excerpt.json')))
            except ValueError:
                failed = True
            if failed:
                _invalid('license_attestation_invalid')
            return snapshot
        except BaseException:
            for fd in descriptors.values():
                os.close(fd)
            raise

    def path(self, name):
        return Path('/proc/self/fd') / str(self._fds[name])

    def validate(self):
        if self._closed:
            _invalid('snapshot_closed')
        failed = False
        try:
            if set(self._fds) != {'manifest.json', *self.manifest.files}:
                failed = True
            for name, fd in self._fds.items():
                if fcntl.fcntl(fd, _GET_SEALS) & _SEALS != _SEALS:
                    failed = True
                if name in self.manifest.files and os.fstat(fd).st_size != self.manifest.files[name].bytes:
                    failed = True
        except (OSError, ValueError):
            failed = True
        if failed:
            _invalid('snapshot_integrity_failed')

    def fingerprint(self):
        self.validate()
        return {'manifest.json': self.digest,
                **{name: entry.sha256 for name, entry in self.manifest.files.items()}}

    def send(self, conn, pid):
        self.validate()
        names = tuple(sorted(self._fds))
        conn.send((str(self.source_dir), self.digest, self.manifest, names))
        for name in names:
            send_handle(conn, self._fds[name], pid)

    @classmethod
    def receive(cls, conn, expected_digest):
        directory, digest, manifest, names = conn.recv()
        descriptors = {}
        try:
            for name in names:
                descriptors[name] = recv_handle(conn)
            if digest != expected_digest or not isinstance(manifest, ArtifactManifest):
                _invalid('snapshot_version_mismatch')
            snapshot = cls(directory, digest, manifest, descriptors)
            snapshot.validate()
            return snapshot
        except BaseException:
            for fd in descriptors.values():
                os.close(fd)
            raise

    def close(self):
        if not self._closed:
            self._closed = True
            for fd in self._fds.values():
                os.close(fd)


def load_snapshot(snapshot, *, timings=None, intra_op_threads=None):
    import time
    snapshot.validate()
    started = time.perf_counter()
    labels = _validate_config(_load_json(snapshot.path('config.json')))
    tokenizer = _validate_tokenizer(snapshot.path('tokenizer.json'))
    if timings is not None:
        timings['tokenizer_load_ms'] = (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    session = _validate_onnx(snapshot.path('model.onnx'), intra_op_threads=intra_op_threads)
    if timings is not None:
        timings['session_load_ms'] = (time.perf_counter() - started) * 1000
    return LoadedNerPackage(snapshot.source_dir, snapshot.manifest, labels, tokenizer, session, snapshot)
