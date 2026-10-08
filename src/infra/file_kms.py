"""Controlled local KEK store for standalone processes, behind KmsProvider.

An operator supplies one 256-bit master key. Each explicitly provisioned
purpose/retention bucket has a distinct random KEK encrypted under that master.
OS advisory locking plus durable_commit serializes atomic state changes across
processes. Wrap/unwrap reload state while holding the same lock; a durable
tombstone prevents another live instance from decrypting or reprovisioning a
destroyed selector. Keys are never cached or derived from selectors.

This is a local file backend, not an enterprise KMS. The operator must restrict
directory access, preserve the master securely, and govern backups. Tombstones
do not prove deletion of filesystem snapshots or copied keys; rollback of the
whole controlled store is outside this backend's trust boundary. Master/KEK
rotation needs coordinated backend governance; this backend does not expose a
pretend rotation API. Version and random key ID are bound to every wrapped DEK.
Windows directory rename durability follows durable_write's stated limitation.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from infra.durable_write import durable_commit
from infra.envelope_crypto import (
    DEK_SIZE_BYTES, NONCE_SIZE_BYTES, InvalidWrappedKeyError, KmsProvider,
    KmsUnavailableError,
)
from infra.strict_json import parse_strict_json

_MAGIC = b"FKM1"
_VERSION = 1
_KEY_ID_BYTES = 16
_HEADER_BYTES = len(_MAGIC) + _KEY_ID_BYTES + 4
_WRAPPED_BYTES = _HEADER_BYTES + NONCE_SIZE_BYTES + DEK_SIZE_BYTES + 16
_STATE_FIELDS = {"format_version", "purpose", "bucket", "key_id", "version",
                 "state", "nonce", "ciphertext"}


def _json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _unavailable() -> KmsUnavailableError:
    return KmsUnavailableError("local key store unavailable")


def _reject_json(_kind):
    raise _unavailable()


class FileKmsProvider(KmsProvider):
    """A controlled directory of authenticated key states; explicit provisioning."""

    def __init__(self, directory: Path, master_key: bytes) -> None:
        if not isinstance(master_key, bytes):
            raise TypeError("master key must be bytes")
        if len(master_key) != DEK_SIZE_BYTES:
            raise ValueError("master key must be 32 bytes")
        self._directory = Path(directory).absolute()
        self._master_key = master_key
        try:
            self._check_directory()
            self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._check_directory()
            if not self._directory.is_dir():
                raise _unavailable()
        except OSError:
            raise _unavailable() from None

    def _check_directory(self) -> None:
        # Do not traverse an operator-visible symlink for any key-store path.
        for path in (self._directory, *self._directory.parents):
            if path.is_symlink():
                raise _unavailable()

    @contextmanager
    def _locked(self):
        handle = None
        acquired = False
        try:
            self._check_directory()
            path = self._directory / ".kms.lock"
            if path.is_symlink():
                raise _unavailable()
            fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            handle = os.fdopen(fd, "r+b", buffering=0)
            # OS locks can cover a byte beyond EOF. Never write a sentinel
            # before acquiring it: another handle may already own that byte.
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                deadline = time.monotonic() + 30
                while True:
                    try:
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise _unavailable() from None
                        time.sleep(0.02)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
            acquired = True
            yield
        except (OSError, ValueError):
            raise _unavailable() from None
        finally:
            if handle is not None:
                if acquired:
                    handle.seek(0)
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                handle.close()

    @staticmethod
    def _selector(purpose: str, bucket: str) -> dict:
        for value in (purpose, bucket):
            if not isinstance(value, str):
                raise TypeError("key selector must use strings")
            if not value.strip():
                raise ValueError("key selector must be nonempty")
        return {"purpose": purpose, "bucket": bucket}

    def _path(self, selector: dict) -> Path:
        name = hashlib.sha256(_json(selector)).hexdigest() + ".key.json"
        path = self._directory / name
        if path.is_symlink():
            raise _unavailable()
        return path

    def _read(self, selector: dict) -> tuple[dict, bytes]:
        path = self._path(selector)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise _unavailable()
        state = parse_strict_json(raw, reject=_reject_json)
        if not isinstance(state, dict) or set(state) != _STATE_FIELDS:
            raise _unavailable()
        if (state["purpose"] != selector["purpose"] or state["bucket"] != selector["bucket"]
                or type(state["format_version"]) is not int or state["format_version"] != _VERSION
                or type(state["version"]) is not int or state["version"] != _VERSION
                or state["state"] not in ("active", "destroyed")):
            raise _unavailable()
        for name, size in (("key_id", _KEY_ID_BYTES), ("nonce", NONCE_SIZE_BYTES),
                           ("ciphertext", 48 if state["state"] == "active" else 16)):
            value = state[name]
            if not isinstance(value, str) or len(value) != size * 2 or value != value.lower():
                raise _unavailable()
            if len(bytes.fromhex(value)) != size:
                raise _unavailable()
        aad = _json({key: value for key, value in state.items() if key not in {"nonce", "ciphertext"}})
        try:
            key = AESGCM(self._master_key).decrypt(bytes.fromhex(state["nonce"]),
                                                  bytes.fromhex(state["ciphertext"]), aad)
        except InvalidTag:
            raise _unavailable() from None
        if len(key) != (DEK_SIZE_BYTES if state["state"] == "active" else 0):
            raise _unavailable()
        return state, key

    def _commit(self, selector: dict, key_id: str, state: str, key: bytes) -> None:
        body = {**selector, "format_version": _VERSION, "key_id": key_id,
                "version": _VERSION, "state": state}
        nonce = os.urandom(NONCE_SIZE_BYTES)
        ciphertext = AESGCM(self._master_key).encrypt(nonce, key, _json(body))
        body.update(nonce=nonce.hex(), ciphertext=ciphertext.hex())
        durable_commit(self._directory, self._path(selector).name, _json(body))

    def provision(self, *, purpose: str, bucket: str) -> None:
        """Create a random independent KEK once; destroyed selectors stay denied."""
        selector = self._selector(purpose, bucket)
        with self._locked():
            if self._path(selector).exists():
                state, _ = self._read(selector)
                if state["state"] != "active":
                    raise _unavailable()
                return
            self._commit(selector, os.urandom(_KEY_ID_BYTES).hex(), "active", os.urandom(DEK_SIZE_BYTES))

    def destroy(self, *, purpose: str, bucket: str) -> None:
        """Replace the KEK with an authenticated tombstone, durable and idempotent."""
        selector = self._selector(purpose, bucket)
        with self._locked():
            state, _ = self._read(selector)
            if state["state"] == "destroyed":
                return
            self._commit(selector, state["key_id"], "destroyed", b"")

    def wrap(self, dek: bytes, *, purpose: str, bucket: str) -> bytes:
        if not isinstance(dek, bytes) or len(dek) != DEK_SIZE_BYTES:
            raise ValueError("only 256-bit DEKs may be wrapped")
        selector = self._selector(purpose, bucket)
        with self._locked():
            state, key = self._read(selector)
            if state["state"] != "active":
                raise _unavailable()
            header = _MAGIC + bytes.fromhex(state["key_id"]) + state["version"].to_bytes(4, "big")
            nonce = os.urandom(NONCE_SIZE_BYTES)
            aad = header + _json(selector)
            return header + nonce + AESGCM(key).encrypt(nonce, dek, aad)

    def unwrap(self, wrapped_dek: bytes, *, purpose: str, bucket: str) -> bytes:
        if (not isinstance(wrapped_dek, bytes) or len(wrapped_dek) != _WRAPPED_BYTES
                or wrapped_dek[:4] != _MAGIC
                or int.from_bytes(wrapped_dek[20:24], "big") != _VERSION):
            raise InvalidWrappedKeyError("invalid local wrapped key")
        selector = self._selector(purpose, bucket)
        with self._locked():
            state, key = self._read(selector)
            if state["state"] != "active":
                raise _unavailable()
            if wrapped_dek[4:20] != bytes.fromhex(state["key_id"]):
                raise InvalidWrappedKeyError("unknown local wrapped key")
            nonce = wrapped_dek[_HEADER_BYTES:_HEADER_BYTES + NONCE_SIZE_BYTES]
            return AESGCM(key).decrypt(nonce, wrapped_dek[_HEADER_BYTES + NONCE_SIZE_BYTES:],
                                       wrapped_dek[:_HEADER_BYTES] + _json(selector))
