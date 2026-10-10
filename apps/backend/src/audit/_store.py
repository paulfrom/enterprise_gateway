"""Private storage primitives shared by the B2 audit catalog and access traces.

Both writers are controlled background/management surfaces: every mutation is
serialized through an OS advisory lock (same pattern as
:mod:`gateway.admin_storage` and :mod:`infra.file_kms`) and committed with
:func:`infra.durable_write.durable_commit`, and each directory carries its own
independent byte quota so catalog and access-event traffic can never crowd out
the mandatory intent/evidence/spool retention space. Failures raise the
controlled :class:`AuditStoreError` / :class:`DurableWriteError`; callers map
them to their contract codes and never fabricate success.
"""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import time

from infra.durable_write import DurableWriteError, durable_commit

__all__ = ["AuditStoreError", "LockedDirectory", "commit_guarded", "read_capped"]


class AuditStoreError(OSError):
    """Controlled audit-storage failure; never carries business content."""

    def __init__(self, detail: str = "audit store unavailable") -> None:
        self.detail = detail
        super().__init__(f"audit store error: {detail}")


def read_capped(path: Path, max_bytes: int) -> bytes | None:
    """Read one regular file with a hard size bound; ``None`` when anything is off.

    Symlinks, unreadable files, and documents above ``max_bytes`` collapse to
    ``None`` so untrusted on-disk state stays invisible rather than fatal (or
    unbounded in memory).
    """
    try:
        if path.is_symlink():
            return None
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            raw = stream.read(max_bytes + 1)
    except OSError:
        return None
    if len(raw) > max_bytes:
        return None
    return raw


class LockedDirectory:
    """One controlled directory; all mutations serialized by an OS lock."""

    def __init__(self, directory, *, create: bool = True) -> None:
        try:
            self._directory = Path(directory).absolute()
        except (OSError, TypeError):
            raise AuditStoreError("invalid directory") from None
        try:
            self._check_directory()
            if create:
                self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._check_directory()
            if not self._directory.is_dir():
                raise AuditStoreError("not a directory")
        except OSError:
            raise AuditStoreError("directory unusable") from None

    @property
    def path(self) -> Path:
        return self._directory

    def _check_directory(self) -> None:
        # Do not traverse an operator-visible symlink for any stored path.
        for path in (self._directory, *self._directory.parents):
            if path.is_symlink():
                raise AuditStoreError("directory path is a symlink")

    @contextmanager
    def locked(self):
        handle = None
        acquired = False
        try:
            self._check_directory()
            path = self._directory / ".audit-store.lock"
            if path.is_symlink():
                raise AuditStoreError("lock path is a symlink")
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
                            raise AuditStoreError("lock timeout") from None
                        time.sleep(0.02)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX)
            acquired = True
        except (OSError, ValueError):
            if handle is not None:
                handle.close()
            raise AuditStoreError("lock unusable") from None
        try:
            yield
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


def _quota_guard(max_bytes: int):
    def check(directory: Path, incoming: int) -> None:
        total = incoming
        try:
            entries = list(directory.iterdir())
        except OSError:
            raise DurableWriteError("quota scan failed") from None
        for entry in entries:
            try:
                if entry.is_file() and not entry.is_symlink():
                    total += entry.stat().st_size
            except OSError:
                raise DurableWriteError("quota scan failed") from None
        if total > max_bytes:
            raise DurableWriteError("directory quota exceeded")

    return check


def commit_guarded(directory: Path, filename: str, data: bytes, *, max_bytes: int):
    """Durable commit under the caller's lock, with an independent byte quota.

    Quota exhaustion surfaces as :class:`DurableWriteError` like any other
    commit failure; the caller maps it to its contract code. The final name
    either exists whole or not at all.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return durable_commit(
        directory, filename, data, capacity_check=_quota_guard(max_bytes)
    )
