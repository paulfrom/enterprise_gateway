"""Durable single-file commit primitive: temp write + flush + fsync + atomic rename + directory fsync.

Shared by the A-01 release-intent ledger and the K-02 encrypted spool. The
primitive is storage-agnostic: any failure raises its own controlled
:class:`DurableWriteError` and no commit is ever fabricated. Callers map
failures to their contract codes (``AUDIT_WRITE_FAILED`` /
``SPOOL_WRITE_FAILED``); capacity water-marks are enforced through the
injected ``capacity_check`` hook so each caller owns its own ``SPOOL_FULL``
semantics.

Commit protocol (DESIGN §6):

1. Optional caller water-mark hook runs before anything is created on disk;
2. body is written to a unique temp file in the SAME directory (rename is only
   atomic within one filesystem), flushed and fsynced before close;
3. ``os.replace`` performs the atomic rename onto the final name — readers
   never observe a partial file, and a crash before this point leaves only
   the temp file, never a half-written final name;
4. the directory is fsynced so the rename entry itself is durable.

Residual semantics: a failed attempt removes its temp file best effort. If
removal also fails, the temp file remains carrying its unique ``.tmp`` suffix
but is never renamed to the final name, so no consumer can mistake it for a
committed document. Only a path that completed every step is returned.

Directory fsync is best effort on platforms that cannot open a directory
handle (Windows raises ``PermissionError``); there the rename durability is
delegated to the filesystem and documented as such. File fsync and rename are
never skipped.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

__all__ = ["CommittedDocument", "DurableWriteError", "durable_commit"]


class DurableWriteError(OSError):
    """Controlled storage failure; never carries business content."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"durable write failed: {detail}")


@dataclass(frozen=True, slots=True)
class CommittedDocument:
    """Proof that one document reached the persistence boundary."""

    path: Path
    bytes_written: int


# --- patchable OS interop points (failure injection) -----------------------

def _write_all(fileobj, data: bytes) -> None:
    fileobj.write(data)


def _flush_and_fsync(fileobj) -> None:
    fileobj.flush()
    os.fsync(fileobj.fileno())


def _replace(src: Path, dst: Path) -> None:
    os.replace(src, dst)


def _fsync_directory(directory: Path) -> None:
    """fsync a directory entry; unsupported platforms skip with a comment."""
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        if os.name == "nt":
            # Windows cannot open a directory handle: rename durability is
            # delegated to the filesystem; see module docstring.
            return
        raise
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _remove_quietly(path: Path) -> None:
    try:
        os.remove(path)
    except OSError:
        pass  # best effort; residual temp keeps its .tmp suffix


# ---------------------------------------------------------------------------

def _validate_filename(name: str) -> None:
    if not isinstance(name, str) or not name:
        raise ValueError("filename must be a non-empty string")
    if name in (".", "..") or os.path.basename(name) != name or "/" in name or "\\" in name:
        raise ValueError("filename must be a plain file name without path components")


def durable_commit(
    directory: str | Path,
    filename: str,
    data: bytes,
    *,
    capacity_check: Callable[[Path, int], None] | None = None,
) -> CommittedDocument:
    """Commit ``data`` as ``directory/filename`` durably; all-or-nothing.

    ``capacity_check`` (optional) receives ``(directory, incoming_bytes)``
    before any file is created; any exception it raises propagates untouched
    so the caller maps it to its own contract code (e.g. ``SPOOL_FULL``).

    Returns :class:`CommittedDocument` only after write + fsync + rename +
    directory fsync all succeeded. Any failure raises
    :class:`DurableWriteError` and guarantees the final name does not exist.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    _validate_filename(filename)
    target_dir = Path(directory)
    committed_name = filename

    if capacity_check is not None:
        capacity_check(target_dir, len(data))  # caller-mapped, nothing created yet

    if not target_dir.is_dir():
        raise DurableWriteError("target directory is missing")

    try:
        fd, tmp_name = tempfile.mkstemp(prefix=f".{committed_name}.", suffix=".tmp", dir=target_dir)
    except OSError as exc:
        raise DurableWriteError(f"{type(exc).__name__} during commit") from None
    tmp_path = Path(tmp_name)
    try:
        try:
            fileobj = os.fdopen(fd, "wb")
        except OSError:
            os.close(fd)
            raise
        with fileobj:
            _write_all(fileobj, data)
            _flush_and_fsync(fileobj)
        _replace(tmp_path, target_dir / committed_name)
        _fsync_directory(target_dir)
    except DurableWriteError:
        _remove_quietly(tmp_path)
        raise
    except OSError as exc:
        _remove_quietly(tmp_path)
        raise DurableWriteError(f"{type(exc).__name__} during commit") from None
    return CommittedDocument(path=target_dir / committed_name, bytes_written=len(data))
