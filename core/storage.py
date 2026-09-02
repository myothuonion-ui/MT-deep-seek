"""Non-destructive migration helpers for the MT Pentester data directory."""

from __future__ import annotations

import logging
import os
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Iterable, Optional


logger = logging.getLogger(__name__)

LEGACY_DATABASE_NAME = "kmn_cyberseek.db"
LEGACY_DATABASE_WAL_NAME = f"{LEGACY_DATABASE_NAME}-wal"
LEGACY_DATABASE_SHM_NAME = f"{LEGACY_DATABASE_NAME}-shm"
LEGACY_DATABASE_JOURNAL_NAME = f"{LEGACY_DATABASE_NAME}-journal"
LEGACY_LOG_NAME = "backend.log"
LEGACY_BRANDED_LOG_NAME = "kmn_cyberseek.log"
CURRENT_DATABASE_NAME = "mt_pentester.db"
CURRENT_DATABASE_WAL_NAME = f"{CURRENT_DATABASE_NAME}-wal"
CURRENT_DATABASE_SHM_NAME = f"{CURRENT_DATABASE_NAME}-shm"
CURRENT_DATABASE_JOURNAL_NAME = f"{CURRENT_DATABASE_NAME}-journal"
CURRENT_LOG_NAME = "mt_pentester.log"
_RENAMES = {
    LEGACY_DATABASE_NAME: CURRENT_DATABASE_NAME,
    LEGACY_DATABASE_WAL_NAME: CURRENT_DATABASE_WAL_NAME,
    LEGACY_DATABASE_SHM_NAME: CURRENT_DATABASE_SHM_NAME,
    LEGACY_DATABASE_JOURNAL_NAME: CURRENT_DATABASE_JOURNAL_NAME,
    LEGACY_LOG_NAME: CURRENT_LOG_NAME,
    LEGACY_BRANDED_LOG_NAME: CURRENT_LOG_NAME,
}


def _copy_regular_file(source: Path, destination: Path) -> bool:
    """Copy one regular file atomically without following or overwriting links."""
    if destination.exists() or destination.is_symlink():
        return False
    source_stat = source.lstat()
    if not stat.S_ISREG(source_stat.st_mode):
        return False
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temp_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=str(destination.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output, length=1024 * 1024)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temp_name, destination)
        except FileExistsError:
            return False
        os.chmod(destination, 0o600)
        return True
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def migrate_runtime_files(data_dir: Path | str) -> list[tuple[str, str]]:
    """Copy recognized legacy runtime files to MT names when destinations are absent."""
    root = Path(data_dir).expanduser().resolve()
    if not root.exists():
        root.mkdir(parents=True, mode=0o700)
    migrated: list[tuple[str, str]] = []
    for legacy_name, current_name in _RENAMES.items():
        source = root / legacy_name
        destination = root / current_name
        if source.exists() and not source.is_symlink() and _copy_regular_file(source, destination):
            migrated.append((legacy_name, current_name))
            logger.warning("Copied legacy runtime file %s to %s; the source was preserved", source, destination)
    return migrated


def migrate_data_directory(
    source_dir: Path | str,
    destination_dir: Path | str,
    *,
    allowed_names: Optional[Iterable[str]] = None,
) -> list[tuple[str, str]]:
    """Copy top-level regular files from a legacy volume without overwriting data.

    Symlinks, devices, sockets, and nested directories are deliberately skipped.
    Runtime database/log names are translated to their MT Pentester equivalents.
    """
    source_root = Path(source_dir).expanduser().resolve()
    destination_root = Path(destination_dir).expanduser().resolve()
    if source_root == destination_root:
        raise ValueError("source and destination data directories must differ")
    if not source_root.is_dir():
        raise ValueError(f"legacy data directory does not exist: {source_root}")
    destination_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    allowed = set(allowed_names) if allowed_names is not None else None

    migrated: list[tuple[str, str]] = []
    for source in sorted(source_root.iterdir()):
        if allowed is not None and source.name not in allowed:
            continue
        destination_name = _RENAMES.get(source.name, source.name)
        if _copy_regular_file(source, destination_root / destination_name):
            migrated.append((source.name, destination_name))
    return migrated
