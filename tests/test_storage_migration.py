"""Non-destructive storage migration regression tests."""

import os
import shutil
import tempfile
from pathlib import Path

from core.storage import migrate_data_directory, migrate_runtime_files


def test_runtime_file_migration_copies_and_preserves_source():
    root = Path(tempfile.mkdtemp(prefix="mt-storage-test-"))
    try:
        legacy = root / "kmn_cyberseek.db"
        legacy.write_bytes(b"sqlite fixture")
        migrated = migrate_runtime_files(root)
        assert migrated == [("kmn_cyberseek.db", "mt_pentester.db")]
        assert legacy.read_bytes() == b"sqlite fixture"
        destination = root / "mt_pentester.db"
        assert destination.read_bytes() == b"sqlite fixture"
        assert os.stat(destination).st_mode & 0o777 == 0o600
    finally:
        shutil.rmtree(root)


def test_runtime_file_migration_never_overwrites_destination():
    root = Path(tempfile.mkdtemp(prefix="mt-storage-test-"))
    try:
        (root / "kmn_cyberseek.db").write_bytes(b"old")
        (root / "mt_pentester.db").write_bytes(b"current")
        assert migrate_runtime_files(root) == []
        assert (root / "mt_pentester.db").read_bytes() == b"current"
    finally:
        shutil.rmtree(root)


def test_runtime_file_migration_copies_default_log_and_sqlite_sidecars():
    root = Path(tempfile.mkdtemp(prefix="mt-storage-sidecars-"))
    try:
        (root / "backend.log").write_text("legacy default log", encoding="utf-8")
        (root / "kmn_cyberseek.db-wal").write_bytes(b"wal fixture")
        (root / "kmn_cyberseek.db-shm").write_bytes(b"shm fixture")
        migrated = migrate_runtime_files(root)
        assert migrated == [
            ("kmn_cyberseek.db-wal", "mt_pentester.db-wal"),
            ("kmn_cyberseek.db-shm", "mt_pentester.db-shm"),
            ("backend.log", "mt_pentester.log"),
        ]
        assert (root / "mt_pentester.db-wal").read_bytes() == b"wal fixture"
        assert (root / "mt_pentester.db-shm").read_bytes() == b"shm fixture"
        assert (root / "mt_pentester.log").read_text(encoding="utf-8") == "legacy default log"
    finally:
        shutil.rmtree(root)


def test_official_legacy_log_wins_without_overwriting_when_both_exist():
    root = Path(tempfile.mkdtemp(prefix="mt-storage-logs-"))
    try:
        (root / "backend.log").write_text("official default", encoding="utf-8")
        (root / "kmn_cyberseek.log").write_text("alternate legacy name", encoding="utf-8")
        assert migrate_runtime_files(root) == [("backend.log", "mt_pentester.log")]
        assert (root / "mt_pentester.log").read_text(encoding="utf-8") == "official default"
    finally:
        shutil.rmtree(root)


def test_volume_migration_skips_links_and_renames_known_files():
    parent = Path(tempfile.mkdtemp(prefix="mt-volume-test-"))
    source = parent / "source"
    destination = parent / "destination"
    source.mkdir()
    destination.mkdir()
    try:
        (source / "backend.log").write_text("legacy log", encoding="utf-8")
        (source / "kmn_cyberseek.db-wal").write_bytes(b"wal")
        (source / "evidence.json").write_text("{}", encoding="utf-8")
        (source / "unsafe-link").symlink_to("/etc/passwd")
        migrated = migrate_data_directory(source, destination)
        assert migrated == [
            ("backend.log", "mt_pentester.log"),
            ("evidence.json", "evidence.json"),
            ("kmn_cyberseek.db-wal", "mt_pentester.db-wal"),
        ]
        assert not (destination / "unsafe-link").exists()
    finally:
        shutil.rmtree(parent)
