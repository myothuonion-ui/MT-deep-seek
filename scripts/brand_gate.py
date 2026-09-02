#!/usr/bin/env python3
"""Reject legacy branding outside the legal notice and explicit migration path."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = {
    "NOTICE",
    "compose.migrate.yml",
    "core/storage.py",
    "docs/data-migration.md",
    "scripts/brand_gate.py",
    "tests/test_storage_migration.py",
}
TEXT_SUFFIXES = {"", ".md", ".txt", ".py", ".json", ".yml", ".yaml", ".toml", ".sh"}
PATTERN = re.compile(r"(?i)(khit\s*minnyo|kmn(?:[-_]|\b))")


def main() -> int:
    violations = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        relative = path.relative_to(ROOT).as_posix()
        if relative in ALLOWLIST:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            if PATTERN.search(line):
                violations.append(f"{relative}:{line_number}")
    if violations:
        raise SystemExit("legacy branding found outside NOTICE/migration files: " + ", ".join(violations))
    print("MT brand independence gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
