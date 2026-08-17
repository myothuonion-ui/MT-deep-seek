#!/usr/bin/env python3
"""Fail CI when the reproducible-install contract drifts.

The committed requirements.lock must contain only exact ``name==version`` pins
(no VCS/URL/editable/range dependencies). Every direct requirement declared in
requirements.txt must be represented in the lock. Hardened container builds must
install that lock with ``--no-deps`` so dependency resolution cannot silently
change between builds.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements.lock"
REQ = ROOT / "requirements.txt"
DOCKERFILE = ROOT / "Dockerfile.hardened"

_PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s;]+)$")
_NAME = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?")


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def meaningful_lines(path: Path) -> list[str]:
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def main() -> int:
    if not LOCK.exists():
        raise SystemExit("reproducibility gate failed: requirements.lock is missing")

    pins: dict[str, str] = {}
    for line in meaningful_lines(LOCK):
        if any(token in line for token in ("http://", "https://", "git+", " @ ", "-e ")):
            raise SystemExit(f"reproducibility gate failed: mutable/external lock entry: {line}")
        match = _PIN.fullmatch(line)
        if not match:
            raise SystemExit(f"reproducibility gate failed: lock entry is not exact: {line}")
        name, version = match.groups()
        key = norm(name)
        if key in pins:
            raise SystemExit(f"reproducibility gate failed: duplicate lock package: {name}")
        pins[key] = version

    direct: set[str] = set()
    for line in meaningful_lines(REQ):
        match = _NAME.match(line)
        if not match:
            raise SystemExit(f"reproducibility gate failed: cannot parse direct requirement: {line}")
        direct.add(norm(match.group(1)))

    missing = sorted(name for name in direct if name not in pins)
    if missing:
        raise SystemExit(
            "reproducibility gate failed: direct dependencies missing from lock: "
            + ", ".join(missing)
        )

    docker = DOCKERFILE.read_text(encoding="utf-8")
    required_fragments = (
        "pip install --no-deps -r /app/requirements.lock",
        "USER 10001:10001",
    )
    for fragment in required_fragments:
        if fragment not in docker:
            raise SystemExit(
                f"reproducibility gate failed: Dockerfile.hardened missing {fragment!r}"
            )

    digest = hashlib.sha256(LOCK.read_bytes()).hexdigest()
    print(f"Reproducibility gate: PASS ({len(pins)} exact pins, lock sha256={digest})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
