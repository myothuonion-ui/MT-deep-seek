"""Read-only adapter for a pinned Claude-BugHunter skill bundle checkout."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Optional

from .base import AdapterPolicyError, AdapterUnavailableError


_SKILL_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,99}$")
_MAX_INDEX_BYTES = 5_000_000
_MAX_SKILL_BYTES = 2_000_000


class ClaudeBugHunterAdapter:
    adapter_id = "claude-bughunter"
    pinned_commit = "f032240d876c40465770ab4839e7257b9e7254e8"

    def __init__(self, root: Optional[str] = None):
        configured = root or os.getenv("CLAUDE_BUGHUNTER_PATH", "/opt/mt-pentester/plugins/claude-bughunter")
        self.root = Path(configured).expanduser().resolve()

    @property
    def index_path(self) -> Path:
        return self.root / "cbh" / "data" / "skill_index.json"

    def status(self) -> dict[str, Any]:
        return {
            "available": self.index_path.is_file(),
            "requirement": f"read-only Claude-BugHunter checkout at {self.pinned_commit}",
            "mode": "knowledge-only",
            "pinned_commit": self.pinned_commit,
        }

    def _load_index(self) -> dict[str, Any]:
        path = self.index_path
        if not path.is_file():
            raise AdapterUnavailableError("Claude-BugHunter read-only skill bundle is not mounted")
        if path.stat().st_size > _MAX_INDEX_BYTES:
            raise AdapterPolicyError("Claude-BugHunter skill index exceeds the size limit")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AdapterPolicyError("Claude-BugHunter skill index is invalid") from exc
        if not isinstance(payload.get("skills"), dict):
            raise AdapterPolicyError("Claude-BugHunter skill index has an unsupported schema")
        return payload

    def list_skills(self, query: str = "", limit: int = 100) -> list[dict[str, str]]:
        needle = query.strip().lower()[:200]
        capped = max(1, min(int(limit), 500))
        skills = self._load_index()["skills"]
        results = []
        for name, description in sorted(skills.items()):
            text = str(description)
            if needle and needle not in name.lower() and needle not in text.lower():
                continue
            results.append({"name": str(name), "description": text[:4000]})
            if len(results) >= capped:
                break
        return results

    def read_skill(self, name: str) -> dict[str, str]:
        if not _SKILL_RE.fullmatch(name or ""):
            raise AdapterPolicyError("invalid Claude-BugHunter skill name")
        index = self._load_index()["skills"]
        if name not in index:
            raise AdapterPolicyError("unknown Claude-BugHunter skill")
        path = (self.root / "skills" / name / "SKILL.md").resolve()
        try:
            path.relative_to(self.root)
        except ValueError as exc:
            raise AdapterPolicyError("skill path escaped the mounted bundle") from exc
        if not path.is_file():
            raise AdapterUnavailableError("selected skill content is not present in the mounted bundle")
        if path.stat().st_size > _MAX_SKILL_BYTES:
            raise AdapterPolicyError("selected skill exceeds the size limit")
        return {
            "name": name,
            "description": str(index[name])[:4000],
            "content": path.read_text(encoding="utf-8"),
            "source_commit": self.pinned_commit,
        }
