"""Validated, read-only registry of MT Pentester capability packs.

Listing a project here does not claim that its code has been vendored or that an
integration is complete.  ``status`` is intentionally explicit so the UI cannot
turn a roadmap entry into a misleading enabled capability.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

_VALID_KINDS = {"engine", "skill-pack", "tool", "knowledge", "benchmark"}
_VALID_STATUSES = {"native", "adapter-planned", "reference-only", "blocked"}


class PluginRegistry:
    def __init__(self, manifest_path: Optional[Path] = None):
        self.manifest_path = manifest_path or Path(__file__).resolve().parents[1] / "config" / "plugins.json"
        self._plugins = self._load()

    def _load(self) -> list[dict]:
        payload = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        plugins = payload.get("plugins")
        if not isinstance(plugins, list):
            raise ValueError("Plugin manifest must contain a 'plugins' list")

        seen: set[str] = set()
        validated: list[dict] = []
        for raw in plugins:
            item = dict(raw)
            plugin_id = str(item.get("id", "")).strip()
            if not plugin_id or plugin_id in seen:
                raise ValueError(f"Invalid or duplicate plugin id: {plugin_id!r}")
            if item.get("kind") not in _VALID_KINDS:
                raise ValueError(f"Invalid plugin kind for {plugin_id}")
            if item.get("status") not in _VALID_STATUSES:
                raise ValueError(f"Invalid plugin status for {plugin_id}")
            if item.get("enabled_by_default") and item.get("status") != "native":
                raise ValueError(f"Only native plugins may be enabled by default: {plugin_id}")
            seen.add(plugin_id)
            validated.append(item)
        return validated

    def public_catalog(self) -> dict:
        counts: dict[str, int] = {}
        for item in self._plugins:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
        return {
            "schema_version": 1,
            "counts": counts,
            "plugins": [dict(item) for item in self._plugins],
        }

