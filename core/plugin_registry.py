"""Validated, read-only registry of MT Pentester capability packs.

Listing a project here does not claim that its code has been vendored or that an
integration is complete.  ``status`` is intentionally explicit so the UI cannot
turn a roadmap entry into a misleading enabled capability.
"""

from __future__ import annotations

import json
import importlib
from pathlib import Path
from typing import Optional

_VALID_KINDS = {"engine", "skill-pack", "tool", "knowledge", "benchmark"}
_VALID_STATUSES = {"native", "adapter-ready", "adapter-planned", "reference-only", "blocked"}


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
            enabled = bool(item.get("enabled_by_default"))
            safe_read_only_default = (
                item.get("status") == "adapter-ready"
                and item.get("mode_ceiling") == "knowledge-only"
                and item.get("execution") == "read-only"
            )
            if enabled and item.get("status") != "native" and not safe_read_only_default:
                raise ValueError(
                    "Only native or explicitly read-only knowledge adapters may "
                    f"be enabled by default: {plugin_id}"
                )
            adapter = item.get("adapter")
            if item.get("status") == "adapter-ready":
                if not isinstance(adapter, dict) or not all(
                    isinstance(adapter.get(key), str) and adapter.get(key)
                    for key in ("module", "class")
                ):
                    raise ValueError(f"Adapter-ready plugin lacks an adapter entry: {plugin_id}")
            seen.add(plugin_id)
            validated.append(item)
        return validated

    @staticmethod
    def _runtime_status(item: dict) -> Optional[dict]:
        adapter = item.get("adapter")
        if not adapter:
            return None
        try:
            module = importlib.import_module(adapter["module"])
            adapter_type = getattr(module, adapter["class"])
            status = adapter_type().status()
            if not isinstance(status, dict):
                raise TypeError("adapter status must be a mapping")
            return status
        except Exception as exc:  # catalog must remain available when an optional tool is absent
            return {
                "available": False,
                "reason": f"adapter status check failed: {type(exc).__name__}",
            }

    def public_catalog(self) -> dict:
        counts: dict[str, int] = {}
        for item in self._plugins:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
        public_plugins = []
        for item in self._plugins:
            public = dict(item)
            runtime = self._runtime_status(item)
            if runtime is not None:
                public["runtime"] = runtime
            public_plugins.append(public)
        return {
            "schema_version": 2,
            "counts": counts,
            "plugins": public_plugins,
        }
