"""BBOT 3.x adapter restricted to passive attack-surface mapping."""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

from core.validators import is_valid_target

from .base import (
    AdapterPolicyError,
    AdapterResult,
    execute_argv,
    public_binary_status,
    require_authorized_scope,
)


_SAFE_PRESETS = {"subdomain-enum", "code-enum"}
_NAME_RE = re.compile(r"[^a-zA-Z0-9_-]+")


def _scope_host(target: str) -> str:
    value = (target or "").strip()
    parsed = urlsplit(value)
    host = parsed.hostname if parsed.scheme else value
    if not host or not is_valid_target(host):
        raise AdapterPolicyError("invalid BBOT target")
    return host


class BBOTAdapter:
    adapter_id = "bbot"

    def __init__(self, binary: Optional[str] = None):
        self.binary = binary or os.getenv("BBOT_PATH", "bbot")

    def status(self) -> dict[str, Any]:
        state = public_binary_status(self.binary, "BBOT CLI 3.0.x")
        state["mode"] = "map-only"
        return state

    def build_argv(
        self,
        target: str,
        *,
        authorization_confirmed: bool,
        allowlist: Optional[str] = None,
        preset: str = "subdomain-enum",
        output_dir: str,
        scan_name: str = "mt-passive-map",
    ) -> list[str]:
        host = _scope_host(target)
        scope = os.getenv("SCOPE_ALLOWLIST", "") if allowlist is None else allowlist
        require_authorized_scope(host, scope, authorization_confirmed)
        if preset not in _SAFE_PRESETS:
            raise AdapterPolicyError("BBOT adapter only permits reviewed passive presets")

        destination = Path(output_dir).expanduser().resolve()
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        safe_name = _NAME_RE.sub("-", scan_name).strip("-")[:64]
        if not safe_name:
            raise AdapterPolicyError("invalid BBOT scan name")

        return [
            self.binary,
            "-t", target.strip(),
            "-p", preset,
            "-rf", "passive",
            "-n", safe_name,
            "-o", str(destination),
            "--json",
            "--no-color",
            "--no-deps",
            "-y",
        ]

    @staticmethod
    def parse_jsonl(output: str, limit: int = 2000) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for line in output.splitlines():
            if len(events) >= limit:
                break
            try:
                item = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(item, dict):
                continue
            events.append({
                "type": str(item.get("type") or item.get("event_type") or "")[:100],
                "data": item.get("data"),
                "scope_distance": item.get("scope_distance"),
                "tags": item.get("tags") if isinstance(item.get("tags"), list) else [],
            })
        return events

    def run(
        self,
        target: str,
        *,
        authorization_confirmed: bool,
        allowlist: Optional[str] = None,
        preset: str = "subdomain-enum",
        timeout_seconds: int = 900,
    ) -> AdapterResult:
        with tempfile.TemporaryDirectory(prefix="mt-bbot-") as output_dir:
            argv = self.build_argv(
                target,
                authorization_confirmed=authorization_confirmed,
                allowlist=allowlist,
                preset=preset,
                output_dir=output_dir,
            )
            result = execute_argv(self.adapter_id, argv, timeout_seconds=timeout_seconds)
        return replace(result, findings=self.parse_jsonl(result.stdout))
