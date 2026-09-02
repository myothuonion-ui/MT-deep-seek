"""Nuclei adapter with a conservative, scope-gated default profile."""

from __future__ import annotations

import json
import os
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


_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}


def _scope_host(target: str) -> str:
    value = (target or "").strip()
    parsed = urlsplit(value)
    if parsed.scheme:
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise AdapterPolicyError("Nuclei target must use http or https")
        if parsed.username or parsed.password:
            raise AdapterPolicyError("credentials are not allowed in target URLs")
        host = parsed.hostname
    else:
        host = value
    if not is_valid_target(host):
        raise AdapterPolicyError("invalid Nuclei target")
    return host


class NucleiAdapter:
    adapter_id = "nuclei"

    def __init__(self, binary: Optional[str] = None, templates_path: Optional[str] = None):
        self.binary = binary or os.getenv("NUCLEI_PATH", "nuclei")
        self.templates_path = templates_path or os.getenv("NUCLEI_TEMPLATES_PATH", "")

    def status(self) -> dict[str, Any]:
        state = public_binary_status(self.binary, "Nuclei CLI 3.11.x")
        templates = Path(self.templates_path) if self.templates_path else None
        state.update({
            "mode": "safe-active",
            "templates_configured": bool(templates and templates.is_dir()),
        })
        return state

    def build_argv(
        self,
        target: str,
        *,
        authorization_confirmed: bool,
        allowlist: Optional[str] = None,
        severities: tuple[str, ...] = ("low", "medium", "high", "critical"),
        rate_limit: int = 50,
        concurrency: int = 10,
    ) -> list[str]:
        host = _scope_host(target)
        scope = os.getenv("SCOPE_ALLOWLIST", "") if allowlist is None else allowlist
        require_authorized_scope(host, scope, authorization_confirmed)

        selected = tuple(dict.fromkeys(item.lower() for item in severities))
        if not selected or any(item not in _SEVERITIES for item in selected):
            raise AdapterPolicyError("invalid Nuclei severity filter")
        if not 1 <= int(rate_limit) <= 500:
            raise AdapterPolicyError("Nuclei rate limit must be between 1 and 500")
        if not 1 <= int(concurrency) <= 50:
            raise AdapterPolicyError("Nuclei concurrency must be between 1 and 50")

        argv = [
            self.binary,
            "-target", target.strip(),
            "-jsonl",
            "-silent",
            "-no-color",
            "-omit-raw",
            "-omit-template",
            "-disable-update-check",
            "-disable-unsigned-templates",
            "-no-interactsh",
            "-exclude-type", "headless,file,code,javascript",
            "-exclude-tags", "fuzz,dos,intrusive",
            "-severity", ",".join(selected),
            "-rate-limit", str(int(rate_limit)),
            "-concurrency", str(int(concurrency)),
            "-timeout", "10",
            "-retries", "1",
            "-max-host-error", "20",
        ]
        if self.templates_path:
            root = Path(self.templates_path).expanduser().resolve()
            if not root.is_dir():
                raise AdapterPolicyError("NUCLEI_TEMPLATES_PATH is not a readable directory")
            argv.extend(["-templates", str(root)])
        return argv

    @staticmethod
    def parse_jsonl(output: str, limit: int = 1000) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for line in output.splitlines():
            if len(findings) >= limit:
                break
            try:
                item = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(item, dict):
                continue
            info = item.get("info") if isinstance(item.get("info"), dict) else {}
            findings.append({
                "template_id": str(item.get("template-id") or item.get("template_id") or "")[:200],
                "name": str(info.get("name") or item.get("name") or "")[:500],
                "severity": str(info.get("severity") or item.get("severity") or "unknown")[:20],
                "matched_at": str(item.get("matched-at") or item.get("matched") or "")[:2000],
                "host": str(item.get("host") or "")[:1000],
                "timestamp": str(item.get("timestamp") or "")[:100],
            })
        return findings

    def run(
        self,
        target: str,
        *,
        authorization_confirmed: bool,
        allowlist: Optional[str] = None,
        timeout_seconds: int = 600,
        severities: tuple[str, ...] = ("low", "medium", "high", "critical"),
        rate_limit: int = 50,
        concurrency: int = 10,
    ) -> AdapterResult:
        argv = self.build_argv(
            target,
            authorization_confirmed=authorization_confirmed,
            allowlist=allowlist,
            severities=severities,
            rate_limit=rate_limit,
            concurrency=concurrency,
        )
        result = execute_argv(self.adapter_id, argv, timeout_seconds=timeout_seconds)
        return replace(result, findings=self.parse_jsonl(result.stdout))
