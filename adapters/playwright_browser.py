"""Optional, scoped Playwright browser adapter.

Playwright is runtime-detected and never auto-installed. Every navigation and
subresource request is scope checked. State-changing interactions require a
second explicit confirmation; arbitrary JavaScript, downloads, and uploads are
not exposed.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
from importlib.metadata import PackageNotFoundError, version
import os
import re
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence
from urllib.parse import urlsplit

from .base import AdapterPolicyError, AdapterUnavailableError, require_authorized_scope


_ALLOWED_ACTIONS = {"navigate", "click", "fill", "select", "wait_for", "screenshot", "capture"}
_INTERACTIVE_ACTIONS = {"click", "fill", "select"}
_ALLOWED_WAIT_STATES = {"attached", "detached", "visible", "hidden"}
_SELECTOR_RE = re.compile(r"^[^\x00\r\n]{1,500}$")
_MAX_ACTIONS = 100
_MAX_SCREENSHOTS = 20


class PlaywrightBrowserAdapter:
    adapter_id = "playwright-browser"
    pinned_version = "1.62.0"

    def __init__(self, artifact_dir: Optional[str] = None):
        configured = artifact_dir or os.getenv(
            "BROWSER_ARTIFACT_DIR",
            os.path.join(tempfile.gettempdir(), "mt-browser-evidence"),
        )
        self.artifact_dir = Path(configured).expanduser().resolve()

    def status(self) -> dict[str, Any]:
        installed = importlib.util.find_spec("playwright") is not None
        installed_version = None
        if installed:
            try:
                installed_version = version("playwright")
            except PackageNotFoundError:
                installed = False
        compatible = installed and installed_version == self.pinned_version
        return {
            "available": compatible,
            "installed": installed,
            "installed_version": installed_version,
            "requirement": (
                f"operator-managed playwright=={self.pinned_version} "
                "with a reviewed Chromium runtime"
            ),
            "mode": "safe-active",
            "auto_install": False,
            "arbitrary_javascript": False,
            "downloads": False,
        }

    @staticmethod
    def _selector(value: Any, index: int) -> str:
        selector = str(value or "")
        if not _SELECTOR_RE.fullmatch(selector):
            raise AdapterPolicyError(
                f"browser action {index} requires a bounded single-line selector"
            )
        return selector

    def validate_actions(
        self,
        target: str,
        actions: Sequence[Mapping[str, Any]],
        *,
        authorization_confirmed: bool,
        interactive_actions_confirmed: bool,
        allowlist: Optional[str],
    ) -> list[dict[str, Any]]:
        require_authorized_scope(target, allowlist, authorization_confirmed)
        if len(actions) > _MAX_ACTIONS:
            raise AdapterPolicyError(f"at most {_MAX_ACTIONS} browser actions are allowed")

        normalized: list[dict[str, Any]] = []
        screenshot_count = 0
        for index, raw in enumerate(actions, 1):
            if not isinstance(raw, Mapping):
                raise AdapterPolicyError(f"browser action {index} must be an object")
            kind = str(raw.get("action", "")).strip().lower()
            if kind not in _ALLOWED_ACTIONS:
                raise AdapterPolicyError(
                    f"browser action {index} has unsupported action: {kind!r}"
                )
            if kind in _INTERACTIVE_ACTIONS and not interactive_actions_confirmed:
                raise AdapterPolicyError(
                    f"browser action '{kind}' requires interactive_actions_confirmed"
                )
            item: dict[str, Any] = {"action": kind}
            if kind == "navigate":
                url = str(raw.get("url", ""))[:2048]
                parsed = urlsplit(url)
                if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    raise AdapterPolicyError(f"browser action {index} has an invalid URL")
                require_authorized_scope(url, allowlist, authorization_confirmed)
                item["url"] = url
            elif kind in {"click", "fill", "select", "wait_for"}:
                item["selector"] = self._selector(raw.get("selector"), index)
                if kind in {"fill", "select"}:
                    value = str(raw.get("value", ""))
                    if len(value) > 2000 or "\x00" in value:
                        raise AdapterPolicyError(
                            f"browser action {index} has an invalid value"
                        )
                    item["value"] = value
                if kind == "wait_for":
                    state = str(raw.get("state", "visible")).lower()
                    if state not in _ALLOWED_WAIT_STATES:
                        raise AdapterPolicyError(
                            f"browser action {index} has unsupported wait state"
                        )
                    item["state"] = state
            elif kind == "screenshot":
                screenshot_count += 1
                if screenshot_count > _MAX_SCREENSHOTS:
                    raise AdapterPolicyError(
                        f"at most {_MAX_SCREENSHOTS} screenshots are allowed"
                    )
                item["label"] = re.sub(
                    r"[^a-zA-Z0-9_.-]+", "-", str(raw.get("label", "page"))
                )[:80] or "page"
                item["full_page"] = bool(raw.get("full_page", False))
            normalized.append(item)
        return normalized

    async def run(
        self,
        target: str,
        actions: Sequence[Mapping[str, Any]],
        *,
        authorization_confirmed: bool,
        interactive_actions_confirmed: bool = False,
        allowlist: Optional[str] = None,
        timeout_seconds: int = 120,
    ) -> dict[str, Any]:
        normalized = self.validate_actions(
            target,
            actions,
            authorization_confirmed=authorization_confirmed,
            interactive_actions_confirmed=interactive_actions_confirmed,
            allowlist=allowlist,
        )
        if not self.status()["available"]:
            raise AdapterUnavailableError(
                f"playwright=={self.pinned_version} runtime is not installed"
            )

        from playwright.async_api import async_playwright

        timeout = max(1, min(int(timeout_seconds), 900))
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.artifact_dir, 0o700)
        except OSError:
            pass

        async def _execute() -> dict[str, Any]:
            started = time.monotonic()
            artifacts: list[dict[str, Any]] = []
            observations: list[dict[str, Any]] = []
            blocked_requests: list[str] = []
            action_log: list[dict[str, Any]] = []
            async with async_playwright() as runtime:
                browser = await runtime.chromium.launch(headless=True)
                context = await browser.new_context(
                    accept_downloads=False,
                    service_workers="block",
                )

                async def scope_route(route, request):
                    parsed = urlsplit(request.url)
                    if parsed.scheme in {"about", "blob", "data"}:
                        await route.continue_()
                        return
                    try:
                        require_authorized_scope(
                            request.url, allowlist, authorization_confirmed
                        )
                    except AdapterPolicyError:
                        if len(blocked_requests) < 100:
                            blocked_requests.append(request.url[:500])
                        await route.abort("blockedbyclient")
                        return
                    await route.continue_()

                await context.route("**/*", scope_route)
                page = await context.new_page()
                page.set_default_timeout(min(timeout * 1000, 30_000))
                await page.goto(target, wait_until="domcontentloaded")

                try:
                    for index, item in enumerate(normalized, 1):
                        kind = item["action"]
                        if kind == "navigate":
                            await page.goto(item["url"], wait_until="domcontentloaded")
                        elif kind == "click":
                            await page.locator(item["selector"]).click()
                        elif kind == "fill":
                            await page.locator(item["selector"]).fill(item["value"])
                        elif kind == "select":
                            await page.locator(item["selector"]).select_option(
                                item["value"]
                            )
                        elif kind == "wait_for":
                            await page.locator(item["selector"]).wait_for(
                                state=item["state"]
                            )
                        elif kind == "screenshot":
                            name = (
                                f"{uuid.uuid4().hex}-{item['label']}.png"
                            )
                            path = self.artifact_dir / name
                            await page.screenshot(
                                path=str(path),
                                full_page=item["full_page"],
                            )
                            os.chmod(path, 0o600)
                            digest = hashlib.sha256(path.read_bytes()).hexdigest()
                            artifacts.append({
                                "kind": "screenshot",
                                "path": str(path),
                                "sha256": digest,
                                "size_bytes": path.stat().st_size,
                            })
                        elif kind == "capture":
                            observations.append({
                                "kind": "browser-state",
                                "url": page.url[:2048],
                                "title": (await page.title())[:500],
                            })

                        log_item = {"step": index, "action": kind, "success": True}
                        if kind in {"fill", "select"}:
                            log_item["value"] = "[REDACTED]"
                        action_log.append(log_item)
                finally:
                    await context.close()
                    await browser.close()

            return {
                "adapter": self.adapter_id,
                "status": "completed",
                "duration_seconds": round(time.monotonic() - started, 3),
                "actions": action_log,
                "observations": observations,
                "artifacts": artifacts,
                "blocked_requests": blocked_requests,
                "policy": {
                    "authorization_confirmed": True,
                    "interactive_actions_confirmed": interactive_actions_confirmed,
                    "arbitrary_javascript": False,
                    "downloads": False,
                    "uploads": False,
                    "ephemeral_context": True,
                },
            }

        try:
            return await asyncio.wait_for(_execute(), timeout=timeout)
        except asyncio.TimeoutError as exc:
            raise AdapterPolicyError(
                f"browser run exceeded the {timeout}-second limit"
            ) from exc
