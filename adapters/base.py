"""Shared subprocess and policy boundary for MT Pentester adapters.

Adapters construct an argument vector and invoke it without a shell. Output is
bounded before it is returned to the API, and a timed-out process group is
terminated so child processes cannot outlive an engagement action.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional


_SAFE_ENV_NAMES = {
    "HOME",
    "LANG",
    "LC_ALL",
    "NO_PROXY",
    "PATH",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "TEMP",
    "TMP",
    "TMPDIR",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
}
_SAFE_ENV_PREFIXES = ("BBOT_", "NUCLEI_")


class AdapterError(RuntimeError):
    """Base class for adapter failures safe to report to the operator."""


class AdapterPolicyError(AdapterError):
    """The requested action did not satisfy authorization or execution policy."""


class AdapterUnavailableError(AdapterError):
    """The external tool or read-only asset bundle is not installed."""


@dataclass(frozen=True)
class AdapterResult:
    adapter: str
    returncode: int
    duration_seconds: float
    findings: list[dict[str, Any]] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "returncode": self.returncode,
            "duration_seconds": self.duration_seconds,
            "findings": self.findings,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "truncated": self.truncated,
        }


def require_authorized_scope(
    target: str,
    allowlist: Optional[str],
    authorization_confirmed: bool,
) -> None:
    """Fail closed unless the operator confirmed authority and target is scoped."""
    from core.validators import is_target_in_scope

    if not authorization_confirmed:
        raise AdapterPolicyError("explicit authorization confirmation is required")
    if not is_target_in_scope(target, allowlist):
        raise AdapterPolicyError("target is outside SCOPE_ALLOWLIST")


def resolve_binary(binary: str) -> Optional[str]:
    """Resolve a configured executable without interpreting any shell text."""
    if not binary or "\x00" in binary:
        return None
    path = Path(binary)
    if path.is_absolute():
        return str(path) if path.is_file() and os.access(path, os.X_OK) else None
    if path.name != binary:
        return None
    return shutil.which(binary)


def public_binary_status(binary: str, requirement: str) -> dict[str, Any]:
    """Return non-secret runtime state for the capability catalog."""
    return {
        "available": resolve_binary(binary) is not None,
        "requirement": requirement,
    }


def _read_bounded(path: str, limit: int) -> tuple[str, bool]:
    size = os.path.getsize(path)
    with open(path, "rb") as handle:
        raw = handle.read(limit + 1)
    truncated = size > limit or len(raw) > limit
    return raw[:limit].decode("utf-8", errors="replace"), truncated


def sanitized_adapter_environment(overrides: Optional[dict[str, str]] = None) -> dict[str, str]:
    """Build a minimal child environment without inheriting application secrets.

    Provider credentials and the backend API token are deliberately excluded.
    Tool-specific values must use a reviewed ``BBOT_`` or ``NUCLEI_`` prefix.
    """
    allowed = {
        key: value
        for key, value in os.environ.items()
        if key in _SAFE_ENV_NAMES or key.startswith(_SAFE_ENV_PREFIXES)
    }
    allowed.setdefault("PATH", os.defpath)
    for key, value in (overrides or {}).items():
        if key not in _SAFE_ENV_NAMES and not key.startswith(_SAFE_ENV_PREFIXES):
            raise AdapterPolicyError(f"adapter environment variable is not permitted: {key}")
        if not isinstance(value, str) or "\x00" in key or "\x00" in value or "=" in key:
            raise AdapterPolicyError("adapter environment contains an invalid entry")
        allowed[key] = value
    return allowed


def execute_argv(
    adapter: str,
    argv: Iterable[str],
    *,
    timeout_seconds: int,
    max_output_bytes: int = 2_000_000,
    cwd: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
) -> AdapterResult:
    """Execute an adapter command with no shell and bounded captured output."""
    args = [str(part) for part in argv]
    if not args or not all(args) or any("\x00" in part for part in args):
        raise AdapterPolicyError("adapter produced an invalid argument vector")
    resolved = resolve_binary(args[0])
    if not resolved:
        raise AdapterUnavailableError(f"{adapter} executable is not installed")
    args[0] = resolved
    timeout = max(1, min(int(timeout_seconds), 3600))

    started = time.monotonic()
    with tempfile.NamedTemporaryFile() as stdout_file, tempfile.NamedTemporaryFile() as stderr_file:
        proc = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            cwd=cwd,
            env=sanitized_adapter_environment(env),
            shell=False,
            start_new_session=True,
        )
        try:
            returncode = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                proc.kill()
            proc.wait()
            raise AdapterError(f"{adapter} timed out after {timeout} seconds") from exc

        stdout_file.flush()
        stderr_file.flush()
        stdout, stdout_truncated = _read_bounded(stdout_file.name, max_output_bytes)
        stderr, stderr_truncated = _read_bounded(stderr_file.name, max_output_bytes)

    return AdapterResult(
        adapter=adapter,
        returncode=returncode,
        duration_seconds=round(time.monotonic() - started, 3),
        stdout=stdout,
        stderr=stderr,
        truncated=stdout_truncated or stderr_truncated,
    )
