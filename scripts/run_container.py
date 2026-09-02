#!/usr/bin/env python3
"""Small PID-1 supervisor for the hardened container profile.

Runs the existing backend, Streamlit UI and docs server without invoking a shell,
and terminates the full child set if any service exits or the container receives
SIGTERM/SIGINT.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.storage import migrate_runtime_files


CHILDREN: List[subprocess.Popen] = []
STOPPING = False


def _terminate_children() -> None:
    global STOPPING
    if STOPPING:
        return
    STOPPING = True

    for proc in CHILDREN:
        if proc.poll() is None:
            proc.terminate()

    deadline = time.monotonic() + 8
    for proc in CHILDREN:
        if proc.poll() is not None:
            continue
        remaining = max(0.0, deadline - time.monotonic())
        try:
            proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            proc.kill()


def _signal_handler(signum, frame) -> None:  # noqa: ARG001
    _terminate_children()


def _spawn(argv: list[str]) -> subprocess.Popen:
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=None,
        stderr=None,
        start_new_session=False,
    )
    CHILDREN.append(proc)
    return proc


def _wait_backend(port: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    url = f"http://127.0.0.1:{port}/health"
    while time.monotonic() < deadline:
        backend = CHILDREN[0]
        if backend.poll() is not None:
            raise RuntimeError(f"backend exited early with code {backend.returncode}")
        try:
            with urllib.request.urlopen(url, timeout=1.5) as response:
                if 200 <= response.status < 500:
                    return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"backend health check did not become ready: {url}")


def main() -> int:
    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    backend_port = os.getenv("BACKEND_PORT", "6000")
    frontend_port = os.getenv("FRONTEND_PORT", "8501")

    db_path = Path(os.getenv("DB_PATH", "/app/data/mt_pentester.db")).expanduser()
    os.makedirs(db_path.parent, exist_ok=True)
    migrate_runtime_files(db_path.parent)

    _spawn([sys.executable, "main.py"])
    try:
        _wait_backend(backend_port)
    except Exception as exc:
        print(f"container supervisor: {exc}", file=sys.stderr, flush=True)
        _terminate_children()
        return 1

    _spawn([
        "streamlit",
        "run",
        "frontend.py",
        "--server.port",
        frontend_port,
        "--server.address",
        "0.0.0.0",
        "--server.headless",
        "true",
    ])
    _spawn([sys.executable, "docs_server.py"])

    try:
        while not STOPPING:
            for proc in CHILDREN:
                code = proc.poll()
                if code is not None:
                    print(
                        f"container supervisor: child pid={proc.pid} exited with code {code}",
                        file=sys.stderr,
                        flush=True,
                    )
                    _terminate_children()
                    return code if code != 0 else 1
            time.sleep(0.5)
    finally:
        _terminate_children()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
