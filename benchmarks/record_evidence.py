#!/usr/bin/env python3
"""Create provenance-rich benchmark evidence without storing a sensitive report.

The raw engagement report may contain targets, usernames, or other secrets. This
script scores it locally, records only the score plus SHA-256 provenance, and can
optionally enforce a minimum touched/confirmed percentage for release gates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from score import load_lab, score

HERE = Path(__file__).resolve().parent
DEFAULT_LAB = HERE / "labs" / "kmn_training_win.json"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def current_commit() -> str:
    env_sha = os.getenv("GITHUB_SHA", "").strip()
    if env_sha:
        return env_sha
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return "unknown"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report", type=Path, help="Authorized-lab Markdown/text report")
    ap.add_argument("--lab", type=Path, default=DEFAULT_LAB)
    ap.add_argument("--out", type=Path, default=HERE / "evidence" / "current_score.json")
    ap.add_argument("--minimum-touched", type=float, default=0.0)
    ap.add_argument("--minimum-confirmed", type=float, default=0.0)
    args = ap.parse_args()

    report_text = args.report.read_text(encoding="utf-8")
    lab = load_lab(str(args.lab))
    result = score(report_text, lab)

    evidence = {
        "schema": 1,
        "kind": "authorized_lab_run",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "code_commit": current_commit(),
        "report_sha256": sha256(args.report),
        "lab_sha256": sha256(args.lab),
        "lab": result["lab"],
        "total": result["total"],
        "touched": result["touched"],
        "confirmed": result["confirmed"],
        "touched_pct": result["touched_pct"],
        "confirmed_pct": result["confirmed_pct"],
        "categories": result["categories"],
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2))

    if result["touched_pct"] < args.minimum_touched:
        raise SystemExit(
            f"benchmark gate failed: touched {result['touched_pct']}% < {args.minimum_touched}%"
        )
    if result["confirmed_pct"] < args.minimum_confirmed:
        raise SystemExit(
            f"benchmark gate failed: confirmed {result['confirmed_pct']}% < {args.minimum_confirmed}%"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
