#!/usr/bin/env python3
from pathlib import Path

required = {
    "frontend.py": ["Full autonomy (all risk levels)", "value=False"],
    "core/validators.py": ["AUTO_DENIED_BINARIES", "ALLOW_UNSCOPED_TARGETS"],
    "core/threat_intel.py": ["_url_is_public", "follow_redirects=False"],
    "core/report_generator.py": ["_display_secret", "INCLUDE_SECRETS_IN_REPORTS"],
    "ai/connector.py": ["Literal[\"low\", \"medium\", \"high\"]", "UNTRUSTED_SESSION_MEMORY"],
    "Dockerfile.hardened": ["pip install --no-deps -r /app/requirements.lock", "USER 10001:10001"],
    "compose.hardened.yml": [
        "read_only: true",
        "cap_drop:",
        "- ALL",
        "no-new-privileges:true",
        "SCOPE_ALLOWLIST: ${SCOPE_ALLOWLIST:?",
        '"127.0.0.1:6000:6000"',
    ],
    "start.sh": ["requirements.lock", "pip install --no-deps -r requirements.lock"],
}
for path, needles in required.items():
    text = Path(path).read_text(encoding="utf-8")
    for needle in needles:
        if needle not in text:
            raise SystemExit(f"security gate failed: {needle!r} missing from {path}")

forbidden = {
    "core/orchestrator.py": ["parts = [f\"  {user}:{secret}", "-U '{user}%{passwd}'"],
    "core/validators.py": ["FULL_AUTO_MODE bypasses the allowlist entirely"],
    "compose.hardened.yml": ["privileged: true", "network_mode: host", '"0.0.0.0:6000:6000"'],
    "Dockerfile.hardened": ["USER root"],
}
for path, needles in forbidden.items():
    text = Path(path).read_text(encoding="utf-8")
    for needle in needles:
        if needle in text:
            raise SystemExit(f"security gate failed: forbidden pattern {needle!r} in {path}")
print("MT security gate: PASS")
