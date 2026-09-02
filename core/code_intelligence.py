"""Bounded, read-only white-box code intelligence.

This is a structural mapper, not a vulnerability oracle. It accepts explicitly
supplied source text, emits routes and review candidates, and never reads a
repository path, runs code, resolves dependencies, or confirms a finding.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any, Mapping


_MAX_FILES = 300
_MAX_TOTAL_BYTES = 5_000_000
_MAX_FILE_BYTES = 500_000
_ALLOWED_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".php", ".rb", ".cs"
}
_SENSITIVE_RE = re.compile(
    r"(?i)(api[_-]?key|authorization|cookie|password|secret|token)\s*[:=]\s*[^\s,;]+"
)
_AUTH_RE = re.compile(
    r"(?i)(authorize|authorization|authenticate|permission|role|jwt|"
    r"login_required|requires?\(|depends\(|current_user|is_admin)"
)
_ROUTE_PATTERNS = (
    re.compile(
        r"@(?:app|router|bp)\.(get|post|put|patch|delete|options|head)"
        r"\(\s*['\"]([^'\"]+)['\"]"
    ),
    re.compile(
        r"(?:app|router)\.(get|post|put|patch|delete|options|head)"
        r"\(\s*['\"]([^'\"]+)['\"]"
    ),
    re.compile(
        r"@(Get|Post|Put|Patch|Delete)Mapping"
        r"(?:\([^'\"]*)?['\"]([^'\"]+)['\"]"
    ),
    re.compile(
        r"(?:HandleFunc|Handle)\(\s*['\"]([^'\"]+)['\"]"
    ),
)
_SINK_RULES = (
    ("python-shell-true", re.compile(r"subprocess\.[A-Za-z_]+\([^\n]*shell\s*=\s*True")),
    ("python-os-system", re.compile(r"\bos\.system\s*\(")),
    ("dynamic-eval", re.compile(r"(?<![A-Za-z_])(eval|exec)\s*\(")),
    ("unsafe-pickle-load", re.compile(r"\bpickle\.loads?\s*\(")),
    ("unsafe-yaml-load", re.compile(r"\byaml\.load\s*\(")),
    ("node-child-exec", re.compile(r"\b(?:child_process\.)?exec\s*\(")),
    ("dom-innerhtml", re.compile(r"\.innerHTML\s*=")),
)
_SOURCE_RE = re.compile(
    r"(?i)(request\.(args|form|json|values)|req\.(body|query|params)|"
    r"Request\.(Query|Form)|r\.URL\.Query|params\[)"
)


class CodeIntelligencePolicyError(ValueError):
    """Raised for invalid or oversized white-box analysis input."""


def _redacted_line(line: str) -> str:
    return _SENSITIVE_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", line)[:300]


def _route_matches(line: str) -> list[tuple[str, str]]:
    found = []
    seen: set[tuple[str, str]] = set()
    for index, pattern in enumerate(_ROUTE_PATTERNS):
        for match in pattern.finditer(line):
            groups = match.groups()
            if index == 3:
                route = ("ANY", groups[0])
            else:
                route = (groups[0].upper(), groups[1])
            if route not in seen:
                seen.add(route)
                found.append(route)
    return found


def analyze_source_bundle(files: Mapping[str, str]) -> dict[str, Any]:
    if not isinstance(files, Mapping):
        raise CodeIntelligencePolicyError("files must be a path-to-text object")
    if len(files) > _MAX_FILES:
        raise CodeIntelligencePolicyError(f"at most {_MAX_FILES} files are allowed")

    normalized: list[tuple[str, str]] = []
    total_bytes = 0
    for raw_path, raw_content in files.items():
        path = str(raw_path).replace("\\", "/")[:1000]
        if path.startswith("/") or ".." in PurePosixPath(path).parts:
            raise CodeIntelligencePolicyError("source paths must be relative and traversal-free")
        if PurePosixPath(path).suffix.lower() not in _ALLOWED_SUFFIXES:
            continue
        if not isinstance(raw_content, str):
            raise CodeIntelligencePolicyError(f"source content must be text: {path}")
        size = len(raw_content.encode("utf-8"))
        if size > _MAX_FILE_BYTES:
            raise CodeIntelligencePolicyError(
                f"source file exceeds {_MAX_FILE_BYTES} bytes: {path}"
            )
        total_bytes += size
        if total_bytes > _MAX_TOTAL_BYTES:
            raise CodeIntelligencePolicyError(
                f"source bundle exceeds {_MAX_TOTAL_BYTES} bytes"
            )
        normalized.append((path, raw_content))

    routes: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    file_nodes: list[dict[str, Any]] = []

    for path, content in sorted(normalized):
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        file_nodes.append({"path": path, "sha256": digest, "bytes": len(content.encode("utf-8"))})
        lines = content.splitlines()
        for line_number, line in enumerate(lines, 1):
            for method, route_path in _route_matches(line):
                start = max(0, line_number - 1)
                window = "\n".join(lines[start:min(len(lines), start + 16)])
                guarded = bool(_AUTH_RE.search(window))
                route_id = hashlib.sha256(
                    f"{path}:{line_number}:{method}:{route_path}".encode("utf-8")
                ).hexdigest()[:16]
                routes.append({
                    "route_id": f"route-{route_id}",
                    "file": path,
                    "line": line_number,
                    "method": method,
                    "path": route_path[:1000],
                    "auth_guard_signal": guarded,
                    "classification": "mapped-route",
                })
                if not guarded:
                    candidates.append({
                        "candidate_id": f"candidate-route-{route_id}",
                        "rule_id": "route-without-nearby-auth-signal",
                        "file": path,
                        "line": line_number,
                        "severity": "review",
                        "status": "candidate",
                        "reason": "No nearby authentication/authorization signal was detected",
                    })

            if _SOURCE_RE.search(line):
                sources.append({
                    "file": path,
                    "line": line_number,
                    "kind": "request-input",
                })
            for rule_id, pattern in _SINK_RULES:
                if pattern.search(line):
                    candidate_id = hashlib.sha256(
                        f"{path}:{line_number}:{rule_id}".encode("utf-8")
                    ).hexdigest()[:16]
                    candidates.append({
                        "candidate_id": f"candidate-sink-{candidate_id}",
                        "rule_id": rule_id,
                        "file": path,
                        "line": line_number,
                        "severity": "review",
                        "status": "candidate",
                        "reason": "Potentially security-sensitive sink requires data-flow review",
                        "redacted_preview": _redacted_line(line.strip()),
                    })

    graph_nodes = [
        {"id": f"file:{item['sha256'][:16]}", "type": "file", "key": item["path"]}
        for item in file_nodes
    ] + [
        {"id": item["route_id"], "type": "endpoint", "key": f"{item['method']} {item['path']}"}
        for item in routes
    ]
    graph_edges = []
    file_ids = {item["path"]: f"file:{item['sha256'][:16]}" for item in file_nodes}
    for route in routes:
        graph_edges.append({
            "from": file_ids[route["file"]],
            "to": route["route_id"],
            "relation": "declares",
        })

    body = {
        "schema": 1,
        "kind": "mt-code-intelligence",
        "files": file_nodes,
        "routes": routes,
        "request_sources": sources[:2000],
        "candidates": candidates[:5000],
        "graph": {"nodes": graph_nodes, "edges": graph_edges},
        "summary": {
            "files_analyzed": len(file_nodes),
            "routes_mapped": len(routes),
            "request_sources": len(sources),
            "review_candidates": len(candidates),
            "total_bytes": total_bytes,
        },
        "guardrails": [
            "Static structure only; supplied code was not executed.",
            "Candidates are not vulnerabilities and require proof verification.",
            "No filesystem path, dependency, or external reference was resolved.",
        ],
    }
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    body["analysis_id"] = f"code-{hashlib.sha256(encoded).hexdigest()[:16]}"
    return body
