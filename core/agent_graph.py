"""Deterministic, dependency-aware engagement task graphs.

The graph plans and tracks bounded roles; it does not execute tools or model
calls. Existing adapter, authorization, scope, approval, and proof boundaries
remain authoritative.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Sequence
from urllib.parse import urlsplit, urlunsplit

from core.validators import is_target_in_scope


_CAPABILITIES = {"network_scan", "api_contracts", "whitebox", "browser"}
_EVENTS = {"start", "complete", "reject", "skip"}
_TERMINAL = {"completed", "rejected", "skipped"}
_SENSITIVE = re.compile(
    r"(authorization|cookie|credential|password|secret|token|api[_-]?key)",
    re.IGNORECASE,
)


class AgentGraphPolicyError(ValueError):
    """Raised when graph creation or transition violates policy."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sanitize(value: Any, key: str = "") -> Any:
    if _SENSITIVE.search(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {
            str(k)[:100]: _sanitize(v, str(k))
            for k, v in list(value.items())[:200]
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in list(value)[:500]]
    if isinstance(value, str):
        return value[:10_000]
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return str(value)[:1000]


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _with_hash(graph: dict[str, Any], integrity_key: str) -> dict[str, Any]:
    graph.pop("graph_hmac_sha256", None)
    graph["graph_hmac_sha256"] = hmac.new(
        integrity_key.encode("utf-8"), _canonical(graph), hashlib.sha256
    ).hexdigest()
    return graph


def _verify_hash(graph: Mapping[str, Any], integrity_key: str) -> None:
    supplied = str(graph.get("graph_hmac_sha256") or "")
    body = copy.deepcopy(dict(graph))
    body.pop("graph_hmac_sha256", None)
    expected = hmac.new(
        integrity_key.encode("utf-8"), _canonical(body), hashlib.sha256
    ).hexdigest()
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise AgentGraphPolicyError("agent graph integrity check failed")


def _task(
    graph_id: str,
    slug: str,
    role: str,
    task_type: str,
    dependencies: Sequence[str],
    *,
    optional: bool = False,
    execution_boundary: str,
    model_route: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    task_id = "task-" + hashlib.sha256(
        f"{graph_id}:{slug}".encode("utf-8")
    ).hexdigest()[:16]
    return {
        "task_id": task_id,
        "slug": slug,
        "role": role,
        "task_type": task_type,
        "status": "pending",
        "dependencies": list(dependencies),
        "optional": optional,
        "execution_boundary": execution_boundary,
        "model_route": dict(model_route or {}),
        "evidence_refs": [],
        "result": {},
    }


def create_engagement_graph(
    target: str,
    objective: str,
    *,
    authorization_confirmed: bool,
    allowlist: Optional[str],
    integrity_key: str,
    capabilities: Optional[Sequence[str]] = None,
    model_router: Any = None,
    sensitivity: str = "standard",
) -> dict[str, Any]:
    target = str(target or "").strip()[:2048]
    objective = str(objective or "").strip()[:2000]
    if not authorization_confirmed:
        raise AgentGraphPolicyError("explicit authorization confirmation is required")
    if not isinstance(integrity_key, str) or len(integrity_key) < 16:
        raise AgentGraphPolicyError("agent graph integrity key is not configured")
    parsed = urlsplit(target)
    if parsed.scheme.lower() in {"http", "https"}:
        if parsed.username or parsed.password:
            raise AgentGraphPolicyError("target URL must not contain user information")
        target = urlunsplit(
            (parsed.scheme.lower(), parsed.netloc, parsed.path or "", "", "")
        )
        parsed = urlsplit(target)
    scope_target = (
        parsed.hostname
        if parsed.scheme.lower() in {"http", "https"} and parsed.hostname
        else target
    )
    if not scope_target or not is_target_in_scope(scope_target, allowlist):
        raise AgentGraphPolicyError("target is outside SCOPE_ALLOWLIST")
    if not objective:
        raise AgentGraphPolicyError("objective is required")
    selected = {
        str(item).strip().lower()
        for item in (capabilities or [])
        if str(item).strip()
    }
    unknown = selected - _CAPABILITIES
    if unknown:
        raise AgentGraphPolicyError(
            "unsupported capabilities: " + ", ".join(sorted(unknown))
        )

    created_at = _now()
    graph_id = "graph-" + hashlib.sha256(
        f"{target}:{objective}:{created_at}".encode("utf-8")
    ).hexdigest()[:20]

    def route(role: str) -> dict[str, Any]:
        if model_router is None:
            return {}
        return model_router.route(role, sensitivity=sensitivity)

    scope = _task(
        graph_id, "scope-policy", "scoper", "scope-policy", [],
        execution_boundary="deterministic-policy-only", model_route=route("scoper"),
    )
    tasks = [scope]
    mapping_ids = []
    if "network_scan" in selected or not selected:
        network = _task(
            graph_id, "surface-map", "mapper", "surface-map",
            [scope["task_id"]], execution_boundary="existing-adapter-policy",
            model_route=route("mapper"),
        )
        tasks.append(network)
        mapping_ids.append(network["task_id"])
    if "api_contracts" in selected:
        contract = _task(
            graph_id, "api-contract-map", "mapper", "api-contract-map",
            [scope["task_id"]], optional=True,
            execution_boundary="non-executing-contract-planner",
            model_route=route("mapper"),
        )
        tasks.append(contract)
        mapping_ids.append(contract["task_id"])
    if "whitebox" in selected:
        whitebox = _task(
            graph_id, "whitebox-map", "code_reviewer", "whitebox-map",
            [scope["task_id"]], optional=True,
            execution_boundary="candidate-only-static-mapper",
            model_route=route("code_reviewer"),
        )
        tasks.append(whitebox)
        mapping_ids.append(whitebox["task_id"])
    if "browser" in selected:
        browser = _task(
            graph_id, "browser-observe", "mapper", "browser-observe",
            [scope["task_id"]], optional=True,
            execution_boundary="scope-checked-browser-adapter",
            model_route=route("mapper"),
        )
        tasks.append(browser)
        mapping_ids.append(browser["task_id"])

    hypothesis = _task(
        graph_id, "hypothesis", "strategist", "hypothesis",
        mapping_ids or [scope["task_id"]],
        execution_boundary="model-proposal-no-execution",
        model_route=route("strategist"),
    )
    verify = _task(
        graph_id, "proof-verification", "verifier", "proof-verification",
        [hypothesis["task_id"]],
        execution_boundary="deterministic-proof-verifier",
        model_route=route("verifier"),
    )
    report = _task(
        graph_id, "report", "reporter", "report",
        [verify["task_id"]],
        execution_boundary="evidence-grounded-output",
        model_route=route("reporter"),
    )
    tasks.extend([hypothesis, verify, report])
    scope["status"] = "ready"
    graph = {
        "schema": 1,
        "kind": "mt-agent-graph",
        "graph_id": graph_id,
        "target": target,
        "objective": objective,
        "authorization_confirmed": True,
        "scope_validated": True,
        "capabilities": sorted(selected or {"network_scan"}),
        "sensitivity": sensitivity,
        "created_at": created_at,
        "updated_at": created_at,
        "tasks": tasks,
        "history": [],
        "summary": {
            "task_count": len(tasks),
            "statuses": {"pending": len(tasks) - 1, "ready": 1},
            "terminal": False,
            "blocked_by_rejection": False,
        },
        "guardrails": [
            "The graph does not execute tools or model calls.",
            "Every executor must re-check authorization, target scope, and approval.",
            "Candidates require deterministic proof verification before reporting.",
            "High-impact actions remain outside autonomous graph transitions.",
        ],
    }
    return _with_hash(graph, integrity_key)


def _validate_graph(graph: Mapping[str, Any]) -> list[dict[str, Any]]:
    if graph.get("kind") != "mt-agent-graph" or graph.get("schema") != 1:
        raise AgentGraphPolicyError("unsupported agent graph schema")
    tasks = graph.get("tasks")
    if not isinstance(tasks, list) or not tasks or len(tasks) > 30:
        raise AgentGraphPolicyError("agent graph must contain 1..30 tasks")
    ids = [str(item.get("task_id") or "") for item in tasks if isinstance(item, Mapping)]
    if len(ids) != len(tasks) or len(set(ids)) != len(ids) or not all(ids):
        raise AgentGraphPolicyError("agent graph task identifiers are invalid")
    known = set(ids)
    valid_statuses = {"pending", "ready", "running", "completed", "rejected", "skipped"}
    for item in tasks:
        if item.get("status") not in valid_statuses:
            raise AgentGraphPolicyError("agent graph has an invalid task status")
        dependencies = item.get("dependencies")
        if not isinstance(dependencies, list) or not set(dependencies).issubset(known):
            raise AgentGraphPolicyError("agent graph has an invalid dependency")
        if item.get("task_id") in dependencies:
            raise AgentGraphPolicyError("agent graph task cannot depend on itself")
    visiting: set[str] = set()
    visited: set[str] = set()
    dependencies_by_id = {
        item["task_id"]: set(item["dependencies"])
        for item in tasks
    }

    def visit(node: str) -> None:
        if node in visiting:
            raise AgentGraphPolicyError("agent graph dependency cycle detected")
        if node in visited:
            return
        visiting.add(node)
        for dependency in dependencies_by_id[node]:
            visit(dependency)
        visiting.remove(node)
        visited.add(node)

    for node in known:
        visit(node)
    return tasks


def transition_engagement_graph(
    graph: Mapping[str, Any],
    task_id: str,
    event: str,
    *,
    integrity_key: str,
    evidence_refs: Optional[Sequence[str]] = None,
    result: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    if not isinstance(integrity_key, str) or len(integrity_key) < 16:
        raise AgentGraphPolicyError("agent graph integrity key is not configured")
    _verify_hash(graph, integrity_key)
    updated = copy.deepcopy(dict(graph))
    tasks = _validate_graph(updated)
    event = str(event or "").strip().lower()
    if event not in _EVENTS:
        raise AgentGraphPolicyError("event must be start, complete, reject, or skip")
    task = next((item for item in tasks if item["task_id"] == task_id), None)
    if task is None:
        raise AgentGraphPolicyError("unknown agent graph task")
    status = task.get("status")
    if status in _TERMINAL:
        raise AgentGraphPolicyError("terminal task cannot transition again")
    if event == "start":
        if status != "ready":
            raise AgentGraphPolicyError("only a ready task can start")
        task["status"] = "running"
    elif event == "complete":
        if status != "running":
            raise AgentGraphPolicyError("only a running task can complete")
        refs = [
            str(item)[:500]
            for item in (evidence_refs or [])
            if str(item).strip()
        ][:100]
        clean_result = _sanitize(dict(result or {}))
        if task.get("task_type") == "proof-verification":
            proof_status = str(clean_result.get("proof_status") or "").lower()
            if proof_status not in {"confirmed", "rejected"} or not refs:
                raise AgentGraphPolicyError(
                    "proof-verification completion requires confirmed/rejected "
                    "proof_status and an evidence reference"
                )
        task["status"] = "completed"
        task["evidence_refs"] = refs
        task["result"] = clean_result
    elif event == "reject":
        if status not in {"ready", "running"}:
            raise AgentGraphPolicyError("only a ready or running task can reject")
        task["status"] = "rejected"
        task["result"] = _sanitize(dict(result or {}))
    else:
        if status not in {"ready", "running"}:
            raise AgentGraphPolicyError("only a ready or running task can skip")
        if not task.get("optional"):
            raise AgentGraphPolicyError("required agent graph tasks cannot be skipped")
        task["status"] = "skipped"
        task["result"] = _sanitize(dict(result or {}))

    completed = {
        item["task_id"]
        for item in tasks
        if item.get("status") in {"completed", "skipped"}
    }
    for item in tasks:
        if item.get("status") == "pending" and set(item["dependencies"]).issubset(completed):
            item["status"] = "ready"

    timestamp = _now()
    updated["updated_at"] = timestamp
    history = list(updated.get("history") or [])[-199:]
    history.append({
        "timestamp": timestamp,
        "task_id": task_id,
        "event": event,
        "status": task["status"],
    })
    updated["history"] = history
    statuses: dict[str, int] = {}
    for item in tasks:
        statuses[item["status"]] = statuses.get(item["status"], 0) + 1
    updated["summary"] = {
        "task_count": len(tasks),
        "statuses": statuses,
        "terminal": all(item["status"] in _TERMINAL for item in tasks),
        "blocked_by_rejection": any(item["status"] == "rejected" for item in tasks),
    }
    return _with_hash(updated, integrity_key)
