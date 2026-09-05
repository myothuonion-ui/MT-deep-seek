import copy
import importlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

from core.agent_graph import (
    AgentGraphPolicyError,
    create_engagement_graph,
    transition_engagement_graph,
)
from core.model_router import ModelRouter, ModelRoutingPolicyError
from core.evidence_graph import EvidenceGraph


_KEY = "test-agent-graph-integrity-key"


def _providers():
    return [
        {
            "code": "local",
            "kind": "ollama",
            "model": "local-sec",
            "privacy": "local",
            "configured": True,
        },
        {
            "code": "deepseek",
            "kind": "openai-compatible",
            "model": "cloud-sec",
            "privacy": "cloud",
            "configured": True,
        },
        {
            "code": "litellm",
            "kind": "openai-compatible",
            "model": "gateway-sec",
            "privacy": "gateway",
            "configured": False,
        },
    ]


def test_routing_disabled_preserves_active_provider_without_silent_switching():
    router = ModelRouter(_providers(), "deepseek")
    route = router.route("strategist", sensitivity="confidential")
    assert route["provider"] == "deepseek"
    assert route["route_source"] == "routing-disabled-active-provider"
    assert route["policy_enforced"] is False
    assert route["privacy_compatible"] is False
    assert route["credentials_exposed"] is False
    assert route["runtime_probed"] is False


def test_explicit_routes_and_privacy_policy_fail_closed():
    router = ModelRouter(
        _providers(),
        "deepseek",
        enabled=True,
        allowed_providers=["deepseek", "local"],
        explicit_routes={"strategist": "local"},
    )
    route = router.route("strategist", sensitivity="restricted")
    assert route["provider"] == "local"
    assert route["privacy_compatible"] is True

    unsafe = ModelRouter(
        _providers(),
        "local",
        enabled=True,
        allowed_providers=["deepseek", "local"],
        explicit_routes={"strategist": "deepseek"},
    )
    with pytest.raises(ModelRoutingPolicyError, match="violates policy"):
        unsafe.route("strategist", sensitivity="confidential")


def test_auto_router_can_choose_an_independent_configured_verifier():
    router = ModelRouter(
        _providers(),
        "deepseek",
        enabled=True,
        auto_select=True,
        allowed_providers=["deepseek", "local"],
    )
    route = router.route(
        "verifier",
        sensitivity="standard",
        independent_of="deepseek",
    )
    assert route["provider"] == "local"
    assert route["independent"] is True
    assert route["route_source"] == "independent-verifier-auto-route"
    assert "api_key" not in json.dumps(router.public_status()).lower()


def test_agent_graph_is_scoped_dependency_aware_and_hmac_protected():
    router = ModelRouter(_providers(), "local")
    with pytest.raises(AgentGraphPolicyError, match="authorization"):
        create_engagement_graph(
            "https://app.example.test",
            "Map and verify",
            authorization_confirmed=False,
            allowlist="*.example.test",
            integrity_key=_KEY,
        )
    with pytest.raises(AgentGraphPolicyError, match="outside SCOPE_ALLOWLIST"):
        create_engagement_graph(
            "https://outside.invalid",
            "Map and verify",
            authorization_confirmed=True,
            allowlist="*.example.test",
            integrity_key=_KEY,
        )

    graph = create_engagement_graph(
        "https://app.example.test/root?token=must-not-persist",
        "Map and verify authorized attack surface",
        authorization_confirmed=True,
        allowlist="*.example.test",
        integrity_key=_KEY,
        capabilities=["network_scan", "api_contracts", "whitebox", "browser"],
        model_router=router,
    )
    assert graph["target"] == "https://app.example.test/root"
    assert "must-not-persist" not in json.dumps(graph)
    assert graph["graph_hmac_sha256"]
    assert [item["status"] for item in graph["tasks"]].count("ready") == 1

    tampered = copy.deepcopy(graph)
    tampered["objective"] = "tampered"
    with pytest.raises(AgentGraphPolicyError, match="integrity"):
        transition_engagement_graph(
            tampered,
            graph["tasks"][0]["task_id"],
            "start",
            integrity_key=_KEY,
        )


def test_agent_graph_requires_dependencies_and_proof_evidence():
    graph = create_engagement_graph(
        "app.example.test",
        "Map, hypothesize, verify, report",
        authorization_confirmed=True,
        allowlist="*.example.test",
        integrity_key=_KEY,
        capabilities=["network_scan", "api_contracts", "whitebox", "browser"],
    )
    by_slug = {item["slug"]: item["task_id"] for item in graph["tasks"]}
    with pytest.raises(AgentGraphPolicyError, match="ready task"):
        transition_engagement_graph(
            graph, by_slug["hypothesis"], "start", integrity_key=_KEY
        )

    graph = transition_engagement_graph(
        graph, by_slug["scope-policy"], "start", integrity_key=_KEY
    )
    graph = transition_engagement_graph(
        graph, by_slug["scope-policy"], "complete", integrity_key=_KEY
    )
    statuses = {item["slug"]: item["status"] for item in graph["tasks"]}
    assert statuses["surface-map"] == "ready"
    assert statuses["api-contract-map"] == "ready"

    for slug in ("api-contract-map", "whitebox-map", "browser-observe"):
        graph = transition_engagement_graph(
            graph, by_slug[slug], "skip", integrity_key=_KEY
        )
    graph = transition_engagement_graph(
        graph, by_slug["surface-map"], "start", integrity_key=_KEY
    )
    graph = transition_engagement_graph(
        graph,
        by_slug["surface-map"],
        "complete",
        integrity_key=_KEY,
        evidence_refs=["node-surface"],
    )
    graph = transition_engagement_graph(
        graph, by_slug["hypothesis"], "start", integrity_key=_KEY
    )
    graph = transition_engagement_graph(
        graph,
        by_slug["hypothesis"],
        "complete",
        integrity_key=_KEY,
        result={"candidate": "review", "password": "must-not-persist"},
    )
    hypothesis = next(item for item in graph["tasks"] if item["slug"] == "hypothesis")
    assert hypothesis["result"]["password"] == "[REDACTED]"

    graph = transition_engagement_graph(
        graph, by_slug["proof-verification"], "start", integrity_key=_KEY
    )
    with pytest.raises(AgentGraphPolicyError, match="evidence reference"):
        transition_engagement_graph(
            graph,
            by_slug["proof-verification"],
            "complete",
            integrity_key=_KEY,
            result={"proof_status": "confirmed"},
        )
    graph = transition_engagement_graph(
        graph,
        by_slug["proof-verification"],
        "complete",
        integrity_key=_KEY,
        evidence_refs=["node-proof"],
        result={"proof_status": "confirmed"},
    )
    assert next(
        item for item in graph["tasks"] if item["slug"] == "report"
    )["status"] == "ready"


def test_agent_graph_persists_task_dependencies_and_checkpoint():
    graph = create_engagement_graph(
        "app.example.test",
        "Persist a bounded engagement plan",
        authorization_confirmed=True,
        allowlist="*.example.test",
        integrity_key=_KEY,
        capabilities=["network_scan", "whitebox"],
    )
    path = Path(tempfile.mkdtemp(prefix="mt-agent-graph-test-")) / "graph.db"
    evidence = EvidenceGraph(path)
    refs = evidence.record_agent_graph(graph)
    assert refs["graph_node_id"].startswith("node-")
    assert len(refs["task_node_ids"]) == len(graph["tasks"])
    assert refs["checkpoint_id"].startswith("checkpoint-")
    stats = evidence.stats()
    assert stats["nodes"]["agent_graph"] == 1
    assert stats["nodes"]["agent_task"] == len(graph["tasks"])
    assert stats["checkpoint_count"] == 1


def test_orchestrator_default_routing_keeps_existing_connector():
    # The repository's lightweight helper uses the legacy "api" alias. Default
    # routing must normalize that alias without constructing another connector.
    from tests._helpers import make_orch

    orch = make_orch(provider="api")
    connector, route = orch._connector_for_role("strategist")
    assert connector is orch.ai_connector
    assert route["provider"] == "deepseek"
    assert route["routing_enabled"] is False


def test_agent_graph_and_model_route_apis_are_authenticated():
    root = Path(tempfile.mkdtemp(prefix="mt-agent-api-test-"))
    environment = {
        "API_AUTH_TOKEN": "agent-api-test-token-with-entropy",
        "AGENT_GRAPH_SIGNING_KEY": "agent-graph-signing-key-test",
        "DB_PATH": str(root / "mt_pentester.db"),
        "EVIDENCE_GRAPH_PATH": str(root / "evidence.db"),
        "LOG_FILE": str(root / "mt_pentester.log"),
        "SCOPE_ALLOWLIST": "*.example.test",
        "ALLOW_UNSCOPED_TARGETS": "false",
        "AI_PROVIDER": "local",
        "MODEL_ROUTING_ENABLED": "false",
        "PATH": f"{root}{os.pathsep}{os.environ.get('PATH', os.defpath)}",
    }
    previous = {key: os.environ.get(key) for key in environment}
    try:
        fake_nmap = root / "nmap"
        fake_nmap.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' 'Nmap version 7.94 ( https://nmap.org )'\n",
            encoding="utf-8",
        )
        fake_nmap.chmod(0o700)
        os.environ.update(environment)
        sys.modules.pop("main", None)
        backend = importlib.import_module("main")
        from fastapi.testclient import TestClient

        client = TestClient(backend.app)
        assert client.get("/api/model-routing/status").status_code == 401
        headers = {"X-API-Key": environment["API_AUTH_TOKEN"]}
        status = client.get("/api/model-routing/status", headers=headers)
        assert status.status_code == 200
        assert status.json()["credentials_exposed"] is False

        # Exercise the new router through the actual application's auth boundary.
        assert client.get("/api/web-assessments").status_code == 401
        web = client.post("/api/web-assessments", headers=headers, json={
            "target": "https://app.example.test/", "authorization_confirmed": True,
        })
        assert web.status_code == 202
        web_id = web.json()["id"]
        assert web.json()["state"] == "queued"
        assert client.get(f"/api/web-assessments/{web_id}", headers=headers).status_code == 200
        assert client.get(f"/api/web-assessments/{web_id}/report", headers=headers).headers["content-type"].startswith("text/markdown")
        assert client.post(f"/api/web-assessments/{web_id}/retest", headers=headers).status_code == 409
        assert client.post(f"/api/web-assessments/{web_id}/cancel", headers=headers).json()["state"] == "cancelled"
        assert client.post(f"/api/web-assessments/{web_id}/resume", headers=headers).status_code == 400
        assert client.post(f"/api/web-assessments/{web_id}/retest", headers=headers).status_code == 202
        assert client.post("/api/web-assessments", headers=headers, json={
            "target": "https://outside.invalid/", "authorization_confirmed": True,
        }).status_code == 400
        untrusted = client.post("/api/verification/evaluate", headers=headers, json={
            "authorization_confirmed": True,
            "finding": {"severity": "critical"},
            "observations": [{"kind": kind, "outcome": "supports", "evidence_refs": ["invented"]}
                             for kind in ("reproduction", "negative_control", "independent_confirmation")],
            "require_independent_confirmation": False,
        })
        assert untrusted.status_code == 200
        assert untrusted.json()["status"] == "candidate"
        assert untrusted.json()["policy"]["require_independent_confirmation"] is True

        planned = client.post(
            "/api/agent-graphs/plan",
            headers=headers,
            json={
                "target": "https://app.example.test",
                "objective": "Map and verify",
                "authorization_confirmed": True,
                "capabilities": ["network_scan", "whitebox"],
            },
        )
        assert planned.status_code == 200
        graph = planned.json()
        scope_task = next(
            item for item in graph["tasks"] if item["slug"] == "scope-policy"
        )
        started = client.post(
            "/api/agent-graphs/transition",
            headers=headers,
            json={
                "graph": graph,
                "task_id": scope_task["task_id"],
                "event": "start",
            },
        )
        assert started.status_code == 200

        tampered = started.json()
        tampered["objective"] = "tampered"
        denied = client.post(
            "/api/agent-graphs/transition",
            headers=headers,
            json={
                "graph": tampered,
                "task_id": scope_task["task_id"],
                "event": "complete",
            },
        )
        assert denied.status_code == 400
        assert "integrity" in denied.json()["detail"]
    finally:
        sys.modules.pop("main", None)
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(root)

