import json
import os
import tempfile
from pathlib import Path
import pytest

from adapters.base import AdapterPolicyError
from adapters.playwright_browser import PlaywrightBrowserAdapter
from core.code_intelligence import (
    CodeIntelligencePolicyError,
    analyze_source_bundle,
)
from core.evidence_graph import EvidenceGraph, EvidenceGraphError


def test_browser_adapter_is_runtime_detected_and_never_auto_installs():
    status = PlaywrightBrowserAdapter().status()
    assert status["available"] in {True, False}
    assert status["installed"] in {True, False}
    assert status["auto_install"] is False
    assert status["arbitrary_javascript"] is False
    assert status["downloads"] is False
    if status["available"]:
        assert status["installed_version"] == "1.62.0"


def test_browser_actions_require_authorization_scope_and_second_confirmation():
    adapter = PlaywrightBrowserAdapter()
    with pytest.raises(AdapterPolicyError, match="authorization"):
        adapter.validate_actions(
            "https://app.example.test",
            [],
            authorization_confirmed=False,
            interactive_actions_confirmed=False,
            allowlist="*.example.test",
        )
    with pytest.raises(AdapterPolicyError, match="outside SCOPE_ALLOWLIST"):
        adapter.validate_actions(
            "https://outside.invalid",
            [],
            authorization_confirmed=True,
            interactive_actions_confirmed=False,
            allowlist="*.example.test",
        )
    with pytest.raises(AdapterPolicyError, match="interactive_actions_confirmed"):
        adapter.validate_actions(
            "https://app.example.test",
            [{"action": "fill", "selector": "#email", "value": "private"}],
            authorization_confirmed=True,
            interactive_actions_confirmed=False,
            allowlist="*.example.test",
        )


def test_browser_navigation_is_individually_scope_checked():
    adapter = PlaywrightBrowserAdapter()
    with pytest.raises(AdapterPolicyError, match="outside SCOPE_ALLOWLIST"):
        adapter.validate_actions(
            "https://app.example.test",
            [{"action": "navigate", "url": "https://outside.invalid/"}],
            authorization_confirmed=True,
            interactive_actions_confirmed=False,
            allowlist="*.example.test",
        )
    actions = adapter.validate_actions(
        "https://app.example.test",
        [
            {"action": "navigate", "url": "https://api.example.test/docs"},
            {"action": "screenshot", "label": "../../proof"},
            {"action": "capture"},
        ],
        authorization_confirmed=True,
        interactive_actions_confirmed=False,
        allowlist="*.example.test",
    )
    assert actions[0]["url"] == "https://api.example.test/docs"
    assert "/" not in actions[1]["label"]


def test_code_intelligence_maps_routes_and_only_emits_candidates():
    analysis = analyze_source_bundle(
        {
            "open.py": (
                '@app.get("/open")\n'
                "def open_route():\n"
                "    token=do-not-store; os.system(request.args['cmd'])\n"
            ),
            "guarded.py": (
                '@app.post("/guarded")\n'
                "def guarded_route(current_user=Depends(require_user)):\n"
                "    return {'ok': True}\n"
            ),
        }
    )
    assert analysis["summary"]["files_analyzed"] == 2
    assert analysis["summary"]["routes_mapped"] == 2
    assert all(item["status"] == "candidate" for item in analysis["candidates"])
    assert not any(
        item["rule_id"] == "route-without-nearby-auth-signal"
        and item["file"] == "guarded.py"
        for item in analysis["candidates"]
    )
    assert any(
        item["rule_id"] == "python-os-system"
        for item in analysis["candidates"]
    )
    encoded = json.dumps(analysis)
    assert "do-not-store" not in encoded
    assert "[REDACTED]" in encoded
    assert "Candidates are not vulnerabilities" in encoded


def test_code_intelligence_rejects_traversal_and_oversized_files():
    with pytest.raises(CodeIntelligencePolicyError, match="traversal-free"):
        analyze_source_bundle({"../secret.py": "print('no')"})
    with pytest.raises(CodeIntelligencePolicyError, match="exceeds"):
        analyze_source_bundle({"large.py": "x" * 500_001})


def test_evidence_graph_redacts_secrets_links_nodes_and_checkpoints():
    tmp_path = Path(tempfile.mkdtemp(prefix="mt-evidence-test-"))
    path = tmp_path / "evidence.db"
    graph = EvidenceGraph(path)
    target = graph.add_node(
        "target",
        "app.example.test",
        {"host": "app.example.test", "api_key": "must-not-persist"},
        {"source": "test", "authorization": "must-not-persist"},
    )
    observation = graph.add_node(
        "observation",
        "obs-1",
        {"status": 200},
        {"source": "test"},
    )
    edge = graph.add_edge(observation, target, "observed_on")
    checkpoint = graph.checkpoint(
        "engagement-1",
        "mapped",
        {"next": "verify", "cookie": "must-not-persist"},
    )

    assert target.startswith("node-")
    assert edge.startswith("edge-")
    assert checkpoint.startswith("checkpoint-")
    assert graph.get_node(target)["payload"]["api_key"] == "[REDACTED]"
    assert graph.get_node(target)["provenance"]["authorization"] == "[REDACTED]"
    assert graph.latest_checkpoint("engagement-1")["state"]["cookie"] == "[REDACTED]"
    assert graph.stats() == {
        "nodes": {"observation": 1, "target": 1},
        "node_count": 2,
        "edge_count": 1,
        "checkpoint_count": 1,
    }
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert "must-not-persist" not in path.read_bytes().decode("latin-1")

    with pytest.raises(EvidenceGraphError, match="unsupported relation"):
        graph.add_edge(observation, target, "owns")


def test_evidence_graph_records_proof_and_code_provenance():
    tmp_path = Path(tempfile.mkdtemp(prefix="mt-proof-graph-test-"))
    graph = EvidenceGraph(tmp_path / "graph.db")
    refs = graph.record_proof_bundle(
        {
            "schema": 1,
            "bundle_id": "proof-1",
            "finding_id": "finding-1",
            "finding": {"title": "Candidate"},
            "status": "confirmed",
        }
    )
    code_node = graph.record_code_analysis(
        {"schema": 1, "analysis_id": "code-1", "summary": {"routes_mapped": 2}}
    )
    assert refs["finding_node_id"].startswith("node-")
    assert refs["proof_node_id"].startswith("node-")
    assert graph.get_node(code_node)["provenance"]["source"] == "code-intelligence"
    assert graph.stats()["edge_count"] == 1


def test_evidence_graph_records_redacted_browser_provenance():
    tmp_path = Path(tempfile.mkdtemp(prefix="mt-browser-graph-test-"))
    graph = EvidenceGraph(tmp_path / "browser.db")
    refs = graph.record_browser_run(
        "https://app.example.test",
        {
            "adapter": "playwright-browser",
            "status": "completed",
            "actions": [
                {"step": 1, "action": "fill", "value": "[REDACTED]"},
                {"step": 2, "action": "capture", "success": True},
            ],
            "policy": {"authorization_confirmed": True},
            "observations": [{"kind": "browser-state", "title": "Home"}],
            "artifacts": [{"kind": "screenshot", "sha256": "abc123", "size_bytes": 12}],
        },
    )
    assert refs["target_node_id"].startswith("node-")
    assert len(refs["observation_node_ids"]) == 1
    assert len(refs["artifact_node_ids"]) == 1
    assert graph.stats()["nodes"]["agent_task"] == 1
    assert graph.stats()["edge_count"] == 4
