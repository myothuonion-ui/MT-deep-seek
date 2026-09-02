"""Evidence bundle, contract planner, and benchmark-metric regression tests."""

import hashlib
import json

from benchmarks.metrics import summarize_proof_bundles
from core.api_contracts import ContractPolicyError, plan_contract
from core.proof_verifier import ProofPolicyError, evaluate_finding


def _observation(kind, outcome="supports", run_id="run-1"):
    return {
        "kind": kind,
        "outcome": outcome,
        "run_id": run_id,
        "source": "fixture",
        "summary": "bounded fixture evidence",
        "evidence_refs": ["artifact://fixture"],
    }


def _must_raise(error_type, callback):
    try:
        callback()
    except error_type:
        return
    raise AssertionError(f"expected {error_type.__name__}")


def test_proof_verifier_requires_explicit_authorization():
    _must_raise(
        ProofPolicyError,
        lambda: evaluate_finding(
            {"finding_id": "F-1", "severity": "low"},
            [],
            authorization_confirmed=False,
        ),
    )


def test_proof_verifier_fails_closed_when_controls_are_missing():
    bundle = evaluate_finding(
        {"finding_id": "F-2", "severity": "high", "name": "Fixture"},
        [_observation("reproduction")],
        authorization_confirmed=True,
    )
    assert bundle["status"] == "reproduced"
    assert "supporting negative control" in bundle["missing_requirements"]
    assert "independent confirmation" in bundle["missing_requirements"]


def test_proof_verifier_confirms_low_risk_with_reproduction_and_control():
    bundle = evaluate_finding(
        {"finding_id": "F-3", "severity": "medium", "name": "Fixture"},
        [
            _observation("reproduction", run_id="repro-1"),
            _observation("negative_control", run_id="control-1"),
        ],
        [{
            "adapter": "http",
            "action": "replay",
            "target": "https://lab.example/items/1",
            "argv": ["--token", "must-not-leak", "--method", "GET"],
            "expected": "controlled fixture response",
        }],
        authorization_confirmed=True,
    )
    assert bundle["status"] == "confirmed"
    assert bundle["replay_plan"][0]["argv"][1] == "[REDACTED]"
    assert bundle["replay_plan"][0]["execution"] == "not-executed"
    assert bundle["bundle_id"].startswith("proof-")
    assert len(bundle["content_sha256"]) == hashlib.sha256().digest_size * 2


def test_proof_verifier_requires_independent_high_risk_confirmation():
    observations = [
        _observation("reproduction", run_id="repro-1"),
        _observation("negative_control", run_id="control-1"),
        _observation("independent_confirmation", run_id="second-tool"),
    ]
    bundle = evaluate_finding(
        {"finding_id": "F-4", "severity": "critical"},
        observations,
        authorization_confirmed=True,
    )
    assert bundle["status"] == "confirmed"
    assert bundle["confidence"] >= 0.98


def test_proof_verifier_refutation_overrides_support():
    bundle = evaluate_finding(
        {"finding_id": "F-5", "severity": "low"},
        [
            _observation("reproduction", run_id="run-1"),
            _observation("negative_control", run_id="control"),
            _observation("refutation", outcome="refutes", run_id="run-2"),
        ],
        authorization_confirmed=True,
    )
    assert bundle["status"] == "rejected"
    assert bundle["confidence"] < 0.1


def _openapi_fixture():
    return {
        "openapi": "3.1.0",
        "security": [{"bearerAuth": []}],
        "paths": {
            "/users/{userId}": {
                "get": {
                    "operationId": "getUser",
                    "parameters": [{
                        "name": "userId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }],
                }
            },
            "/health": {"get": {"operationId": "health", "security": []}},
        },
    }


def test_openapi_planner_creates_authorization_matrix_without_execution():
    plan = plan_contract(
        _openapi_fixture(),
        "https://api.example.test/v1",
        authorization_confirmed=True,
        allowlist="api.example.test",
    )
    assert plan["kind"] == "openapi"
    assert plan["operation_count"] == 2
    assert any(
        item["kind"] == "authorization-object-matrix"
        and item["operation_id"] == "getUser"
        for item in plan["test_intents"]
    )
    assert all(item["execution"] == "not-executed" for item in plan["test_intents"])
    assert len(plan["spec_sha256"]) == 64


def test_contract_planner_accepts_safe_yaml_and_rejects_out_of_scope():
    yaml_spec = """
openapi: 3.0.3
paths:
  /items:
    get:
      operationId: listItems
"""
    plan = plan_contract(
        yaml_spec,
        "http://lab.example",
        authorization_confirmed=True,
        allowlist="*.example",
    )
    assert plan["operation_count"] == 1
    _must_raise(
        ContractPolicyError,
        lambda: plan_contract(
            yaml_spec,
            "https://outside.invalid",
            authorization_confirmed=True,
            allowlist="*.example",
        ),
    )


def test_graphql_planner_builds_field_access_intents():
    schema = {
        "data": {
            "__schema": {
                "types": [
                    {"name": "Query", "fields": [{"name": "viewer"}]},
                    {"name": "Mutation", "fields": [{"name": "updateProfile"}]},
                ]
            }
        }
    }
    plan = plan_contract(
        schema,
        "https://graphql.example.test/graphql",
        kind="graphql",
        authorization_confirmed=True,
        allowlist="graphql.example.test",
    )
    assert plan["field_count"] == 2
    assert any(item["risk"] == "medium" for item in plan["test_intents"])


def test_proof_metrics_compute_precision_recall_and_evidence_coverage():
    confirmed = evaluate_finding(
        {"finding_id": "real", "severity": "low"},
        [_observation("reproduction"), _observation("negative_control")],
        [{"adapter": "http", "action": "replay", "argv": []}],
        authorization_confirmed=True,
    )
    rejected = evaluate_finding(
        {"finding_id": "safe", "severity": "low"},
        [_observation("refutation", outcome="refutes")],
        authorization_confirmed=True,
    )
    metrics = summarize_proof_bundles(
        [confirmed, rejected],
        ground_truth={"real": True, "safe": False},
    )
    assert metrics["confirmation_rate"] == 0.5
    assert metrics["negative_control_coverage"] == 0.5
    assert metrics["ground_truth"]["precision"] == 1.0
    assert metrics["ground_truth"]["recall"] == 1.0
    assert json.dumps(metrics)

