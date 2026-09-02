"""Durable, local evidence graph with provenance and secret redaction."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional


_NODE_TYPES = {
    "target", "service", "endpoint", "finding", "observation",
    "proof_bundle", "artifact", "contract_plan", "code_analysis", "agent_task",
    "source_file",
}
_RELATIONS = {
    "has", "declares", "observed_on", "supports", "refutes", "proves",
    "derived_from", "targets", "planned_for", "depends_on",
}
_SENSITIVE = re.compile(
    r"(authorization|cookie|credential|password|secret|token|api[_-]?key)",
    re.IGNORECASE,
)


class EvidenceGraphError(ValueError):
    """Raised when graph data violates schema or relationship policy."""


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


def _json(value: Any) -> str:
    return json.dumps(_sanitize(value), sort_keys=True, separators=(",", ":"))


class EvidenceGraph:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS evidence_nodes (
                    node_id TEXT PRIMARY KEY,
                    node_type TEXT NOT NULL,
                    node_key TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    provenance_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(node_type, node_key)
                );
                CREATE TABLE IF NOT EXISTS evidence_edges (
                    edge_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(source_id, target_id, relation),
                    FOREIGN KEY(source_id) REFERENCES evidence_nodes(node_id),
                    FOREIGN KEY(target_id) REFERENCES evidence_nodes(node_id)
                );
                CREATE TABLE IF NOT EXISTS evidence_checkpoints (
                    checkpoint_id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    state_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_evidence_nodes_type
                    ON evidence_nodes(node_type);
                CREATE INDEX IF NOT EXISTS idx_evidence_edges_source
                    ON evidence_edges(source_id);
                CREATE INDEX IF NOT EXISTS idx_evidence_checkpoints_engagement
                    ON evidence_checkpoints(engagement_id, created_at);
                """
            )

    def add_node(
        self,
        node_type: str,
        node_key: str,
        payload: Mapping[str, Any],
        provenance: Optional[Mapping[str, Any]] = None,
    ) -> str:
        node_type = str(node_type).lower()
        node_key = str(node_key)[:1000]
        if node_type not in _NODE_TYPES:
            raise EvidenceGraphError(f"unsupported node type: {node_type!r}")
        if not node_key:
            raise EvidenceGraphError("node key is required")
        node_id = "node-" + hashlib.sha256(
            f"{node_type}:{node_key}".encode("utf-8")
        ).hexdigest()[:24]
        now = _now()
        with self._connect() as db:
            db.execute(
                """
                INSERT INTO evidence_nodes
                    (node_id,node_type,node_key,payload_json,provenance_json,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(node_id) DO UPDATE SET
                    payload_json=excluded.payload_json,
                    provenance_json=excluded.provenance_json,
                    updated_at=excluded.updated_at
                """,
                (
                    node_id, node_type, node_key, _json(payload),
                    _json(provenance or {}), now, now,
                ),
            )
        return node_id

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> str:
        relation = str(relation).lower()
        if relation not in _RELATIONS:
            raise EvidenceGraphError(f"unsupported relation: {relation!r}")
        with self._connect() as db:
            present = db.execute(
                "SELECT node_id FROM evidence_nodes WHERE node_id IN (?,?)",
                (source_id, target_id),
            ).fetchall()
            if len({row["node_id"] for row in present}) != 2:
                raise EvidenceGraphError("both edge nodes must exist")
            edge_id = "edge-" + hashlib.sha256(
                f"{source_id}:{relation}:{target_id}".encode("utf-8")
            ).hexdigest()[:24]
            db.execute(
                """
                INSERT INTO evidence_edges
                    (edge_id,source_id,target_id,relation,payload_json,created_at)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(edge_id) DO UPDATE SET payload_json=excluded.payload_json
                """,
                (edge_id, source_id, target_id, relation, _json(payload or {}), _now()),
            )
        return edge_id

    def checkpoint(
        self,
        engagement_id: str,
        stage: str,
        state: Mapping[str, Any],
    ) -> str:
        engagement_id = str(engagement_id)[:300]
        stage = str(stage)[:200]
        if not engagement_id or not stage:
            raise EvidenceGraphError("checkpoint engagement_id and stage are required")
        body = _json(state)
        checkpoint_id = "checkpoint-" + hashlib.sha256(
            f"{engagement_id}:{stage}:{body}:{_now()}".encode("utf-8")
        ).hexdigest()[:24]
        with self._connect() as db:
            db.execute(
                """
                INSERT INTO evidence_checkpoints
                    (checkpoint_id,engagement_id,stage,state_json,created_at)
                VALUES (?,?,?,?,?)
                """,
                (checkpoint_id, engagement_id, stage, body, _now()),
            )
        return checkpoint_id

    def latest_checkpoint(self, engagement_id: str) -> Optional[dict[str, Any]]:
        with self._connect() as db:
            row = db.execute(
                """
                SELECT checkpoint_id,engagement_id,stage,state_json,created_at
                FROM evidence_checkpoints
                WHERE engagement_id=?
                ORDER BY created_at DESC LIMIT 1
                """,
                (str(engagement_id)[:300],),
            ).fetchone()
        if not row:
            return None
        return {
            "checkpoint_id": row["checkpoint_id"],
            "engagement_id": row["engagement_id"],
            "stage": row["stage"],
            "state": json.loads(row["state_json"]),
            "created_at": row["created_at"],
        }

    def get_node(self, node_id: str) -> Optional[dict[str, Any]]:
        with self._connect() as db:
            row = db.execute(
                """
                SELECT node_id,node_type,node_key,payload_json,provenance_json,
                       created_at,updated_at
                FROM evidence_nodes WHERE node_id=?
                """,
                (node_id,),
            ).fetchone()
        if not row:
            return None
        return {
            "node_id": row["node_id"],
            "node_type": row["node_type"],
            "node_key": row["node_key"],
            "payload": json.loads(row["payload_json"]),
            "provenance": json.loads(row["provenance_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def stats(self) -> dict[str, Any]:
        with self._connect() as db:
            nodes = {
                row["node_type"]: row["count"]
                for row in db.execute(
                    "SELECT node_type,COUNT(*) AS count FROM evidence_nodes GROUP BY node_type"
                )
            }
            edge_count = db.execute(
                "SELECT COUNT(*) AS count FROM evidence_edges"
            ).fetchone()["count"]
            checkpoint_count = db.execute(
                "SELECT COUNT(*) AS count FROM evidence_checkpoints"
            ).fetchone()["count"]
        return {
            "nodes": nodes,
            "node_count": sum(nodes.values()),
            "edge_count": edge_count,
            "checkpoint_count": checkpoint_count,
        }

    def record_proof_bundle(self, bundle: Mapping[str, Any]) -> dict[str, str]:
        finding_id = str(bundle.get("finding_id") or "finding")[:300]
        finding_node = self.add_node(
            "finding", finding_id, bundle.get("finding") or {},
            {"source": "proof-verifier"},
        )
        proof_key = str(bundle.get("bundle_id") or bundle.get("content_sha256") or "proof")
        proof_node = self.add_node(
            "proof_bundle", proof_key, bundle,
            {"source": "proof-verifier", "schema": bundle.get("schema")},
        )
        relation = "proves" if bundle.get("status") == "confirmed" else (
            "refutes" if bundle.get("status") == "rejected" else "supports"
        )
        self.add_edge(proof_node, finding_node, relation)
        return {"finding_node_id": finding_node, "proof_node_id": proof_node}

    def record_contract_plan(self, plan: Mapping[str, Any]) -> str:
        plan_node = self.add_node(
            "contract_plan",
            str(plan.get("plan_id") or "contract"),
            plan,
            {"source": "api-contract-planner", "schema": plan.get("schema")},
        )
        base_url = str(plan.get("base_url") or "")[:2048]
        if base_url:
            target_node = self.add_node(
                "target",
                base_url,
                {"base_url": base_url},
                {"source": "api-contract-planner"},
            )
            self.add_edge(plan_node, target_node, "planned_for")
        return plan_node

    def record_code_analysis(self, analysis: Mapping[str, Any]) -> str:
        analysis_node = self.add_node(
            "code_analysis",
            str(analysis.get("analysis_id") or "analysis"),
            analysis,
            {"source": "code-intelligence", "schema": analysis.get("schema")},
        )
        file_nodes: dict[str, str] = {}
        for item in list(analysis.get("files") or [])[:300]:
            if not isinstance(item, Mapping):
                continue
            path = str(item.get("path") or "")[:1000]
            digest = str(item.get("sha256") or "")[:128]
            if not path:
                continue
            file_node = self.add_node(
                "source_file",
                f"{path}:{digest}",
                {"path": path, "sha256": digest, "bytes": item.get("bytes")},
                {"source": "code-intelligence"},
            )
            file_nodes[path] = file_node
            self.add_edge(analysis_node, file_node, "derived_from")
        for route in list(analysis.get("routes") or [])[:5000]:
            if not isinstance(route, Mapping):
                continue
            path = str(route.get("file") or "")[:1000]
            route_key = (
                f"{path}:{route.get('line')}:{route.get('method')}:{route.get('path')}"
            )
            endpoint_node = self.add_node(
                "endpoint",
                route_key,
                route,
                {"source": "code-intelligence"},
            )
            if path in file_nodes:
                self.add_edge(file_nodes[path], endpoint_node, "declares")
        return analysis_node

    def record_browser_run(
        self,
        target: str,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        target_key = str(target)[:2048]
        target_node = self.add_node(
            "target",
            target_key,
            {"target": target_key},
            {"source": "playwright-browser"},
        )
        run_key = hashlib.sha256(
            f"{target_key}:{_json(result.get('actions') or [])}:{_now()}".encode("utf-8")
        ).hexdigest()
        task_node = self.add_node(
            "agent_task",
            f"browser-{run_key}",
            {
                "adapter": result.get("adapter"),
                "status": result.get("status"),
                "actions": result.get("actions") or [],
                "policy": result.get("policy") or {},
            },
            {"source": "playwright-browser"},
        )
        self.add_edge(task_node, target_node, "targets")
        observation_nodes = []
        for index, observation in enumerate(list(result.get("observations") or [])[:500]):
            if not isinstance(observation, Mapping):
                continue
            key = hashlib.sha256(
                f"{run_key}:observation:{index}:{_json(observation)}".encode("utf-8")
            ).hexdigest()
            node = self.add_node(
                "observation",
                key,
                observation,
                {"source": "playwright-browser", "task_node_id": task_node},
            )
            self.add_edge(node, target_node, "observed_on")
            self.add_edge(node, task_node, "derived_from")
            observation_nodes.append(node)
        artifact_nodes = []
        for index, artifact in enumerate(list(result.get("artifacts") or [])[:100]):
            if not isinstance(artifact, Mapping):
                continue
            key = str(artifact.get("sha256") or f"{run_key}:artifact:{index}")
            node = self.add_node(
                "artifact",
                key,
                artifact,
                {"source": "playwright-browser", "task_node_id": task_node},
            )
            self.add_edge(node, task_node, "derived_from")
            artifact_nodes.append(node)
        return {
            "target_node_id": target_node,
            "task_node_id": task_node,
            "observation_node_ids": observation_nodes,
            "artifact_node_ids": artifact_nodes,
        }
