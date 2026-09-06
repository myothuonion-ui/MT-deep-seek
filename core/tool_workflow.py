"""Typed native HTTP dispatch and a redacted, signed execution ledger.

Only the existing scoped transport executes requests. The ledger describes what
ran; a successful tool call is never itself proof of a vulnerability.
"""
from dataclasses import dataclass
import hashlib
import hmac
import json
import time
import uuid


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def seal(value, key):
    clean = {k: v for k, v in value.items() if k != "signature"}
    return {**clean, "signature": hmac.new(key, canonical(clean).encode(), hashlib.sha256).hexdigest()}


def authentic(value, key, job_id):
    if not isinstance(value, dict) or value.get("job_id") != job_id:
        return False
    signature = value.get("signature")
    return isinstance(signature, str) and hmac.compare_digest(signature, seal(value, key)["signature"])


@dataclass(frozen=True)
class HTTPToolRequest:
    job_id: str
    task_id: str
    url: str
    actor: str = "anonymous"
    tool: str = "mt-scoped-http"
    method: str = "GET"

    def __post_init__(self):
        if self.tool != "mt-scoped-http" or self.method != "GET":
            raise ValueError("Unsupported native tool request")
        if not all(isinstance(x, str) and x for x in (self.job_id, self.task_id, self.url, self.actor)):
            raise ValueError("Invalid native tool request")

    def record(self):
        return {**self.__dict__, "id": uuid.uuid4().hex, "state": "running",
                "started_at": time.time(), "finished_at": None, "evidence_refs": []}


class NativeToolRouter:
    def execute(self, request, transport, credentials=None):
        if not isinstance(request, HTTPToolRequest):
            raise ValueError("A typed HTTP tool request is required")
        return transport.get(request.url, credentials)


def project_graph(graph, bundle):
    """Idempotent projection of verified records; SQLite jobs remain authoritative."""
    job_id = bundle["job_id"]
    graph.clear_web_projection(job_id)
    prefix = "web:" + job_id + ":"
    target = graph.add_node("target", prefix + "target", {"url": bundle["target"], "job_id": job_id})
    calls, artifacts = {}, {}
    for call in bundle["tool_calls"]:
        if not call["integrity_valid"]:
            continue
        node = graph.add_node("agent_task", prefix + call["id"], call)
        graph.add_edge(node, target, "targets")
        calls[call["id"]] = node
    for artifact in bundle["artifacts"]:
        if not artifact["integrity_valid"]:
            continue
        node = graph.add_node("artifact", prefix + artifact["id"], artifact)
        graph.add_edge(node, target, "observed_on")
        if artifact.get("tool_call_id") in calls:
            graph.add_edge(node, calls[artifact["tool_call_id"]], "derived_from")
        for route in artifact.get("source_refs", []):
            source = graph.add_node("source_file", prefix + route["file"], {"path": route["file"]})
            endpoint = graph.add_node("endpoint", prefix + route["route_id"], route)
            graph.add_edge(source, endpoint, "declares")
            graph.add_edge(node, endpoint, "observed_on")
        artifacts[artifact["id"]] = node
    for finding in bundle["findings"]:
        node = graph.add_node("finding", prefix + finding["id"], finding)
        graph.add_edge(node, target, "observed_on")
        if finding["integrity_valid"]:
            for ref in finding["evidence_refs"]:
                if ref in artifacts:
                    graph.add_edge(artifacts[ref], node, "supports")
    return {"state": "synced", "tool_calls": len(calls), "artifacts": len(artifacts)}
