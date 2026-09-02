"""Read-only OpenAPI and GraphQL test-plan generation.

The planner performs no requests. It converts an authorized, in-scope contract
into typed test intents for a later policy-gated browser/API executor.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Optional
from urllib.parse import urlsplit

import yaml

from core.validators import is_target_in_scope


_MAX_SPEC_BYTES = 2_000_000
_MAX_OPERATIONS = 1000
_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head")
_OBJECT_HINTS = ("id", "uuid", "account", "order", "user", "tenant", "project")


class ContractPolicyError(ValueError):
    """Raised when contract planning violates authorization or scope policy."""


def _load_spec(spec: Any) -> Mapping[str, Any]:
    if isinstance(spec, Mapping):
        payload = dict(spec)
    elif isinstance(spec, str):
        if len(spec.encode("utf-8")) > _MAX_SPEC_BYTES:
            raise ContractPolicyError("contract exceeds the 2 MB size limit")
        try:
            payload = yaml.safe_load(spec)
        except yaml.YAMLError as exc:
            raise ContractPolicyError(f"invalid contract document: {exc}") from exc
    else:
        raise ContractPolicyError("contract must be an object or JSON/YAML string")
    if not isinstance(payload, Mapping):
        raise ContractPolicyError("contract root must be an object")
    return payload


def _authorize_base_url(
    base_url: str,
    authorization_confirmed: bool,
    allowlist: Optional[str],
) -> str:
    if not authorization_confirmed:
        raise ContractPolicyError("explicit authorization confirmation is required")
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ContractPolicyError("base_url must be an absolute HTTP(S) URL")
    if not is_target_in_scope(parsed.hostname, allowlist):
        raise ContractPolicyError(
            f"contract target '{parsed.hostname}' is outside SCOPE_ALLOWLIST"
        )
    return f"{parsed.scheme}://{parsed.netloc}"


def _plan_id(spec: Mapping[str, Any], base_url: str, kind: str) -> tuple[str, str]:
    encoded = json.dumps(
        spec, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    key = hashlib.sha256(f"{kind}:{base_url}:{digest}".encode("utf-8")).hexdigest()
    return f"contract-{key[:16]}", digest


def _object_parameters(path: str, operation: Mapping[str, Any]) -> list[str]:
    candidates = []
    for token in path.split("{")[1:]:
        name = token.split("}", 1)[0].strip()
        if name:
            candidates.append(name)
    for item in operation.get("parameters") or []:
        if isinstance(item, Mapping) and item.get("in") in {"path", "query"}:
            name = str(item.get("name", "")).strip()
            if name:
                candidates.append(name)
    return sorted({
        name for name in candidates
        if any(hint in name.lower() for hint in _OBJECT_HINTS)
    })


def plan_openapi(
    spec: Any,
    base_url: str,
    *,
    authorization_confirmed: bool,
    allowlist: Optional[str],
) -> dict[str, Any]:
    payload = _load_spec(spec)
    if "openapi" not in payload and "swagger" not in payload:
        raise ContractPolicyError("document is not an OpenAPI/Swagger contract")
    scoped_base = _authorize_base_url(base_url, authorization_confirmed, allowlist)
    paths = payload.get("paths")
    if not isinstance(paths, Mapping):
        raise ContractPolicyError("OpenAPI contract has no paths object")

    root_security = payload.get("security") or []
    operations: list[dict[str, Any]] = []
    intents: list[dict[str, Any]] = []
    for path, path_item in paths.items():
        if not isinstance(path_item, Mapping):
            continue
        for method in _HTTP_METHODS:
            operation = path_item.get(method)
            if not isinstance(operation, Mapping):
                continue
            if len(operations) >= _MAX_OPERATIONS:
                raise ContractPolicyError(
                    f"contract exceeds {_MAX_OPERATIONS} operations"
                )
            operation_id = str(operation.get("operationId") or f"{method}:{path}")
            security = operation.get("security", root_security)
            object_parameters = _object_parameters(str(path), operation)
            item = {
                "operation_id": operation_id[:300],
                "method": method.upper(),
                "path": str(path)[:2000],
                "security_required": bool(security),
                "object_parameters": object_parameters,
                "content_types": sorted(
                    str(key)[:200]
                    for key in (
                        (operation.get("requestBody") or {}).get("content") or {}
                    )
                )[:20],
            }
            operations.append(item)
            intents.append({
                "kind": "baseline",
                "operation_id": item["operation_id"],
                "method": item["method"],
                "path": item["path"],
                "risk": "low",
                "execution": "not-executed",
            })
            if item["security_required"]:
                intents.append({
                    "kind": "unauthenticated-control",
                    "operation_id": item["operation_id"],
                    "method": item["method"],
                    "path": item["path"],
                    "expected": "reject without credentials",
                    "risk": "low",
                    "execution": "not-executed",
                })
            if item["security_required"] and object_parameters:
                intents.append({
                    "kind": "authorization-object-matrix",
                    "operation_id": item["operation_id"],
                    "method": item["method"],
                    "path": item["path"],
                    "parameters": object_parameters,
                    "requirements": [
                        "two explicitly authorized test identities",
                        "owned and non-owned fixture objects",
                        "negative control before confirmation",
                    ],
                    "risk": "medium",
                    "execution": "not-executed",
                })

    plan_id, digest = _plan_id(payload, scoped_base, "openapi")
    return {
        "schema": 1,
        "kind": "openapi",
        "plan_id": plan_id,
        "spec_sha256": digest,
        "base_url": scoped_base,
        "operation_count": len(operations),
        "operations": operations,
        "test_intents": intents,
        "guardrails": [
            "Plan only; no network request was performed.",
            "Every future request must pass scope and typed-executor policy again.",
            "Authorization tests require controlled identities and negative controls.",
            "External $ref documents are not fetched automatically.",
        ],
    }


def plan_graphql(
    spec: Any,
    base_url: str,
    *,
    authorization_confirmed: bool,
    allowlist: Optional[str],
) -> dict[str, Any]:
    payload = _load_spec(spec)
    scoped_base = _authorize_base_url(base_url, authorization_confirmed, allowlist)
    schema = payload.get("data", payload)
    if isinstance(schema, Mapping):
        schema = schema.get("__schema", schema)
    if not isinstance(schema, Mapping) or not isinstance(schema.get("types"), list):
        raise ContractPolicyError("document is not a GraphQL introspection schema")

    fields: list[dict[str, str]] = []
    for type_item in schema["types"][:2000]:
        if not isinstance(type_item, Mapping):
            continue
        type_name = str(type_item.get("name", ""))
        if type_name not in {"Query", "Mutation"}:
            continue
        for field in (type_item.get("fields") or [])[:1000]:
            if isinstance(field, Mapping) and field.get("name"):
                fields.append({
                    "type": type_name.lower(),
                    "field": str(field["name"])[:300],
                })
    if len(fields) > _MAX_OPERATIONS:
        raise ContractPolicyError(
            f"GraphQL schema exceeds {_MAX_OPERATIONS} query/mutation fields"
        )

    intents = [{
        "kind": "graphql-field-access-matrix",
        "field_type": item["type"],
        "field": item["field"],
        "requirements": [
            "authorized test identity",
            "unauthenticated negative control",
            "second-role authorization control",
        ],
        "risk": "medium" if item["type"] == "mutation" else "low",
        "execution": "not-executed",
    } for item in fields]

    plan_id, digest = _plan_id(payload, scoped_base, "graphql")
    return {
        "schema": 1,
        "kind": "graphql",
        "plan_id": plan_id,
        "spec_sha256": digest,
        "base_url": scoped_base,
        "field_count": len(fields),
        "fields": fields,
        "test_intents": intents,
        "guardrails": [
            "Plan only; no GraphQL request or introspection was performed.",
            "Mutation intents require explicit review by the future executor.",
            "Every future request must pass scope and authorization policy again.",
        ],
    }


def plan_contract(
    spec: Any,
    base_url: str,
    *,
    kind: str = "auto",
    authorization_confirmed: bool,
    allowlist: Optional[str],
) -> dict[str, Any]:
    payload = _load_spec(spec)
    selected = kind.strip().lower()
    if selected == "auto":
        selected = "openapi" if ("openapi" in payload or "swagger" in payload) else "graphql"
    if selected == "openapi":
        return plan_openapi(
            payload,
            base_url,
            authorization_confirmed=authorization_confirmed,
            allowlist=allowlist,
        )
    if selected == "graphql":
        return plan_graphql(
            payload,
            base_url,
            authorization_confirmed=authorization_confirmed,
            allowlist=allowlist,
        )
    raise ContractPolicyError("kind must be auto, openapi, or graphql")

