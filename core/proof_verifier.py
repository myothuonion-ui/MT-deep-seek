"""Deterministic proof bundles for evidence-based vulnerability confirmation.

This module never executes a command. It evaluates bounded observations produced
by already-authorized tools and creates a replayable, redacted evidence bundle.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional, Sequence


_ALLOWED_KINDS = {
    "reproduction",
    "negative_control",
    "independent_confirmation",
    "refutation",
}
_ALLOWED_OUTCOMES = {"supports", "refutes", "inconclusive"}
_SENSITIVE_KEYS = re.compile(
    r"(authorization|cookie|credential|password|secret|token|api[_-]?key)",
    re.IGNORECASE,
)
_SENSITIVE_FLAGS = {
    "--api-key", "--authorization", "--cookie", "--header",
    "--password", "--proxy-password", "--token",
}
_MAX_OBSERVATIONS = 50
_MAX_REPLAY_STEPS = 30
_MAX_TEXT = 4000


class ProofPolicyError(ValueError):
    """Raised when a proof request violates a deterministic policy boundary."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bounded_text(value: Any, limit: int = _MAX_TEXT) -> str:
    return str(value or "")[:limit]


def _redact(value: Any, key: str = "") -> Any:
    if _SENSITIVE_KEYS.search(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {
            _bounded_text(k, 100): _redact(v, str(k))
            for k, v in list(value.items())[:100]
        }
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in list(value)[:200]]
    if isinstance(value, str):
        return _bounded_text(value)
    if isinstance(value, (bool, int, float)) or value is None:
        return value
    return _bounded_text(value)


def _redact_argv(argv: Sequence[Any]) -> list[str]:
    clean: list[str] = []
    hide_next = False
    for raw in list(argv)[:200]:
        token = _bounded_text(raw, 1000)
        lower = token.lower()
        if hide_next:
            clean.append("[REDACTED]")
            hide_next = False
            continue
        if "=" in token:
            flag, _value = token.split("=", 1)
            if flag.lower() in _SENSITIVE_FLAGS:
                clean.append(f"{flag}=[REDACTED]")
                continue
        clean.append(token)
        if lower in _SENSITIVE_FLAGS:
            hide_next = True
    return clean


def _canonical(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _normalize_observation(raw: Mapping[str, Any], index: int) -> dict[str, Any]:
    kind = _bounded_text(raw.get("kind"), 50).lower()
    outcome = _bounded_text(raw.get("outcome"), 50).lower()
    if kind not in _ALLOWED_KINDS:
        raise ProofPolicyError(f"observation {index} has unsupported kind: {kind!r}")
    if outcome not in _ALLOWED_OUTCOMES:
        raise ProofPolicyError(f"observation {index} has unsupported outcome: {outcome!r}")

    evidence_refs = raw.get("evidence_refs") or []
    if not isinstance(evidence_refs, (list, tuple)):
        raise ProofPolicyError(f"observation {index} evidence_refs must be a list")

    return {
        "kind": kind,
        "outcome": outcome,
        "source": _bounded_text(raw.get("source"), 200),
        "run_id": _bounded_text(raw.get("run_id") or f"run-{index}", 200),
        "timestamp": _bounded_text(raw.get("timestamp") or _utc_now(), 100),
        "summary": _bounded_text(raw.get("summary")),
        "evidence_refs": [_bounded_text(item, 1000) for item in evidence_refs[:50]],
        "environment_fingerprint": _bounded_text(
            raw.get("environment_fingerprint"), 500
        ),
    }


def _normalize_replay_step(raw: Mapping[str, Any], index: int) -> dict[str, Any]:
    action = _bounded_text(raw.get("action"), 100)
    adapter = _bounded_text(raw.get("adapter"), 100)
    if not action or not adapter:
        raise ProofPolicyError(
            f"replay step {index} requires typed adapter and action fields"
        )
    argv = raw.get("argv") or []
    if not isinstance(argv, (list, tuple)):
        raise ProofPolicyError(f"replay step {index} argv must be a list")
    return {
        "step": index,
        "adapter": adapter,
        "action": action,
        "target": _bounded_text(raw.get("target"), 2048),
        "argv": _redact_argv(argv),
        "expected": _bounded_text(raw.get("expected"), 2000),
        "requires_authorization": True,
        "execution": "not-executed",
    }


def evaluate_finding(
    finding: Mapping[str, Any],
    observations: Sequence[Mapping[str, Any]],
    replay_steps: Sequence[Mapping[str, Any]] = (),
    *,
    authorization_confirmed: bool,
    require_negative_control: bool = True,
    require_independent_confirmation: Optional[bool] = None,
    evidence_validator: Optional[Callable[[Mapping[str, Any]], bool]] = None,
) -> dict[str, Any]:
    """Evaluate observations and return a hashed, redacted proof bundle.

    A high/critical finding always requires independent confirmation. An
    internal executor must supply evidence_validator to resolve and authenticate
    artifacts bound to each observation. API-submitted labels alone are never
    proof. Authorization is mandatory even though this function performs no
    network or subprocess activity.
    """
    if not authorization_confirmed:
        raise ProofPolicyError("explicit authorization confirmation is required")
    if not isinstance(finding, Mapping):
        raise ProofPolicyError("finding must be an object")
    if len(observations) > _MAX_OBSERVATIONS:
        raise ProofPolicyError(f"at most {_MAX_OBSERVATIONS} observations are allowed")
    if len(replay_steps) > _MAX_REPLAY_STEPS:
        raise ProofPolicyError(f"at most {_MAX_REPLAY_STEPS} replay steps are allowed")

    normalized = [
        _normalize_observation(item, index + 1)
        for index, item in enumerate(observations)
    ]
    replay = [
        _normalize_replay_step(item, index + 1)
        for index, item in enumerate(replay_steps)
    ]

    severity = _bounded_text(finding.get("severity") or finding.get("risk_level"), 30).lower()
    # A caller can strengthen policy but cannot disable the high/critical floor.
    require_independent_confirmation = (
        severity in {"high", "critical"} or bool(require_independent_confirmation)
    )
    trusted = []
    for item in normalized:
        try:
            valid = bool(item["evidence_refs"] and evidence_validator and evidence_validator(item))
        except Exception:
            valid = False
        if valid:
            trusted.append(item)

    supports_reproduction = {
        item["run_id"] for item in trusted
        if item["kind"] == "reproduction" and item["outcome"] == "supports"
    }
    supports_control = any(
        item["kind"] == "negative_control" and item["outcome"] == "supports"
        for item in trusted
    )
    supports_independent = any(
        item["kind"] == "independent_confirmation" and item["outcome"] == "supports"
        and bool(item["source"])
        and all(item["run_id"] != other["run_id"] and item["source"] != other["source"]
                for other in trusted if other["kind"] == "reproduction")
        for item in trusted
    )
    refuted = any(
        item["outcome"] == "refutes"
        and item["kind"] in {"reproduction", "independent_confirmation", "refutation"}
        for item in trusted
    )

    missing: list[str] = []
    if len(trusted) != len(normalized) or not trusted:
        missing.append("trusted executor evidence")
    if not supports_reproduction:
        missing.append("supporting reproduction")
    if require_negative_control and not supports_control:
        missing.append("supporting negative control")
    if require_independent_confirmation and not supports_independent:
        missing.append("independent confirmation")

    if refuted:
        status = "rejected"
        confidence = 0.05
    elif not supports_reproduction:
        status = "candidate"
        confidence = 0.25
    elif missing:
        status = "reproduced"
        confidence = 0.65
    else:
        status = "confirmed"
        confidence = 0.98 if supports_independent else 0.92

    finding_copy = _redact(dict(finding))
    finding_id = _bounded_text(
        finding.get("finding_id") or finding.get("id") or finding.get("name") or "finding",
        200,
    )
    body: dict[str, Any] = {
        "schema": 1,
        "kind": "mt-proof-bundle",
        "generated_at": _utc_now(),
        "finding_id": finding_id,
        "finding": finding_copy,
        "status": status,
        "confidence": confidence,
        "confidence_kind": "policy-score-not-calibrated-probability",
        "trusted_observation_count": len(trusted),
        "policy": {
            "authorization_confirmed": True,
            "require_negative_control": require_negative_control,
            "require_independent_confirmation": require_independent_confirmation,
        },
        "missing_requirements": missing,
        "observations": normalized,
        "replay_plan": replay,
        "summary": {
            "reproduction_runs": len(supports_reproduction),
            "negative_control": supports_control,
            "independent_confirmation": supports_independent,
            "refuted": refuted,
            "evidence_reference_count": sum(
                len(item["evidence_refs"]) for item in normalized
            ),
        },
    }
    digest = hashlib.sha256(_canonical(body)).hexdigest()
    body["bundle_id"] = f"proof-{digest[:16]}"
    body["content_sha256"] = digest
    return body


