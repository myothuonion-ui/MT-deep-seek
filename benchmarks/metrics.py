"""Aggregate non-sensitive effectiveness metrics from MT proof bundles."""

from __future__ import annotations

from typing import Any, Mapping, Sequence


_VALID_STATUSES = {"candidate", "reproduced", "confirmed", "rejected"}


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def summarize_proof_bundles(
    bundles: Sequence[Mapping[str, Any]],
    ground_truth: Mapping[str, bool] | None = None,
) -> dict[str, Any]:
    """Return aggregate-only metrics; raw targets and evidence are not copied."""
    status_counts = {status: 0 for status in _VALID_STATUSES}
    replayable = 0
    controlled = 0
    independently_confirmed = 0
    evidence_references = 0
    finding_status: dict[str, str] = {}

    for index, bundle in enumerate(bundles):
        status = str(bundle.get("status", "")).lower()
        if status not in _VALID_STATUSES:
            raise ValueError(f"bundle {index + 1} has unsupported status: {status!r}")
        finding_id = str(bundle.get("finding_id") or f"finding-{index + 1}")[:200]
        status_counts[status] += 1
        finding_status[finding_id] = status
        summary = bundle.get("summary") or {}
        replayable += bool(bundle.get("replay_plan"))
        controlled += bool(summary.get("negative_control"))
        independently_confirmed += bool(summary.get("independent_confirmation"))
        evidence_references += int(summary.get("evidence_reference_count") or 0)

    total = len(bundles)
    result: dict[str, Any] = {
        "schema": 1,
        "kind": "mt-proof-metrics",
        "total_findings": total,
        "status_counts": status_counts,
        "confirmation_rate": _ratio(status_counts["confirmed"], total),
        "reproduction_rate": _ratio(
            status_counts["confirmed"] + status_counts["reproduced"], total
        ),
        "rejection_rate": _ratio(status_counts["rejected"], total),
        "replay_plan_coverage": _ratio(replayable, total),
        "negative_control_coverage": _ratio(controlled, total),
        "independent_confirmation_coverage": _ratio(
            independently_confirmed, total
        ),
        "evidence_references": evidence_references,
    }

    if ground_truth is not None:
        truth = {str(key): bool(value) for key, value in ground_truth.items()}
        tp = fp = fn = tn = 0
        for finding_id, vulnerable in truth.items():
            predicted = finding_status.get(finding_id) == "confirmed"
            if predicted and vulnerable:
                tp += 1
            elif predicted and not vulnerable:
                fp += 1
            elif not predicted and vulnerable:
                fn += 1
            else:
                tn += 1
        precision = _ratio(tp, tp + fp)
        recall = _ratio(tp, tp + fn)
        result["ground_truth"] = {
            "evaluated": len(truth),
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "true_negative": tn,
            "precision": precision,
            "recall": recall,
            "f1": round(
                2 * precision * recall / (precision + recall), 4
            ) if precision + recall else 0.0,
        }
    return result

