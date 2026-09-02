# Proof verification and API contract planning

MT Pentester separates planning, execution, and confirmation. Neither endpoint
documented here executes a command or makes a network request.

## Proof states

`POST /api/verification/evaluate` converts bounded observations into a redacted,
hashed proof bundle.

- `candidate`: no supporting reproduction.
- `reproduced`: an effect was observed, but required controls are incomplete.
- `confirmed`: reproduction and the required negative control succeeded.
  High and critical findings also require an independent confirmation.
- `rejected`: a reproduction or independent check refuted the claim.

Authorization confirmation is mandatory. Replay steps are typed
`adapter`/`action` records, remain marked `not-executed`, and redact common
credential-bearing flags and fields. A later executor must re-check scope and
authorization before running them.

Example request:

```bash
curl --fail --silent \
  -H "X-API-Key: $API_AUTH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "authorization_confirmed": true,
    "finding": {
      "finding_id": "LAB-001",
      "name": "Authorized fixture access-control finding",
      "severity": "high"
    },
    "observations": [
      {"kind":"reproduction","outcome":"supports","run_id":"fixture-repro","source":"reviewed-http-adapter","evidence_refs":["artifact://fixture/reproduction"]},
      {"kind":"negative_control","outcome":"supports","run_id":"fixture-control","source":"reviewed-http-adapter","evidence_refs":["artifact://fixture/control"]},
      {"kind":"independent_confirmation","outcome":"supports","run_id":"fixture-second-check","source":"independent-reviewer","evidence_refs":["artifact://fixture/confirmation"]}
    ]
  }' \
  http://127.0.0.1:6000/api/verification/evaluate
```

## OpenAPI and GraphQL plans

`POST /api/contracts/plan` accepts an OpenAPI/Swagger document or GraphQL
introspection JSON and an explicitly authorized in-scope base URL. It produces
typed, non-executing test intents: baselines, unauthenticated controls,
authorization-object matrices, and GraphQL field-access matrices.

The planner never fetches external `$ref` documents, never performs
introspection itself, and rejects base URLs outside `SCOPE_ALLOWLIST`.
Generated intents are input for the future browser/API executor, not evidence
that a test ran.

## Benchmark metrics

`benchmarks/metrics.py` aggregates proof bundles without copying raw targets or
evidence. Schema v2 benchmark records can include confirmation/rejection rates,
replay and control coverage, precision, recall, F1, duration, model/provider,
and API cost. A current benchmark remains pending until a fresh authorized-lab
run produces the evidence file.
