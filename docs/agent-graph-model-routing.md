# Agent graph and model routing

Alpha.6 adds two orchestration foundations while preserving the existing
authorization, scope, approval, adapter, and proof boundaries.

## Signed task graph

`POST /api/agent-graphs/plan` creates a non-executing task DAG. A typical
graph contains:

1. deterministic scope policy;
2. network, API-contract, white-box, or browser mapping tasks;
3. a hypothesis task;
4. deterministic proof verification;
5. evidence-grounded reporting.

Each task has an explicit role, dependency list, status, execution-boundary
label, evidence references, and public model-route plan. The graph is signed
with HMAC-SHA-256. Configure `AGENT_GRAPH_SIGNING_KEY` with a separate random
secret of at least 16 characters; when it is absent, the backend API token is
used.

`POST /api/agent-graphs/transition` accepts only start, complete, reject, and
skip events. It verifies the HMAC and dependency graph before changing state.
Required tasks cannot be skipped. Proof verification can complete only with:

- `result.proof_status` equal to `confirmed` or `rejected`; and
- at least one evidence reference.

Transitions redact secret-like result keys, remain bounded, and persist graph,
task, dependency, target, and checkpoint provenance in the local evidence
graph. They do not call a model, browser, scanner, or shell. An executor must
still enter through the relevant existing policy-gated adapter.

## Task-aware model router

The router recognizes scoper, mapper, code-reviewer, strategist, tactical,
verifier, and reporter roles. Its plan reports provider, model, privacy class,
route source, independence, configuration state, and task profile without
returning credential names or values.

Routing is disabled by default:

```env
MODEL_ROUTING_ENABLED=false
```

In this state every orchestration role uses `AI_PROVIDER`. The route plan
reports a privacy incompatibility if one exists but never silently transfers
data to another provider.

Cross-provider routing is opt-in and allowlisted:

```env
MODEL_ROUTING_ENABLED=true
MODEL_ROUTING_ALLOWED_PROVIDERS=local,litellm
MODEL_ROUTING_SENSITIVITY=confidential
MODEL_ROUTE_STRATEGIST=litellm
MODEL_ROUTE_VERIFIER=local
```

Provider codes must already exist in the provider catalog and be configured.
`restricted` tasks can use only local providers; `confidential` tasks can
use local or operator-managed gateway providers; `standard` tasks may use an
allowed cloud provider. Set `MODEL_ROUTING_AUTO_SELECT=true` to let the
verifier prefer a configured allowed provider different from the proposing
provider.

The router does not probe provider reachability or model context capacity while
planning. Its response marks those values as operator-configured/not-probed.
Real model calls retain the connector's existing timeouts and fail-closed
behavior.

## API examples

```bash
curl --fail --silent \
  -H "X-API-Key: $API_AUTH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "https://lab.example",
    "objective": "Map and verify the authorized web attack surface",
    "authorization_confirmed": true,
    "capabilities": ["network_scan", "api_contracts", "whitebox", "browser"],
    "sensitivity": "confidential"
  }' \
  http://127.0.0.1:6000/api/agent-graphs/plan
```

```bash
curl --fail --silent \
  -H "X-API-Key: $API_AUTH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "role": "verifier",
    "sensitivity": "confidential",
    "independent_of": "litellm"
  }' \
  http://127.0.0.1:6000/api/model-routing/plan
```
