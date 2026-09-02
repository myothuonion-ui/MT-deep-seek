# Browser, white-box, and evidence graph

Alpha.5 adds three bounded capabilities without expanding MT Pentester's
authorization or autonomous-execution boundary.

## Optional browser executor

`PlaywrightBrowserAdapter` accepts a target and at most 100 typed actions.
The initial URL, explicit navigate actions, and every browser request are
checked against `SCOPE_ALLOWLIST`. A fresh Chromium context blocks service
workers and downloads and is destroyed after each run.

The API exposes only:

- `navigate`, `wait_for`, `screenshot`, and `capture` after explicit
  engagement authorization;
- `click`, `fill`, and `select` only when
  `interactive_actions_confirmed` is also true.

It does not expose arbitrary JavaScript, uploads, downloads, extension loading,
or persistent browser profiles. Fill and select values are redacted from the
action log. Screenshot files are owner-only and include SHA-256 provenance.

Playwright is not part of `requirements.lock` or the default container. The
adapter reports `runtime.available=false` unless the operator separately
installs the pinned Python package and reviewed Chromium runtime.

## White-box source mapper

`POST /api/whitebox/analyze` accepts an explicit JSON map of relative paths to
source text. The mapper supports common Python, JavaScript/TypeScript, Java, Go,
PHP, Ruby, and C# extensions, with limits of 300 files, 500 KB per file, and
5 MB total.

It maps routes, nearby authentication/authorization signals, request-input
sources, and security-sensitive sinks. It never opens a path from disk, fetches
dependencies or external references, or executes supplied code. Every emitted
review item has `status: candidate`; proof verification remains the only path
to confirmation.

## Durable evidence graph

`EvidenceGraph` stores redacted nodes, typed edges, provenance, and
engagement checkpoints in SQLite. The default path is
`mt_evidence_graph.db` beside the configured application database and can be
overridden with `EVIDENCE_GRAPH_PATH`.

Supported records include findings, proof bundles, contract plans, code
analyses, targets, endpoints, observations, artifacts, services, and agent
tasks. Secret-like keys are replaced with `[REDACTED]` before serialization.
The database is created with owner-only permissions.

`GET /api/evidence-graph/stats` exposes aggregate node, edge, and checkpoint
counts only. Evidence payload retrieval is deliberately not exposed by this
release.
