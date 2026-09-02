# MT Security Hardening

Inherited-source provenance and the pinned baseline are recorded in `NOTICE`.

## Application hardening already applied

Deny-by-default target scope; autonomous interpreter, launcher, executable-path, dynamic-loader, and host-mutation blocking; no FULL_AUTO allowlist bypass; fail-closed high-risk verifier behavior; strict AI response enums/ranges; explicit local-provider precedence; untrusted-memory fencing; bounded, provenance-tagged Claude methodology routing; initial-command allowlist/verifier enforcement; shell-safe captured credential injection; local-only credential memory; SSRF/redirect validation for threat-intel fetches; argv-based bounded brute-force subprocesses with temp-secret cleanup; masked report secrets; owner-only DB/report/.env permissions; serialized Metasploit handler commands; and non-destructive startup port selection.

## Autonomous execution boundary

`FULL_AUTO_MODE` and per-session auto-approval skip routine prompts, not policy.
Autonomous commands still require a bare allowlisted executable name, explicit
scope, shell-free argv parsing, and a safe environment. Launchers such as
`sudo`, `env`, and `timeout`, loader variables such as `LD_PRELOAD`, host
mutation utilities, process-execution flags, and executable paths are routed to
manual review. Missing or malformed verifier output rejects high-risk
auto-execution instead of approving it.

## Evidence confirmation boundary

Scanner matches and heuristic CVE lookups are not automatically treated as
proof. A deterministic proof bundle requires an explicitly authorized
engagement, supporting reproduction, a negative control, and—at high or critical
severity—independent confirmation. Rejected bundles suppress the legacy match;
incomplete bundles remain potential. Replay steps are redacted and remain
`not-executed` until a separate executor re-validates authorization and scope.

OpenAPI and GraphQL contracts are parsed locally with bounded document and
operation limits. Planning performs no requests, never fetches external
references, and rejects base URLs outside `SCOPE_ALLOWLIST`.

## Browser and code-intelligence boundary

The Playwright adapter is optional, pinned, runtime-detected, disabled by
default, and never auto-installed. Each top-level navigation and subresource
request is checked against `SCOPE_ALLOWLIST`. Browser contexts are ephemeral;
downloads, uploads, service workers, and arbitrary JavaScript are not exposed.
Navigation, waiting, capture, and screenshots require engagement authorization;
click, fill, and select require a second explicit interactive-action
confirmation. Filled values are redacted from action logs and screenshots are
owner-only files with SHA-256 provenance.

White-box intelligence only accepts bounded path-to-source-text input supplied
to the authenticated API. It does not open repository paths, execute code,
resolve dependencies, or fetch references. Routes, nearby auth signals, request
sources, and sensitive sinks produce review candidates, never confirmed
vulnerabilities.

The evidence graph stores redacted nodes, edges, provenance, and engagement
checkpoints in an owner-only local SQLite file. The public stats endpoint
returns counts only; it does not dump evidence payloads.

## Agent graph and model-routing boundary

Agent graphs are non-executing HMAC-signed state machines. Tasks cannot start
until dependencies complete, required policy/proof tasks cannot be skipped,
and proof-verification completion requires a confirmed or rejected proof status
plus an evidence reference. A graph transition never calls a tool or model;
the eventual executor must re-check authorization, scope, approvals, and its
own adapter policy. Graph nodes, dependencies, and checkpoints are persisted in
the redacted evidence graph.

Task-aware model routing is disabled by default. Disabled routing always
preserves the active provider and reports when that provider does not meet a
requested privacy tier; it never silently switches providers. Enabled
cross-provider routing requires an explicit provider allowlist. Per-role routes
must name configured, allowed providers that satisfy standard, confidential, or
restricted privacy policy. Runtime reachability and context capacity are
reported as not probed until a real call occurs. Provider credential names and
values are never accepted or returned by the router.

## Runtime isolation and reproducibility

The hardened profile adds `Dockerfile.hardened` + `compose.hardened.yml` with a non-root user, read-only root filesystem, dropped Linux capabilities, `no-new-privileges`, bounded tmpfs, localhost-only published ports, PID/memory/CPU limits and an explicit `SCOPE_ALLOWLIST` requirement. Child services are supervised by `scripts/run_container.py` without shell invocation.

`requirements.lock` is installed with `--no-deps`; `scripts/verify_reproducible.py` rejects non-exact lock entries and CI builds/smoke-tests the hardened image. CI action references are pinned to immutable commit SHAs and `pip-audit` is a blocking dependency-vulnerability gate.

## Benchmark evidence

The historical v2.2.7 benchmark remains documented. A post-hardening/current score is only valid after a fresh authorized-lab run. `benchmarks/record_evidence.py` records score metadata plus report/lab SHA-256 provenance without committing the raw sensitive report. Until that evidence exists, the current live benchmark is reported as pending rather than estimated.

This remains a dual-use authorized security-testing tool. Use only on systems you own or have explicit permission to test.
