# MT Security Hardening

Inherited-source provenance and the pinned baseline are recorded in `NOTICE`.

## Application hardening already applied

Deny-by-default target scope; autonomous interpreter blocking; no FULL_AUTO allowlist bypass; strict AI response enums/ranges; explicit local-provider precedence; untrusted-memory fencing; initial-command allowlist/verifier enforcement; shell-safe captured credential injection; local-only credential memory; SSRF/redirect validation for threat-intel fetches; argv-based bounded brute-force subprocesses with temp-secret cleanup; masked report secrets; owner-only DB/report/.env permissions; serialized Metasploit handler commands; and non-destructive startup port selection.

## Runtime isolation and reproducibility

The hardened profile adds `Dockerfile.hardened` + `compose.hardened.yml` with a non-root user, read-only root filesystem, dropped Linux capabilities, `no-new-privileges`, bounded tmpfs, localhost-only published ports, PID/memory/CPU limits and an explicit `SCOPE_ALLOWLIST` requirement. Child services are supervised by `scripts/run_container.py` without shell invocation.

`requirements.lock` is installed with `--no-deps`; `scripts/verify_reproducible.py` rejects non-exact lock entries and CI builds/smoke-tests the hardened image. CI action references are pinned to immutable commit SHAs and `pip-audit` is a blocking dependency-vulnerability gate.

## Benchmark evidence

The historical v2.2.7 benchmark remains documented. A post-hardening/current score is only valid after a fresh authorized-lab run. `benchmarks/record_evidence.py` records score metadata plus report/lab SHA-256 provenance without committing the raw sensitive report. Until that evidence exists, the current live benchmark is reported as pending rather than estimated.

This remains a dual-use authorized security-testing tool. Use only on systems you own or have explicit permission to test.
