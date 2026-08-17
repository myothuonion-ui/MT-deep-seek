# Hardened Runtime

`compose.hardened.yml` is the recommended containment profile for running this
repository when you want the AI/operator process and every child tool to remain
inside one restricted container boundary.

## Security properties

- non-root UID/GID `10001:10001`
- read-only root filesystem
- writable state limited to `/app/data` plus bounded tmpfs mounts
- all Linux capabilities dropped by default
- `no-new-privileges` enabled
- PID, memory and CPU limits
- backend/frontend/docs ports published on `127.0.0.1` only
- explicit `SCOPE_ALLOWLIST` required before Compose will start
- `ALLOW_UNSCOPED_TARGETS=false`
- secret-bearing reports disabled
- services supervised without shell invocation

This profile intentionally does **not** grant raw-socket or other elevated
capabilities. Some low-level scanning tools may therefore be unavailable or may
fall back to less privileged modes. Do not weaken the profile globally; if a
specific authorized lab requires an extra capability, treat that as a separate,
reviewed environment decision.

## Start

Set a strong API token and an explicit authorized scope, then start the hardened
profile:

```bash
export API_AUTH_TOKEN='replace-with-a-long-random-secret'
export SCOPE_ALLOWLIST='10.10.10.0/24,lab.example'
docker compose -f compose.hardened.yml up --build
```

The UI remains available only on the local machine:

- Streamlit: `http://127.0.0.1:8501`
- API: `http://127.0.0.1:6000`
- docs: `http://127.0.0.1:3500`

## Reproducible dependency snapshot

The hardened image installs `requirements.lock` with `--no-deps`, and CI runs
`scripts/verify_reproducible.py` to reject range/VCS/URL lock entries or missing
direct dependencies. GitHub Actions used by CI are pinned to immutable commit
SHAs.

The Python base image is version-pinned (`python:3.11.13-slim-bookworm`). For
release-grade bit-for-bit provenance, a release maintainer may additionally pin
the base image digest for the chosen registry mirror and record that digest in
the release notes.

## Benchmark evidence

Runtime hardening is not counted as proof that target coverage improved. Current
coverage evidence must come from a fresh authorized-lab report and be recorded
with `benchmarks/record_evidence.py`; the raw report should stay outside Git.
