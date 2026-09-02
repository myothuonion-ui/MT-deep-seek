# MT Pentester

[![CI and security gates](https://github.com/myothuonion-ui/MT-deep-seek/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/myothuonion-ui/MT-deep-seek/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-3.0.0--alpha.2-brightgreen)](_version.py)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)

Policy-gated, multi-provider AI penetration-testing platform for authorized environments. MT Pentester separates orchestration, model providers, capability plugins, evidence, and execution policy so new integrations do not bypass the security boundary.

License and inherited-source notices are recorded in [NOTICE](NOTICE); they do not imply sponsorship or endorsement of MT Pentester.

---

## Recommended hardened mode

The strongest default runtime is `compose.hardened.yml`. It runs the application as a non-root user with a read-only root filesystem, dropped Linux capabilities, `no-new-privileges`, resource limits, localhost-only published ports and a mandatory explicit target scope.

```bash
export API_AUTH_TOKEN="$(openssl rand -hex 32)"
export SCOPE_ALLOWLIST='10.10.10.0/24,lab.example'
docker compose -f compose.hardened.yml up --build
```

Then open `http://127.0.0.1:8501`.

The image includes Nmap, a checksum-verified Nuclei 3.11.1 binary, a pinned Nuclei template snapshot, and a pinned read-only Claude-BugHunter skill bundle. Nmap uses unprivileged connect scans under the hardened profile. BBOT is an optional external runtime because its GPL toolchain and dependency environment are intentionally isolated from the locked application environment.

Review [the hardened runtime](docs/hardened-runtime.md), [tool adapters](docs/tool-adapters.md), and [data migration](docs/data-migration.md) before changing the containment boundary.

---

## Standard local installation

**Prerequisites:** Python 3.10+, Nmap/security tooling for local runs, and Ollama or a configured cloud/gateway provider if AI is required.

```bash
git clone https://github.com/myothuonion-ui/MT-deep-seek.git
cd MT-deep-seek
./start.sh
```

`start.sh` now requires the committed `requirements.lock` by default and installs it with `--no-deps`, preventing dependency resolution from drifting between runs. A development-only unlocked fallback requires explicit `ALLOW_UNLOCKED_INSTALL=true`.

---

## Architecture

```text
Streamlit Frontend  (8501)
         │
FastAPI Backend     (6000)
   Orchestrator │ Policy Gate │ Evidence │ Capability Registry
          │           │
   Provider-neutral   │──── typed argv for autonomous actions
   AI Connector       │──── Nmap / Nuclei / passive BBOT adapters
          │           │──── read-only Claude-BugHunter knowledge
 Ollama │ DeepSeek │ OpenRouter │ NVIDIA NIM │ Gemini │ LiteLLM
```

---

## Quick Start

1. Set an explicit `SCOPE_ALLOWLIST` for systems you own or are authorized to test.
2. Run the hardened Compose profile or `./start.sh`.
3. Open `http://127.0.0.1:8501`.
4. Configure Ollama, DeepSeek, OpenRouter, NVIDIA NIM, Gemini, or LiteLLM under **Settings → AI Configuration**.
5. Create a session and confirm authorization.
6. Review AI decisions, command approvals, scan results and evidence as the session progresses.

---

## Security defaults

```env
API_AUTH_TOKEN=
BACKEND_HOST=127.0.0.1
SCOPE_ALLOWLIST=
ALLOW_UNSCOPED_TARGETS=false
REQUIRE_APPROVAL_HIGH_RISK=true
FULL_AUTO_MODE=false
INCLUDE_SECRETS_IN_REPORTS=false
```

An empty `SCOPE_ALLOWLIST` denies targets unless the unsafe development override is deliberately enabled. The hardened Compose profile requires a non-empty allowlist before it will start.

### AI — Ollama

```env
AI_PROVIDER=local
OLLAMA_URL=http://192.168.1.50:11434
OLLAMA_MODEL=deepseek-r1:8b
OLLAMA_CONTEXT_WINDOW=8192
```

### AI — cloud and gateway providers

```env
# Pick one: deepseek, openrouter, nvidia_nim, gemini, litellm
AI_PROVIDER=deepseek

DEEPSEEK_API_KEY=
DEEPSEEK_MODEL=deepseek-v4-flash

OPENROUTER_API_KEY=
OPENROUTER_MODEL=openrouter/auto

NVIDIA_NIM_API_KEY=
NVIDIA_NIM_MODEL=nvidia/nemotron-3-super-120b-a12b

GEMINI_API_KEY=
GEMINI_MODEL=gemini-2.5-flash

LITELLM_MASTER_KEY=
LITELLM_API_BASE=http://localhost:4000/v1
LITELLM_MODEL=planner-strong
```

Credentials are read from runtime environment variables or container secrets. The settings UI never writes API keys back to `.env`.

### Capability registry

`config/plugins.json` tracks engines, skill packs, deterministic tools, knowledge sources, and benchmarks. `adapter-ready` means MT Pentester ships a policy-gated integration; `/api/plugins` separately reports whether its runtime is installed. Roadmap/reference entries are never presented as working integrations.

### Ports

```env
BACKEND_PORT=6000
FRONTEND_PORT=8501
DOCS_PORT=3500
```

---

## Reproducible builds and CI

- `requirements.lock` contains the exact Python dependency snapshot.
- `scripts/verify_reproducible.py` rejects ranges, VCS/URL lock entries and missing direct dependencies.
- `Dockerfile.hardened` installs the lock with `--no-deps`, pins external assets, and runs as UID/GID 10001.
- GitHub Actions references are pinned to immutable commit SHAs.
- `pip-audit` is a blocking dependency-vulnerability gate.
- CI runs the full non-root container, probes its health endpoint, and verifies a real Nmap TCP-connect scan without added Linux capabilities.

---

## Benchmark evidence

The documented v2.2.7 pre-coverage-engine baseline is **45.7% touched / 2.9% confirmed**. A current score is not guessed from tests or code inspection; it must come from a fresh authorized-lab report.

```bash
python benchmarks/record_evidence.py /path/to/current_report.md \
  --lab benchmarks/labs/mt_training_win.json \
  --out benchmarks/evidence/current_score.json
```

Only score/provenance metadata is committed. The raw report stays outside Git because it may contain sensitive engagement data. See `benchmarks/README.md` and `benchmarks/evidence/README.md`.

---

## Further Reading

- [Security hardening](SECURITY_HARDENING.md)
- [AI providers and LiteLLM](docs/ai-providers.md)
- [Hardened runtime](docs/hardened-runtime.md)
- [Tool adapters](docs/tool-adapters.md)
- [Data migration](docs/data-migration.md)
- [Coverage benchmarks](benchmarks/README.md)
- [Features & Architecture Detail](features.md)
- [Changelog](change_log.md)

---

## Disclaimer

**For authorised security testing and educational purposes only.**

Only use against systems you own or have explicit written permission to test. The developers assume no liability for misuse or damage. Full-auto operation should be confined to isolated, explicitly authorized lab environments.

---

## License

MIT for MT Pentester contributions — see [LICENSE](LICENSE). Required inherited and third-party attribution is retained in [NOTICE](NOTICE).
