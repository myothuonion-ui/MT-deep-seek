# MT-deep-seek — Hardened KMN-CyberSeek

> Security-hardened derivative pinned to upstream KMN-CyberSeek v2.3.3 (`3e8b08a...`). See `SECURITY_HARDENING.md`. Authorized security testing only.

# KMN-CyberSeek

![Version](https://img.shields.io/badge/Version-2.3.3-brightgreen)
![Python](https://img.shields.io/badge/Python-3.10%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

AI-driven autonomous penetration testing framework. Executes an engagement pipeline from OSINT/recon through validation/exploitation using an LLM (DeepSeek API or local Ollama) with explicit authorization and safety controls.

**Upstream repository:** [https://github.com/KhitMinnyo/KMN-CyberSeek](https://github.com/KhitMinnyo/KMN-CyberSeek)

---

## Recommended hardened mode

The strongest default runtime is `compose.hardened.yml`. It runs the application as a non-root user with a read-only root filesystem, dropped Linux capabilities, `no-new-privileges`, resource limits, localhost-only published ports and a mandatory explicit target scope.

```bash
export API_AUTH_TOKEN='replace-with-a-long-random-secret'
export SCOPE_ALLOWLIST='10.10.10.0/24,lab.example'
docker compose -f compose.hardened.yml up --build
```

Then open `http://127.0.0.1:8501`.

The profile intentionally grants no raw-socket/elevated capabilities. Some low-level tools may therefore be unavailable or fall back to less privileged operation. Review `docs/hardened-runtime.md` before changing that boundary.

---

## Standard local installation

**Prerequisites:** Python 3.10+, optional Nmap/security tooling, and Ollama or a DeepSeek API key if AI is required.

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
   Orchestrator │ Scanner │ AI Connector │ SQLite DB
         │               │               │
   AI Engine         Scan tools       Command execution
  DeepSeek/Ollama                   inside runtime boundary
```

---

## Quick Start

1. Set an explicit `SCOPE_ALLOWLIST` for systems you own or are authorized to test.
2. Run the hardened Compose profile or `./start.sh`.
3. Open `http://127.0.0.1:8501`.
4. Configure Ollama/DeepSeek under **Settings → AI Configuration**.
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

### AI — DeepSeek API

```env
AI_PROVIDER=api
DEEPSEEK_API_KEY=sk-...
DEEPSEEK_MODEL=deepseek-chat
```

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
- `Dockerfile.hardened` installs the lock with `--no-deps` and runs as UID/GID 10001.
- GitHub Actions references are pinned to immutable commit SHAs.
- `pip-audit` is a blocking dependency-vulnerability gate.
- CI builds and smoke-tests the hardened image on every `main`/`agent/**` change.

---

## Benchmark evidence

The documented v2.2.7 pre-coverage-engine baseline is **45.7% touched / 2.9% confirmed**. A current score is not guessed from tests or code inspection; it must come from a fresh authorized-lab report.

```bash
python benchmarks/record_evidence.py /path/to/current_report.md \
  --lab benchmarks/labs/kmn_training_win.json \
  --out benchmarks/evidence/current_score.json
```

Only score/provenance metadata is committed. The raw report stays outside Git because it may contain sensitive engagement data. See `benchmarks/README.md` and `benchmarks/evidence/README.md`.

---

## Further Reading

- [Security hardening](SECURITY_HARDENING.md)
- [Hardened runtime](docs/hardened-runtime.md)
- [Coverage benchmarks](benchmarks/README.md)
- [Features & Architecture Detail](features.md)
- [Changelog](change_log.md)

---

## Disclaimer

**For authorised security testing and educational purposes only.**

Only use against systems you own or have explicit written permission to test. The developers assume no liability for misuse or damage. Full-auto operation should be confined to isolated, explicitly authorized lab environments.

---

## License

MIT — see [LICENSE](LICENSE).
