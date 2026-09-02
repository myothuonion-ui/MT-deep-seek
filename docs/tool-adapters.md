# Tool Adapters

MT Pentester exposes external capabilities through reviewed adapters, not
arbitrary command strings. Every network action requires the authenticated API,
an explicit authorization confirmation, and a target inside `SCOPE_ALLOWLIST`.
Adapter child processes receive a minimized environment; backend authentication
and AI-provider credentials are not inherited. Only reviewed runtime variables,
proxy settings, and tool-prefixed `BBOT_`/`NUCLEI_` settings are forwarded.

## Runtime matrix

| Adapter | Default image | Maximum mode | Execution boundary |
|---|---:|---|---|
| Nmap | Included | safe-active | Existing scanner plus unprivileged TCP-connect smoke test |
| Nuclei 3.11.1 | Included | safe-active | Typed argv; bounded rate/concurrency; no DAST, OAST, headless, file, code, or JavaScript templates |
| Nuclei templates | Included | safe-active | Read-only snapshot pinned to commit `e5f19e6144135e107962bb943231413796fd7fe7` |
| Claude-BugHunter | Included | knowledge-only | Read-only index/content pinned to commit `f032240d876c40465770ab4839e7257b9e7254e8`; upstream scripts are not executed |
| BBOT 3.0.2 | Optional | map-only | Typed argv; passive-module filter; dependency auto-install disabled |

The live availability for every adapter is returned by `GET /api/plugins`.
`adapter-ready` describes the MT integration; `runtime.available` describes the
current machine or container.

## Nuclei

The hardened image verifies the official Linux archive checksum before
installing Nuclei. The adapter always adds these controls:

- JSONL output with raw request/response and encoded template bodies omitted;
- unsigned templates disabled;
- Interactsh/OAST disabled;
- DAST/fuzz, intrusive, denial-of-service, headless, file, code, and JavaScript
  content excluded;
- rate limit capped at 500 requests/second and concurrency capped at 50;
- update checks disabled so a running engagement cannot silently change assets.

Example authenticated request against an authorized lab:

```bash
curl --fail --silent \
  -H "X-API-Key: $API_AUTH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "https://lab.example",
    "authorization_confirmed": true,
    "severities": ["medium", "high", "critical"],
    "rate_limit": 25,
    "concurrency": 5
  }' \
  http://127.0.0.1:6000/api/adapters/nuclei/scan
```

For a local installation, point `NUCLEI_PATH` to the reviewed executable and
`NUCLEI_TEMPLATES_PATH` to a read-only, versioned template directory.

## Claude-BugHunter

The adapter searches `cbh/data/skill_index.json` and reads only an indexed
`skills/<name>/SKILL.md` beneath the pinned bundle root. It rejects traversal,
unknown names, oversized files, and malformed indexes. It never calls the
bundle's shell scripts or terminal runner.

```bash
curl --fail --silent \
  -H "X-API-Key: $API_AUTH_TOKEN" \
  'http://127.0.0.1:6000/api/adapters/claude-bughunter/skills?q=idor&limit=20'
```

A local operator can set `CLAUDE_BUGHUNTER_PATH` to a read-only checkout of the
commit recorded above. Keep the bundle's own `LICENSE` and `NOTICE` files with
every copy.

## BBOT

BBOT is not installed into the default Python environment. Its GPL-3.0 runtime
and large dependency graph should live in a separate `pipx`/virtual environment
or an operator-managed image. Install the reviewed 3.0.2 release, then provide
its executable with `BBOT_PATH`.

```bash
pipx install 'bbot==3.0.2'
export BBOT_PATH="$(command -v bbot)"
```

The MT adapter permits only the `subdomain-enum` and `code-enum` presets, adds
the passive-module filter, disables dependency auto-install, and captures
newline-delimited JSON. It does not expose arbitrary BBOT modules or config
overrides through the API.

```bash
curl --fail --silent \
  -H "X-API-Key: $API_AUTH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "lab.example",
    "authorization_confirmed": true,
    "preset": "subdomain-enum"
  }' \
  http://127.0.0.1:6000/api/adapters/bbot/map
```

## Why the ceilings are fixed

Installing a tool does not grant it more authority than the engagement policy.
Higher-impact workflows, custom templates, OAST, dependency installation, and
active BBOT modules require a separate reviewed implementation and cannot be
enabled with request parameters.
