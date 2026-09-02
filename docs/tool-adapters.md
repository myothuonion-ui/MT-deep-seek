# Tool Adapters

MT Pentester exposes external capabilities through reviewed adapters, not
arbitrary command strings. Every network action requires the authenticated API,
an explicit authorization confirmation, and a target inside `SCOPE_ALLOWLIST`.
Adapter child processes receive a minimized environment; backend authentication
and AI-provider credentials are not inherited. Only reviewed runtime variables,
proxy settings, and tool-prefixed `BBOT_`/`BROWSER_`/`NUCLEI_` settings
are forwarded.

## Runtime matrix

| Adapter | Default image | Maximum mode | Execution boundary |
|---|---:|---|---|
| Nmap | Included | safe-active | Existing scanner plus unprivileged TCP-connect smoke test |
| Nuclei 3.11.1 | Included | safe-active | Typed argv; bounded rate/concurrency; no DAST, OAST, headless, file, code, or JavaScript templates |
| Nuclei templates | Included | safe-active | Read-only snapshot pinned to commit `e5f19e6144135e107962bb943231413796fd7fe7` |
| Claude-BugHunter | Included | knowledge-only | Automatically routes up to 3 relevant, bounded skill excerpts into untrusted AI context; pinned provenance; upstream scripts are not executed |
| BBOT 3.0.2 | Optional | map-only | Typed argv; passive-module filter; dependency auto-install disabled |
| Playwright 1.62.0 | Optional | safe-active | Ephemeral Chromium; every request scope checked; interactive actions require second confirmation |

The live availability for every adapter is returned by `GET /api/plugins`.
`adapter-ready` describes the MT integration; `runtime.available` describes the
current machine or container.

## Playwright browser

Playwright is deliberately absent from the default lock and hardened image.
`GET /api/adapters/browser/status` reports available only when the
operator-managed Python package is exactly 1.62.0 and its reviewed Chromium
runtime is installed. A local operator can prepare an isolated runtime:

```bash
python -m pip install 'playwright==1.62.0'
python -m playwright install chromium
```

The API exposes only navigate, click, fill, select, wait-for, screenshot, and
metadata capture actions. It exposes no arbitrary JavaScript, upload, or
download primitive. All top-level navigation and subresource hosts must be in
`SCOPE_ALLOWLIST`; third-party assets outside scope are blocked. Click, fill,
and select require `interactive_actions_confirmed: true` in addition to the
normal authorization confirmation. Each run uses a new browser context and
redacts fill/select values from its action log.

```bash
curl --fail --silent \
  -H "X-API-Key: $API_AUTH_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "https://lab.example",
    "authorization_confirmed": true,
    "actions": [
      {"action": "navigate", "url": "https://lab.example/login"},
      {"action": "screenshot", "label": "login"},
      {"action": "capture"}
    ]
  }' \
  http://127.0.0.1:6000/api/adapters/browser/run
```

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

The orchestrator now routes the most relevant methodology into each AI turn.
Selection uses the engagement objective, phase, discovered services,
vulnerability labels, and latest command. The default budget is three skills
and 1,800 characters per excerpt, with the pinned source commit included in the
memory payload. Skill text is explicitly marked untrusted and cannot override
authorization, scope, approval, or typed-argv policy.

Configure routing with `CLAUDE_SKILL_ROUTING`, `CLAUDE_SKILL_MAX`, and
`CLAUDE_SKILL_EXCERPT_CHARS`. Set `CLAUDE_SKILL_ROUTING=false` to disable it.
If the bundle is absent or invalid, routing degrades to no methodology context
without weakening execution policy.

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
