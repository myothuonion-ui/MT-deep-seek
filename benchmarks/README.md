# Coverage Benchmarks

Turns "did the engagement get better?" into a number. Each lab has a ground-truth
vulnerability set; `score.py` compares an engagement report against it and reports
coverage. This is the yardstick for every coverage-engine milestone (see
`docs/coverage-engine-buildplan.md`).

## Usage

```bash
# Score a downloaded Markdown report
python benchmarks/score.py /path/to/mt_report_<id>.md

# Choose a lab explicitly / machine-readable output
python benchmarks/score.py report.md --lab benchmarks/labs/mt_training_win.json --json
```

**Metrics**
- **touched** — the AI at least attempted / mentioned the vuln (signal anywhere in the report).
- **confirmed** — a signal appears in a confirmed section (Confirmed Compromises / Credentials Captured / Vulnerability Findings).

## Labs
- `labs/mt_training_win.json` — Windows Server 2019 training lab (192.168.100.194), 35 ground-truth items across 5 categories.

## Historical baseline (pre-coverage-engine, v2.2.7)

Scored against the 2026-08-13 autonomous run (`Win-Server_3f66b862`):

| Metric | Score |
|--------|-------|
| Touched | **16 / 35 (45.7%)** |
| Confirmed | **1 / 35 (2.9%)** |

By category (touched / total):

| Category | Touched | Notes |
|----------|---------|-------|
| web_cms | 0 / 6 | WebDAV + WordPress completely missed (no wpscan/davtest) |
| app_servers | 6 / 8 | Tomcat/GlassFish/Jenkins probed, none confirmed |
| network_fileshare | 5 / 6 | SMB/FTP touched, abandoned early, none confirmed |
| remote_admin_db | 5 / 9 | MySQL root **confirmed**; no brute-force (SSH/RDP/WinRM) |
| windows_system | 0 / 6 | no post-exploitation → no internal findings |

## Current evidence policy

A post-hardening/current score is only considered valid when it comes from a fresh
run against an authorized lab. Do **not** infer a score from unit tests, playbook
coverage, or code inspection.

Record a real run without committing the sensitive raw report:

```bash
python benchmarks/record_evidence.py /path/to/current_report.md \
  --lab benchmarks/labs/mt_training_win.json \
  --out benchmarks/evidence/current_score.json
```

The resulting JSON stores only score/provenance metadata: code commit, UTC time,
report SHA-256, lab SHA-256, category scores and touched/confirmed percentages.
See `benchmarks/evidence/README.md`.

Schema v2 can also aggregate redacted proof bundles and optional ground truth.
It records precision, recall, F1, confirmation/rejection rates, replay coverage,
negative-control coverage, independent-confirmation coverage, runtime and model
cost without copying raw targets or evidence into the benchmark artifact:

```bash
python benchmarks/record_evidence.py report.md \
  --proof-bundles /path/to/redacted-proof-bundles.json \
  --ground-truth /path/to/ground-truth.json \
  --duration-seconds 1234 \
  --api-cost-usd 2.50 \
  --provider openrouter \
  --model reviewed-model \
  --run-id authorized-lab-2026-09
```

**Target after the coverage engine:** raise *touched* toward ~90% and improve
*confirmed* substantially. Until `benchmarks/evidence/current_score.json` exists
from a fresh authorized-lab run, the repository should report the current live
benchmark as **pending**, not as an estimated or manufactured number.
