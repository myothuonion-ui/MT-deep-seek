# Benchmark Evidence

This directory stores **score/provenance metadata**, not raw engagement reports.
Raw reports can contain target details, usernames, credentials, or other sensitive
engagement data and should remain outside Git.

## Record a current authorized-lab run

```bash
python benchmarks/record_evidence.py /path/to/report.md \
  --lab benchmarks/labs/kmn_training_win.json \
  --out benchmarks/evidence/current_score.json
```

The evidence JSON records the code commit, UTC timestamp, report SHA-256, lab
SHA-256, category scores, and touched/confirmed percentages. That makes a claimed
benchmark result reproducible against the exact report and lab definition without
publishing the report itself.

Optional release gates can be applied with `--minimum-touched` and
`--minimum-confirmed`.

## Evidence status

The repository currently contains a documented **historical pre-coverage-engine**
baseline in `benchmarks/README.md` (v2.2.7: 45.7% touched / 2.9% confirmed).
A new `current_score.json` must only be committed after a fresh run against an
authorized lab. Do not manufacture or hand-edit current benchmark evidence.
