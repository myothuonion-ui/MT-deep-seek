# MT Security Hardening

Pinned baseline: KMN-CyberSeek v2.3.3, commit `3e8b08a36c6af989f30c1d564f1a1c00579dbf43`.

Changes include deny-by-default target scope; autonomous interpreter blocking; no FULL_AUTO allowlist bypass; strict AI response enums/ranges; explicit local-provider precedence; untrusted-memory fencing; initial-command allowlist/verifier enforcement; shell-safe captured credential injection; local-only credential memory; SSRF/redirect validation for threat-intel fetches; argv-based bounded brute-force subprocesses with temp-secret cleanup; masked report secrets; owner-only DB/report/.env permissions; serialized Metasploit handler commands; and non-destructive startup port selection.

This remains a dual-use authorized security-testing tool. Use only on systems you own or have explicit permission to test.
