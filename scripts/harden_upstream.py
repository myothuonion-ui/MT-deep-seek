#!/usr/bin/env python3
"""Apply MT security hardening to pinned KMN-CyberSeek v2.3.3.

Critical transforms are fail-closed: if the pinned upstream layout changes, the
bootstrap job stops instead of publishing a partially-hardened tree.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    p = ROOT / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def exact(path: str, old: str, new: str, *, expected: int = 1, required: bool = True) -> None:
    text = read(path)
    count = text.count(old)
    if count != expected:
        if required:
            raise RuntimeError(f"{path}: expected {expected} match(es), found {count}: {old[:100]!r}")
        return
    write(path, text.replace(old, new))


def rx(path: str, pattern: str, repl: str, *, required: bool = True, flags: int = 0) -> None:
    text = read(path)
    out, count = re.subn(pattern, repl, text, count=1, flags=flags)
    if count != 1:
        if required:
            raise RuntimeError(f"{path}: expected one regex match, found {count}: {pattern[:120]!r}")
        return
    write(path, out)


# ── P0: operator intent + execution policy boundary ─────────────────────────
exact(
    "frontend.py",
    '''                auto_approval = st.checkbox(\n                    "Auto-approve low-risk commands",\n                    value=True,\n                    help="Automatically execute low-risk commands without manual approval"\n                )''',
    '''                auto_approval = st.checkbox(\n                    "Full autonomy (all risk levels)",\n                    value=False,\n                    help=("Explicitly allow autonomous execution across all risk levels. "\n                          "Scope, autonomous allowlists and verifier gates still apply. "\n                          "Use only on isolated targets you own or are authorized to test.")\n                )''',
)

# Strict AI response schema and explicit provider precedence.
exact("ai/connector.py", "from typing import Dict, List, Optional, Any", "from typing import Dict, List, Optional, Any, Literal")
exact(
    "ai/connector.py",
    '''class AIResponse(BaseModel):\n    """Standardized AI response format."""\n    reasoning: str = Field(..., description="AI's thought process and analysis")\n    suggested_command: str = Field(..., description="Command to execute")\n    risk_level: str = Field(..., description="low/medium/high risk classification")\n    target_info: Optional[Dict[str, Any]] = Field(None, description="Additional target information")\n    confidence: float = Field(0.0, description="Confidence score (0.0 to 1.0)")\n    attack_phase: str = Field(..., description="Current attack phase: osint, reconnaissance, enumeration, vulnerability_analysis, exploitation, post_exploitation, privilege_escalation, lateral_movement, credential_reuse")''',
    '''class AIResponse(BaseModel):\n    """Strict AI response consumed by deterministic execution policy gates."""\n    reasoning: str = Field(..., min_length=1, description="AI analysis")\n    suggested_command: str = Field(..., description="Command proposed for policy review")\n    risk_level: Literal["low", "medium", "high"]\n    target_info: Optional[Dict[str, Any]] = None\n    confidence: float = Field(0.0, ge=0.0, le=1.0)\n    attack_phase: Literal[\n        "osint", "reconnaissance", "enumeration", "vulnerability_analysis",\n        "exploitation", "post_exploitation", "privilege_escalation",\n        "lateral_movement", "credential_reuse"\n    ]''',
)
rx(
    "ai/connector.py",
    r'''        # FORCE API mode if we have a valid, non-placeholder API key\n        is_valid_api_key = \(.*?        # URLs for different providers''',
    '''        # Explicit provider selection wins over key auto-detection. A stale cloud\n        # key must never silently override an operator-selected local provider.\n        is_valid_api_key = (\n            self.api_key and len(self.api_key) > 10 and\n            not any(pattern in self.api_key.lower() for pattern in placeholder_patterns)\n        )\n        configured_provider = (os.getenv("AI_PROVIDER") or "").strip().lower()\n        requested_provider = (provider or configured_provider or ("api" if is_valid_api_key else "local")).lower()\n        if requested_provider not in {"local", "api"}:\n            requested_provider = "local"\n        if requested_provider == "api" and is_valid_api_key:\n            self.provider = "api"\n        elif requested_provider == "api":\n            logger.warning("API provider selected without a valid API key; falling back to local.")\n            self.provider = "local"\n            self.api_key = None\n        else:\n            self.provider = "local"\n            self.api_key = None\n        logger.info(f"Using AI provider: {self.provider}")\n\n        # URLs for different providers''',
    flags=re.S,
)
exact(
    "ai/connector.py",
    '            mem_block = f"\\n\\n=== SESSION MEMORY ===\\n{trimmed_memory}"',
    '            mem_block = ("\\n\\n<<<UNTRUSTED_SESSION_MEMORY>>>\\n" + trimmed_memory + "\\n<<<END_UNTRUSTED_SESSION_MEMORY>>>")',
)
exact(
    "ai/connector.py",
    '                mem_block = f"\\n\\n=== SESSION MEMORY ===\\n{trimmed}"',
    '                mem_block = ("\\n\\n<<<UNTRUSTED_SESSION_MEMORY>>>\\n" + trimmed + "\\n<<<END_UNTRUSTED_SESSION_MEMORY>>>")',
)

# Deny-by-default target scope. FULL_AUTO never disables the structural allowlist.
exact(
    "core/validators.py",
    '''    If allowlist_str is empty/unset, scope is unrestricted (default, backward\n    compatible for solo/homelab use). Set SCOPE_ALLOWLIST in .env to enforce a\n    hard technical boundary on what this tool is permitted to target.''',
    '''    Scope is deny-by-default. If allowlist_str is empty/unset, targets are\n    rejected unless ALLOW_UNSCOPED_TARGETS=true is explicitly configured.''',
)
exact(
    "core/validators.py",
    '        return True  # No allowlist configured -> unrestricted',
    '        return os.getenv("ALLOW_UNSCOPED_TARGETS", "false").lower() == "true"',
)
exact(
    "core/validators.py",
    '    if not entries:\n        return True',
    '    if not entries:\n        return os.getenv("ALLOW_UNSCOPED_TARGETS", "false").lower() == "true"',
)
exact(
    "core/validators.py",
    '_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")',
    '''_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")\n\n# General-purpose interpreters make a binary allowlist equivalent to arbitrary\n# code execution. Autonomous mode routes these to human review.\nAUTO_DENIED_BINARIES = {\n    "bash", "sh", "zsh", "dash", "fish", "python", "python2", "python3",\n    "perl", "ruby", "php", "node", "nodejs", "powershell", "pwsh",\n}''',
)
exact(
    "core/validators.py",
    '''    When FULL_AUTO_MODE=true in the environment this check is bypassed entirely —\n    the operator has explicitly opted into unrestricted AI-driven execution.\n\n    NOT applied to commands a human explicitly typed or clicked "approve" on —''',
    '''    FULL_AUTO_MODE bypasses routine approval, but never bypasses this structural\n    allowlist. Human-reviewed commands remain a separate trust boundary.\n\n    NOT applied to commands a human explicitly typed or clicked "approve" on —''',
)
exact(
    "core/validators.py",
    '''    # FULL_AUTO_MODE bypasses the allowlist entirely.\n    if os.getenv("FULL_AUTO_MODE", "false").lower() == "true":\n        return None\n\n''',
    "",
)
exact(
    "core/validators.py",
    '''        binary = os.path.basename(tokens[idx])\n        if binary not in ALLOWED_BINARIES:''',
    '''        binary = os.path.basename(tokens[idx])\n        if binary in AUTO_DENIED_BINARIES:\n            return f"Interpreter '{binary}' requires human review in autonomous mode"\n        if binary not in ALLOWED_BINARIES:''',
)

# Orchestrator: persistence permissions, configurable approval, safe credential quoting.
exact("core/orchestrator.py", '        self.db_path = "kmn_cyberseek.db"', '        self.db_path = os.getenv("DB_PATH", "kmn_cyberseek.db")')
exact(
    "core/orchestrator.py",
    '''            conn.commit()\n            conn.close()\n            logger.info(f"Database initialized at {self.db_path}")''',
    '''            conn.commit()\n            conn.close()\n            try:\n                os.chmod(self.db_path, 0o600)\n            except OSError:\n                pass\n            logger.info(f"Database initialized at {self.db_path}")''',
)
exact(
    "core/orchestrator.py",
    '        command_lower = command.lower()\n\n        # Exact substring patterns',
    '        if os.getenv("REQUIRE_APPROVAL_HIGH_RISK", "true").lower() not in {"1", "true", "yes", "on"}:\n            return False\n        command_lower = command.lower()\n\n        # Exact substring patterns',
)
# Two raw -U append paths (smbclient and rpcclient).
exact(
    "core/orchestrator.py",
    '            command += f" -U \'{user}%{passwd}\'"',
    '            command += " -U " + shlex.quote(f"{user}%{passwd}")',
    expected=2,
)
exact(
    "core/orchestrator.py",
    '                command = re.sub(r\'\'\'-U\\s+["\']["\']\'\'\', f"-U \'{user}%{passwd}\'", command)',
    '                command = re.sub(r\'\'\'-U\\s+["\']["\']\'\'\', "-U " + shlex.quote(f"{user}%{passwd}"), command)',
)
exact(
    "core/orchestrator.py",
    '                    lambda m: f"{user}:{passwd}@{m.group(0)}",',
    '                    lambda m: shlex.quote(f"{user}:{passwd}@{m.group(0)}"),',
)
exact(
    "core/orchestrator.py",
    '            parts = [f"  {user}:{secret}  [{stype}]  service={service}"]',
    '            parts = [f"  credential_user={user}  [secret:{stype}:stored-locally]  service={service}"]',
)

# Initial AI command now goes through allowlist + verifier before autonomous execution.
rx(
    "core/orchestrator.py",
    r'''            # Kick off execution or queue for approval\.\n            # When auto_approve=True.*?                logger\.info\(f"Initial command queued for approval: \{_cmd\[:100\]\}"\)''',
    '''            # Kick off execution or queue for approval through the same safety\n            # boundary used by subsequent loop turns.\n            if FULL_AUTO_MODE or session.auto_approve:\n                _candidate = _cmd\n                _allow_err = is_allowlisted_command(_candidate)\n                if _allow_err:\n                    self.queue_for_approval(session_id, _candidate)\n                    logger.warning(f"Initial auto-exec blocked by allowlist: {_allow_err}")\n                elif ai_response.risk_level == "high":\n                    vet = await self._vet_command(session_id, _candidate, ai_response.reasoning or "")\n                    if vet.get("verdict") == "reject":\n                        self.queue_for_approval(session_id, _candidate)\n                        logger.warning(f"Initial high-risk command rejected by verifier: {vet.get('reason','')}")\n                    else:\n                        _candidate = vet.get("command") or _candidate\n                        _allow_err = is_allowlisted_command(_candidate)\n                        if _allow_err:\n                            self.queue_for_approval(session_id, _candidate)\n                        else:\n                            asyncio.create_task(self.execute_command(session_id, _candidate))\n                else:\n                    asyncio.create_task(self.execute_command(session_id, _candidate))\n            else:\n                self.queue_for_approval(session_id, _cmd)\n                logger.info(f"Initial command queued for approval: {_cmd[:100]}")''',
    flags=re.S,
)

# Runtime settings update persistence + os.environ + module global consistently.
exact("main.py", '    set_key(env_path, "AI_PROVIDER", provider_code)', '    set_key(env_path, "AI_PROVIDER", provider_code)\n    os.environ["AI_PROVIDER"] = provider_code')
exact(
    "main.py",
    '''        gname = _orch.set_feature_flag(ui_name, val)\n        if gname:\n            try:''',
    '''        gname = _orch.set_feature_flag(ui_name, val)\n        if gname:\n            os.environ[gname] = "true" if val else "false"\n            try:''',
)
exact(
    "main.py",
    '    os.environ["FULL_AUTO_MODE"] = str(settings.full_auto_mode).lower()\n    os.environ["OLLAMA_CONTEXT_WINDOW"] = str(settings.ollama_context_window)',
    '    os.environ["FULL_AUTO_MODE"] = str(settings.full_auto_mode).lower()\n    import core.orchestrator as _orch\n    _orch.set_feature_flag("full_auto_mode", settings.full_auto_mode)\n    os.environ["OLLAMA_CONTEXT_WINDOW"] = str(settings.ollama_context_window)',
)
exact(
    "main.py",
    '    set_key(env_path, "REQUIRE_APPROVAL_HIGH_RISK", str(settings.require_approval_high_risk).lower())',
    '    set_key(env_path, "REQUIRE_APPROVAL_HIGH_RISK", str(settings.require_approval_high_risk).lower())\n    os.environ["REQUIRE_APPROVAL_HIGH_RISK"] = str(settings.require_approval_high_risk).lower()',
)

# ── P1: SSRF, subprocess/temp cleanup, secret exports, startup safety ─────────
exact("core/threat_intel.py", "import logging\nimport re", "import ipaddress\nimport logging\nimport re\nimport socket")
exact("core/threat_intel.py", "from urllib.parse import quote_plus", "from urllib.parse import quote_plus, urljoin, urlsplit")
rx(
    "core/threat_intel.py",
    r'''async def _fetch\(url: str\) -> Optional\[str\]:\n.*?\n\nasync def _search_candidate_urls''',
    '''def _url_is_public(url: str) -> bool:\n    """Reject non-HTTP URLs and destinations resolving to non-global addresses."""\n    try:\n        parsed = urlsplit(url)\n        if parsed.scheme not in {"http", "https"} or not parsed.hostname:\n            return False\n        if parsed.username or parsed.password:\n            return False\n        port = parsed.port or (443 if parsed.scheme == "https" else 80)\n        infos = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)\n        addresses = {ipaddress.ip_address(info[4][0]) for info in infos}\n        return bool(addresses) and all(addr.is_global for addr in addresses)\n    except Exception:\n        return False\n\n\nasync def _fetch(url: str) -> Optional[str]:\n    """Bounded public-web fetch with redirect-by-redirect SSRF validation."""\n    current = url\n    try:\n        async with httpx.AsyncClient(timeout=_FETCH_TIMEOUT, follow_redirects=False) as client:\n            for _ in range(4):\n                if not _url_is_public(current):\n                    logger.warning(f"Threat-intel blocked non-public URL: {current}")\n                    return None\n                async with client.stream("GET", current, headers={"User-Agent": USER_AGENT}) as resp:\n                    if 300 <= resp.status_code < 400 and resp.headers.get("location"):\n                        current = urljoin(current, resp.headers["location"])\n                        continue\n                    resp.raise_for_status()\n                    data = bytearray()\n                    async for chunk in resp.aiter_bytes():\n                        room = _MAX_PAGE_CHARS - len(data)\n                        if room <= 0:\n                            break\n                        data.extend(chunk[:room])\n                    return bytes(data).decode(resp.encoding or "utf-8", errors="replace")\n            logger.warning(f"Threat-intel redirect limit exceeded: {url}")\n            return None\n    except Exception as e:\n        logger.warning(f"Threat-intel fetch failed for {url} (non-fatal, skipping): {e}")\n        return None\n\n\nasync def _search_candidate_urls''',
    flags=re.S,
)

# Brute-force worker: no shell, validate host/port, process-group timeout, cleanup temp secrets.
exact("core/bruteforce_worker.py", "import os\nimport shutil", "import os\nimport shutil\nimport signal")
exact(
    "core/bruteforce_worker.py",
    "from typing import Awaitable, Callable, Dict, List, Optional",
    "from typing import Awaitable, Callable, Dict, List, Optional\n\nfrom core.validators import is_valid_target",
)
rx(
    "core/bruteforce_worker.py",
    r'''    async def _default_attack_runner\(.*?\n    @staticmethod\n    def _head''',
    '''    async def _default_attack_runner(\n        self, service: str, host: str, port, users: List[str], passwords: List[str]\n    ) -> List[Dict]:\n        """Run hydra/netexec without a shell; keep temp credentials private and bounded."""\n        tool = _SERVICE_TOOL.get(service)\n        if not tool or not shutil.which(tool) or not is_valid_target(host):\n            return []\n        try:\n            port_i = int(port)\n            if not 1 <= port_i <= 65535:\n                return []\n        except (TypeError, ValueError):\n            return []\n        temp_paths: List[str] = []\n        try:\n            import tempfile\n            uf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".u")\n            os.chmod(uf.name, 0o600)\n            temp_paths.append(uf.name)\n            uf.write("\\n".join(users)); uf.close()\n            if passwords and passwords[0].startswith("@file:"):\n                _, path, n = passwords[0].split(":", 2)\n                pf_path = path if n == "0" else self._head(path, int(n))\n                if n != "0":\n                    os.chmod(pf_path, 0o600)\n                    temp_paths.append(pf_path)\n            else:\n                pf = tempfile.NamedTemporaryFile("w", delete=False, suffix=".p")\n                os.chmod(pf.name, 0o600)\n                temp_paths.append(pf.name)\n                pf.write("\\n".join(passwords)); pf.close()\n                pf_path = pf.name\n            if tool == "hydra":\n                argv = ["hydra", "-L", uf.name, "-P", pf_path, "-f", "-o", "/dev/stdout", "-t", "4", f"{service}://{host}:{port_i}"]\n            else:\n                argv = [tool, service, host, "-u", uf.name, "-p", pf_path, "--continue-on-success"]\n            proc = await asyncio.create_subprocess_exec(\n                *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,\n                start_new_session=True,\n            )\n            try:\n                out, _ = await asyncio.wait_for(proc.communicate(), timeout=_max_seconds())\n            except asyncio.TimeoutError:\n                try:\n                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)\n                except (ProcessLookupError, PermissionError, OSError):\n                    proc.kill()\n                await proc.wait()\n                return []\n            return self._parse_hits(out.decode(errors="replace"), service, host, port_i)\n        except Exception as e:\n            logger.warning(f"bruteforce runner error: {e}")\n            return []\n        finally:\n            for path in temp_paths:\n                try:\n                    os.unlink(path)\n                except OSError:\n                    pass\n\n    @staticmethod\n    def _head''',
    flags=re.S,
)

# Serialize commands per Metasploit handler to avoid output-marker races.
exact(
    "core/shell_manager.py",
    '        self._marker_event: asyncio.Event    = asyncio.Event()\n        self._buf_snapshot_start: int        = 0',
    '        self._marker_event: asyncio.Event    = asyncio.Event()\n        self._buf_snapshot_start: int        = 0\n        self._command_lock: asyncio.Lock      = asyncio.Lock()',
)
exact(
    "core/shell_manager.py",
    '    async def run_command(self, msf_id: int, command: str) -> str:\n        """Run a command in an active session and return captured output."""',
    '    async def run_command(self, msf_id: int, command: str) -> str:\n        """Serialize per-handler command execution to protect marker correlation."""\n        async with self._command_lock:\n            return await self._run_command_locked(msf_id, command)\n\n    async def _run_command_locked(self, msf_id: int, command: str) -> str:\n        """Run a command in an active session and return captured output."""',
)

# Reports mask raw secrets unless operator explicitly opts in; artifacts are owner-only.
exact(
    "core/report_generator.py",
    "logger = logging.getLogger(__name__)",
    '''logger = logging.getLogger(__name__)\n\ndef _display_secret(value) -> str:\n    raw = str(value or "")\n    if os.getenv("INCLUDE_SECRETS_IN_REPORTS", "false").lower() in {"1", "true", "yes", "on"}:\n        return raw\n    return "********" if raw else ""\n\ndef _secure_file(path: str) -> None:\n    try:\n        os.chmod(path, 0o600)\n    except OSError:\n        pass''',
)
text = read("core/report_generator.py")
text = text.replace('(cred.get("secret") or "")[:64]', '_display_secret(cred.get("secret"))')
text = text.replace("(c.get('secret') or '')[:64]", "_display_secret(c.get('secret'))")
text = text.replace('secret = str(c.get("secret", ""))', 'secret = _display_secret(c.get("secret", ""))')
text = text.replace('    return output_path', '    _secure_file(output_path)\n    return output_path')
write("core/report_generator.py", text)

# Startup picks a free port; it never TERM/KILLs an unrelated process by PID.
text = read("start.sh")
text = text.replace('_try_kill_port "$BACKEND_PORT"\n', '')
text = text.replace('_try_kill_port "$FRONTEND_PORT"\n', '')
text = text.replace('_try_kill_port "$DOCS_PORT"\n', '')
text = text.replace('Please install Python 3.8+ first.', 'Please install Python 3.10+ first.')
text = text.replace('    cp .env.example .env 2>/dev/null || touch .env', '    cp .env.example .env 2>/dev/null || touch .env\n    chmod 600 .env 2>/dev/null || true')
write("start.sh", text)

# Secure defaults in env template.
text = read(".env.example")
text = text.replace(
    '# --- Scope Allowlist (optional) ---\n# Comma-separated IPs/CIDRs/hostnames that new sessions are allowed to target.\n# Leave empty to allow any target (default - solo/homelab use). Example:\n# SCOPE_ALLOWLIST=10.0.0.0/8,lab.local,*.lab.local\nSCOPE_ALLOWLIST=',
    '# --- Scope Allowlist (deny-by-default) ---\n# Comma-separated IPs/CIDRs/hostnames that new sessions are allowed to target.\n# Empty means deny all unless ALLOW_UNSCOPED_TARGETS=true is explicitly set.\n# SCOPE_ALLOWLIST=10.0.0.0/8,lab.local,*.lab.local\nSCOPE_ALLOWLIST=\nALLOW_UNSCOPED_TARGETS=false',
)
text = text.replace('AUTO_APPROVE_LOW_RISK=true', 'AUTO_APPROVE_LOW_RISK=false')
text = text.replace(
    '# When true, the AI executes ALL suggested commands without human approval,\n# regardless of risk level, keyword backstop, or binary allowlist.',
    '# When true, the AI may execute across risk levels without routine approval,\n# but scope, autonomous allowlists/interpreter blocks and verifier gates remain enforced.',
)
if "INCLUDE_SECRETS_IN_REPORTS=" not in text:
    text += '\n# Sensitive exports are masked unless explicitly enabled for a controlled report.\nINCLUDE_SECRETS_IN_REPORTS=false\nREQUIRE_APPROVAL_HIGH_RISK=true\n'
write(".env.example", text)

# Existing tests: hardened scope semantics + autonomous interpreter rejection.
exact(
    "tests/test_validators.py",
    '''def test_scope_unrestricted_when_empty():\n    assert is_target_in_scope("8.8.8.8", "")\n    assert is_target_in_scope("8.8.8.8", None)''',
    '''def test_scope_denied_when_empty():\n    import os\n    old = os.environ.pop("ALLOW_UNSCOPED_TARGETS", None)\n    try:\n        assert not is_target_in_scope("8.8.8.8", "")\n        assert not is_target_in_scope("8.8.8.8", None)\n        os.environ["ALLOW_UNSCOPED_TARGETS"] = "true"\n        assert is_target_in_scope("8.8.8.8", "")\n    finally:\n        if old is None:\n            os.environ.pop("ALLOW_UNSCOPED_TARGETS", None)\n        else:\n            os.environ["ALLOW_UNSCOPED_TARGETS"] = old''',
)
exact(
    "tests/test_validators.py",
    '    assert is_allowlisted_command("wpscan --url http://x --batch") is None',
    '    assert is_allowlisted_command("wpscan --url http://x --batch") is None\n    assert is_allowlisted_command("python3 -c \'print(1)\'") is not None',
)

# New hardening regressions.
write(
    "tests/test_mt_security_hardening.py",
    '''import os\nfrom pydantic import ValidationError\n\nfrom ai.connector import AIResponse, KMN_AI_Connector\nfrom core.validators import is_allowlisted_command, is_target_in_scope\nfrom core.threat_intel import _url_is_public\nfrom core.report_generator import _display_secret\n\n\ndef test_ai_response_schema_is_strict():\n    try:\n        AIResponse(reasoning="x", suggested_command="echo ok", risk_level="HIGH", confidence=2, attack_phase="reconnaissance")\n        assert False, "invalid enum/range should fail"\n    except ValidationError:\n        pass\n\ndef test_explicit_local_provider_beats_stale_api_key():\n    old = os.environ.get("DEEPSEEK_API_KEY")\n    os.environ["DEEPSEEK_API_KEY"] = "sk-real-looking-stale-key-123456789"\n    try:\n        c = KMN_AI_Connector(provider="local")\n        assert c.provider == "local"\n        assert c.api_key is None\n    finally:\n        if old is None:\n            os.environ.pop("DEEPSEEK_API_KEY", None)\n        else:\n            os.environ["DEEPSEEK_API_KEY"] = old\n\ndef test_scope_is_deny_by_default():\n    old = os.environ.pop("ALLOW_UNSCOPED_TARGETS", None)\n    try:\n        assert not is_target_in_scope("8.8.8.8", "")\n    finally:\n        if old is not None:\n            os.environ["ALLOW_UNSCOPED_TARGETS"] = old\n\ndef test_full_auto_does_not_bypass_interpreter_gate():\n    old = os.environ.get("FULL_AUTO_MODE")\n    os.environ["FULL_AUTO_MODE"] = "true"\n    try:\n        assert is_allowlisted_command("python3 -c 'print(1)'") is not None\n    finally:\n        if old is None:\n            os.environ.pop("FULL_AUTO_MODE", None)\n        else:\n            os.environ["FULL_AUTO_MODE"] = old\n\ndef test_report_secrets_mask_by_default():\n    old = os.environ.pop("INCLUDE_SECRETS_IN_REPORTS", None)\n    try:\n        assert _display_secret("hunter2") == "********"\n    finally:\n        if old is not None:\n            os.environ["INCLUDE_SECRETS_IN_REPORTS"] = old\n\ndef test_ssrf_guard_blocks_local_addresses():\n    assert not _url_is_public("http://127.0.0.1/admin")\n    assert not _url_is_public("http://169.254.169.254/latest/meta-data/")\n''',
)

write(
    "scripts/security_gate.py",
    '''#!/usr/bin/env python3\nfrom pathlib import Path\n\nrequired = {\n    "frontend.py": ["Full autonomy (all risk levels)", "value=False"],\n    "core/validators.py": ["AUTO_DENIED_BINARIES", "ALLOW_UNSCOPED_TARGETS"],\n    "core/threat_intel.py": ["_url_is_public", "follow_redirects=False"],\n    "core/report_generator.py": ["_display_secret", "INCLUDE_SECRETS_IN_REPORTS"],\n    "ai/connector.py": ["Literal[\\\"low\\\", \\\"medium\\\", \\\"high\\\"]", "UNTRUSTED_SESSION_MEMORY"],\n}\nfor path, needles in required.items():\n    text = Path(path).read_text(encoding="utf-8")\n    for needle in needles:\n        if needle not in text:\n            raise SystemExit(f"security gate failed: {needle!r} missing from {path}")\n\nforbidden = {\n    "core/orchestrator.py": ["parts = [f\\\"  {user}:{secret}", "-U '{user}%{passwd}'"],\n    "core/validators.py": ["FULL_AUTO_MODE bypasses the allowlist entirely"],\n}\nfor path, needles in forbidden.items():\n    text = Path(path).read_text(encoding="utf-8")\n    for needle in needles:\n        if needle in text:\n            raise SystemExit(f"security gate failed: forbidden pattern {needle!r} in {path}")\nprint("MT security gate: PASS")\n''',
)

write(
    "pyproject.toml",
    '''[tool.pytest.ini_options]\nasyncio_mode = "auto"\ntestpaths = ["tests"]\n\n[tool.ruff]\ntarget-version = "py310"\nline-length = 120\n''',
)

exact("_version.py", '__version__ = "2.3.3"', '__version__ = "2.4.0-hardened.1"')
write(
    "SECURITY_HARDENING.md",
    '''# MT Security Hardening\n\nPinned baseline: KMN-CyberSeek v2.3.3, commit `3e8b08a36c6af989f30c1d564f1a1c00579dbf43`.\n\nChanges include deny-by-default target scope; autonomous interpreter blocking; no FULL_AUTO allowlist bypass; strict AI response enums/ranges; explicit local-provider precedence; untrusted-memory fencing; initial-command allowlist/verifier enforcement; shell-safe captured credential injection; local-only credential memory; SSRF/redirect validation for threat-intel fetches; argv-based bounded brute-force subprocesses with temp-secret cleanup; masked report secrets; owner-only DB/report/.env permissions; serialized Metasploit handler commands; and non-destructive startup port selection.\n\nThis remains a dual-use authorized security-testing tool. Use only on systems you own or have explicit permission to test.\n''',
)

print("MT hardening applied successfully")
