Warning: truncated output (original token count: 69558)
Total output lines: 5786

"""
MT Pentester Orchestrator Module
Manages penetration testing sessions, coordinates between AI, scanner, and execution.
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import shlex
import signal
import sqlite3
import subprocess
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any

# ---------------------------------------------------------------------------
# Credential extraction patterns
# Ordered from most to least specific. All patterns must have exactly 2 groups:
# (username, password) - or (hash, cracked_password) for hash-cracker output.
# ---------------------------------------------------------------------------
_CRED_PATTERNS: List[re.Pattern] = [
    # hydra: [22][ssh] host: 10.0.0.1   login: admin   password: password123
    re.compile(r'\[\d+\]\[\w+\]\s+host:\s*\S+\s+login:\s*(\S+)\s+password:\s*(\S+)', re.IGNORECASE),
    # medusa: ACCOUNT FOUND: [ssh] Host: 10.0.0.1 User: admin Password: secret
    re.compile(r'ACCOUNT FOUND.*User:\s*(\S+)\s+Password:\s*(\S+)', re.IGNORECASE),
    # ncrack: Discovered credentials ... on ... 22/tcp ... 'admin' 'pass'
    re.compile(r"Discovered credentials.*?'([^']+)'\s+'([^']+)'", re.IGNORECASE),
    # crackmapexec: [+] IP\user:pass (Pwn3d!) or without domain
    re.compile(r'\[\+\]\s+[\w.\-]+\\(\w+):(\S+)', re.IGNORECASE),
    # nmap NSE http-auth-finder / http-brute style: username: admin  password: secret
    re.compile(r'username[:\s]+(\S+)[,\s]+password[:\s]+(\S+)', re.IGNORECASE),
    # john/hashcat cracked: HASH (PASSWORD) — two groups: (hash, cracked_password)
    re.compile(r'^(\S+)\s+\((.+?)\)\s*$', re.MULTILINE),  # john --show style
    re.compile(r'^([^:]+):([^:]+):\d+:\d+:::',  re.MULTILINE),  # /etc/shadow dump - user:hash
]

from ai.connector import MTPentesterAIConnector, AIResponse
from ai.providers import normalize_provider, public_provider_catalog
from core.model_router import ModelRouter
from core.scanner import Scanner
from core.memory_index import FindingsIndex
from core.skill_router import ClaudeSkillRouter
from core.validators import (
    autonomous_scope_rejection,
    is_allowlisted_command,
    is_cidr,
    is_target_in_scope,
    is_valid_target,
    parse_autonomous_argv,
)
from core import cve_lookup
from core import threat_intel
from core.shell_manager import ShellManager, get_local_ip, COMMON_PAYLOADS
from core import playbooks as _playbooks
from core import coverage as _coverage
from core import vuln_validate as _vuln_validate
from core import exploit_map as _exploit_map
from core.bruteforce_worker import BruteforceWorker

logger = logging.getLogger(__name__)

# How long to wait for a single executed command before killing it (seconds).
# Configurable since brute-force/full-port-range tools can legitimately run long.
COMMAND_TIMEOUT = int(os.getenv("COMMAND_TIMEOUT", "600"))

# FULL_AUTO_MODE bypasses keyword/risk approval, but never the structural
# allowlist, per-command scope check, or argv-only autonomous execution boundary.
# Session-level authorization_confirmed is also required to create a session.
FULL_AUTO_MODE: bool = os.getenv("FULL_AUTO_MODE", "false").lower() == "true"

# COVERAGE_ENGINE: when true, the orchestrator drives a per-service methodology
# (playbooks) and derives objective progress from measured coverage. Default ON —
# toggleable at runtime from the Settings page (no .env editing required).
COVERAGE_ENGINE: bool = os.getenv("COVERAGE_ENGINE", "true").lower() == "true"

# BRUTEFORCE_ENABLED: run the decoupled brute-force worker against discovered auth
# services (produces credentials the main loop reuses). Default ON.
BRUTEFORCE_ENABLED: bool = os.getenv("BRUTEFORCE_ENABLED", "true").lower() == "true"

# Feature flags exposed to the Settings UI. Names map to the module globals above
# (and FULL_AUTO_MODE). Toggling updates the live global immediately AND is
# persisted to .env by the API so it survives a restart.
_FEATURE_FLAGS = {
    "coverage_engine": "COVERAGE_ENGINE",
    "bruteforce_enabled": "BRUTEFORCE_ENABLED",
    "full_auto_mode": "FULL_AUTO_MODE",
}


def get_feature_flags() -> Dict[str, bool]:
    """Current values of the user-toggleable feature flags."""
    return {ui: bool(globals().get(gname, False)) for ui, gname in _FEATURE_FLAGS.items()}


def set_feature_flag(ui_name: str, enabled: bool) -> Optional[str]:
    """Update a feature flag's live value. Returns the .env key name on success,
    or None if the flag is unknown. Persistence to .env is the caller's job."""
    gname = _FEATURE_FLAGS.get(ui_name)
    if not gname:
        return None
    globals()[gname] = bool(enabled)
    logger.info(f"Feature flag {gname} set to {bool(enabled)} (runtime)")
    return gname

# Canonical stage progression order. The AI reports attack_phase in its JSON
# responses; this list is the source of truth for valid transitions.
# Rules enforced by _advance_stage():
#   1. Stage can only move FORWARD (never regress to an earlier stage).
#   2. Stage can skip at most 1 step per AI response (prevents 5-command full-run).
_STAGE_ORDER: List[str] = [
    "osint",
    "reconnaissance",
    "enumeration",
    "vulnerability_analysis",
    "exploitation",
    "post_exploitation",
    "privilege_escalation",
    "lateral_movement",
    "credential_reuse",
]
_STAGE_INDEX: Dict[str, int] = {s: i for i, s in enumerate(_STAGE_ORDER)}

# Stages at which a reverse-shell listener should already be running so any
# session the AI catches is delivered to the monitored multi/handler.
_EXPLOIT_STAGES = frozenset({
    "exploitation",
    "post_exploitation",
    "privilege_escalation",
    "lateral_movement",
    "credential_reuse",
})


def _advance_stage(current: str, proposed: str) -> str:
    """Return the stage the session should move to.

    Guarantees:
    - Never regresses (if proposed is earlier than current, keep current).
    - Skips at most 1 stage per call (AI can't jump from recon → credential_reuse
      in a single decision — it must walk through each phase).
    """
    curr_idx = _STAGE_INDEX.get(current, 0)
    prop_idx = _STAGE_INDEX.get(proposed, curr_idx)

    if prop_idx <= curr_idx:
        # Regression attempt or same stage — stay where we are.
        return current

    # Allow at most one-step advancement per AI decision.
    next_idx = min(prop_idx, curr_idx + 1)
    return _STAGE_ORDER[next_idx]


def _detect_exhausted_target(cmds: List[str], stage: str) -> str:
    """Heuristic: detect which service/attack-vector the AI was repeatedly attempting.

    Scans the normalised text of recent commands and returns a short label that
    is added to session.exhausted_services so the AI knows to skip it.
    Falls back to a stage-scoped label if no specific tool is recognisable.
    """
    joined = " ".join(cmds).lower()
    # SMB family
    if any(t in joined for t in ["smbclient", "enum4linux", "smbmap", "rpcclient",
                                  "crackmapexec smb", "nxc smb", "nmap -p 139,445",
                                  "nmap -p445", "nmap -p 445"]):
        return "smb"
    # FTP
    if "ftp" in joined and ("nmap" not in joined or "ftp" in joined.replace("nmap", "")):
        return "ftp"
    # Tomcat
    if "8080" in joined or "tomcat" in joined or "manager/html" in joined:
        return "tomcat_8080"
    # GlassFish
    if any(p in joined for p in ["4848", "8181", "glassfish"]):
        return "glassfish"
    # SSH brute-force
    if "hydra" in joined and "ssh" in joined:
        return "ssh_bruteforce"
    if "medusa" in joined and "ssh" in joined:
        return "ssh_bruteforce"
    # Web directory brute
    if any(t in joined for t in ["gobuster", "dirb", "ffuf", "dirbuster"]):
        return "web_dir_enum"
    # Nikto
    if "nikto" in joined:
        return "nikto_web"
    # Metasploit exploit module
    if "exploit/" in joined or "auxiliary/" in joined:
        return f"msf_{stage}"
    # RDP
    if "3389" in joined or "rdp" in joined:
        return "rdp"
    # SNMP
    if "snmp" in joined or "161" in joined:
        return "snmp"
    # Fallback: label by stage
    return f"{stage}_exhausted"


# Service test-lifecycle ordering. Transitions only ever move a service UP this
# ladder (a tested service never reverts to untested).
_SERVICE_STATE_ORDER: Dict[str, int] = {
    "untested": 0,
    "in_progress": 1,
    "tested": 2,
    "exploited": 3,
}

# Output signals that a service was not merely probed but actually compromised /
# yielded sensitive data — used to promote a service straight to 'exploited'.
#
# These are intentionally NARROW. Broad words like "password", "hash", "200 ok",
# and "database" were removed because they appear in normal recon output (web login
# pages, whatweb CMS detection, HTTP status lines) and would incorrectly mark
# services as exploited after routine enumeration.
_EXPLOIT_SIGNALS = (
    "meterpreter",
    "session opened",
    "session 1 opened",
    "shell opened",
    "command shell session",
    "uid=0",                    # root shell (not generic uid=www-data etc.)
    "pwn3d",                    # crackmapexec success marker
    "root@",                    # root prompt in captured output
    "reverse shell",
    "dumped",                   # credential dump tools (secretsdump, mimikatz)
    "flag{",                    # CTF-style flag capture
)

# Commands that merely ENUMERATE and routinely print "NT AUTHORITY\SYSTEM" (as a
# well-known SID) — these must NOT be treated as a compromise on that string alone.
_ENUM_ONLY_TOOLS = (
    "enum4linux", "rpcclient", "smbmap", "ldapsearch", "nmap ",
    "crackmapexec", "nxc ", "smbclient -l", "smbclient //", "getent",
)


def _is_windows_rce_proof(command: str, output: str) -> bool:
    """True when a command's output proves Windows code execution (web-shell /
    exec giving a SYSTEM/user identity), while excluding enumeration tools that
    merely list the SYSTEM SID. This catches web-shell RCE (e.g. cmd.php?cmd=whoami
    returning 'nt authority\\system') that the Unix/msf-centric signals miss.
    """
    o = (output or "").lower()
    c = (command or "").lower()
    win_identity = (
        "nt authority\\system" in o
        or "nt authority\\local service" in o
        or "nt authority\\network service" in o
        or (bool(re.search(r"\bwhoami\b", c)) and bool(re.search(r"^\w[\w.-]*\\[\w.$-]+", o, re.M)))
    )
    if not win_identity:
        return False
    # Exclude pure-enumeration commands (they print the SYSTEM SID during listing).
    if any(t in c for t in _ENUM_ONLY_TOOLS):
        return False
    return True


def _detect_privilege_level(output: str) -> Optional[str]:
    """Infer the privilege level proven by a command's output, or None if the
    output doesn't clearly show a shell / code-execution context.

    Ordered most-privileged first so 'root' wins over a generic 'user' match.
    """
    o = (output or "").lower()
    # Highest privilege (Unix root / Windows SYSTEM)
    if "uid=0" in o or re.search(r'\broot@', o) or "nt authority\\system" in o:
        return "root/SYSTEM"
    # Windows administrator
    if re.search(r'\badministrator\b', o) and ("whoami" in o or "\\" in o):
        return "administrator"
    # Any confirmed shell but non-privileged user (uid=NNN where NNN != 0)
    if re.search(r'uid=\d+', o) or "meterpreter" in o or "command shell session" in o:
        return "user"
    # Windows non-priv user context from `whoami` (domain\user)
    if re.search(r'\b\w+\\\w+\b', o) and "whoami" in o:
        return "user"
    return None


def _is_local_target(target: str) -> bool:
    """Return True if target is a private, loopback, or link-local IP address.

    Local/private IPs should not be passed to internet-based OSINT tools
    (Google Dorks, crt.sh, theHarvester, Shodan, etc.) — those calls would
    be useless at best and leak the engagement target at worst.
    Returns False for hostnames/domains (they are always treated as public).
    """
    try:
        addr = ipaddress.ip_address(target)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False  # it's a hostname — treat as public


def _is_hostname(target: str) -> bool:
    """True if the target is a hostname/domain (not a bare IP or CIDR)."""
    t = (target or "").strip()
    if not t or "/" in t:
        return False
    try:
        ipaddress.ip_address(t)
        return False  # it's an IP
    except ValueError:
        return True   # it's a hostname


def _cvss_to_risk(score: Optional[float]) -> str:
    """Map a CVSS score to the low/medium/high vocabulary used everywhere else
    in this codebase (there's no 'critical' tier in the UI/prompt, so 9-10 folds
    into 'high')."""
    if score is None:
        return "unknown"
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


class Session:
    """Represents a penetration testing session."""

    def __init__(self, session_id: str, target_ip: str, target_domain: Optional[str] = None,
                 auto_approve: bool = False, authorization_confirmed: bool = False):
        self.session_id = session_id
        self.target_ip = target_ip
        self.target_domain = target_domain
        self.created_at = datetime.now()
        self.status = "initialized"  # initialized, scanning, analyzing, executing, completed, failed
        self.scan_results: List[Dict] = []
        self.discovered_hosts: List[Dict] = []
        self.discovered_services: List[Dict] = []
        self.credentials: List[Dict] = []
        self.commands_executed: List[Dict] = []
        self.ai_decisions: List[Dict] = []
        self.evidence: List[Dict] = []
        self.vulnerabilities: List[Dict] = []
        self.current_stage = "reconnaissance"
        # Agentic loop settings
        self.auto_approve = auto_approve
        self.max_auto_depth = 15  # Maximum consecutive auto-executed commands before requiring human review
        self.auto_depth_counter = 0  # Current count of consecutive auto-executed commands
        self.last_auto_success = False  # Track if last auto-execution found something critical
        # Audit trail: operator confirmed authorization to test this target
        self.authorization_confirmed = authorization_confirmed
        # Domain / web attack surface tracking.
        # Populated incrementally by _auto_parse_tool_output() as recon/enum
        # commands complete in the ReAct loop.
        self.discovered_subdomains: List[str] = []
        self.web_applications: List[Dict] = []      # {url, status_code, title, tech}
        self.discovered_api_endpoints: List[str] = []
        # Context-window management: episode summaries compress older command
        # history into structured text so the AI's memory fits in small-context
        # Ollama models without losing critical findings.
        self.episode_summaries: List[str] = []
        self._episode_cmd_count: int = 0   # commands since last episode summary
        self._EPISODE_SIZE: int = 5        # create a summary every N commands

        # ── Strategic layer (Plan-Act-Observe-Reflect) ────────────────────────
        # The tactical loop (_process_command_output) picks the *next command*.
        # The strategic layer periodically steps back, reflects on the whole
        # engagement, and maintains a plan + objective progress so the AI knows
        # where it is heading and when it is DONE.
        #
        # objective: the engagement goal in plain language. Default is to reach
        #   the highest privilege level and stop. Configurable per session.
        self.objective: str = (
            "Gain the highest privilege level possible on the target "
            "(root / SYSTEM locally, or Domain Admin in an AD environment), "
            "enumerating and documenting every exploitable path, then stop."
        )
        # strategic_plan: ordered list of planned steps produced by the strategist,
        #   e.g. [{"step": "...", "status": "pending|in_progress|done", "rationale": "..."}]
        self.strategic_plan: List[Dict] = []
        # objective_progress: strategist's 0.0-1.0 estimate of how close the
        #   engagement is to the objective, plus a short justification.
        self.objective_progress: float = 0.0
        self.objective_progress_note: str = ""
        # objective_complete: set True by the strategist when the goal is reached.
        #   When True the agentic loop halts auto-execution and reports.
        self.objective_complete: bool = False
        # reflections: rolling list of strategist reflections (compact text).
        self.reflections: List[str] = []
        # Counter driving how often the strategist runs (every _PLANNER_INTERVAL
        # completed commands). Cheaper than reflecting after every single step.
        self._planner_cmd_count: int = 0
        self._PLANNER_INTERVAL: int = int(os.getenv("PLANNER_INTERVAL", "5"))
        # Stage the strategist last reflected on. Lets us trigger a fresh pass
        # whenever the engagement advances a stage (a real milestone) instead of
        # waiting for the every-N-commands cadence — which never fires if the
        # session stalls before N commands, leaving objective_progress frozen.
        self._last_strategist_stage: str = ""

        # Credential-reuse dispatch dedup: fingerprints of reuse commands already
        # generated, so the deterministic trigger never queues the same check twice.
        self._reuse_dispatched: set = set()

        # Auto-pivot: attack vectors that have been exhausted (looped out) and
        # should be skipped. Persisted to DB so pivots survive backend restarts.
        self.exhausted_services: List[str] = []
        # Safety cap: after this many consecutive auto-pivots without advancing
        # the stage, stop and wait for manual intervention.
        self._auto_pivot_count: int = 0
        self._MAX_AUTO_PIVOTS: int = int(os.getenv("MAX_AUTO_PIVOTS", "6"))

        # Empty-response recovery: the LLM (esp. local Ollama / DeepSeek) sometimes
        # returns valid JSON with an EMPTY suggested_command. Without handling, the
        # agentic loop silently halts at status=ready. We retry with an explicit
        # directive up to _MAX_EMPTY_RETRIES, then halt visibly.
        self._empty_response_count: int = 0
        self._MAX_EMPTY_RETRIES: int = int(os.getenv("MAX_EMPTY_RETRIES", "3"))

        # Confirmed compromises: captured whenever a command's output proves code
        # execution / shell access on a service. Each entry:
        #   {service, host, port, command, privilege, signal, proof, timestamp}
        # Surfaced to the AI so it pivots to post-exploitation instead of
        # re-running the same exploit (a common cause of enumeration loops).
        self.compromise_evidence: List[Dict] = []

        # Auto-started Metasploit multi/handler for this engagement. When the AI
        # reaches the exploitation stage the orchestrator spins up a managed
        # listener and records its LHOST/LPORT/payload here so (a) the AI is told
        # to deliver its reverse payloads to THIS listener and (b) any caught
        # session lands in the monitored handler → shows in the Shells tab.
        self.exploit_lhost: str = ""
        self.exploit_lport: int = 0
        self.exploit_payload: str = ""
        self._auto_handler_started: bool = False

        # Operator steering: free-text instructions the user sends mid-engagement
        # ("focus on GlassFish", "skip SMB", "try Ghostcat on 8009"). Injected as a
        # HIGHEST-PRIORITY block into every subsequent AI decision so the human can
        # redirect the autonomous loop without stopping it. Rebuilt on restart from
        # the persisted ai_decisions (context="operator_instruction").
        self.operator_instructions: List[str] = []

        # Status-chat transcript for this session (messenger-style). Each entry:
        #   {"role": "user"|"ai", "text": str, "timestamp": iso}
        # Persisted to the chat_messages table so it survives backend restarts and
        # can be reviewed later.
        self.chat_history: List[Dict] = []

        # Coverage engine (opt-in): per-service methodology coverage, keyed by
        # "host:port". Only populated when COVERAGE_ENGINE is enabled.
        self.service_coverage: Dict[str, dict] = {}

    def to_dict(self) -> Dict:
        """Convert session to dictionary."""
        return {
            "session_id": self.session_id,
            "target_ip": self.target_ip,
            "target_domain": self.target_domain,
            "created_at": self.created_at.isoformat(),
            "status": self.status,
            "current_stage": self.current_stage,
            "scan_results_count": len(self.scan_results),
            "discovered_hosts_count": len(self.discovered_hosts),
            "discovered_services_count": len(self.discovered_services),
            "credentials_count": len(self.credentials),
            "commands_executed_count": len(self.commands_executed),
            "ai_decisions_count": len(self.ai_decisions),
            "evidence_count": len(self.evidence),
            "vulnerabilities_count": len(self.vulnerabilities),
            "authorization_confirmed": self.authorization_confirmed,
            "discovered_subdomains_count": len(self.discovered_subdomains),
            "web_applications_count": len(self.web_applications),
            "api_endpoints_count": len(self.discovered_api_endpoints),
            # Strategic layer state (surfaced to the dashboard so the operator
            # can see the AI's plan, objective progress, and completion status).
            "objective": self.objective,
            "objective_progress": round(self.objective_progress, 2),
            "objective_progress_note": self.objective_progress_note,
            "objective_complete": self.objective_complete,
            "strategic_plan": self.strategic_plan,
            "reflections": self.reflections[-5:],
            "exhausted_services": self.exhausted_services,
            "compromise_evidence": self.compromise_evidence,
            "operator_instructions": self.operator_instructions,
            "chat_history": self.chat_history[-100:],
            "service_coverage": {
                k: {
                    "pct": round(_coverage.coverage_ratio(v) * 100),
                    "state": _coverage.service_state(v),
                    "pending": [st.intent for st in _coverage.pending_steps(v)][:6],
                }
                for k, v in self.service_coverage.items()
            } if self.service_coverage else {},
        }


class Orchestrator:
    """Main orchestrator for AI-driven penetration testing."""
    
    def __init__(self, ai_connector: MTPentesterAIConnector, scanner: Scanner):
        self.ai_connector = ai_connector
        self.scanner = scanner
        self.sessions: Dict[str, Session] = {}
        self.pending_commands: Dict[str, Dict] = {}  # command_id -> command_data
        self.db_path = os.getenv("DB_PATH", "mt_pentester.db")
        # Shared, non-session-scoped reference cache built by threat-intel research
        # (core/threat_intel.py) - see _load_threat_intel_cache()
        self.threat_intel_cache: List[Dict] = []
        # Optional async callable(message_type: str, data: Dict) -> None for
        # broadcasting real-time command output to WebSocket clients. Set by
        # main.py after orchestrator is created: orchestrator.broadcast_callback = broadcast_message
        self.broadcast_callback: Optional[Any] = None
        # Per-session live-output buffer for polling by Streamlit frontend.
        # Keyed by session_id → current running command's accumulated output (last
        # _LIVE_OUTPUT_MAX chars). Cleared when command finishes.
        self._live_output: Dict[str, str] = {}
        _LIVE_OUTPUT_MAX = 8000  # keep last N chars so the buffer doesn't grow forever

        # Shell session managers — one ShellManager per pentest session_id.
        # Each manager holds the persistent msfconsole multi/handler process(es)
        # and tracks active meterpreter/shell connections for that session.
        self._shell_managers: Dict[str, ShellManager] = {}

        # Decoupled brute-force workers — one per pentest session (M5).
        self._brute_workers: Dict[str, BruteforceWorker] = {}

        # ── Stuck-session watchdog ────────────────────────────────────────────
        # Detects sessions wedged in an active status (analyzing/executing) with
        # no progress — a dead asyncio task, a hung await, etc. — and nudges them
        # back into motion, then flags them if nudging doesn't help.
        self._last_activity: Dict[str, float] = {}   # session_id -> monotonic ts
        self._watchdog_nudges: Dict[str, int] = {}    # session_id -> nudge count
        self._WATCHDOG_INTERVAL = int(os.getenv("WATCHDOG_INTERVAL", "60"))
        # A running command self-terminates at COMMAND_TIMEOUT, so anything idle
        # longer than that (plus a buffer) means the driving task has died.
        self._WATCHDOG_STALL = int(
            os.getenv("WATCHDOG_STALL_SECONDS", str(COMMAND_TIMEOUT + 180))
        )
        # 'analyzing'/'ready' have NO command running, so they should never idle
        # for long — a much shorter stall revives a stuck-at-ready session quickly.
        self._WATCHDOG_STALL_IDLE = int(os.getenv("WATCHDOG_STALL_IDLE_SECONDS", "120"))
        self._WATCHDOG_MAX_NUDGES = int(os.getenv("WATCHDOG_MAX_NUDGES", "2"))

        # Initialize database
        self._init_database()

        # Restore incomplete sessions from database.
        # Sessions that were mid-flight (scanning/analyzing/executing) are
        # queued into self._sessions_to_auto_resume so the caller can restart
        # their AI loop after the event loop is running (see auto_resume_sessions).
        self._sessions_to_auto_resume: list = []
        self._restore_sessions()

        # Load the threat-intel reference cache
        self._load_threat_intel_cache()

        logger.info("Orchestrator initialized")
    
    def _init_database(self):
        """Initialize SQLite database for session persistence."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    target_ip TEXT NOT NULL,
                    target_domain TEXT,
                    created_at TIMESTAMP NOT NULL,
                    status TEXT NOT NULL,
                    current_stage TEXT NOT NULL,
                    auto_approve BOOLEAN DEFAULT FALSE,
                    authorization_confirmed BOOLEAN DEFAULT FALSE
                )
            ''')

            # Add auto_approve column if it doesn't exist (for migration)
            try:
                cursor.execute("ALTER TABLE sessions ADD COLUMN auto_approve BOOLEAN DEFAULT FALSE")
            except sqlite3.OperationalError:
                pass  # Column already exists

            # Add authorization_confirmed column if it doesn't exist (for migration)
            try:
                cursor.execute("ALTER TABLE sessions ADD COLUMN authorization_confirmed BOOLEAN DEFAULT FALSE")
            except sqlite3.OperationalError:
                pass  # Column already exists

            # Strategic layer columns (Phase 1 — added as migration so existing DBs upgrade).
            _strategic_cols = [
                ("objective",              "TEXT DEFAULT ''"),
                ("strategic_plan",         "TEXT DEFAULT '[]'"),
                ("reflections",            "TEXT DEFAULT '[]'"),
                ("objective_progress",     "REAL DEFAULT 0.0"),
                ("objective_progress_note","TEXT DEFAULT ''"),
                ("objective_complete",     "BOOLEAN DEFAULT FALSE"),
                ("exhausted_services",     "TEXT DEFAULT '[]'"),
            ]
            for col_name, col_def in _strategic_cols:
                try:
                    cursor.execute(f"ALTER TABLE sessions ADD COLUMN {col_name} {col_def}")
                except sqlite3.OperationalError:
                    pass  # Column already exists
            
            # Create scan results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    scan_data TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            ''')
            
            # Create commands table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    command_id TEXT NOT NULL,
                    command_text TEXT NOT NULL,
                    status TEXT NOT NULL,
                    output TEXT,
                    risk_level TEXT,
                    timestamp TIMESTAMP NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            ''')
            
            # Create evidence table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    evidence_data TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            ''')

            # Create vulnerabilities table - structured findings register, separate from
            # the free-text 'evidence' table so results can be queried/reported on
            # (by CVE, by risk level, by status) instead of grepped out of blobs.
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    host TEXT,
                    port INTEGER,
                    service TEXT,
                    service_version TEXT,
                    name TEXT NOT NULL,
                    description TEXT,
                    risk_level TEXT DEFAULT 'unknown',
                    cve_ids TEXT,             -- JSON array, e.g. ["CVE-2021-41773"]
                    cvss_score REAL,
                    reference_urls TEXT,      -- JSON array of URLs
                    source_tool TEXT NOT NULL,   -- e.g. 'nmap-vuln-script', 'vulners'
                    status TEXT DEFAULT 'confirmed',  -- confirmed, suspected, false_positive, remediated
                    discovered_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            ''')

            # Create credentials table - captures username/password pairs found by
            # brute-force tools (hydra, medusa, ncrack), credential-dump tools
            # (crackmapexec, impacket), and NSE scripts. Populated automatically by
            # _extract_and_store_credentials() after every command execution.
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    secret TEXT NOT NULL,      -- password OR hash (labelled by secret_type)
                    secret_type TEXT DEFAULT 'password',  -- 'password' | 'hash'
                    service TEXT,
                    host TEXT,
                    port INTEGER,
                    source_command TEXT,       -- first 300 chars of the command that found it
                    discovered_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            ''')

            # Create scheduled_scans table - recurring scan configurations.
            # The background scheduler (see core/scheduler.py, wired via main.py)
            # reads this table every minute and auto-creates sessions when due.
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scheduled_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_ip TEXT NOT NULL,
                    target_domain TEXT,
                    label TEXT,                   -- human-readable name
                    schedule_type TEXT NOT NULL,  -- 'daily' | 'weekly' | 'once'
                    schedule_time TEXT NOT NULL,  -- HH:MM (24h, UTC)
                    schedule_day INTEGER,         -- 0=Mon..6=Sun for weekly; NULL for others
                    status TEXT DEFAULT 'active', -- 'active' | 'paused' | 'deleted'
                    next_run TIMESTAMP,
                    last_run TIMESTAMP,
                    last_session_id TEXT,
                    created_at TIMESTAMP NOT NULL
                )
            ''')

            # Create threat_intel table - a shared, non-session-scoped reference cache
            # populated by AI-directed open-web research (core/threat_intel.py).
            # Deliberately NOT tied to any session_id: the goal is a local database
            # that gets more useful over time and future sessions can all draw on it.
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_intel (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    topic TEXT,
                    cve_ids TEXT,              -- JSON array
                    title TEXT NOT NULL,
                    description TEXT,
                    affected_software TEXT,
                    severity TEXT,
                    source_url TEXT NOT NULL,
                    source_tool TEXT DEFAULT 'web-research',
                    verified BOOLEAN DEFAULT FALSE,
                    discovered_at TIMESTAMP NOT NULL
                )
            ''')

            # AI decisions table — persists every reasoning step so the history
            # survives backend restarts.  Separate from 'commands' because not
            # every decision results in a command (loop-prevention, critique-reject,
            # strategist-completion records have no suggested command).
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ai_decisions (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  TEXT NOT NULL,
                    timestamp   TEXT NOT NULL,
                    reasoning   TEXT,
                    suggested_command TEXT,
                    risk_level  TEXT,
                    confidence  REAL,
                    attack_phase TEXT,
                    context     TEXT,
                    model_route_json TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            ''')
            try:
                cursor.execute(
                    "ALTER TABLE ai_decisions ADD COLUMN model_route_json TEXT"
                )
            except sqlite3.OperationalError:
                pass

            # Shell handler config — persists LHOST/LPORT/payload so the user
            # can restart a handler with the same settings after a backend restart.
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS shell_handlers (
                    handler_id  TEXT PRIMARY KEY,
                    session_id  TEXT NOT NULL,
                    lhost       TEXT NOT NULL,
                    lport       INTEGER NOT NULL,
                    payload     TEXT NOT NULL,
                    status      TEXT DEFAULT 'stopped',
                    started_at  TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            ''')

            # Status-chat transcript per session (messenger-style, persisted).
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role       TEXT NOT NULL,
                    text       TEXT NOT NULL,
                    timestamp  TIMESTAMP NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            ''')

            # Shell sessions log — each connected meterpreter/shell session.
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS shell_sessions_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    shell_id    TEXT NOT NULL,
                    handler_id  TEXT NOT NULL,
                    session_id  TEXT NOT NULL,
                    msf_id      INTEGER NOT NULL,
                    shell_type  TEXT NOT NULL,
                    target_ip   TEXT,
                    status      TEXT DEFAULT 'open',
                    opened_at   TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                )
            ''')

            conn.commit()
            conn.close()
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass
            logger.info(f"Database initialized at {self.db_path}")
            
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize database: {e}")
    
    def _save_ai_decision(self, session_id: str, decision: Dict) -> None:
        """Persist a single AI decision record to the database.

        Non-fatal: a write failure is logged as a warning and never propagates
        to the caller — the in-memory list is the source of truth during the
        session; the DB copy is for restart-recovery only.
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO ai_decisions
                       (session_id, timestamp, reasoning, suggested_command,
                        risk_level, confidence, attack_phase, context,
                        model_route_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    session_id,
                    decision.get("timestamp", datetime.now().isoformat()),
                    decision.get("reasoning", ""),
                    decision.get("suggested_command", ""),
                    decision.get("risk_level", ""),
                    decision.get("confidence"),
                    decision.get("attack_phase"),
                    decision.get("context"),
                    json.dumps(decision.get("model_route") or {}),
                ),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.warning(f"Failed to persist AI decision for session {session_id}: {e}")

    def create_session(self, target_ip: str, target_domain: Optional[str] = None,
                      session_name: Optional[str] = None, auto_approve: bool = False,
                      max_auto_depth: int = 5, authorization_confirmed: bool = False,
                      objective: Optional[str] = None) -> str:
        """Create a new penetration testing session.

        Raises:
            ValueError: if the target fails format validation, falls outside an
                configured SCOPE_ALLOWLIST, or authorization was not confirmed.
        """
        # Defense in depth: re-validate here even though the API layer (main.py)
        # already checks this, since this method can be called from other contexts.
        if not is_valid_target(target_ip):
            raise ValueError(f"Invalid target IP/hostname: {target_ip!r}")
        if target_domain and not is_valid_target(target_domain):
            raise ValueError(f"Invalid target domain: {target_domain!r}")

        if not authorization_confirmed:
            raise ValueError(
                "Authorization not confirmed. You must confirm you own this target or have "
                "explicit permission to test it before a session can be created."
            )

        scope_allowlist = os.getenv("SCOPE_ALLOWLIST")
        if not is_target_in_scope(target_ip, scope_allowlist):
            raise ValueError(f"Target '{target_ip}' is not in the configured SCOPE_ALLOWLIST.")
        if target_domain and not is_target_in_scope(target_domain, scope_allowlist):
            raise ValueError(f"Domain '{target_domain}' is not in the configured SCOPE_ALLOWLIST.")

        session_id = str(uuid.uuid4())
        if session_name:
            # Sanitise the name into a safe slug (no spaces/special chars) so the
            # session_id is clean in URLs, file paths, and msf rc files.
            _slug = re.sub(r"[^A-Za-z0-9._-]+", "-", session_name.strip()).strip("-")
            _slug = _slug or "session"
            session_id = f"{_slug}_{session_id[:8]}"

        session = Session(session_id, target_ip, target_domain, auto_approve, authorization_confirmed)
        session.max_auto_depth = max_auto_depth  # Allow customizing max auto depth
        # Per-session engagement objective. Falls back to the Session default
        # ("highest privilege") when the operator doesn't specify one.
        if objective and objective.strip():
            session.objective = objective.strip()

        self.sessions[session_id] = session

        # Save to database
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sessions (session_id, target_ip, target_domain, created_at, status, current_stage, auto_approve, authorization_confirmed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (session_id, target_ip, target_domain, session.created_at, session.status, session.current_stage, auto_approve, authorization_confirmed))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"Failed to save session to database: {e}")

        # Record the authorization confirmation as evidence for the audit trail
        self.add_evidence(session_id, "authorization_confirmation", {
            "authorization_confirmed": authorization_confirmed,
            "target_ip": target_ip,
            "target_domain": target_domain,
            "confirmed_at": session.created_at.isoformat()
        })

        logger.info(f"Created new session: {session_id} for target {target_ip} (auto_approve: {auto_approve}, max_auto_depth: {max_auto_depth})")
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session details."""
        session = self.sessions.get(session_id)
        if session:
            return session.to_dict()
        return None
    
    def get_sessions(self) -> List[Dict]:
        """Get all active sessions."""
        return [session.to_dict() for session in self.sessions.values()]
    
    async def start_reconnaissance(self, session_id: str):
        """Start initial reconnaissance for a session."""
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        session.status = "scanning"
        # For a real domain/host target, begin in the OSINT stage so subdomain
        # enumeration / dorking / crt.sh run first; a bare private IP skips OSINT.
        _do_osint = self._should_run_osint(session)
        session.current_stage = "osint" if _do_osint else "reconnaissance"

        try:
            logger.info(f"Starting reconnaissance for session {session_id}")

            # --- Domain detection: fire passive DNS recon in background --------
            # If the primary target looks like a hostname/domain (not a bare IP
            # or CIDR), launch whois + dig immediately in parallel with the nmap
            # scan so the AI has DNS context on its very first analysis pass.
            import ipaddress as _ip_mod

            def _is_domain_name(t: str) -> bool:
                """Return True if t is a domain/hostname (not an IP or CIDR)."""
                t = t.strip()
                if "/" in t:
                    return False  # CIDR
                try:
                    _ip_mod.ip_address(t)
                    return False  # bare IP
                except ValueError:
                    return True

            _domain_candidate = (session.target_domain or session.target_ip or "").strip()
            if _is_domain_name(_domain_candidate):
                asyncio.create_task(
                    self._run_initial_domain_recon(session_id, _domain_candidate)
                )
                logger.info(
                    f"Domain target detected ({_domain_candidate}): "
                    "initial passive DNS recon launched in background"
                )

            # --- Subnet mode: ping-sweep first, then full-scan live hosts -------
            if is_cidr(session.target_ip):
                logger.info(
                    f"CIDR target detected ({session.target_ip}) — running ping sweep first"
                )
                sweep_results = await self.scanner.perform_subnet_sweep(session.target_ip)
                session.scan_results.append(sweep_results)
                self._save_scan_results(session_id, "nmap_sweep", sweep_results)
                live_ips = [h["ip"] for h in self.scanner.parse_nmap_results(sweep_results)
                            if h.get("ip")]
                logger.info(
                    f"Subnet sweep found {len(live_ips)} live host(s): {live_ips}"
                )
                # Full scan on the subnet (nmap handles multiple IPs natively)
                scan_target = session.target_ip  # pass CIDR to nmap directly
                if not live_ips:
                    logger.warning(
                        f"No live hosts found in {session.target_ip} — scan may be blocked"
                    )
            else:
                scan_target = session.target_ip

            # Initial recon: top-1000-port scan with service detection.
            # "full" (-p- all 65535 ports) is too slow for internet targets;
            # the AI will queue deeper scans on interesting ports if needed.
            scan_results = await self.scanner.perform_nmap_scan(scan_target, "default")
            session.scan_results.append(scan_results)

            # Save scan results to database
            self._save_scan_results(session_id, "nmap_initial", scan_results)

            # Parse scan results — dedup by IP / (host,port) so a re-scan or
            # restore never produces duplicate entries in the session lists.
            discovered_hosts = self.scanner.parse_nmap_results(scan_results)
            self._merge_hosts(session, discovered_hosts)
            self._merge_services(session, discovered_hosts)

            # Coverage engine: seed per-service playbooks from the scan (no-op off).
            self._ensure_coverage(session)
            self._recompute_coverage_progress(session)

            # Kick off the decoupled brute-force worker on auth services (no-op off).
            self._maybe_start_bruteforce(session_id)

            # Nmap done. For a domain/host target, hold in the OSINT stage so the AI
            # does open-source recon first (the OSINT block guides it, then it
            # advances osint→reconnaissance→enumeration). For a bare IP, jump
            # straight to enumeration as before.
            session.status = "analyzing"
            session.current_stage = "osint" if _do_osint else "enumeration"
            self._save_session_status(session_id, session)

            # Auto-trigger threat-intel background research for any service names
            # not yet in the cache. This is the "database gets better over time
            # automatically" feature: each new scan enriches the shared cache so
            # future sessions can cross-reference it without a manual research step.
            # Runs as fire-and-forget background tasks so it never delays the scan.
            self._schedule_auto_threat_intel(session_id)

            # Vulnerability scanning runs in the background so it never blocks AI
            # analysis from starting.  Findings land in session.vulnerabilities as they
            # arrive — subsequent AI iterations (triggered after each command) will
            # see them automatically.  Any failure here is non-fatal and logged.
            asyncio.create_task(self._run_vulnerability_analysis(session_id))

            logger.info(f"Scan complete. Triggering AI analysis for session {session_id}")

            # Create a background task for AI analysis so it doesn't block
            asyncio.create_task(self._analyze_with_ai(session_id))

        except Exception as e:
            logger.error(f"Reconnaissance failed for session {session_id}: {e}")
            session.status = "failed"
            session.current_stage = "error"
            self._save_session_status(session_id, session)

    def _schedule_auto_threat_intel(self, session_id: str):
        """Fire background threat-intel research tasks for each unique service
        name discovered in this session that isn't already covered by the local
        cache. Capped at 3 service topics per scan to limit network load and
        API usage. Each task runs independently - failures are non-fatal."""
        _MAX_AUTO_TOPICS = 3

        session = self.sessions.get(session_id)
        if not session:
            return

        # Build set of service names already well-covered by the cache.
        cached_topics = set()
        for entry in self.threat_intel_cache:
            topic = (entry.get("topic") or "").strip().lower()
            affected = (entry.get("affected_software") or "").strip().lower()
            if topic:
                cached_topics.add(topic)
            if affected:
                cached_topics.add(affected)

        # Collect unique, non-trivial service names from this session.
        seen = set()
        topics_to_research = []
        for svc in session.discovered_services:
            name = (svc.get("service") or "").strip().lower()
            if not name or name in ("unknown", "tcpwrapped", "open", ""):
                continue
            if name in seen:
                continue
            seen.add(name)
            # Skip if any cached entry already mentions this service name.
            if any(name in ct for ct in cached_topics):
                logger.info(
                    f"Auto threat-intel: skipping '{name}' (already in cache)"
                )
                continue
            topics_to_research.append(name)
            if len(topics_to_research) >= _MAX_AUTO_TOPICS:
                break

        for topic in topics_to_research:
            logger.info(
                f"Auto threat-intel: scheduling background research for "
                f"service '{topic}' discovered in session {session_id}"
            )
            asyncio.create_task(self.run_threat_intel_research(topic))

    async def _run_initial_domain_recon(self, session_id: str, domain: str):
        """Fire-and-forget passive DNS recon for domain targets.
        Runs whois + dig concurrently with the nmap scan.  Results are stored
        in session.evidence so the AI has DNS context on its first analysis pass.
        Any failure here is logged and silently swallowed — it must never block
        the main reconnaissance pipeline.
        """
        session = self.sessions.get(session_id)
        if not session:
            return

        async def _run_cmd(args: List[str], timeout: int = 20) -> str:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *args,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                return stdout.decode("utf-8", errors="replace").strip()
            except Exception as exc:
                return f"[error: {exc}]"

        try:
            # Run all DNS lookups concurrently
            whois_out, dig_any, dig_ns, dig_mx, dig_txt = await asyncio.gather(
                _run_cmd(["whois", domain], timeout=30),
                _run_cmd(["dig", domain, "ANY", "+noall", "+answer"], timeout=15),
                _run_cmd(["dig", domain, "NS", "+short"], timeout=10),
                _run_cmd(["dig", domain, "MX", "+short"], timeout=10),
                _run_cmd(["dig", domain, "TXT", "+short"], timeout=10),
            )

            results = {
                "domain": domain,
                "whois": whois_out[:2000],
                "dns_any": dig_any[:1500],
                "dns_ns": dig_ns[:300],
                "dns_mx": dig_mx[:300],
                "dns_txt": dig_txt[:500],
            }

            # Extract subdomains hinted at in DNS records
            import re as _re
            sub_pattern = _re.compile(
                rf'\b((?:[\w\-]+\.)+{_re.escape(domain)})\b', _re.IGNORECASE
            )
            for match in sub_pattern.finditer(dig_any):
                sub = match.group(1).rstrip(".")
                if sub.lower() != domain.lower() and sub not in session.discovered_subdomains:
                    session.discovered_subdomains.append(sub)

            self.add_evidence(session_id, "domain_recon", results)
            logger.info(
                f"Initial domain recon done for {domain}: "
                f"NS={dig_ns[:60].strip()!r}, "
                f"hints={len(session.discovered_subdomains)} subdomains"
            )

        except Exception as exc:
            logger.warning(f"Initial domain recon failed for {domain}: {exc} (non-fatal)")

    # ── Attack-surface auto-parsing helpers ─────────────────────────────────

    def _parse_and_store_subdomains(self, session: "Session", command: str, output: str) -> int:
        """Parse subdomain-discovery tool output and store unique findings.

        Handles output formats from: subfinder, amass, gobuster dns, dnsx,
        dnsrecon, fierce, dnsenum, crt.sh curl command.
        Returns the count of newly added subdomains.
        """
        import re as _re

        base_domain = (session.target_domain or (
            session.target_ip
            if "." in session.target_ip and not session.target_ip[0].isdigit()
            else None
        ))
        if not base_domain:
            return 0

        # Match any token that looks like a FQDN ending with the base domain
        sub_pattern = _re.compile(
            rf'\b((?:[\w\-]+\.)+{_re.escape(base_domain)})\b', _re.IGNORECASE
        )
        found = {m.group(1).rstrip(".").lower() for m in sub_pattern.finditer(output)}

        added = 0
        for sub in sorted(found):
            if sub == base_domain.lower():
                continue
            if sub not in session.discovered_subdomains:
                session.discovered_subdomains.append(sub)
                added += 1

        if added:
            logger.info(
                f"Session {session.session_id}: stored {added} new subdomains "
                f"from {command.split()[0]!r}"
            )
        return added

    def _parse_and_store_web_apps(self, session: "Session", command: str, output: str) -> int:
        """Parse httpx / gowitness / aquatone output and store live web services.

        httpx line format: https://sub.domain.com [200] [Page Title] [tech1,tech2]
        Returns count of newly added entries.
        """
        import re as _re

        httpx_re = _re.compile(
            r'(https?://[\w\-\.]+(?::\d+)?)'      # URL
            r'(?:\s+\[(\d+)\])?'                   # [status_code]
            r'(?:\s+\[([^\]]*)\])?'                # [title]
            r'(?:\s+\[([^\]]*)\])?',               # [tech]
            _re.IGNORECASE
        )

        existing_urls = {app.get("url", "") for app in session.web_applications}
        added = 0

        for m in httpx_re.finditer(output):
            url = m.group(1)
            if url in existing_urls:
                continue
            session.web_applications.append({
                "url": url,
                "status_code": int(m.group(2)) if m.group(2) else None,
                "title": (m.group(3) or "").strip() or None,
                "tech": (m.group(4) or "").strip() or None,
            })
            existing_urls.add(url)
            added += 1

        if added:
            logger.info(
                f"Session {session.session_id}: stored {added} new web apps "
                f"from {command.split()[0]!r}"
            )
        return added

    def _parse_and_store_api_endpoints(self, session: "Session", command: str, output: str) -> int:
        """Parse ffuf/gobuster JSON/text output and store discovered API paths.
        Returns count of newly added endpoints.
        """
        import re as _re
        import json as _json

        added = 0
        existing = set(session.discovered_api_endpoints)

        # Try to parse ffuf JSON output first
        try:
            data = _json.loads(output)
            for result in data.get("results", []):
                path = result.get("input", {}).get("FUZZ", "") or result.get("url", "")
                if path and path not in existing:
                    session.discovered_api_endpoints.append(path)
                    existing.add(path)
                    added += 1
            if added:
                logger.info(f"Session {session.session_id}: stored {added} API endpoints from ffuf JSON")
            return added
        except (_json.JSONDecodeError, AttributeError):
            pass

        # Fall back to regex: extract /api/... or /v1/... paths from plain text
        path_re = _re.compile(r'(/(?:api|v\d+|rest|graphql|gql|swagger|openapi)[/\w\-\.]*)', _re.IGNORECASE)
        for m in path_re.finditer(output):
            path = m.group(1)
            if path not in existing:
                session.discovered_api_endpoints.append(path)
                existing.add(path)
                added += 1

        if added:
            logger.info(f"Session {session.session_id}: stored {added} API endpoints from text output")
        return added

    def _auto_parse_tool_output(self, session: "Session", command: str, output: str):
        """Dispatch auto-parsing for known tool outputs.
        Called at the start of _process_command_output so that newly discovered
        subdomains / web apps appear in the AI memory on the very same turn.
        """
        if not command or not output:
            return

        import os as _os
        tokens = command.strip().split()
        binary = _os.path.basename(tokens[0]) if tokens else ""

        _SUBDOMAIN_TOOLS = {
            "subfinder", "amass", "gobuster", "dnsx", "dnsrecon",
            "fierce", "dnsenum", "dnswalk", "sublist3r",
        }
        _WEB_TOOLS = {"httpx", "gowitness", "aquato…39558 tokens truncated…ptional[str] = None,
    ) -> tuple[MTPentesterAIConnector, Dict[str, Any]]:
        """Return an explicitly policy-routed connector and public provenance.

        Default behavior remains the active connector. Cross-provider calls are
        possible only after MODEL_ROUTING_ENABLED and the provider allowlist are
        configured; invalid enabled policy fails closed.
        """
        active_provider = normalize_provider(self.ai_connector.provider)
        router = ModelRouter.from_environment(
            public_provider_catalog(),
            active_provider,
        )
        sensitivity = os.getenv(
            "MODEL_ROUTING_SENSITIVITY", "standard"
        ).strip().lower()
        route = router.route(
            role,
            sensitivity=sensitivity,
            independent_of=independent_of,
        )
        provider = route["provider"]
        if provider == active_provider:
            active_model = (
                getattr(self.ai_connector, "local_model", "")
                if provider == "local"
                else getattr(self.ai_connector, "api_model", "")
            )
            if isinstance(active_model, str) and active_model:
                route["model"] = active_model
            return self.ai_connector, route

        cache = self.__dict__.setdefault("_routed_ai_connectors", {})
        key = (provider, route["model"])
        connector = cache.get(key)
        if connector is None:
            kwargs: Dict[str, Any] = {"provider": provider}
            if provider == "local":
                kwargs["local_model"] = route["model"]
            else:
                kwargs["api_model"] = route["model"]
            connector = MTPentesterAIConnector(**kwargs)
            cache[key] = connector
        return connector, route

    async def _run_strategist(self, session_id: str):
        """Run one strategic reflection pass. Updates session.strategic_plan,
        objective_progress, reflections, and objective_complete. Uses
        ask_raw_async so the strategist can never inject a command into the
        execution loop."""
        session = self.sessions.get(session_id)
        if not session:
            return

        from ai.prompts import STRATEGIST_PROMPT

        context = self._build_strategist_context(session)
        routed_ai, _model_route = self._connector_for_role("strategist")
        result = await routed_ai.ask_raw_async(STRATEGIST_PROMPT, context)
        if not result or not isinstance(result, dict):
            logger.info(f"Strategist returned no usable JSON for {session_id}; keeping prior plan.")
            return

        # ── Progress ──────────────────────────────────────────────────────────
        try:
            prog = float(result.get("objective_progress", session.objective_progress))
            session.objective_progress = max(0.0, min(1.0, prog))
        except (TypeError, ValueError):
            pass
        session.objective_progress_note = str(result.get("priority", ""))[:400]

        # ── Plan ──────────────────────────────────────────────────────────────
        plan = result.get("plan")
        if isinstance(plan, list) and plan:
            cleaned = []
            for item in plan[:8]:
                if isinstance(item, dict) and item.get("step"):
                    cleaned.append({
                        "step": str(item.get("step", ""))[:300],
                        "rationale": str(item.get("rationale", ""))[:300],
                        "status": str(item.get("status", "pending"))[:20],
                    })
            if cleaned:
                session.strategic_plan = cleaned

        # ── Reflection log ────────────────────────────────────────────────────
        reflection = str(result.get("reflection", "")).strip()
        if reflection:
            stamped = f"[{datetime.now().isoformat(timespec='seconds')}] {reflection[:500]}"
            session.reflections.append(stamped)
            session.reflections = session.reflections[-20:]  # bound growth

        # ── Completion detection ──────────────────────────────────────────────
        # Only honour completion when the strategist both sets the flag AND gives
        # a non-empty reason, and progress is high — defends against a spurious
        # true from a confused model.
        complete = bool(result.get("objective_complete"))
        reason = str(result.get("completion_reason", "")).strip()
        if complete and reason and session.objective_progress >= 0.85:
            session.objective_complete = True
            _d = {
                "timestamp": datetime.now().isoformat(),
                "reasoning": f"OBJECTIVE COMPLETE (strategist): {reason}",
                "suggested_command": "",
                "risk_level": "low",
                "confidence": session.objective_progress,
                "context": "strategist_completion",
            }
            session.ai_decisions.append(_d)
            self._save_ai_decision(session_id, _d)
            self.add_evidence(session_id, "objective_complete", {
                "objective": session.objective,
                "reason": reason,
                "progress": session.objective_progress,
                "at": datetime.now().isoformat(),
            })
            logger.info(f"Session {session_id}: strategist declared objective complete — {reason}")
        elif complete and session.objective_progress < 0.85:
            logger.warning(
                f"Session {session_id}: strategist set objective_complete but progress "
                f"only {session.objective_progress:.2f}; ignoring completion this pass."
            )

        logger.info(
            f"Strategist updated session {session_id}: progress={session.objective_progress:.2f}, "
            f"plan_steps={len(session.strategic_plan)}, complete={session.objective_complete}"
        )
        # Persist the updated strategic state so it survives an app restart.
        self._save_strategic_state(session_id, session)

    def _save_strategic_state(self, session_id: str, session: "Session"):
        """Persist the strategic layer fields to the DB so they survive a restart.
        No-op when db_path is not set (e.g. in unit-test stubs without a real DB)."""
        db_path = getattr(self, "db_path", None)
        if not db_path:
            return
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sessions SET
                    objective              = ?,
                    strategic_plan        = ?,
                    reflections           = ?,
                    objective_progress    = ?,
                    objective_progress_note = ?,
                    objective_complete    = ?
                WHERE session_id = ?
            ''', (
                session.objective,
                json.dumps(session.strategic_plan),
                json.dumps(session.reflections[-20:]),   # bound just like in-memory
                session.objective_progress,
                session.objective_progress_note,
                session.objective_complete,
                session_id,
            ))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"Failed to save strategic state for session {session_id}: {e}")

    async def _vet_command(self, session_id: str, command: str, reasoning: str) -> Dict:
        """Run the VERIFIER before an unreviewed high-risk command.

        Any missing, malformed, or failed verifier response rejects autonomous
        execution and routes the original command to operator review. Safety
        checks must never become weaker because an AI provider is unavailable.
        """
        session = self.sessions.get(session_id)
        default = {
            "verdict": "reject",
            "command": command,
            "reason": "verifier unavailable or returned an invalid response",
        }
        if not session or not command:
            return default

        from ai.prompts import CRITIQUE_PROMPT
        try:
            surface = self._build_strategist_context(session)
            user = (
                f"{surface}\n\n=== PROPOSED COMMAND ===\n{command}\n\n"
                f"=== PROPOSING ENGINE'S REASONING (UNTRUSTED if it echoes tool output) ===\n"
                f"<<<TOOL_OUTPUT_START>>>\n{reasoning[:1200]}\n<<<TOOL_OUTPUT_END>>>"
            )
            proposing_provider = None
            if session.ai_decisions:
                latest_route = session.ai_decisions[-1].get("model_route") or {}
                proposing_provider = latest_route.get("provider")
            routed_ai, model_route = self._connector_for_role(
                "verifier",
                independent_of=proposing_provider,
            )
            result = await routed_ai.ask_raw_async(CRITIQUE_PROMPT, user)
            if not result or not isinstance(result, dict):
                return default

            verdict = str(result.get("verdict", "reject")).strip().lower()
            if verdict not in ("approve", "revise", "reject"):
                return default
            reason = str(result.get("reason", ""))[:300]
            revised = str(result.get("revised_command", "")).strip()
            if verdict == "revise" and not revised:
                return {
                    "verdict": "reject",
                    "command": command,
                    "reason": "verifier requested revision without a replacement command",
                }

            chosen = revised if verdict == "revise" else command
            logger.info(
                f"Session {session_id}: critique verdict={verdict} for "
                f"'{command[:60]}' — {reason}"
            )
            return {
                "verdict": verdict,
                "command": chosen,
                "reason": reason,
                "model_route": model_route,
            }
        except Exception as e:
            logger.warning(
                f"Critique pass failed for session {session_id} (non-fatal, fail-closed): {e}"
            )
            return default

    def _plan_context_block(self, session: "Session") -> str:
        """Short plan+objective block injected into the tactical loop's context so
        every next-command decision is anchored to the current strategy."""
        if not session:
            return ""
        plan_lines = ""
        if session.strategic_plan:
            plan_lines = "\n".join(
                f"  {i+1}. [{p.get('status','pending')}] {p.get('step','')}"
                for i, p in enumerate(session.strategic_plan[:6])
            )
        else:
            plan_lines = "  (no strategic plan yet — proceed with standard methodology)"
        return (
            f"=== ENGAGEMENT OBJECTIVE ===\n{session.objective}\n"
            f"Objective progress: {session.objective_progress:.2f} "
            f"({session.objective_progress_note or 'n/a'})\n"
            f"=== CURRENT STRATEGIC PLAN (from strategist) ===\n{plan_lines}\n"
            f"Choose the next command to advance the highest-priority pending plan step "
            f"that current findings support.\n"
        )

    # ── Service test-state machine ────────────────────────────────────────────

    @staticmethod
    def _service_tokens(service: Dict) -> List[str]:
        """Lowercase tokens that identify a service inside a command string:
        its port number and its service name (when meaningful)."""
        tokens: List[str] = []
        port = str(service.get("port", "")).strip()
        if port:
            tokens.append(port)
        name = (service.get("service") or "").strip().lower()
        if name and name not in ("unknown", "tcpwrapped", ""):
            tokens.append(name)
        return tokens

    @staticmethod
    def _promote_service(service: Dict, new_state: str):
        """Move a service UP the test ladder only (never downgrade)."""
        cur = service.get("test_state", "untested")
        if _SERVICE_STATE_ORDER.get(new_state, 0) > _SERVICE_STATE_ORDER.get(cur, 0):
            service["test_state"] = new_state

    def _services_referenced(self, session: "Session", command: str) -> List[Dict]:
        """Return the discovered services a command targets.

        Precise-port matching wins: if the command explicitly names one or more
        discovered service ports (as standalone numbers), ONLY those services are
        returned — so 'gobuster ...:8080' never touches the port-80 http service.
        Only when no discovered port appears in the command do we fall back to
        service-name matching (the web case 'whatweb http://host' with no port)."""
        if not command:
            return []
        cmd_l = command.lower()

        port_hits: List[Dict] = []
        for svc in session.discovered_services:
            port = str(svc.get("port", "")).strip()
            if port and re.search(rf"(?<!\d){re.escape(port)}(?!\d)", cmd_l):
                port_hits.append(svc)
        if port_hits:
            return port_hits

        # No explicit port in the command — fall back to service-name matching.
        name_hits: List[Dict] = []
        for svc in session.discovered_services:
            name_tokens = self._service_tokens(svc)[1:]
            if any(t in cmd_l for t in name_tokens):
                name_hits.append(svc)
        return name_hits

    def _mark_services_in_progress(self, session: "Session", command: str):
        """When a command that references a service is about to run, mark that
        service in_progress so the AI knows work is underway on it."""
        for svc in self._services_referenced(session, command):
            self._promote_service(svc, "in_progress")

    def _settle_service_states(self, session: "Session", command: str,
                               output: str, success: bool):
        """After a command completes, settle the state of any service it touched:
        promote to 'exploited' when the output shows compromise, otherwise
        'tested'. Deterministic — replaces the old substring 'tested' heuristic.

        Only a SUCCESSFUL command settles state; a failed command leaves the
        service at in_progress/untested so it gets retried rather than being
        wrongly marked done."""
        if not success:
            return
        out_l = (output or "").lower()
        _matched = [sig for sig in _EXPLOIT_SIGNALS if sig in out_l]
        # Windows web-shell / exec RCE proof (guarded against enumeration output).
        if _is_windows_rce_proof(command, output):
            _matched.append("windows-rce")
        exploited = bool(_matched)
        settle_state = "exploited" if exploited else "tested"
        referenced = self._services_referenced(session, command)
        for svc in referenced:
            self._promote_service(svc, settle_state)
        if exploited:
            self._capture_exploitation_evidence(
                session, command, output, referenced, _matched
            )

    def _capture_exploitation_evidence(self, session: "Session", command: str,
                                       output: str, services: List[Dict],
                                       matched_signals: List[str]) -> None:
        """Record proof of a confirmed compromise: privilege level, the proof
        snippet, and which service it landed on. Deduped per (service, privilege)
        so repeated confirmations don't spam the evidence log. Best-effort — never
        raises into the command loop."""
        try:
            privilege = _detect_privilege_level(output) or "unknown"
            # Trimmed proof snippet centred on the first matched signal.
            proof = (output or "").strip()
            if matched_signals:
                low = output.lower()
                idx = low.find(matched_signals[0])
                if idx != -1:
                    start = max(0, idx - 120)
                    proof = output[start:idx + 240].strip()
            proof = proof[:400]

            target_svc = services[0] if services else {}
            svc_name = target_svc.get("service", "unknown")
            host = target_svc.get("host", session.target_ip)
            port = target_svc.get("port", "")

            # Dedup: same service + privilege already captured → skip.
            fp = f"{svc_name}:{port}:{privilege}"
            if any(
                f"{e.get('service')}:{e.get('port')}:{e.get('privilege')}" == fp
                for e in session.compromise_evidence
            ):
                return

            entry = {
                "service": svc_name,
                "host": host,
                "port": port,
                "command": command[:300],
                "privilege": privilege,
                "signal": ", ".join(matched_signals[:4]),
                "proof": proof,
                "timestamp": datetime.now().isoformat(),
            }
            session.compromise_evidence.append(entry)
            logger.warning(
                f"COMPROMISE CONFIRMED on {svc_name}:{port} ({host}) — "
                f"privilege={privilege}, signal='{entry['signal']}'"
            )
            # Persist to the evidence table for the report.
            self.add_evidence(session.session_id, "exploitation", entry)
        except Exception as e:
            logger.warning(f"Failed to capture exploitation evidence (non-fatal): {e}")

    def _exhausted_context_block(self, session: "Session") -> str:
        """Render exhausted attack vectors for the AI prompt. Empty when none."""
        if not session.exhausted_services:
            return ""
        return (
            "\n=== EXHAUSTED ATTACK VECTORS — DO NOT RETRY ===\n"
            + "\n".join(f"- {s}" for s in session.exhausted_services)
            + "\nThese vectors have been looped on and abandoned. Choose a DIFFERENT "
            "service, port, or technique. Do not suggest a command targeting an "
            "exhausted vector.\n"
        )

    def add_operator_instruction(self, session_id: str, instruction: str) -> Dict:
        """Record a free-text steering instruction from the human operator. It is
        injected (highest priority) into every subsequent AI decision so the loop
        can be redirected live without being stopped. Logged as an ai_decision so
        it shows in the timeline and survives a backend restart."""
        session = self.sessions.get(session_id)
        if not session:
            return {"status": "error", "message": "Session not found"}
        instruction = (instruction or "").strip()
        if not instruction:
            return {"status": "error", "message": "Empty instruction"}

        session.operator_instructions.append(instruction)
        # Keep the active set bounded so the prompt doesn't grow without limit.
        if len(session.operator_instructions) > 12:
            session.operator_instructions = session.operator_instructions[-12:]

        _d = {
            "timestamp": datetime.now().isoformat(),
            "reasoning": f"OPERATOR INSTRUCTION: {instruction}",
            "suggested_command": "",
            "risk_level": "low",
            "confidence": 1.0,
            "context": "operator_instruction",
        }
        session.ai_decisions.append(_d)
        self._save_ai_decision(session_id, _d)
        logger.info(f"Session {session_id}: operator instruction added: {instruction[:120]}")
        return {"status": "success", "instruction": instruction,
                "active_count": len(session.operator_instructions)}

    def _status_summary_for_operator(self, session: "Session") -> str:
        """Compact plain-text snapshot of the engagement for the status-chat AI."""
        svcs = ", ".join(
            f"{s.get('service','?')}:{s.get('port','?')}({s.get('test_state','untested')})"
            for s in session.discovered_services[:25]
        ) or "none"
        creds = ", ".join(
            f"{c.get('username','?')}@{c.get('service','?')}" for c in session.credentials[:10]
        ) or "none"
        vulns = "; ".join(
            f"{v.get('name','?')}[{v.get('risk_level','?')}]" for v in session.vulnerabilities[:12]
        ) or "none"
        comps = "; ".join(
            f"{c.get('service','?')}:{c.get('port','?')}={c.get('privilege','?')}"
            for c in session.compromise_evidence[:8]
        ) or "none"
        last_cmds = "; ".join(
            (c.get("command", "") or "")[:70] for c in session.commands_executed[-6:]
        ) or "none"
        plan = "; ".join(
            f"{p.get('step','')}[{p.get('status','')}]" for p in session.strategic_plan[:8]
        ) or "none"
        return (
            f"TARGET: {session.target_ip} ({session.target_domain or 'no domain'})\n"
            f"STATUS: {session.status}  STAGE: {session.current_stage}\n"
            f"OBJECTIVE: {session.objective}\n"
            f"PROGRESS: {int(session.objective_progress * 100)}% — {session.objective_progress_note or 'n/a'}\n"
            f"PLAN: {plan}\n"
            f"SERVICES ({len(session.discovered_services)}): {svcs}\n"
            f"CREDENTIALS ({len(session.credentials)}): {creds}\n"
            f"VULNERABILITIES ({len(session.vulnerabilities)}): {vulns}\n"
            f"CONFIRMED COMPROMISES ({len(session.compromise_evidence)}): {comps}\n"
            f"EXHAUSTED VECTORS: {', '.join(session.exhausted_services) or 'none'}\n"
            f"RECENT COMMANDS: {last_cmds}\n"
            f"TOTAL COMMANDS: {len(session.commands_executed)}  DECISIONS: {len(session.ai_decisions)}"
        )

    async def answer_operator_question(self, session_id: str, question: str) -> Dict:
        """One-off status-chat: answer the operator's question about the CURRENT
        engagement from live session state. Read-only — does NOT touch the agentic
        loop or execute anything. Returns {"status","answer"}."""
        session = self.sessions.get(session_id)
        if not session:
            return {"status": "error", "message": "Session not found"}
        question = (question or "").strip()
        if not question:
            return {"status": "error", "message": "Empty question"}

        summary = self._status_summary_for_operator(session)
        system_prompt = (
            "You are the assistant to a penetration tester, reporting on an autonomous "
            "engagement in progress. Answer the operator's question CONCISELY and "
            "factually using ONLY the session state provided. If asked what to do next, "
            "give a brief recommendation grounded in the discovered services/vulns. "
            "Do not fabricate findings. Respond as JSON: {\"answer\": \"...\"}."
        )
        user_prompt = (
            f"=== CURRENT SESSION STATE ===\n{summary}\n\n"
            f"OPERATOR QUESTION: {question}\n\n"
            "Return ONLY JSON: {\"answer\": \"...\"}"
        )
        # Record the operator's question in the transcript first so it shows even
        # if the AI call then fails.
        self._append_chat(session_id, "user", question)
        try:
            routed_ai, _model_route = self._connector_for_role("reporter")
            data = await routed_ai.ask_raw_async(system_prompt, user_prompt)
            answer = ""
            if isinstance(data, dict):
                answer = str(data.get("answer") or "").strip()
            if not answer:
                answer = "The AI did not return a usable answer. Try rephrasing the question."
            self._append_chat(session_id, "ai", answer)
            return {"status": "success", "answer": answer}
        except Exception as e:
            logger.warning(f"answer_operator_question failed for {session_id}: {e}")
            self._append_chat(session_id, "ai", f"[error] {e}")
            return {"status": "error", "message": f"AI query failed: {e}"}

    def _append_chat(self, session_id: str, role: str, text: str) -> None:
        """Add one chat message to the session transcript and persist it."""
        session = self.sessions.get(session_id)
        if not session:
            return
        entry = {"role": role, "text": text, "timestamp": datetime.now().isoformat()}
        session.chat_history.append(entry)
        if len(session.chat_history) > 200:
            session.chat_history = session.chat_history[-200:]
        if not getattr(self, "db_path", None):
            return
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                "INSERT INTO chat_messages (session_id, role, text, timestamp) "
                "VALUES (?, ?, ?, ?)",
                (session_id, role, text, entry["timestamp"]),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.warning(f"Failed to persist chat message for {session_id}: {e}")

    # ── Coverage engine (opt-in via COVERAGE_ENGINE) ──────────────────────────

    @staticmethod
    def _svc_key(svc: dict) -> str:
        return f"{svc.get('host') or ''}:{svc.get('port') or ''}"

    def _ensure_coverage(self, session: "Session") -> None:
        """Build/refresh per-service playbook coverage for discovered services.
        Idempotent; no-op unless COVERAGE_ENGINE is enabled."""
        if not COVERAGE_ENGINE:
            return
        for svc in session.discovered_services:
            key = self._svc_key(svc)
            if key and key not in session.service_coverage:
                try:
                    session.service_coverage[key] = _coverage.build_service_coverage(svc)
                except Exception as e:
                    logger.warning(f"coverage build failed for {key}: {e}")
        # Activate the post-exploitation checklist once a foothold exists.
        if session.compromise_evidence and "__postex__" not in session.service_coverage:
            session.service_coverage["__postex__"] = _coverage.build_postex_coverage()

    def _update_coverage_from_command(self, session: "Session", command: str) -> None:
        """After a command runs, mark any playbook steps it attempted as done."""
        if not COVERAGE_ENGINE or not command:
            return
        for cov in session.service_coverage.values():
            try:
                _coverage.match_and_mark(cov, command)
            except Exception:
                pass

    def _recompute_coverage_progress(self, session: "Session") -> None:
        """Derive objective progress + completion from measured coverage."""
        if not COVERAGE_ENGINE or not session.service_coverage:
            return
        # Separate the post-exploitation record from per-service coverage.
        svc_covs = [v for k, v in session.service_coverage.items() if k != "__postex__"]
        postex_cov = session.service_coverage.get("__postex__")
        enum_cov = [_coverage.enumeration_coverage(c) for c in svc_covs]
        covered_ratio = (
            sum(1 for c in svc_covs if _coverage.is_service_covered(c)) / len(svc_covs)
            if svc_covs else 0.0
        )
        vulns = session.vulnerabilities or []
        validated = sum(1 for v in vulns if (v.get("status") or "") == "confirmed")
        vuln_ratio = (validated / len(vulns)) if vulns else 0.0
        footholds = len(session.compromise_evidence or [])
        postex_ratio = _coverage.coverage_ratio(postex_cov) if postex_cov else 0.0
        progress = _coverage.compute_progress(
            recon_done=bool(session.discovered_services),
            enum_coverages=enum_cov,
            validated_vuln_ratio=vuln_ratio,
            footholds=footholds,
            post_ex_coverage=postex_ratio,
        )
        session.objective_progress = progress
        session.objective_complete = _coverage.is_objective_complete(
            progress, covered_ratio, footholds
        )

    def _should_run_osint(self, session: "Session") -> bool:
        """OSINT applies to a real public domain/host, not a bare private IP.
        A domain target (drhmonegyi.cc) should get subdomain enum, crt.sh, dorks,
        etc.; a lab IP (192.168.x) correctly skips internet OSINT."""
        if _is_local_target(session.target_ip):
            return False
        if (session.target_domain or "").strip():
            return True
        return _is_hostname(session.target_ip)

    def _osint_context_block(self, session: "Session") -> str:
        """Inject the OSINT checklist while the engagement is in the OSINT stage
        against a real domain/host. Always-on (not coverage-gated) — a domain
        target must never silently skip OSINT. Fades once the stage advances."""
        if session.current_stage != "osint" or not self._should_run_osint(session):
            return ""
        dom = (session.target_domain or session.target_ip or "").strip()
        return (
            "\n=== OSINT (do this FIRST — real domain/host target) ===\n"
            f"Target: {dom}\n"
            "Gather open-source intelligence before deeper scanning:\n"
            f"- Subdomain enumeration: subfinder -d {dom} / amass / assetfinder\n"
            f"- Certificate transparency: curl -s 'https://crt.sh/?q=%25.{dom}&output=json'\n"
            f"- DNS: dnsrecon -d {dom}; dig ANY {dom}; try zone transfer (dig AXFR @ns {dom})\n"
            f"- Google dorking: site:{dom} (filetype:, inurl:admin/login, exposed panels)\n"
            f"- theHarvester -d {dom} -b all  (emails, hosts, employees)\n"
            f"- Web fingerprint + WAF: whatweb {dom}; wafw00f {dom}\n"
            f"- Archived URLs: gau {dom} / waybackurls {dom}\n"
            "Advance past OSINT only after collecting subdomains, DNS, and a web "
            "fingerprint of the main site.\n"
        )

    def _exploit_hints_block(self, session: "Session") -> str:
        """Surface curated, high-signal exploit candidates for the discovered
        services so the AI attempts known paths (Ghostcat, WAR deploy, INTO
        OUTFILE, EternalBlue, etc.) instead of improvising."""
        if not COVERAGE_ENGINE or not session.discovered_services:
            return ""
        keys: List[str] = []
        for svc in session.discovered_services:
            for k in _playbooks.classify_service(svc):
                if k not in keys:
                    keys.append(k)
        cands = _exploit_map.candidates_for(keys)
        if not cands:
            return ""
        lines = ["\n=== KNOWN EXPLOIT CANDIDATES (attempt the relevant ones) ==="]
        for c in cands[:14]:
            cve = f" [{c['cve']}]" if c.get("cve") else ""
            tool = f"  →  {c['tool']}" if c.get("tool") else ""
            lines.append(f"- {c['name']}{cve}: {c['technique']}{tool}")
        lines.append("")
        return "\n".join(lines)

    def _coverage_context_block(self, session: "Session") -> str:
        """Render the per-service methodology checklist (pending steps) for the AI
        so it works the full playbook and does not abandon a service early."""
        if not COVERAGE_ENGINE or not session.service_coverage:
            return ""
        lines = ["\n=== METHODOLOGY COVERAGE (work every pending step; do NOT skip a service) ==="]
        shown = 0
        for svc in session.discovered_services:
            key = self._svc_key(svc)
            cov = session.service_coverage.get(key)
            if not cov:
                continue
            pend = _coverage.pending_steps(cov)
            if not pend:
                continue
            svc_name = svc.get("service", "?")
            ratio = int(_coverage.coverage_ratio(cov) * 100)
            lines.append(f"- {svc_name} ({key}) [{ratio}% covered] pending:")
            for st in pend[:6]:
                lines.append(f"    · {st.intent}")
            shown += 1
            if shown >= 8:
                break
        # Post-exploitation checklist (once a foothold exists).
        postex = session.service_coverage.get("__postex__")
        postex_lines: List[str] = []
        if postex:
            pend = _coverage.pending_steps(postex)
            if pend:
                postex_lines.append("- POST-EXPLOITATION (a foothold exists — enumerate the host):")
                for st in pend[:8]:
                    postex_lines.append(f"    · {st.intent}")

        if shown == 0 and not postex_lines:
            return ""
        lines.extend(postex_lines)
        lines.append(
            "Choose your next command to complete a pending step above. A service is "
            "only done when its whole checklist is attempted.\n"
        )
        return "\n".join(lines)

    def _operator_context_block(self, session: "Session") -> str:
        """Render active operator instructions for the AI prompt. Highest priority
        — placed so the model treats these as overriding directives. Empty when
        the operator hasn't sent any."""
        if not session.operator_instructions:
            return ""
        lines = ["\n=== OPERATOR INSTRUCTIONS (HIGHEST PRIORITY — FOLLOW THESE) ==="]
        for i, instr in enumerate(session.operator_instructions[-8:], 1):
            lines.append(f"{i}. {instr}")
        lines.append(
            "These are direct orders from the human operator running this engagement. "
            "Obey them over your own default methodology. If an instruction says to "
            "focus on / skip / avoid something, do exactly that in your next command.\n"
        )
        return "\n".join(lines)

    def _handler_context_block(self, session: "Session") -> str:
        """Tell the AI a managed listener is live and how to deliver shells to it.
        Empty until the handler has been auto-started (exploitation stage)."""
        if not session.exploit_lhost:
            return ""
        return (
            "\n=== MANAGED PAYLOAD LISTENER (deliver your shells HERE) ===\n"
            f"A Metasploit multi/handler is LISTENING:\n"
            f"  LHOST   = {session.exploit_lhost}\n"
            f"  LPORT   = {session.exploit_lport}\n"
            f"  PAYLOAD = {session.exploit_payload}\n"
            "When you exploit, your reverse payload MUST connect back to this "
            "LHOST:LPORT using this payload — then the session is caught and "
            "controllable in the Shells tab. Rules:\n"
            f"  - msfvenom: use LHOST={session.exploit_lhost} LPORT={session.exploit_lport} "
            f"-p {session.exploit_payload}\n"
            "  - Metasploit exploit modules: set LHOST/LPORT/PAYLOAD to the above; do NOT "
            "run your own multi/handler — one is already listening.\n"
            "  - Non-msf reverse shells (nc, bash -i, powershell): point them at "
            f"{session.exploit_lhost}:{session.exploit_lport}.\n"
        )

    def _compromise_context_block(self, session: "Session") -> str:
        """Render confirmed compromises for the AI prompt. Empty string when none,
        so it adds nothing to the context until access is actually proven."""
        if not session.compromise_evidence:
            return ""
        lines = ["\n=== CONFIRMED COMPROMISES (you ALREADY have access here) ==="]
        for e in session.compromise_evidence[-8:]:
            lines.append(
                f"- {e.get('service','?')}:{e.get('port','?')} on {e.get('host','?')} "
                f"→ privilege={e.get('privilege','?')} via `{(e.get('command') or '')[:80]}`"
            )
        lines.append(
            "Do NOT re-run the exploit on an already-compromised service. Instead "
            "move to post-exploitation: enumerate the foothold, harvest credentials, "
            "escalate privileges, or pivot to a new target. If privilege is 'user', "
            "prioritise privilege escalation; if 'root/SYSTEM', document and pivot.\n"
        )
        return "\n".join(lines)

    def _service_state_counts(self, session: "Session") -> Dict[str, int]:
        counts = {k: 0 for k in _SERVICE_STATE_ORDER}
        for svc in session.discovered_services:
            counts[svc.get("test_state", "untested")] = counts.get(
                svc.get("test_state", "untested"), 0
            ) + 1
        return counts

    # ── Hybrid memory index (semantic + lexical retrieval) ────────────────────

    def _get_findings_index(self, session_id: str) -> FindingsIndex:
        """Lazily create the per-session FindingsIndex. Uses setdefault on the
        instance dict so it works even when the orchestrator was built without a
        fresh __init__ (e.g. restored sessions, tests)."""
        indexes = self.__dict__.setdefault("_findings_indexes", {})
        idx = indexes.get(session_id)
        if idx is None:
            idx = FindingsIndex(connector=self.ai_connector)
            indexes[session_id] = idx
        return idx

    def _index_finding(self, session_id: str, text: str, meta: Optional[Dict] = None):
        """Add one finding to the session's retrieval index (best-effort)."""
        try:
            self._get_findings_index(session_id).add(text, meta)
        except Exception as e:
            logger.debug(f"Finding index add failed for {session_id} (non-fatal): {e}")

    def _retrieve_relevant_findings(self, session_id: str, query: str,
                                    k: int = 4) -> List[Dict]:
        """Retrieve the top-k findings most relevant to `query` from the session
        index. Returns [] on any error so memory building never fails."""
        try:
            return self._get_findings_index(session_id).retrieve(query, k=k)
        except Exception as e:
            logger.debug(f"Finding retrieval failed for {session_id} (non-fatal): {e}")
            return []

    def _get_skill_router(self) -> ClaudeSkillRouter:
        """Lazily create the read-only methodology router."""
        router = self.__dict__.get("_claude_skill_router")
        if router is None:
            router = ClaudeSkillRouter()
            self.__dict__["_claude_skill_router"] = router
        return router

    def _build_methodology_guidance(self, session: "Session") -> Optional[Dict[str, Any]]:
        """Return bounded, provenance-tagged methodology relevant to this turn."""
        try:
            latest_command = ""
            if session.commands_executed:
                latest_command = session.commands_executed[-1].get("command", "")[:300]

            services = [
                {
                    "service": item.get("service", ""),
                    "port": item.get("port", ""),
                    "version": item.get("version", ""),
                }
                for item in session.discovered_services[-30:]
            ]
            vulnerabilities = []
            for item in session.vulnerabilities[-20:]:
                if isinstance(item, dict):
                    vulnerabilities.append(
                        item.get("title")
                        or item.get("name")
                        or item.get("type")
                        or item.get("description", "")[:200]
                    )
                else:
                    vulnerabilities.append(str(item)[:200])

            routed = self._get_skill_router().route({
                "objective": session.objective,
                "stage": session.current_stage,
                "services": services,
                "vulnerabilities": vulnerabilities,
                "latest_command": latest_command,
            })
            return routed if routed.get("enabled") else None
        except Exception as exc:
            logger.debug(f"Claude methodology routing failed (non-fatal): {exc}")
            return None

    def _build_ai_memory(self, session_id: str) -> str:
        """Build compressed AI memory from session history.

        Returns a compact JSON string that fits within the configured context
        window budget.  Older history is represented as episode summaries
        (compact text) rather than raw command output, so the total size stays
        bounded even across 50+ command sessions.
        """
        session = self.sessions.get(session_id)
        if not session:
            return "No session memory available"

        try:
            # ── Episode history (older commands, already compressed) ───────────
            # Include up to the last 3 episode summaries as a narrative history
            # of what the AI did before the current episode window.
            episode_block = ""
            if session.episode_summaries:
                recent_episodes = session.episode_summaries[-3:]
                episode_block = "\n\n".join(recent_episodes)

            # ── Recent raw commands (current episode, uncompressed) ────────────
            # Last _EPISODE_SIZE commands — these are the ones not yet summarised.
            fresh_window = session.commands_executed[-session._EPISODE_SIZE:]
            successful_commands = [c for c in fresh_window if c.get("success", False)][-8:]

            # Compress command info
            compressed_commands = []
            for cmd in successful_commands:
                compressed_commands.append({
                    'command': cmd.get('command', '')[:100],
                    'summary': self._extract_command_summary(cmd.get('output', '')),
                    'timestamp': cmd.get('timestamp', '')
                })
            
            # Compress services info using the explicit test-state machine
            # (untested -> in_progress -> tested -> exploited). This replaces the
            # old "does the port number appear in any command" substring guess,
            # which produced false positives (e.g. port '80' matching '8080').
            services_summary = {}
            for service in session.discovered_services:
                port_str = str(service.get('port', ''))
                key = f"{service.get('service', 'unknown')}:{port_str}"
                state = service.get('test_state', 'untested')
                if key not in services_summary:
                    services_summary[key] = {
                        'service': service.get('service', 'unknown'),
                        'port': port_str,
                        'test_state': state,
                        # keep a boolean too for any downstream consumer that
                        # still expects `tested`
                        'tested': _SERVICE_STATE_ORDER.get(state, 0) >= _SERVICE_STATE_ORDER['tested'],
                    }
                elif _SERVICE_STATE_ORDER.get(state, 0) > _SERVICE_STATE_ORDER.get(
                    services_summary[key].get('test_state', 'untested'), 0
                ):
                    services_summary[key]['test_state'] = state
                    services_summary[key]['tested'] = (
                        _SERVICE_STATE_ORDER.get(state, 0) >= _SERVICE_STATE_ORDER['tested']
                    )
            
            # Compress evidence
            critical_evidence = []
            for evidence in session.evidence[-10:]:  # Last 10 evidence items
                ev_data = evidence.get('data', {})
                if isinstance(ev_data, dict):
                    # Extract key fields
                    compressed_ev = {
                        'type': evidence.get('type', ''),
                        'key_findings': str(ev_data).replace('"', "'")[:200]  # Simple string representation
                    }
                    critical_evidence.append(compressed_ev)
            
            # Credentials found (useful for reuse tracking)
            found_credentials = [
                {
                    'username': c.get('username', ''),
                    'service': c.get('service', ''),
                    'host': c.get('host', ''),
                    'secret_type': c.get('secret_type', ''),
                }
                for c in session.credentials[-10:]
            ]

            # ── Semantic recall of older findings ─────────────────────────────
            # Query the hybrid index with the objective + current stage + latest
            # command so critical earlier findings (creds, vulns, endpoints) that
            # scrolled out of the recent window are pulled back into context.
            last_cmd_text = ""
            if session.commands_executed:
                last_cmd_text = session.commands_executed[-1].get("command", "")
            recall_query = (
                f"{session.objective} {session.current_stage} {last_cmd_text}"
            ).strip()
            relevant_findings = [
                {"finding": r["text"][:400], "relevance": r["score"], "via": r["method"]}
                for r in self._retrieve_relevant_findings(session_id, recall_query, k=4)
            ]

            # Route at most a few relevant read-only methodology excerpts. Skill
            # content is provenance-tagged and remains inside the connector's
            # untrusted-memory fence; no upstream runner or script is executed.
            methodology_guidance = self._build_methodology_guidance(session)

            # Build memory structure
            memory = {
                # Strategic anchor: objective + plan + progress so the tactical
                # loop always reasons in service of the goal, not in a vacuum.
                'objective': session.objective,
                'objective_progress': round(session.objective_progress, 2),
                'objective_progress_note': session.objective_progress_note,
                'strategic_plan': session.strategic_plan[:6],
                'latest_reflection': session.reflections[-1] if session.reflections else None,
                'session_summary': {
                    'session_id': session_id,
                    'target': session.target_ip,
                    'domain': session.target_domain or 'N/A',
                    'stage': session.current_stage,
                    'total_commands': len(session.commands_executed),
                    'successful_commands': len([c for c in session.commands_executed if c.get('success', False)]),
                    'discovered_services': len(session.discovered_services),
                    'evidence_count': len(session.evidence),
                    'vulnerabilities_count': len(session.vulnerabilities),
                    'subdomains_found': len(session.discovered_subdomains),
                    'web_apps_found': len(session.web_applications),
                    'api_endpoints_found': len(session.discovered_api_endpoints),
                    'episodes': len(session.episode_summaries),
                },
                # Older history as compressed episode narratives
                'episode_history': episode_block[:3000] if episode_block else None,
                # Current window: recent un-summarised commands (full detail)
                'recent_successful_commands': compressed_commands,
                'services_discovered': list(services_summary.values()),
                'vulnerabilities_found': self._summarize_vulnerabilities(session),
                'critical_evidence': critical_evidence,
                # Domain attack surface
                'discovered_subdomains': session.discovered_subdomains[:50],
                'web_applications': session.web_applications[:20],
                'api_endpoints': session.discovered_api_endpoints[:30],
                # Credentials for reuse tracking
                'credentials_found': found_credentials,
                # Semantically-recalled older findings (hybrid retrieval)
                'relevant_past_findings': relevant_findings,
                'methodology_guidance': methodology_guidance,
                'compressed_at': datetime.now().isoformat()
            }
            
            # Return as compact JSON (single line to save tokens)
            return json.dumps(memory, separators=(',', ':'))
            
        except Exception as e:
            logger.error(f"Failed to build AI memory for session {session_id}: {e}")
            return json.dumps({'error': str(e)})
    
    def _get_relevant_threat_intel_context(self, session_id: str, max_entries: int = 6) -> str:
        """Return a compact block of threat-intel cache entries relevant to the services
        discovered in this session, for injection into AI prompts. Only includes entries
        whose topic/affected_software/title matches at least one discovered service name.
        Returns an empty string when nothing relevant is cached (no extra tokens wasted)."""
        session = self.sessions.get(session_id)
        if not session or not self.threat_intel_cache:
            return ""

        service_names = {
            (s.get("service") or "").strip().lower()
            for s in session.discovered_services
            if s.get("service") and s["service"].lower() not in ("unknown", "tcpwrapped", "")
        }
        if not service_names:
            return ""

        relevant = []
        seen_titles: set = set()
        for entry in self.threat_intel_cache:
            title = entry.get("title") or ""
            if title in seen_titles:
                continue
            haystack = " ".join([
                entry.get("topic") or "", entry.get("affected_software") or "",
                title, entry.get("description") or ""
            ]).lower()
            if any(name in haystack for name in service_names):
                relevant.append(entry)
                seen_titles.add(title)
                if len(relevant) >= max_entries:
                    break

        if not relevant:
            return ""

        lines = [
            "Threat-intel cache (unverified web research — treat as leads, not confirmed facts):"
        ]
        for e in relevant:
            cves = ", ".join(e.get("cve_ids") or []) or "no CVE"
            sev = e.get("severity") or "?"
            sw = e.get("affected_software") or ""
            lines.append(
                f"  • {e['title']} | CVE: {cves} | severity: {sev}"
                + (f" | software: {sw}" if sw else "")
            )
        return "\n".join(lines)

    def _format_credentials_for_ai(self, session) -> str:
        """Format discovered credentials for inclusion in the AI prompt.

        Shows the full username + secret so the AI can embed them directly in
        command flags rather than guessing or relying on interactive prompts.
        Shows at most 10 most recent credentials to keep token usage bounded.
        Returns a ready-to-paste summary string, or 'None discovered yet.'
        """
        if not session.credentials:
            return "None discovered yet."
        lines = []
        for c in session.credentials[-10:]:
            user    = c.get('username', '?')
            secret  = c.get('secret', '')
            stype   = c.get('secret_type', 'password')
            service = c.get('service') or c.get('host') or '?'
            host    = c.get('host', '')
            parts = [f"  credential_user={user}  [secret:{stype}:stored-locally]  service={service}"]
            if host and host != service:
                parts.append(f"  host={host}")
            lines.append("".join(parts))
        return "\n".join(lines)

    def _summarize_vulnerabilities(self, session: Session) -> List[Dict]:
        """Compact vulnerability findings for inclusion in AI prompts/memory -
        just the fields useful for deciding what to target next, not full
        descriptions/references (keeps token usage down)."""
        summary = []
        for v in session.vulnerabilities[:20]:
            summary.append({
                "host": v.get("host"),
                "port": v.get("port"),
                "service": v.get("service"),
                "name": v.get("name"),
                "risk": v.get("risk_level"),
                "cve_ids": v.get("cve_ids") or [],
                "cvss": v.get("cvss_score"),
                "source": v.get("source_tool"),
                "status": v.get("status")
            })
        return summary

    def _extract_command_summary(self, output: str) -> str:
        """Extract key summary from command output."""
        if not output:
            return "No output"
        
        # Look for key indicators
        lines = output.split('\n')
        key_lines = []
        
        for line in lines:
            line_lower = line.lower()
            # Look for interesting findings
            if any(keyword in line_lower for keyword in [
                'vulnerable', 'found', 'success', 'login', 'password', 
                'credential', 'admin', 'root', 'shell', 'access',
                'open', 'running', 'detected', 'version'
            ]):
                if len(line) < 200:  # Avoid huge lines
                    key_lines.append(line.strip())
            
            if len(key_lines) >= 3:  # Limit to 3 key lines
                break
        
        if key_lines:
            return ' | '.join(key_lines)
        
        # If no key lines found, return first 100 chars
        return output[:100] + ('...' if len(output) > 100 else '')
    
    def get_session_report(self, session_id: str) -> Dict:
        """Generate a comprehensive report for a session."""
        session = self.sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        return {
            "session": session.to_dict(),
            "scan_results": session.scan_results,
            "discovered_hosts": session.discovered_hosts,
            "discovered_services": session.discovered_services,
            "commands_executed": session.commands_executed,
            "ai_decisions": session.ai_decisions,
            "evidence": session.evidence,
            "vulnerabilities": session.vulnerabilities,
            "credentials": session.credentials,
            "summary": {
                "total_hosts": len(session.discovered_hosts),
                "total_services": len(session.discovered_services),
                "total_commands": len(session.commands_executed),
                "successful_commands": len([c for c in session.commands_executed if c.get("success", False)]),
                "ai_decisions_count": len(session.ai_decisions),
                "evidence_count": len(session.evidence),
                "total_vulnerabilities": len(session.vulnerabilities)
            }
        }

    def delete_session(self, session_id: str) -> Dict:
        """Delete a specific session and all its associated data from database and memory."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Delete from all relevant tables in correct order (due to foreign key constraints)
            # Start with child tables, then parent table
            cursor.execute('DELETE FROM scan_results WHERE session_id = ?', (session_id,))
            cursor.execute('DELETE FROM commands WHERE session_id = ?', (session_id,))
            cursor.execute('DELETE FROM evidence WHERE session_id = ?', (session_id,))
            cursor.execute('DELETE FROM vulnerabilities WHERE session_id = ?', (session_id,))
            cursor.execute('DELETE FROM credentials WHERE session_id = ?', (session_id,))
            cursor.execute('DELETE FROM ai_decisions WHERE session_id = ?', (session_id,))
            # Shell + chat tables (best-effort: older DBs may not have them yet).
            for _tbl in ("shell_handlers", "shell_sessions_log", "chat_messages"):
                try:
                    cursor.execute(f'DELETE FROM {_tbl} WHERE session_id = ?', (session_id,))
                except sqlite3.OperationalError:
                    pass
            cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))

            conn.commit()
            conn.close()

            # Stop and drop any live shell manager for this session.
            _mgr = self._shell_managers.pop(session_id, None)
            if _mgr is not None:
                try:
                    asyncio.create_task(_mgr.stop_all())
                except Exception:
                    pass

            # Remove from memory
            if session_id in self.sessions:
                del self.sessions[session_id]
            
            # Remove any pending commands for this session
            command_ids_to_remove = [
                cmd_id for cmd_id, cmd_data in self.pending_commands.items()
                if cmd_data.get("session_id") == session_id
            ]
            for cmd_id in command_ids_to_remove:
                del self.pending_commands[cmd_id]
            
            logger.info(f"Successfully deleted session {session_id} from database and memory")
            return {
                "status": "success",
                "message": f"Session {session_id} deleted successfully",
                "session_id": session_id
            }
            
        except sqlite3.Error as e:
            logger.error(f"Failed to delete session {session_id} from database: {e}")
            return {
                "status": "error",
                "message": f"Failed to delete session: {str(e)}",
                "session_id": session_id
            }

    def delete_all_sessions(self) -> Dict:
        """Delete all sessions and all associated data from database and memory."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Delete from all tables in correct order (due to foreign key constraints)
            cursor.execute('DELETE FROM scan_results')
            cursor.execute('DELETE FROM commands')
            cursor.execute('DELETE FROM evidence')
            cursor.execute('DELETE FROM vulnerabilities')
            cursor.execute('DELETE FROM credentials')
            cursor.execute('DELETE FROM ai_decisions')
            for _tbl in ("shell_handlers", "shell_sessions_log", "chat_messages"):
                try:
                    cursor.execute(f'DELETE FROM {_tbl}')
                except sqlite3.OperationalError:
                    pass
            cursor.execute('DELETE FROM sessions')

            conn.commit()
            conn.close()

            # Stop all live shell managers.
            for _mgr in list(self._shell_managers.values()):
                try:
                    asyncio.create_task(_mgr.stop_all())
                except Exception:
                    pass
            self._shell_managers.clear()

            # Clear memory (capture count before clearing so we report it accurately)
            deleted_count = len(self.sessions)
            self.sessions.clear()
            self.pending_commands.clear()

            logger.info(f"Successfully deleted all {deleted_count} sessions from database and memory")
            return {
                "status": "success",
                "message": "All sessions deleted successfully",
                "deleted_count": deleted_count
            }
            
        except sqlite3.Error as e:
            logger.error(f"Failed to delete all sessions from database: {e}")
            return {
                "status": "error",
                "message": f"Failed to delete all sessions: {str(e)}"
            }
