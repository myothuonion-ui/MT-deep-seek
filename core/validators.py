"""
MT Pentester Validators Module
Centralized safety checks: target format validation, scope allowlisting, and a
binary allowlist used to gate the fully-autonomous (zero-human-review) auto-execute path.

These are defense-in-depth controls, not a claim of perfect shell parsing. They exist to
shrink blast radius for two realistic failure modes of an LLM-driven agent that shells out:
1. A malformed/hostile "target" string reaching a shell command via string interpolation.
2. The LLM being steered (via misclassification or indirect prompt injection from
   attacker-controlled scan/tool output) into suggesting a command that should never
   run without a human looking at it first.
"""

import ipaddress
import os
import re
import shlex
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

# --- Target format validation -------------------------------------------------

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def is_cidr(value: str) -> bool:
    """Return True if value is a valid IPv4/IPv6 CIDR network (e.g. 192.168.1.0/24).
    strict=False so host bits set (192.168.1.5/24) are still accepted."""
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
        # Reject host addresses presented as plain IPs with no prefix — those
        # are handled by ip_address() in is_valid_target(). A valid CIDR must
        # contain a "/" character.
        return "/" in value
    except ValueError:
        return False


def is_valid_target(value: Optional[str]) -> bool:
    """Return True if value is a plain IP address, hostname, or CIDR network
    with no shell metacharacters. CIDR notation (192.168.1.0/24) is now
    accepted to support subnet-level scanning.
    """
    if not value or not isinstance(value, str):
        return False
    value = value.strip()
    if not value or len(value) > 253:
        return False

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass

    if is_cidr(value):
        return True

    return bool(_HOSTNAME_RE.match(value))


# --- Scope allowlisting ---------------------------------------------------------

def is_target_in_scope(target: Optional[str], allowlist_str: Optional[str]) -> bool:
    """Check a target against an optional SCOPE_ALLOWLIST (comma-separated IPs,
    CIDR ranges, exact hostnames, or "*.suffix" wildcard hostnames).

    Scope is deny-by-default. If allowlist_str is empty/unset, targets are
    rejected unless ALLOW_UNSCOPED_TARGETS=true is explicitly configured.
    """
    if not target:
        return False
    if not allowlist_str or not allowlist_str.strip():
        return os.getenv("ALLOW_UNSCOPED_TARGETS", "false").lower() == "true"

    entries = [e.strip() for e in allowlist_str.split(",") if e.strip()]
    if not entries:
        return os.getenv("ALLOW_UNSCOPED_TARGETS", "false").lower() == "true"

    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        target_ip = None

    # Handle CIDR target: check that the target subnet is contained within
    # or equal to at least one allowlist entry.
    try:
        target_net = ipaddress.ip_network(target, strict=False) if "/" in target else None
    except ValueError:
        target_net = None

    target_lower = target.lower()
    for entry in entries:
        if target_ip is not None:
            try:
                if target_ip in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass  # entry wasn't an IP/CIDR, fall through to hostname checks

        if target_net is not None:
            try:
                allowlist_net = ipaddress.ip_network(entry, strict=False)
                # Target subnet must be a subnet of (or equal to) the allowlist entry
                if target_net.subnet_of(allowlist_net):
                    return True
            except (ValueError, TypeError):
                pass

        entry_lower = entry.lower()
        if entry_lower == target_lower:
            return True
        if entry_lower.startswith("*.") and target_lower.endswith(entry_lower[1:]):
            return True

    return False


# --- Binary allowlist for the autonomous auto-execute path ----------------------

# Comprehensive Kali Linux toolset allowlist for the autonomous auto-execute path.
# Covers recon, web-app, brute-force, exploitation, AD/SMB, post-exploitation,
# wireless, forensics, scripting, and standard shell utilities.
# FULL_AUTO_MODE never bypasses this list — see is_allowlisted_command().
ALLOWED_BINARIES = {
    # ── Reconnaissance & scanning ───────────────────────────────────────
    "nmap", "masscan", "rustscan", "unicornscan",
    "netdiscover", "arp-scan", "hping3", "fping", "p0f",
    "tcpdump", "tshark", "wireshark", "netstat", "ss", "iptables", "ip",
    "ping", "ping6", "traceroute", "traceroute6", "mtr",
    "whois", "dig", "nslookup", "host",
    "fierce", "dnsrecon", "dnsenum", "dnswalk", "dnsmap",
    "sublist3r", "amass", "subfinder", "assetfinder", "dnsx", "httpx",
    "aquatone", "eyewitness", "gowitness",

    # ── Web application ─────────────────────────────────────────────────
    "whatweb", "nikto", "gobuster", "dirb", "dirsearch", "ffuf",
    "wfuzz", "feroxbuster",
    "wpscan", "joomscan", "droopescan", "cmseek",
    "sqlmap", "ghauri", "commix", "xsser", "dalfox", "arjun",
    "nuclei", "jaeles",
    "nosqlmap", "jwt_tool", "jwttool",
    "burpsuite", "zaproxy", "mitmproxy",
    "cutycapt", "wkhtmltoimage",

    # ── Brute-force & credential attacks ───────────────────────────────
    "hydra", "ncrack", "medusa", "crowbar", "patator",
    "crackmapexec", "cme",
    "cewl", "crunch", "cupp", "rsmangler", "mentalist",
    "hashcat", "john", "hash-identifier", "hashid", "haiti",
    "ophcrack", "samdump2", "chntpw",

    # ── Exploitation & frameworks ───────────────────────────────────────
    "msfconsole", "msfvenom", "msfdb", "msfrpc",
    "searchsploit",
    "nc", "ncat", "netcat", "socat",
    "pwncat", "pwncat-cs",
    "rlwrap",
    "beef-xss",

    # ── SMB / Windows / Active Directory ────────────────────────────────
    "smbclient", "smbmap", "smbget",
    "enum4linux", "enum4linux-ng",
    "rpcclient", "net", "rpcinfo",
    "ldapsearch", "ldapdomaindump", "ldapmodify", "ldapadd",
    "kinit", "klist", "kdestroy", "kvno",
    "bloodhound", "bloodhound-python", "neo4j",
    "kerbrute",
    "impacket-secretsdump", "impacket-psexec", "impacket-wmiexec",
    "impacket-smbexec", "impacket-getuserspns", "impacket-getnpusers",
    "impacket-ntlmrelayx", "impacket-smbserver", "impacket-lookupsid",
    "impacket-reg", "impacket-dcomexec", "impacket-atexec",
    "impacket-ticketer", "impacket-goldenPac", "impacket-rpcdump",
    "evil-winrm",
    "xfreerdp", "rdesktop", "freerdp",
    "winexe",

    # ── Post-exploitation & pivoting ────────────────────────────────────
    "proxychains", "proxychains4",
    "chisel", "ligolo-ng", "ligolo",
    "pspy", "pspy32", "pspy64",
    "linpeas", "winpeas", "linenum",
    "unix-privesc-check", "linux-exploit-suggester",
    "gtfobins",

    # ── Wireless ────────────────────────────────────────────────────────
    "aircrack-ng", "airmon-ng", "aireplay-ng", "airodump-ng",
    "airdecap-ng", "packetforge-ng", "airbase-ng",
    "kismet", "wifite", "bettercap",
    "hostapd", "hostapd-wpe",
    "hcxtools", "hcxdumptool",
    "reaver", "bully", "pixiewps",
    "wpa_supplicant", "iw", "iwconfig", "iwlist",

    # ── Vulnerability analysis ──────────────────────────────────────────
    "openvas", "openvas-start", "gvm-cli", "gvm-check-setup",
    "lynis", "chkrootkit", "rkhunter",
    "testssl", "sslscan", "sslyze",
    "certutil", "openssl",

    # ── Network utilities ───────────────────────────────────────────────
    "curl", "wget",
    "ssh", "ssh-keyscan", "ssh-keygen", "ssh-copy-id", "scp", "sftp",
    "responder", "mitm6", "arpspoof", "ettercap",
    "tcpflow", "ngrep", "dsniff", "sslstrip",
    "nfqueue", "scapy",
    "proxytunnel", "corkscrew",

    # ── Forensics & reverse engineering ─────────────────────────────────
    "binwalk", "strings", "file", "hexdump", "xxd",
    "objdump", "readelf", "nm", "strace", "ltrace",
    "radare2", "r2", "r2pm",
    "gdb", "gdbserver",
    "volatility", "volatility3",
    "foremost", "scalpel", "bulk_extractor", "photorec",
    "exiftool", "steghide", "stegcracker", "zsteg",
    "pdfinfo", "pdfcrack",

    # ── Scripting runtimes ──────────────────────────────────────────────
    "python3", "python", "python2",
    "bash", "sh", "zsh", "dash", "fish",
    "perl", "ruby", "php",
    "node", "nodejs", "npm",
    "go", "java", "javac", "jar",
    "gcc", "g++", "make", "cmake",
    "powershell", "pwsh",

    # ── Standard shell utilities ─────────────────────────────────────────
    "echo", "printf", "cat", "tac",
    "ls", "ll", "la", "dir",
    "mkdir", "cp", "mv", "rm", "rmdir", "ln", "touch",
    "grep", "egrep", "fgrep", "rg", "ag",
    "awk", "gawk", "sed", "head", "tail", "less", "more",
    "sort", "uniq", "wc", "tr", "cut", "paste", "join",
    "find", "locate", "which", "whereis", "type",
    "xargs", "parallel",
    "chmod", "chown", "chgrp", "stat", "lsattr", "chattr", "getfacl", "setfacl",
    "id", "whoami", "groups", "uname", "hostname", "uptime", "uname",
    "ps", "pstree", "top", "htop", "kill", "pkill", "killall", "signal",
    "jobs", "fg", "bg", "nohup", "disown",
    "screen", "tmux",
    "date", "cal", "bc", "expr",
    "base64", "base32",
    "zip", "unzip", "tar", "gzip", "gunzip", "bzip2", "xz", "lzma",
    "7z", "7za", "rar", "unrar",
    "tee", "timeout", "watch", "time",
    "env", "printenv",
    "diff", "patch", "cmp",
    "wget", "curl",

    # ── Package management ───────────────────────────────────────────────
    "apt-get", "apt", "apt-cache", "dpkg",
    "pip", "pip3", "pip2",
    "gem", "bundle",

    # ── OSINT ────────────────────────────────────────────────────────────
    "theharvester", "recon-ng", "maltego",
    "shodan",

    # ── Version control / misc ───────────────────────────────────────────
    "git", "svn",
    "docker", "kubectl",
    "jq", "yq", "xmllint",
    "nc", "ncat",
}

# "curl/wget SOMETHING | bash/sh/python" is a classic download-and-execute chain.
# Block it outright even though the individual binaries are each allowlisted
# (bash/python are legitimately needed for non-interactive `-c` one-liners).
_DOWNLOAD_EXEC_RE = re.compile(
    r"\b(curl|wget)\b[^;&|\n]*\|\s*(bash|sh|python3?|perl|ruby)\b", re.IGNORECASE
)

_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# General-purpose interpreters make a binary allowlist equivalent to arbitrary
# code execution. Autonomous mode routes these to human review.
AUTO_DENIED_BINARIES = {
    "bash", "sh", "zsh", "dash", "fish", "python", "python2", "python3",
    "perl", "ruby", "php", "node", "nodejs", "powershell", "pwsh",
}

# Launchers and host-mutating utilities can turn an otherwise safe child argv
# into arbitrary code execution or modify the MT runtime host. They remain
# available after explicit operator review, but never execute autonomously.
AUTO_REVIEW_ONLY_BINARIES = {
    "sudo", "env", "xargs", "parallel", "timeout", "watch", "nohup",
    "nice", "ionice", "setsid",
    "apt", "apt-get", "dpkg", "pip", "pip2", "pip3", "npm", "gem", "bundle",
    "go", "java", "javac", "jar", "gcc", "g++", "make", "cmake",
    "git", "svn", "docker", "kubectl",
    "rm", "rmdir", "mv", "cp", "dd", "tee", "chmod", "chown", "chgrp",
    "mount", "umount", "systemctl", "service", "kill", "pkill", "killall",
    "iptables", "ssh-copy-id",
}

# Environment variables with loader/interpreter semantics can hijack an
# allowlisted executable before its own argv is processed.
AUTO_DENIED_ENV_NAMES = {
    "PATH", "LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME",
    "BASH_ENV", "ENV", "SHELLOPTS", "PERL5OPT", "RUBYOPT", "NODE_OPTIONS",
}

_AUTO_REVIEW_FLAGS = {
    "find": {"-delete", "-exec", "-execdir", "-ok", "-okdir"},
    "nc": {"-e", "--exec", "-c"},
    "ncat": {"-e", "--exec", "-c"},
    "socat": {"exec", "system"},
}


def is_allowlisted_command(command: Optional[str]) -> Optional[str]:
    """Gate for the fully-autonomous auto-execute path (no human review).

    Returns None if the command is allowed to run, or a short human-readable
    rejection reason if it should instead be routed to manual approval.

    FULL_AUTO_MODE bypasses routine approval, but never bypasses this structural
    allowlist. Human-reviewed commands remain a separate trust boundary.

    NOT applied to commands a human explicitly typed or clicked "approve" on —
    that's a legitimate trust boundary and operators should retain full
    flexibility to run any tool they choose to review themselves.
    """
    if not command or not command.strip():
        return "Empty command"

    if "`" in command or "$(" in command:
        return "Command substitution (backticks or $()) is not allowed in auto-executed commands"

    if _DOWNLOAD_EXEC_RE.search(command):
        return "Download-and-execute pattern (curl/wget piped into a shell/interpreter) is not allowed in auto-executed commands"

    segments = re.split(r"&&|\|\||;|\||\n", command)
    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue
        try:
            tokens = shlex.split(segment)
        except ValueError as exc:
            return f"Invalid command quoting: {exc}"
        idx = 0
        # Allow ordinary per-command values, but block variables that can alter
        # executable resolution, dynamic linking, or interpreter startup.
        while idx < len(tokens) and _ENV_ASSIGNMENT_RE.match(tokens[idx]):
            env_name = tokens[idx].split("=", 1)[0]
            if env_name in AUTO_DENIED_ENV_NAMES:
                return f"Environment variable '{env_name}' requires human review in autonomous mode"
            idx += 1
        if idx >= len(tokens):
            continue

        executable = tokens[idx]
        if "/" in executable or "\\" in executable:
            return "Executable paths require human review in autonomous mode"
        binary = os.path.basename(executable)
        if binary in AUTO_DENIED_BINARIES:
            return f"Interpreter '{binary}' requires human review in autonomous mode"
        if binary in AUTO_REVIEW_ONLY_BINARIES:
            return f"Launcher or host-mutating binary '{binary}' requires human review in autonomous mode"
        if binary not in ALLOWED_BINARIES:
            return f"Binary '{binary}' is not in the auto-execute allowlist"

        review_flags = _AUTO_REVIEW_FLAGS.get(binary, set())
        lowered_args = {token.lower().rstrip(";") for token in tokens[idx + 1:]}
        if review_flags & lowered_args:
            flag = sorted(review_flags & lowered_args)[0]
            return f"Flag '{flag}' for '{binary}' requires human review in autonomous mode"
        if binary == "socat" and any(
            token.lower().startswith(("exec:", "system:"))
            for token in tokens[idx + 1:]
        ):
            return "socat process execution requires human review in autonomous mode"

    return None


def parse_autonomous_argv(command: Optional[str]) -> Tuple[List[str], Dict[str, str], Optional[str]]:
    """Convert a single autonomous command into argv without invoking a shell.

    Shell control operators are rejected. Leading ``NAME=value`` assignments are
    returned separately so callers can build an explicit child environment.
    Human-reviewed commands use a separate execution boundary.
    """
    rejection = is_allowlisted_command(command)
    if rejection:
        return [], {}, rejection

    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars="|&;<>")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError as exc:
        return [], {}, f"Invalid command quoting: {exc}"

    shell_tokens = {"|", "||", "&", "&&", ";", "<", ">", "<<", ">>", "<>", ">&", "<&"}
    bad = next((token for token in tokens if token in shell_tokens or set(token) <= set("|&;<>") and token), None)
    if bad:
        return [], {}, f"Shell operator '{bad}' requires human review"

    env_updates: Dict[str, str] = {}
    while tokens and _ENV_ASSIGNMENT_RE.match(tokens[0]):
        name, value = tokens.pop(0).split("=", 1)
        env_updates[name] = value

    if not tokens:
        return [], {}, "Command contains no executable"
    if tokens[0] == "sudo":
        return [], {}, "sudo requires human review in autonomous mode"

    return tokens, env_updates, None


_URL_RE = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
_SCOPED_VALUE_FLAGS = {"--host", "--hostname", "--target", "--url", "--domain", "--server"}


def extract_command_targets(command: Optional[str]) -> List[str]:
    """Best-effort extraction of explicit network targets from a command."""
    if not command:
        return []
    found: List[str] = []

    for match in _URL_RE.findall(command):
        host = urlsplit(match.rstrip(").,;")).hostname
        if host:
            found.append(host)

    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    expect_scoped_value = False
    for token in tokens:
        if expect_scoped_value:
            candidate = token.strip("[](),;'")
            parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
            if parsed.hostname:
                found.append(parsed.hostname)
            expect_scoped_value = False
            continue

        if token in _SCOPED_VALUE_FLAGS:
            expect_scoped_value = True
            continue
        if any(token.startswith(f"{flag}=") for flag in _SCOPED_VALUE_FLAGS):
            value = token.split("=", 1)[1]
            parsed = urlsplit(value if "://" in value else f"//{value}")
            if parsed.hostname:
                found.append(parsed.hostname)
            continue

        candidate = token.strip("[](),;'")
        if "@" in candidate and not candidate.startswith("@"):  # user@host
            candidate = candidate.rsplit("@", 1)[1]
        candidate = candidate.split(":", 1)[0] if candidate.count(":") == 1 else candidate
        try:
            ipaddress.ip_network(candidate, strict=False)
            found.append(candidate)
        except ValueError:
            pass

    # Preserve order for deterministic audit messages.
    return list(dict.fromkeys(found))


def autonomous_scope_rejection(command: Optional[str], allowlist: Optional[str]) -> Optional[str]:
    """Reject every explicitly detected target outside the engagement scope."""
    for target in extract_command_targets(command):
        if not is_target_in_scope(target, allowlist):
            return f"Command target '{target}' is outside SCOPE_ALLOWLIST"
    return None
