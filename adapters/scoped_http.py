"""Bounded same-origin GET transport with DNS pinning and no proxy inheritance."""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import re
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit, urlunsplit

from adapters.base import AdapterPolicyError, require_authorized_scope
from core.validators import is_target_in_scope


@dataclass(frozen=True)
class WebScope:
    target: str
    allowlist: str
    paths: tuple[str, ...] = ("/",)
    excluded_paths: tuple[str, ...] = ()

    def __post_init__(self):
        if not self.allowlist.strip():
            raise AdapterPolicyError("Web assessments require an explicit SCOPE_ALLOWLIST")
        for prefix in (*self.paths, *self.excluded_paths):
            if not prefix.startswith("/") or any(c in prefix for c in "%?#\\") or ".." in prefix:
                raise AdapterPolicyError("Scope paths must be literal absolute path prefixes")
        self.check(self.target)

    @staticmethod
    def origin(url):
        p = urlsplit(url)
        return p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)

    def check(self, url):
        if not isinstance(url, str) or len(url) > 2048 or re.search(r"[\x00-\x20\x7f\\]", url):
            raise AdapterPolicyError("Invalid assessment URL")
        p = urlsplit(url)
        if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
            raise AdapterPolicyError("An absolute HTTP(S) URL without credentials is required")
        if p.query or p.fragment:
            raise AdapterPolicyError("Query strings and fragments are not supported by this GET profile")
        if self.origin(url) != self.origin(self.target):
            raise AdapterPolicyError("URL is outside the engagement origin")
        path = p.path or "/"
        decoded = unquote(path)
        if decoded != path or any(x in path.split("/") for x in {".", ".."}) or "//" in path:
            raise AdapterPolicyError("Encoded or ambiguous paths are not supported")
        # GET can still have side effects; prohibit common action routes as well
        # as operator exclusions. Only operator-approved read-only areas belong here.
        if re.search(r"(?i)(?:^|[/_-])(logout|signout|delete|remove|unsubscribe|reset|checkout)(?:$|[/_.-])", path):
            raise AdapterPolicyError("Action-like routes are excluded from the GET profile")
        def within(prefix):
            return prefix == "/" or path == prefix.rstrip("/") or path.startswith(prefix.rstrip("/") + "/")
        if not any(within(x) for x in self.paths) or any(within(x) for x in self.excluded_paths):
            raise AdapterPolicyError("URL is outside allowed paths")
        require_authorized_scope(url, self.allowlist, True)
        return urlunsplit((p.scheme, p.netloc, path, "", ""))


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        sock = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except BaseException:
            sock.close()
            raise


class ScopedHTTP:
    """One request per call. Redirects are recorded, never followed implicitly."""
    def __init__(self, scope: WebScope, timeout=10, max_bytes=262144):
        self.scope = scope
        self.timeout = max(1, min(timeout, 20))
        self.max_bytes = max(1024, min(max_bytes, 1_000_000))

    def get(self, url, credentials=None):
        url = self.scope.check(url)
        p = urlsplit(url)
        port = p.port or (443 if p.scheme == "https" else 80)
        addresses = sorted({a[4][0] for a in socket.getaddrinfo(p.hostname, port, type=socket.SOCK_STREAM)})
        if not addresses:
            raise AdapterPolicyError("Target has no resolved addresses")
        for address in addresses:
            ip = ipaddress.ip_address(address)
            # A hostname authorization alone must not authorize rebinding into
            # loopback, link-local or a private network. Explicit IP/CIDR needed.
            if not ip.is_global and not is_target_in_scope(address, self.scope.allowlist):
                raise AdapterPolicyError("Non-public resolved address requires explicit IP/CIDR scope")
        headers = {"User-Agent": "MT-Web-Assessment/1", "Accept": "text/html,application/json", "Accept-Encoding": "identity"}
        if credentials:
            if set(credentials) - {"Authorization", "Cookie"}:
                raise AdapterPolicyError("Unsupported credential header")
            if p.scheme != "https" and ipaddress.ip_address(addresses[0]).is_global:
                raise AdapterPolicyError("Credentials require HTTPS for public targets")
            for key, value in credentials.items():
                if not isinstance(value, str) or not value or re.search(r"[\x00-\x1f\x7f]", value):
                    raise AdapterPolicyError("Invalid credential value")
                headers[key] = value
        host = f"[{p.hostname}]" if ":" in p.hostname else p.hostname
        headers["Host"] = f"{host}:{port}"
        if p.scheme == "https":
            conn = _PinnedHTTPS(p.hostname, port, addresses[0], self.timeout)
        else:
            conn = http.client.HTTPConnection(addresses[0], port, timeout=self.timeout)
        started = time.monotonic()
        try:
            conn.request("GET", p.path or "/", headers=headers)
            response = conn.getresponse()
            # Enforce wall-clock budget between bounded reads, even if a server
            # drip-feeds data faster than the socket's inactivity timeout.
            chunks, count = [], 0
            while count <= self.max_bytes:
                if time.monotonic() - started >= self.timeout:
                    raise TimeoutError("HTTP response deadline exceeded")
                chunk = response.read1(min(16384, self.max_bytes + 1 - count))
                if not chunk:
                    break
                chunks.append(chunk)
                count += len(chunk)
            raw = b"".join(chunks)
            body = raw[:self.max_bytes]
            raw_headers = {k.lower(): v for k, v in response.getheaders()}
            return {
                "url": url, "status": response.status, "body": body,
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "truncated": len(raw) > self.max_bytes,
                "headers": raw_headers,
                "duration_seconds": round(time.monotonic() - started, 3),
            }
        finally:
            conn.close()
