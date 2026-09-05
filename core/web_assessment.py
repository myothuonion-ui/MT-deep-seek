"""Persistent, bounded Web/API assessment worker.

This initial executable profile supports same-origin GET mapping, deterministic
header review and controlled two-account object-authorization checks. The LLM
can rank approved tasks; it cannot create commands, assert proof or alter scope.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from adapters.base import AdapterPolicyError
from adapters.scoped_http import ScopedHTTP, WebScope
from core.code_intelligence import analyze_source_bundle
from core.proof_verifier import evaluate_finding


class AssessmentError(ValueError):
    pass


class HaltAssessment(Exception):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a" and len(self.links) < 100:
            href = dict(attrs).get("href", "")
            if href and len(href) <= 2048:
                self.links.append(href)


def validate_spec(raw, allowlist):
    if not isinstance(raw, dict) or len(canonical(raw)) > 6_000_000:
        raise AssessmentError("Invalid or oversized assessment input")
    if raw.get("authorization_confirmed") is not True:
        raise AssessmentError("Explicit testing authorization is required")
    supported = {"target", "authorization_confirmed", "allowed_paths", "excluded_paths", "max_requests", "max_seconds", "max_pages", "ai_planning", "accounts", "authorization_checks", "source_files"}
    if set(raw) - supported:
        raise AssessmentError("Unsupported assessment field")
    def prefixes(name, default):
        value = raw.get(name, default)
        if not isinstance(value, list) or not 0 <= len(value) <= 30 or not all(isinstance(x, str) for x in value):
            raise AssessmentError("Invalid path scope")
        return tuple(value)
    scope = WebScope(raw.get("target", ""), allowlist, prefixes("allowed_paths", ["/"]), prefixes("excluded_paths", []))
    spec = {"target": scope.check(scope.target), "authorization_confirmed": True,
            "allowed_paths": list(scope.paths), "excluded_paths": list(scope.excluded_paths)}
    for key, default, low, high in [("max_requests", 40, 2, 200), ("max_seconds", 180, 10, 600), ("max_pages", 10, 1, 30)]:
        value = raw.get(key, default)
        if type(value) is not int or not low <= value <= high:
            raise AssessmentError(f"{key} must be an integer from {low} to {high}")
        spec[key] = value
    if type(raw.get("ai_planning", False)) is not bool:
        raise AssessmentError("ai_planning must be boolean")
    spec["ai_planning"] = raw.get("ai_planning", False)
    accounts = raw.get("accounts", {})
    if not isinstance(accounts, dict) or len(accounts) > 5:
        raise AssessmentError("At most five test account references are supported")
    for name, account in accounts.items():
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", name) or not isinstance(account, dict):
            raise AssessmentError("Invalid account name")
        if set(account) != {"secret_env", "kind"} or account["kind"] not in {"bearer", "cookie"}:
            raise AssessmentError("Accounts require kind (bearer/cookie) and secret_env")
        if not re.fullmatch(r"MT_WEB_ACCOUNT_[A-Z0-9_]{1,80}", str(account["secret_env"])):
            raise AssessmentError("Account secret references must start with MT_WEB_ACCOUNT_")
    spec["accounts"] = accounts
    checks = raw.get("authorization_checks", [])
    if not isinstance(checks, list) or len(checks) > 20:
        raise AssessmentError("At most twenty controlled authorization checks are supported")
    normalized = []
    for check in checks:
        fields = {"url", "owner", "other", "marker", "ownership_confirmed"}
        if not isinstance(check, dict) or set(check) != fields or check["ownership_confirmed"] is not True:
            raise AssessmentError("Each authorization check requires a controlled fixture and explicit ownership confirmation")
        if check["owner"] == check["other"] or any(x not in accounts for x in (check["owner"], check["other"])):
            raise AssessmentError("Authorization checks require two distinct test accounts")
        if accounts[check["owner"]]["secret_env"] == accounts[check["other"]]["secret_env"]:
            raise AssessmentError("Test accounts must use distinct credential references")
        marker = check["marker"]
        if not isinstance(marker, str) or not 8 <= len(marker) <= 128 or re.search(r"[\x00-\x1f]", marker):
            raise AssessmentError("Use an 8–128 character synthetic fixture marker")
        normalized.append({**check, "url": scope.check(check["url"])})
    spec["authorization_checks"] = normalized
    source = raw.get("source_files", {})
    # Raw source is processed once and is neither persisted nor sent to a model.
    spec["source_analysis"] = analyze_source_bundle(source) if source else None
    return spec


class WebAssessments:
    def __init__(self, db_path, signing_key, allowlist_getter, ai=None, transport_factory=ScopedHTTP):
        if not signing_key or len(signing_key) < 16:
            raise AssessmentError("Assessment evidence signing key is required")
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.key = signing_key.encode()
        self.allowlist_getter = allowlist_getter
        self.ai = ai
        self.transport_factory = transport_factory
        self.owner = uuid.uuid4().hex
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS web_jobs (id TEXT PRIMARY KEY, state TEXT NOT NULL, lease REAL NOT NULL DEFAULT 0, owner TEXT, cancel INTEGER NOT NULL DEFAULT 0, body TEXT NOT NULL)")
        os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def create(self, raw):
        spec = validate_spec(raw, self.allowlist_getter())
        job_id = uuid.uuid4().hex
        tasks = [{"id": "map-0", "kind": "map", "url": spec["target"]}]
        tasks += [{"id": f"auth-{i}", "kind": "authorization", "check": check} for i, check in enumerate(spec["authorization_checks"])]
        body = {"id": job_id, "spec": spec, "created_at": time.time(), "started_at": None,
                "requests_used": 0, "ai_calls": 0, "ai_status": "disabled" if not spec["ai_planning"] else "pending",
                "pending": tasks, "finished_tasks": [], "in_flight": None,
                "seen": [spec["target"]], "artifacts": [], "findings": [], "coverage_gaps": [], "events": []}
        with self.connect() as db:
            db.execute("INSERT INTO web_jobs(id,state,body) VALUES(?, 'queued', ?)", (job_id, canonical(body)))
        return self.get(job_id)

    def get(self, job_id):
        with self.connect() as db:
            row = db.execute("SELECT * FROM web_jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            raise AssessmentError("Assessment not found")
        data = json.loads(row["body"])
        data["state"] = row["state"]
        data["cancel_requested"] = bool(row["cancel"])
        return data

    def list(self):
        with self.connect() as db:
            rows = db.execute("SELECT id,state,body FROM web_jobs ORDER BY rowid DESC LIMIT 100").fetchall()
        return [{"id": row["id"], "state": row["state"], "target": json.loads(row["body"])["spec"]["target"]} for row in rows]

    def cancel(self, job_id):
        self.get(job_id)
        with self.connect() as db:
            db.execute("UPDATE web_jobs SET cancel=1,state=CASE WHEN state IN ('queued','paused') THEN 'cancelled' ELSE state END WHERE id=?", (job_id,))
        return self.get(job_id)

    def resume(self, job_id):
        job = self.get(job_id)
        spec = job["spec"]
        WebScope(spec["target"], self.allowlist_getter(), tuple(spec["allowed_paths"]), tuple(spec["excluded_paths"]))
        with self.connect() as db:
            changed = db.execute("UPDATE web_jobs SET state='queued',cancel=0 WHERE id=? AND state='paused'", (job_id,)).rowcount
        if not changed:
            raise AssessmentError("Only paused assessments can be resumed")
        return self.get(job_id)

    def _save(self, body, state="running"):
        body.pop("state", None)
        body.pop("cancel_requested", None)
        with self.connect() as db:
            changed = db.execute("UPDATE web_jobs SET body=?, state=?,lease=? WHERE id=? AND owner=? AND state='running'",
                                 (canonical(body), state, time.time() + 90, body["id"], self.owner)).rowcount
        if not changed:
            raise HaltAssessment("Worker lease was lost")

    def claim(self):
        now = time.time()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            expired = db.execute("SELECT * FROM web_jobs WHERE state='running' AND lease<?", (now,)).fetchall()
            for row in expired:
                body = json.loads(row["body"])
                if body["in_flight"]:
                    task_id = body["in_flight"]["id"]
                    body["pending"] = [x for x in body["pending"] if x["id"] != task_id]
                    body["coverage_gaps"].append("Interrupted task " + task_id + "; outcome unknown and not automatically replayed")
                    body["in_flight"] = None
                db.execute("UPDATE web_jobs SET state='paused',owner=NULL,body=? WHERE id=?", (canonical(body), row["id"]))
            row = db.execute("SELECT * FROM web_jobs WHERE state='queued' AND cancel=0 ORDER BY rowid LIMIT 1").fetchone()
            if row is None:
                return None
            db.execute("UPDATE web_jobs SET state='running',owner=?,lease=? WHERE id=?", (self.owner, now + 90, row["id"]))
            return json.loads(row["body"])

    async def _heartbeat(self, job_id):
        while True:
            await asyncio.sleep(10)
            with self.connect() as db:
                db.execute("UPDATE web_jobs SET lease=? WHERE id=? AND owner=? AND state='running'", (time.time() + 90, job_id, self.owner))

    def _check_budget(self, body):
        with self.connect() as db:
            row = db.execute("SELECT cancel,owner,state FROM web_jobs WHERE id=?", (body["id"],)).fetchone()
        if not row or row["owner"] != self.owner or row["state"] != "running":
            raise HaltAssessment("Worker lease was lost")
        if row["cancel"]:
            raise HaltAssessment("Operator cancelled the assessment")
        spec = body["spec"]
        if body["requests_used"] >= spec["max_requests"]:
            raise HaltAssessment("HTTP request budget exhausted")
        if time.time() - body["started_at"] >= spec["max_seconds"]:
            raise HaltAssessment("Assessment time budget exhausted")

    def _credentials(self, spec, actor):
        if actor == "anonymous":
            return None
        account = spec["accounts"][actor]
        value = os.getenv(account["secret_env"], "")
        if not value:
            raise AssessmentError("A required test account secret is unavailable")
        if account["kind"] == "bearer":
            return {"Authorization": "Bearer " + value}
        return {"Cookie": value}

    def _artifact(self, body, response, actor, marker):
        # Raw response bodies, cookies and arbitrary headers never enter storage.
        artifact = {
            "id": uuid.uuid4().hex, "job_id": body["id"], "task_id": body["in_flight"]["id"],
            "url": response["url"], "actor": actor, "status": response["status"],
            "body_sha256": response["body_sha256"], "truncated": response["truncated"],
            "marker_present": bool(marker and marker.encode() in response["body"]),
            "marker_sha256": hashlib.sha256(marker.encode()).hexdigest() if marker else None,
            "header_names": sorted(response["headers"].keys()), "timestamp": time.time(),
        }
        artifact["signature"] = hmac.new(self.key, canonical(artifact).encode(), hashlib.sha256).hexdigest()
        body["artifacts"].append(artifact)
        self._save(body)
        return artifact

    def _seal_finding(self, finding):
        finding["signature"] = hmac.new(self.key, canonical(finding).encode(), hashlib.sha256).hexdigest()
        return finding

    def _finding_valid(self, finding):
        clean = dict(finding)
        signature = clean.pop("signature", "")
        expected = hmac.new(self.key, canonical(clean).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)

    def verify_artifact(self, artifact, job_id):
        clean = dict(artifact)
        signature = clean.pop("signature", "")
        expected = hmac.new(self.key, canonical(clean).encode(), hashlib.sha256).hexdigest()
        return clean.get("job_id") == job_id and hmac.compare_digest(signature, expected)

    async def _request(self, body, url, actor="anonymous", marker=""):
        self._check_budget(body)
        spec = body["spec"]
        # Re-read current global scope at every request, including resumed jobs.
        scope = WebScope(spec["target"], self.allowlist_getter(), tuple(spec["allowed_paths"]), tuple(spec["excluded_paths"]))
        scope.check(url)
        credentials = self._credentials(spec, actor)
        remaining = max(1, min(10, int(spec["max_seconds"] - (time.time() - body["started_at"]))))
        transport = self.transport_factory(scope, timeout=remaining)
        body["requests_used"] += 1
        self._save(body)  # reserve BEFORE dispatch; interrupted requests still count
        response = await asyncio.to_thread(transport.get, url, credentials)
        artifact = self._artifact(body, response, actor, marker)
        if response["status"] == 429 or response["status"] >= 500:
            raise HaltAssessment("Target returned throttling/server errors; assessment stopped")
        return response, artifact

    async def _map(self, body, task):
        response, artifact = await self._request(body, task["url"])
        if not 200 <= response["status"] < 300:
            body["coverage_gaps"].append(f"{task['id']}: HTTP {response['status']}; redirects are not followed")
            return
        headers = response["headers"]
        if "text/html" in headers.get("content-type", "").lower():
            for header, remediation in [
                ("content-security-policy", "Review and deploy a Content-Security-Policy appropriate for this application."),
                ("x-content-type-options", "Set X-Content-Type-Options: nosniff on applicable responses."),
            ]:
                if header not in headers:
                    body["findings"].append(self._seal_finding({"id": uuid.uuid4().hex, "title": "Review missing " + header,
                        "url": task["url"], "severity": "info", "status": "candidate",
                        "impact": "Defense-in-depth observation; exploitability has not been established.",
                        "remediation": remediation, "evidence_refs": [artifact["id"]], "reproduction": ["GET the affected page and inspect response headers."]}))
            parser = Links()
            parser.feed(response["body"].decode("utf-8", errors="replace"))
            spec = body["spec"]
            scope = WebScope(spec["target"], self.allowlist_getter(), tuple(spec["allowed_paths"]), tuple(spec["excluded_paths"]))
            for href in parser.links:
                if len(body["seen"]) >= spec["max_pages"]:
                    body["coverage_gaps"].append("Page discovery limit reached; additional links were not visited")
                    break
                try:
                    url = scope.check(urljoin(task["url"], href))
                except (AdapterPolicyError, ValueError):
                    continue
                if url not in body["seen"]:
                    body["seen"].append(url)
                    body["pending"].append({"id": f"map-{len(body['seen'])}", "kind": "map", "url": url})
        if response["truncated"]:
            body["coverage_gaps"].append(task["id"] + ": response truncated; mapping is partial")

    async def _authorization(self, body, task):
        check = task["check"]
        spec = body["spec"]
        if self._credentials(spec, check["owner"]) == self._credentials(spec, check["other"]):
            raise AssessmentError("Two test accounts resolved to identical credentials")
        artifacts = []
        # Controlled fixture: owner baseline, unauthenticated negative control,
        # different account, then repeat from fresh HTTP connections.
        for actor in [check["owner"], "anonymous", check["other"], check["owner"], check["other"]]:
            _, artifact = await self._request(body, check["url"], actor, check["marker"])
            artifacts.append(artifact)
            await asyncio.sleep(0.2)
        verified = all(self.verify_artifact(a, body["id"]) for a in artifacts)
        owner1, control, other1, owner2, other2 = artifacts
        allowed = lambda a: 200 <= a["status"] < 300 and a["marker_present"] and not a["truncated"]
        denied = lambda a: a["status"] in {401, 403, 404} and not a["marker_present"] and not a["truncated"]
        baseline_valid = verified and allowed(owner1) and allowed(owner2) and denied(control)
        if baseline_valid and allowed(other1) and allowed(other2):
            observations = [
                {"kind": "reproduction", "outcome": "supports", "run_id": other1["id"],
                 "source": "mt-scoped-http", "evidence_refs": [owner1["id"], other1["id"], owner2["id"], other2["id"]]},
                {"kind": "negative_control", "outcome": "supports", "run_id": control["id"],
                 "source": "mt-scoped-http", "evidence_refs": [control["id"]]},
            ]
            by_id = {a["id"]: a for a in artifacts}
            proof = evaluate_finding(
                {"finding_id": task["id"], "severity": "medium", "url": check["url"]},
                observations, authorization_confirmed=True,
                evidence_validator=lambda observation: all(
                    ref in by_id and self.verify_artifact(by_id[ref], body["id"])
                    for ref in observation["evidence_refs"]),
            )
            body["findings"].append(self._seal_finding({"id": uuid.uuid4().hex, "title": "Cross-account access to a controlled fixture",
                "url": check["url"], "severity": "medium", "status": proof["status"], "proof_bundle": proof,
                "impact": "A second authorized test account read the owner-only fixture marker. Severity requires business-impact review.",
                "remediation": "Enforce object ownership and tenant authorization on every request; add a cross-account regression test.",
                "evidence_refs": [a["id"] for a in artifacts],
                "reproduction": ["Create an owner-only synthetic fixture and configure two distinct test accounts.",
                                 "GET the fixture as its owner; verify the fixture marker.",
                                 "GET without credentials; verify access is denied.",
                                 "GET as the other account; the same fixture marker is returned.",
                                 "Repeat owner and other-account requests on fresh connections."]}))
        elif baseline_valid and denied(other1) and denied(other2):
            body["events"].append({"task": task["id"], "result": "No cross-account access observed for this fixture"})
        else:
            body["coverage_gaps"].append(task["id"] + ": controls or reproduction were inconclusive; no confirmation issued")

    async def _rank(self, body):
        if not body["spec"]["ai_planning"] or body["ai_calls"]:
            return
        body["ai_calls"] = 1
        body["ai_status"] = "attempted"
        self._save(body)
        # Send IDs and test categories only; no source, URLs, credentials, body
        # text or attacker-supplied page content enters this model call.
        tasks = [{"id": x["id"], "kind": x["kind"]} for x in body["pending"]]
        try:
            if self.ai is None:
                raise ValueError("No configured planner")
            result = await asyncio.wait_for(self.ai.ask_raw_async(
                'Order the approved security assessment tasks. Return only JSON {"task_ids": [ids]}. Prioritize controlled authorization checks. You cannot add tasks.',
                canonical({"tasks": tasks})), timeout=15)
            ids = result.get("task_ids") if isinstance(result, dict) else None
            if not isinstance(ids, list) or any(not isinstance(x, str) for x in ids) or len(ids) != len(tasks) or set(ids) != {t["id"] for t in tasks}:
                raise ValueError("Invalid planner result")
            by_id = {x["id"]: x for x in body["pending"]}
            body["pending"] = [by_id[x] for x in ids]
            body["ai_status"] = "ranked-approved-tasks"
        except Exception:
            body["ai_status"] = "deterministic-fallback"
        self._save(body)

    async def run_once(self):
        body = self.claim()
        if body is None:
            return False
        heartbeat = asyncio.create_task(self._heartbeat(body["id"]))
        state = "completed"
        try:
            body["started_at"] = body["started_at"] or time.time()
            self._save(body)
            await self._rank(body)
            while body["pending"]:
                self._check_budget(body)
                task = body["pending"][0]
                body["in_flight"] = task
                self._save(body)
                try:
                    if task["kind"] == "map":
                        await self._map(body, task)
                    elif task["kind"] == "authorization":
                        await self._authorization(body, task)
                    else:
                        raise AssessmentError("Unsupported task kind")
                except (AssessmentError, AdapterPolicyError, OSError, ValueError) as exc:
                    # Exception messages may include secrets or server text.
                    body["coverage_gaps"].append(task["id"] + ": " + type(exc).__name__ + "; task could not be completed")
                body["finished_tasks"].append(task["id"])
                body["pending"] = [x for x in body["pending"] if x["id"] != task["id"]]
                body["in_flight"] = None
                self._save(body)
                await asyncio.sleep(0.2)
        except HaltAssessment as exc:
            body["coverage_gaps"].append(str(exc))
            state = "cancelled" if self.get(body["id"])["cancel_requested"] else "partial"
        except asyncio.CancelledError:
            # Leave a running lease for recovery; never silently replay an
            # action whose response might have been lost at process shutdown.
            raise
        except Exception as exc:
            body["coverage_gaps"].append("Worker stopped: " + type(exc).__name__)
            state = "partial"
        finally:
            heartbeat.cancel()
            try:
                await heartbeat
            except asyncio.CancelledError:
                pass
        if body["coverage_gaps"] and state == "completed":
            state = "partial"
        if self.get(body["id"])["cancel_requested"]:
            state = "cancelled"
        body["completed_at"] = time.time()
        self._save(body, state)
        return True

    async def worker(self):
        while True:
            try:
                worked = await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                worked = False  # lease recovery will expose the interrupted job
            if not worked:
                await asyncio.sleep(1)

    def report(self, job_id):
        body = self.get(job_id)
        # Return plain Markdown; escape user-controlled punctuation/HTML so a
        # downloaded report never becomes an injection surface in a renderer.
        def safe(value):
            text = str(value).replace("<", "&lt;").replace(">", "&gt;")
            return re.sub(r"([\\`*_{}\[\]()#!|])", r"\\\1", text).replace("\n", " ")
        artifacts = {a["id"]: a for a in body["artifacts"] if self.verify_artifact(a, job_id)}
        lines = ["# MT Web Assessment", "", "Target: " + safe(body["spec"]["target"]),
                 "State: " + safe(body["state"]), "Requests used: " + str(body["requests_used"]),
                 "AI planner: " + safe(body["ai_status"]), "", "## Scope and coverage", "",
                 "Same-origin bounded GET mapping, header review and explicitly configured two-account fixture checks.",
                 "Allowed paths: " + safe(body["spec"]["allowed_paths"]),
                 "Excluded paths: " + safe(body["spec"]["excluded_paths"]),
                 "No findings does not establish that the application is secure.",
                 "Form login, JavaScript execution, mutation testing and general exploit discovery are not covered by this profile.", ""]
        if body["spec"]["source_analysis"]:
            lines += ["Source map: " + safe(body["spec"]["source_analysis"]["summary"]), "Static candidates require separate runtime validation.", ""]
        lines += ["## Findings", ""]
        if not body["findings"]:
            lines += ["No findings were established by the completed checks.", ""]
        for finding in body["findings"]:
            valid = self._finding_valid(finding) and bool(finding["evidence_refs"]) and all(ref in artifacts for ref in finding["evidence_refs"])
            status = finding["status"] if valid else "candidate — evidence integrity check failed"
            lines += ["### " + safe(finding["title"]), "", "Status: " + safe(status),
                      "Severity: " + safe(finding["severity"]), "URL: " + safe(finding["url"]),
                      "Impact: " + safe(finding["impact"]), "Remediation: " + safe(finding["remediation"]), "", "Reproduction:", ""]
            lines += [f"{i}. {safe(step)}" for i, step in enumerate(finding["reproduction"], 1)]
            lines += ["", "Evidence:", ""]
            for ref in finding["evidence_refs"]:
                a = artifacts.get(ref)
                lines.append("- " + (safe(f"{ref}: actor={a['actor']}; HTTP={a['status']}; body_sha256={a['body_sha256']}; marker={a['marker_present']}") if a else "Unavailable or invalid artifact"))
            lines.append("")
        lines += ["## Coverage gaps", ""]
        gaps = list(dict.fromkeys(body["coverage_gaps"]))
        if body["pending"]:
            gaps.append(f"{len(body['pending'])} tasks are unfinished")
        lines += ["- " + safe(gap) for gap in gaps] or ["No additional execution gaps recorded within this limited profile."]
        return "\n".join(lines) + "\n"
