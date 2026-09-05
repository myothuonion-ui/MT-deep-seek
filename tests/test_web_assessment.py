"""Real loopback integration tests; no model calls or external targets."""
import asyncio
import hashlib
import json
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from adapters.base import AdapterPolicyError
from adapters.scoped_http import ScopedHTTP, WebScope
from core.proof_verifier import evaluate_finding
from core.web_assessment import AssessmentError, WebAssessments, canonical

MARKER = "MT-SYNTHETIC-FIXTURE-12345"


class LabHandler(BaseHTTPRequestHandler):
    calls = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).calls.append(self.path)
        credential = self.headers.get("Authorization", "")
        status, body, content_type = 200, b"<html>Lab</html>", "text/html"
        if self.path.startswith("/api/"):
            content_type = "application/json"
            allowed = credential in {"Bearer owner-test-secret", "Bearer other-test-secret"}
            if self.path == "/api/secure" and credential != "Bearer owner-test-secret":
                allowed = False
            status = 200 if allowed else 403
            body = json.dumps({"fixture": MARKER}).encode() if allowed else b'{"error":"denied"}'
        elif self.path == "/links":
            body = b'<a href="/public">ok</a><a href="https://outside.invalid/">outside</a><a href="/logout">logout</a>'
        elif self.path == "/redirect":
            status = 302
        elif self.path == "/throttle":
            status = 429
        elif self.path == "/large":
            body = b"x" * 300000
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if status == 302:
            self.send_header("Location", "https://outside.invalid/")
        self.send_header("Set-Cookie", "private=session-secret")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class WebAssessmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = patch.dict(os.environ, {"MT_WEB_ACCOUNT_OWNER": "owner-test-secret", "MT_WEB_ACCOUNT_OTHER": "other-test-secret"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.scope = "127.0.0.1"
        self.service = self.make_service()
        LabHandler.calls = []

    def make_service(self, **kwargs):
        return WebAssessments(Path(self.tmp.name) / "web.db", "test-signing-key-32-characters-long", lambda: self.scope, **kwargs)

    def spec(self, path="/", authorization_path=None, **changes):
        spec = {"target": self.url + path, "authorization_confirmed": True, "max_requests": 30}
        if authorization_path:
            spec["accounts"] = {
                "owner": {"kind": "bearer", "secret_env": "MT_WEB_ACCOUNT_OWNER"},
                "other": {"kind": "bearer", "secret_env": "MT_WEB_ACCOUNT_OTHER"},
            }
            spec["authorization_checks"] = [{"url": self.url + authorization_path, "owner": "owner", "other": "other", "marker": MARKER, "ownership_confirmed": True}]
        spec.update(changes)
        return spec

    def run_job(self, spec):
        job = self.service.create(spec)
        asyncio.run(self.service.run_once())
        return self.service.get(job["id"])

    def test_real_http_confirms_only_controlled_cross_account_access(self):
        job = self.run_job(self.spec(authorization_path="/api/vulnerable"))
        confirmed = [f for f in job["findings"] if f["status"] == "confirmed"]
        self.assertEqual(job["state"], "completed")
        self.assertEqual(job["requests_used"], 6)
        self.assertEqual(len(confirmed), 1)
        self.assertEqual(len(confirmed[0]["evidence_refs"]), 5)
        self.assertEqual(confirmed[0]["proof_bundle"]["trusted_observation_count"], 2)
        report = self.service.report(job["id"])
        self.assertIn("Cross-account access", report)
        self.assertIn("confirmed", report)
        for secret in ("owner-test-secret", "other-test-secret", "session-secret", MARKER):
            self.assertNotIn(secret, report)
        stored = Path(self.tmp.name, "web.db").read_bytes()
        for secret in (b"owner-test-secret", b"other-test-secret", b"session-secret"):
            self.assertNotIn(secret, stored)

    def test_secure_fixture_is_not_reported_as_vulnerable(self):
        job = self.run_job(self.spec(authorization_path="/api/secure"))
        self.assertFalse(any(f["status"] == "confirmed" for f in job["findings"]))
        self.assertTrue(any("No cross-account" in e["result"] for e in job["events"]))

    def test_same_runtime_credentials_do_not_confirm(self):
        with patch.dict(os.environ, {"MT_WEB_ACCOUNT_OTHER": "owner-test-secret"}):
            job = self.run_job(self.spec(authorization_path="/api/vulnerable"))
        self.assertEqual(job["state"], "partial")
        self.assertEqual(job["requests_used"], 1)
        self.assertFalse(any(f["status"] == "confirmed" for f in job["findings"]))

    def test_missing_credentials_are_visible_as_coverage_gap(self):
        with patch.dict(os.environ, {"MT_WEB_ACCOUNT_OTHER": ""}):
            job = self.run_job(self.spec(authorization_path="/api/vulnerable"))
        self.assertEqual(job["state"], "partial")
        self.assertTrue(job["coverage_gaps"])

    def test_request_budget_stops_mid_proof_without_confirmation(self):
        job = self.run_job(self.spec(authorization_path="/api/vulnerable", max_requests=2))
        self.assertEqual(job["requests_used"], 2)
        self.assertEqual(job["state"], "partial")
        self.assertFalse(any(f["status"] == "confirmed" for f in job["findings"]))

    def test_cancel_before_start_makes_zero_requests(self):
        job = self.service.create(self.spec())
        self.service.cancel(job["id"])
        self.assertFalse(asyncio.run(self.service.run_once()))
        self.assertEqual(self.service.get(job["id"])["state"], "cancelled")
        self.assertEqual(LabHandler.calls, [])

    def test_revoked_scope_blocks_queued_work(self):
        job = self.service.create(self.spec())
        self.scope = "outside.invalid"
        asyncio.run(self.service.run_once())
        self.assertEqual(self.service.get(job["id"])["requests_used"], 0)
        self.assertEqual(LabHandler.calls, [])

    def test_crash_recovery_never_automatically_replays_unknown_task(self):
        job = self.service.create(self.spec(authorization_path="/api/secure"))
        body = self.service.claim()
        body["started_at"] = time.time()
        body["in_flight"] = body["pending"][0]
        body["requests_used"] = 1
        self.service._save(body)
        with self.service.connect() as db:
            db.execute("UPDATE web_jobs SET lease=0 WHERE id=?", (job["id"],))
        replacement = self.make_service()
        self.assertIsNone(replacement.claim())
        recovered = replacement.get(job["id"])
        self.assertEqual(recovered["state"], "paused")
        self.assertNotIn("map-0", [t["id"] for t in recovered["pending"]])
        replacement.resume(job["id"])
        asyncio.run(replacement.run_once())
        self.assertNotIn("/", LabHandler.calls)
        self.assertEqual(replacement.get(job["id"])["state"], "partial")

    def test_second_worker_cannot_claim_running_job(self):
        self.service.create(self.spec())
        self.assertIsNotNone(self.service.claim())
        self.assertIsNone(self.make_service().claim())

    def test_crawler_stays_in_origin_and_excludes_actions(self):
        job = self.run_job(self.spec(path="/links"))
        self.assertEqual(set(LabHandler.calls), {"/links", "/public"})
        self.assertEqual(len(job["seen"]), 2)

    def test_redirects_are_not_followed(self):
        job = self.run_job(self.spec(path="/redirect"))
        self.assertEqual(LabHandler.calls, ["/redirect"])
        self.assertEqual(job["state"], "partial")

    def test_throttling_stops_with_partial_report(self):
        job = self.run_job(self.spec(path="/throttle"))
        self.assertEqual(job["requests_used"], 1)
        self.assertEqual(job["state"], "partial")
        self.assertIn("throttling", self.service.report(job["id"]))

    def test_response_size_is_bounded(self):
        response = ScopedHTTP(WebScope(self.url, "127.0.0.1"), max_bytes=1024).get(self.url + "/large")
        self.assertEqual(len(response["body"]), 1024)
        self.assertTrue(response["truncated"])

    def test_tampered_evidence_downgrades_report(self):
        job = self.run_job(self.spec(authorization_path="/api/vulnerable"))
        for a in job["artifacts"]:
            a["body_sha256"] = "tampered"
        with self.service.connect() as db:
            db.execute("UPDATE web_jobs SET body=? WHERE id=?", (canonical(job), job["id"]))
        report = self.service.report(job["id"])
        self.assertNotIn("Status: confirmed", report)
        self.assertIn("integrity check failed", report)

    def test_finding_status_cannot_be_changed_without_signature(self):
        job = self.run_job(self.spec())
        job["findings"][0]["status"] = "confirmed"
        with self.service.connect() as db:
            db.execute("UPDATE web_jobs SET body=? WHERE id=?", (canonical(job), job["id"]))
        self.assertNotIn("Status: confirmed", self.service.report(job["id"]))

    def test_ai_only_ranks_known_tasks_and_receives_no_target_or_secrets(self):
        received = []
        class AI:
            async def ask_raw_async(self, system, payload):
                received.append(payload)
                tasks = json.loads(payload)["tasks"]
                return {"task_ids": [t["id"] for t in reversed(tasks)]}
        self.service = self.make_service(ai=AI())
        job = self.run_job(self.spec(authorization_path="/api/secure", ai_planning=True))
        self.assertEqual(job["ai_status"], "ranked-approved-tasks")
        self.assertEqual(job["finished_tasks"][0], "auth-0")
        self.assertEqual(job["ai_calls"], 1)
        for private in (self.url, MARKER, "owner-test-secret"):
            self.assertNotIn(private, received[0])

    def test_malicious_ai_task_injection_falls_back(self):
        class AI:
            async def ask_raw_async(self, *_):
                return {"task_ids": ["run-shell-command"]}
        self.service = self.make_service(ai=AI())
        job = self.run_job(self.spec(ai_planning=True))
        self.assertEqual(job["ai_status"], "deterministic-fallback")
        self.assertEqual(LabHandler.calls, ["/"])

    def test_source_is_optional_and_raw_text_not_persisted(self):
        source = "# unique-source-sentinel\n@app.get('/test')\ndef test(): pass"
        job = self.run_job(self.spec(source_files={"app.py": source}))
        self.assertEqual(job["spec"]["source_analysis"]["summary"]["files_analyzed"], 1)
        self.assertNotIn("unique-source-sentinel", canonical(job))

    def test_invalid_scope_and_credentials_rejected(self):
        for changes in [
            {"authorization_confirmed": False}, {"target": "https://outside.invalid/"},
            {"target": self.url + "/%2e%2e/admin"}, {"target": self.url + "/?token=secret"},
            {"allowed_paths": ["/api"], "target": self.url + "/apix"},
            {"accounts": {"a": {"kind": "bearer", "secret_env": "API_AUTH_TOKEN"}}},
            {"max_requests": True}, {"shell": "echo nope"},
        ]:
            with self.subTest(changes=changes):
                with self.assertRaises((AssessmentError, AdapterPolicyError)):
                    self.service.create(self.spec(**changes))

    def test_hostname_does_not_authorize_private_dns_rebinding(self):
        client = ScopedHTTP(WebScope("https://lab.example/", "lab.example"))
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]):
            with self.assertRaises(AdapterPolicyError):
                client.get("https://lab.example/")

    def test_empty_global_scope_always_denies_even_with_unsafe_legacy_override(self):
        self.scope = ""
        with patch.dict(os.environ, {"ALLOW_UNSCOPED_TARGETS": "true"}):
            with self.assertRaises(AdapterPolicyError):
                self.service.create(self.spec())


class ProofTrustTests(unittest.TestCase):
    def observations(self):
        return [{"kind": kind, "outcome": "supports", "source": source, "run_id": str(i), "evidence_refs": [str(i)]}
                for i, (kind, source) in enumerate([("reproduction", "tool-a"), ("negative_control", "tool-a"), ("independent_confirmation", "tool-b")])]

    def test_labels_without_trusted_executor_can_never_confirm(self):
        proof = evaluate_finding({"severity": "critical"}, self.observations(), authorization_confirmed=True,
                                 require_negative_control=False, require_independent_confirmation=False)
        self.assertEqual(proof["status"], "candidate")
        self.assertTrue(proof["policy"]["require_independent_confirmation"])

    def test_missing_or_invalid_artifact_is_fail_closed(self):
        for validator in [lambda _: False, lambda _: 1 / 0]:
            proof = evaluate_finding({"severity": "low"}, self.observations(), authorization_confirmed=True, evidence_validator=validator)
            self.assertEqual(proof["status"], "candidate")

    def test_independent_confirmation_must_have_different_run_and_source(self):
        observations = self.observations()
        observations[-1]["source"] = "tool-a"
        proof = evaluate_finding({"severity": "high"}, observations, authorization_confirmed=True, evidence_validator=lambda _: True)
        self.assertEqual(proof["status"], "reproduced")

    def test_trusted_distinct_evidence_can_confirm_and_hash_is_valid(self):
        proof = evaluate_finding({"severity": "high"}, self.observations(), authorization_confirmed=True, evidence_validator=lambda _: True)
        self.assertEqual(proof["status"], "confirmed")
        self.assertEqual(proof["confidence_kind"], "policy-score-not-calibrated-probability")
        digest = proof.pop("content_sha256")
        proof.pop("bundle_id")
        self.assertEqual(digest, hashlib.sha256(canonical(proof).encode()).hexdigest())


if __name__ == "__main__":
    unittest.main()
