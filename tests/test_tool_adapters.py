"""Policy, typed-argv, parsing, and read-only adapter regression tests."""

import json
import importlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

from adapters import AdapterPolicyError
from adapters.base import execute_argv, sanitized_adapter_environment
from adapters.bbot import BBOTAdapter
from adapters.claude_bughunter import ClaudeBugHunterAdapter
from adapters.nuclei import NucleiAdapter


def _must_raise(error_type, callback):
    try:
        callback()
    except error_type:
        return
    raise AssertionError(f"expected {error_type.__name__}")


def test_nuclei_builds_bounded_argv_and_enforces_scope():
    adapter = NucleiAdapter(binary="nuclei")
    argv = adapter.build_argv(
        "https://app.example.test/login",
        authorization_confirmed=True,
        allowlist="*.example.test",
        severities=("high", "critical"),
        rate_limit=25,
        concurrency=5,
    )
    assert argv[:3] == ["nuclei", "-target", "https://app.example.test/login"]
    assert "-no-interactsh" in argv
    assert "-disable-unsigned-templates" in argv
    assert "headless,file,code,javascript" in argv
    assert "fuzz,dos,intrusive" in argv
    assert "25" in argv and "5" in argv

    _must_raise(
        AdapterPolicyError,
        lambda: adapter.build_argv(
            "https://outside.example/;whoami",
            authorization_confirmed=True,
            allowlist="*.example.test",
        ),
    )
    _must_raise(
        AdapterPolicyError,
        lambda: adapter.build_argv(
            "app.example.test",
            authorization_confirmed=False,
            allowlist="*.example.test",
        ),
    )


def test_nuclei_jsonl_parser_returns_normalized_findings():
    line = json.dumps({
        "template-id": "CVE-2099-0001",
        "info": {"name": "Fixture finding", "severity": "high"},
        "matched-at": "https://app.example.test/path",
        "host": "app.example.test",
    })
    findings = NucleiAdapter.parse_jsonl(f"noise\n{line}\n")
    assert findings == [{
        "template_id": "CVE-2099-0001",
        "name": "Fixture finding",
        "severity": "high",
        "matched_at": "https://app.example.test/path",
        "host": "app.example.test",
        "timestamp": "",
    }]


def test_bbot_adapter_is_passive_only_and_rejects_unreviewed_presets():
    root = tempfile.mkdtemp(prefix="mt-bbot-argv-")
    try:
        adapter = BBOTAdapter(binary="bbot")
        argv = adapter.build_argv(
            "example.test",
            authorization_confirmed=True,
            allowlist="example.test",
            output_dir=root,
        )
        assert argv[:3] == ["bbot", "-t", "example.test"]
        assert argv[argv.index("-rf") + 1] == "passive"
        assert "--no-deps" in argv and "-y" in argv
        _must_raise(
            AdapterPolicyError,
            lambda: adapter.build_argv(
                "example.test",
                authorization_confirmed=True,
                allowlist="example.test",
                preset="web-heavy",
                output_dir=root,
            ),
        )
    finally:
        shutil.rmtree(root)


def test_claude_bughunter_adapter_reads_only_indexed_skill_content():
    root = Path(tempfile.mkdtemp(prefix="mt-cbh-adapter-"))
    try:
        index = root / "cbh" / "data" / "skill_index.json"
        skill = root / "skills" / "hunt-fixture" / "SKILL.md"
        index.parent.mkdir(parents=True)
        skill.parent.mkdir(parents=True)
        index.write_text(json.dumps({"skills": {"hunt-fixture": "Fixture skill"}}), encoding="utf-8")
        skill.write_text("# Fixture\n\nRead-only content.\n", encoding="utf-8")
        adapter = ClaudeBugHunterAdapter(str(root))
        assert adapter.status()["available"]
        assert adapter.list_skills("fixture")[0]["name"] == "hunt-fixture"
        assert adapter.read_skill("hunt-fixture")["content"].startswith("# Fixture")
        _must_raise(AdapterPolicyError, lambda: adapter.read_skill("../../etc/passwd"))
    finally:
        shutil.rmtree(root)


def test_shared_executor_does_not_interpret_argument_metacharacters():
    root = Path(tempfile.mkdtemp(prefix="mt-adapter-exec-"))
    marker = root / "must-not-exist"
    fake = root / "fake-adapter"
    try:
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "print(json.dumps({'argv': sys.argv[1:]}))\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        payload = f"literal;touch {marker}"
        result = execute_argv("fixture", [str(fake), payload], timeout_seconds=5)
        assert result.returncode == 0
        assert json.loads(result.stdout)["argv"] == [payload]
        assert not marker.exists()
    finally:
        shutil.rmtree(root)


def test_adapter_environment_does_not_inherit_application_secrets():
    previous_secret = os.environ.get("DEEPSEEK_API_KEY")
    previous_tool_value = os.environ.get("BBOT_FIXTURE_TOKEN")
    os.environ["DEEPSEEK_API_KEY"] = "must-not-reach-adapter"
    os.environ["BBOT_FIXTURE_TOKEN"] = "tool-scoped-fixture"
    try:
        child_env = sanitized_adapter_environment()
        assert "DEEPSEEK_API_KEY" not in child_env
        assert child_env["BBOT_FIXTURE_TOKEN"] == "tool-scoped-fixture"
        _must_raise(
            AdapterPolicyError,
            lambda: sanitized_adapter_environment({"GEMINI_API_KEY": "not-permitted"}),
        )
    finally:
        if previous_secret is None:
            os.environ.pop("DEEPSEEK_API_KEY", None)
        else:
            os.environ["DEEPSEEK_API_KEY"] = previous_secret
        if previous_tool_value is None:
            os.environ.pop("BBOT_FIXTURE_TOKEN", None)
        else:
            os.environ["BBOT_FIXTURE_TOKEN"] = previous_tool_value


def test_nuclei_api_requires_auth_and_enforces_scope():
    root = Path(tempfile.mkdtemp(prefix="mt-adapter-api-"))
    fake = root / "nuclei"
    fake_nmap = root / "nmap"
    environment = {
        "API_AUTH_TOKEN": "adapter-api-test-token",
        "DB_PATH": str(root / "mt_pentester.db"),
        "LOG_FILE": str(root / "mt_pentester.log"),
        "SCOPE_ALLOWLIST": "app.example.test",
        "ALLOW_UNSCOPED_TARGETS": "false",
        "NUCLEI_PATH": str(fake),
        "NUCLEI_TEMPLATES_PATH": str(root),
        "PATH": f"{root}{os.pathsep}{os.environ.get('PATH', os.defpath)}",
    }
    previous = {key: os.environ.get(key) for key in environment}
    try:
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json\n"
            "print(json.dumps({"
            "'template-id': 'fixture-template', "
            "'info': {'name': 'Fixture finding', 'severity': 'high'}, "
            "'matched-at': 'https://app.example.test/', "
            "'host': 'app.example.test'}))\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        fake_nmap.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' 'Nmap version 7.94 ( https://nmap.org )'\n",
            encoding="utf-8",
        )
        fake_nmap.chmod(0o700)
        os.environ.update(environment)
        sys.modules.pop("main", None)
        backend = importlib.import_module("main")
        from fastapi.testclient import TestClient

        client = TestClient(backend.app)
        payload = {
            "target": "https://app.example.test/",
            "authorization_confirmed": True,
            "severities": ["high"],
            "rate_limit": 10,
            "concurrency": 2,
        }
        assert client.post("/api/adapters/nuclei/scan", json=payload).status_code == 401

        headers = {"X-API-Key": environment["API_AUTH_TOKEN"]}
        response = client.post("/api/adapters/nuclei/scan", json=payload, headers=headers)
        assert response.status_code == 200
        body = response.json()
        assert body["returncode"] == 0
        assert body["findings_count"] == 1
        assert body["findings"][0]["template_id"] == "fixture-template"

        payload["target"] = "https://outside.example.test/"
        denied = client.post("/api/adapters/nuclei/scan", json=payload, headers=headers)
        assert denied.status_code == 400
        assert "outside SCOPE_ALLOWLIST" in denied.json()["detail"]
    finally:
        sys.modules.pop("main", None)
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        shutil.rmtree(root)
