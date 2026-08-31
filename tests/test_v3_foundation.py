import os

from ai.connector import KMN_AI_Connector
from ai.providers import normalize_provider, public_provider_catalog
from core.plugin_registry import PluginRegistry
from core.validators import (
    autonomous_scope_rejection,
    extract_command_targets,
    parse_autonomous_argv,
)


def test_provider_alias_and_unknown_provider():
    assert normalize_provider("api") == "deepseek"
    assert normalize_provider("NVIDIA") == "nvidia_nim"
    try:
        normalize_provider("made-up-provider")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown provider was accepted")


def test_openrouter_connector_uses_dedicated_configuration():
    old_model = os.environ.get("OPENROUTER_MODEL")
    old_deepseek = os.environ.get("DEEPSEEK_API_KEY")
    try:
        os.environ["OPENROUTER_MODEL"] = "vendor/model"
        os.environ["DEEPSEEK_API_KEY"] = "sk-stale-deepseek-key-123"
        connector = KMN_AI_Connector(
            provider="openrouter",
            api_key="sk-openrouter-runtime-key-123",
        )
        assert connector.provider == "openrouter"
        assert connector.api_model == "vendor/model"
        assert connector.api_url == "https://openrouter.ai/api/v1/chat/completions"
        assert connector.api_key == "sk-openrouter-runtime-key-123"
    finally:
        if old_model is None:
            os.environ.pop("OPENROUTER_MODEL", None)
        else:
            os.environ["OPENROUTER_MODEL"] = old_model
        if old_deepseek is None:
            os.environ.pop("DEEPSEEK_API_KEY", None)
        else:
            os.environ["DEEPSEEK_API_KEY"] = old_deepseek


def test_public_provider_catalog_never_exposes_secret_names_or_values():
    old_key = os.environ.get("GEMINI_API_KEY")
    try:
        os.environ["GEMINI_API_KEY"] = "super-secret-gemini-key"
        catalog = public_provider_catalog()
        encoded = repr(catalog)
        assert "super-secret-gemini-key" not in encoded
        assert "api_key_env" not in encoded
        assert any(item["code"] == "gemini" and item["configured"] for item in catalog)
    finally:
        if old_key is None:
            os.environ.pop("GEMINI_API_KEY", None)
        else:
            os.environ["GEMINI_API_KEY"] = old_key


def test_plugin_manifest_is_honest_about_planned_and_blocked_integrations():
    catalog = PluginRegistry().public_catalog()
    by_id = {item["id"]: item for item in catalog["plugins"]}
    assert by_id["mt-core"]["status"] == "native"
    assert by_id["shannon"]["status"] == "adapter-planned"
    assert by_id["cai"]["status"] == "blocked"
    assert not by_id["claude-bughunter"]["enabled_by_default"]


def test_autonomous_parser_produces_argv_without_shell():
    argv, env, error = parse_autonomous_argv("MODE=safe nmap -sV 10.10.10.5")
    assert error is None
    assert argv == ["nmap", "-sV", "10.10.10.5"]
    assert env == {"MODE": "safe"}


def test_autonomous_parser_rejects_shell_and_interpreter_paths():
    for command in [
        "nmap 10.10.10.5 | bash",
        "nmap 10.10.10.5 && whoami",
        "python3 -c 'print(1)'",
        "sudo nmap 10.10.10.5",
    ]:
        _argv, _env, error = parse_autonomous_argv(command)
        assert error


def test_command_scope_extracts_urls_and_ips():
    targets = extract_command_targets("nuclei --url https://app.example.test/login -target 10.10.10.8")
    assert "app.example.test" in targets
    assert "10.10.10.8" in targets
    assert autonomous_scope_rejection(
        "nmap -sV 10.10.10.8", "10.10.10.0/24,*.example.test"
    ) is None
    assert "outside SCOPE_ALLOWLIST" in autonomous_scope_rejection(
        "curl https://evil.example/", "10.10.10.0/24,*.example.test"
    )
