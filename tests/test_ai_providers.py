import os
from contextlib import contextmanager

from ai.connector import KMN_AI_Connector


_PROVIDER_ENV = (
    "AI_PROVIDER",
    "DEEPSEEK_API_KEY",
    "OPENAI_API_KEY",
    "NVIDIA_API_KEY",
    "GEMINI_API_KEY",
    "DEEPSEEK_MODEL",
    "NVIDIA_MODEL",
    "GEMINI_MODEL",
)


@contextmanager
def _provider_env(**values):
    """Temporarily isolate provider-related environment variables.

    The repository's lightweight regression runner calls test functions directly,
    so these tests intentionally avoid pytest fixtures such as monkeypatch.
    """
    old = {name: os.environ.get(name) for name in _PROVIDER_ENV}
    try:
        for name in _PROVIDER_ENV:
            os.environ.pop(name, None)
        for name, value in values.items():
            os.environ[name] = value
        yield
    finally:
        for name in _PROVIDER_ENV:
            if old[name] is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = old[name]


def test_nvidia_provider_uses_official_openai_compatible_endpoint():
    with _provider_env(
        AI_PROVIDER="nvidia",
        NVIDIA_API_KEY="nvapi-valid-key-1234567890",
    ):
        connector = KMN_AI_Connector()

        assert connector.provider == "nvidia"
        assert connector.api_model == "z-ai/glm-5.2"
        assert connector.cloud_api_url == "https://integrate.api.nvidia.com/v1/chat/completions"
        payload = connector._cloud_payload([{"role": "user", "content": "test"}], 0.3)
        assert payload["model"] == "z-ai/glm-5.2"
        assert "response_format" not in payload


def test_nvidia_model_is_operator_configurable():
    with _provider_env(
        AI_PROVIDER="nvidia",
        NVIDIA_API_KEY="nvapi-valid-key-1234567890",
        NVIDIA_MODEL="deepseek-ai/deepseek-v4-pro",
    ):
        connector = KMN_AI_Connector()

        assert connector.provider == "nvidia"
        assert connector.api_model == "deepseek-ai/deepseek-v4-pro"


def test_gemini_provider_uses_google_openai_compatible_endpoint():
    with _provider_env(
        AI_PROVIDER="gemini",
        GEMINI_API_KEY="AIza-valid-key-1234567890",
    ):
        connector = KMN_AI_Connector()

        assert connector.provider == "gemini"
        assert connector.api_model == "gemini-3.6-flash"
        assert connector.cloud_api_url == (
            "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
        )
        payload = connector._cloud_payload([{"role": "user", "content": "test"}], 0.3)
        assert "response_format" not in payload


def test_deepseek_alias_preserves_existing_api_provider_behavior():
    with _provider_env(DEEPSEEK_API_KEY="sk-real-looking-key-1234567890"):
        connector = KMN_AI_Connector(provider="deepseek")

        assert connector.provider == "api"
        assert connector.api_model == "deepseek-chat"
        assert connector.cloud_api_url == "https://api.deepseek.com/chat/completions"
        payload = connector._cloud_payload([{"role": "user", "content": "test"}], 0.3)
        assert payload["response_format"] == {"type": "json_object"}


def test_cloud_provider_without_valid_key_fails_closed_to_local():
    with _provider_env(
        AI_PROVIDER="nvidia",
        NVIDIA_API_KEY="your_nvidia_api_key_here",
    ):
        connector = KMN_AI_Connector()

        assert connector.provider == "local"
        assert connector.api_key is None


def test_new_cloud_secret_does_not_silently_change_provider():
    with _provider_env(
        NVIDIA_API_KEY="nvapi-valid-key-1234567890",
        GEMINI_API_KEY="AIza-valid-key-1234567890",
    ):
        connector = KMN_AI_Connector()

        assert connector.provider == "local"
        assert connector.api_key is None


def test_explicit_local_provider_ignores_all_cloud_keys():
    with _provider_env(
        DEEPSEEK_API_KEY="sk-real-looking-key-1234567890",
        NVIDIA_API_KEY="nvapi-real-looking-key-1234567890",
        GEMINI_API_KEY="AIza-real-looking-key-1234567890",
    ):
        connector = KMN_AI_Connector(provider="local")

        assert connector.provider == "local"
        assert connector.api_key is None
