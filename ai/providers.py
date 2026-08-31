"""Provider registry for MT Pentester.

The orchestrator talks to one stable connector while this module owns provider-
specific endpoints, credential names, model defaults, and public metadata.  No
secret value is ever returned by the public registry helpers.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class ProviderSpec:
    code: str
    label: str
    kind: str
    api_key_env: Optional[str]
    model_env: str
    default_model: str
    api_base: Optional[str] = None
    api_base_env: Optional[str] = None
    privacy: str = "cloud"

    def resolved_api_base(self) -> Optional[str]:
        configured = os.getenv(self.api_base_env or "", "").strip() if self.api_base_env else ""
        return (configured or self.api_base or "").rstrip("/") or None

    def resolved_model(self) -> str:
        return os.getenv(self.model_env, "").strip() or self.default_model

    def has_credentials(self) -> bool:
        if self.kind == "ollama":
            return True
        return bool(self.api_key_env and os.getenv(self.api_key_env, "").strip())

    def public_dict(self) -> dict:
        data = asdict(self)
        data.pop("api_key_env", None)
        data["configured"] = self.has_credentials()
        data["model"] = self.resolved_model()
        data["api_base"] = self.resolved_api_base()
        return data


PROVIDERS: Dict[str, ProviderSpec] = {
    "local": ProviderSpec(
        code="local",
        label="Local (Ollama)",
        kind="ollama",
        api_key_env=None,
        model_env="OLLAMA_MODEL",
        default_model="deepseek-r1:8b",
        api_base="http://localhost:11434",
        api_base_env="OLLAMA_URL",
        privacy="local",
    ),
    "deepseek": ProviderSpec(
        code="deepseek",
        label="DeepSeek API",
        kind="openai-compatible",
        api_key_env="DEEPSEEK_API_KEY",
        model_env="DEEPSEEK_MODEL",
        default_model="deepseek-v4-flash",
        api_base="https://api.deepseek.com",
        api_base_env="DEEPSEEK_API_BASE",
    ),
    "openrouter": ProviderSpec(
        code="openrouter",
        label="OpenRouter",
        kind="openai-compatible",
        api_key_env="OPENROUTER_API_KEY",
        model_env="OPENROUTER_MODEL",
        default_model="openrouter/auto",
        api_base="https://openrouter.ai/api/v1",
        api_base_env="OPENROUTER_API_BASE",
    ),
    "nvidia_nim": ProviderSpec(
        code="nvidia_nim",
        label="NVIDIA NIM",
        kind="openai-compatible",
        api_key_env="NVIDIA_NIM_API_KEY",
        model_env="NVIDIA_NIM_MODEL",
        default_model="nvidia/nemotron-3-super-120b-a12b",
        api_base="https://integrate.api.nvidia.com/v1",
        api_base_env="NVIDIA_NIM_API_BASE",
    ),
    "gemini": ProviderSpec(
        code="gemini",
        label="Google Gemini",
        kind="openai-compatible",
        api_key_env="GEMINI_API_KEY",
        model_env="GEMINI_MODEL",
        default_model="gemini-2.5-flash",
        api_base="https://generativelanguage.googleapis.com/v1beta/openai",
        api_base_env="GEMINI_API_BASE",
    ),
    "litellm": ProviderSpec(
        code="litellm",
        label="LiteLLM Gateway",
        kind="openai-compatible",
        api_key_env="LITELLM_MASTER_KEY",
        model_env="LITELLM_MODEL",
        default_model="planner-strong",
        api_base="http://localhost:4000/v1",
        api_base_env="LITELLM_API_BASE",
        privacy="gateway",
    ),
}


_ALIASES = {
    "api": "deepseek",
    "ollama": "local",
    "nvidia": "nvidia_nim",
    "nvidia-nim": "nvidia_nim",
    "google": "gemini",
    "gateway": "litellm",
}


def normalize_provider(value: Optional[str]) -> str:
    code = (value or "local").strip().lower().replace(" ", "_")
    code = _ALIASES.get(code, code)
    if code not in PROVIDERS:
        supported = ", ".join(sorted(PROVIDERS))
        raise ValueError(f"Unsupported AI provider {value!r}. Supported: {supported}")
    return code


def get_provider(value: Optional[str]) -> ProviderSpec:
    return PROVIDERS[normalize_provider(value)]


def public_provider_catalog() -> list[dict]:
    return [spec.public_dict() for spec in PROVIDERS.values()]
