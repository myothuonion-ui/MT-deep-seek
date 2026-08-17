"""
KMN-CyberSeek AI Connector Module.

Supported providers:
- local: Ollama
- api: DeepSeek API (backward-compatible alias)
- nvidia: NVIDIA hosted NIM API
- gemini: Google Gemini OpenAI-compatible API
"""

import asyncio
import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Literal, Optional

import httpx
import requests
from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv(override=True)
logger = logging.getLogger(__name__)


_CLOUD_PROVIDERS = {"api", "nvidia", "gemini"}
_PROVIDER_ALIASES = {
    "deepseek": "api",
    "ollama": "local",
}
_PLACEHOLDER_PATTERNS = (
    "your_deepseek_api_key_here",
    "your_nvidia_api_key_here",
    "your_gemini_api_key_here",
    "your-api-key-here",
    "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "nvapi-xxxxxxxx",
    "sk-test",
    "sk-demo",
    "placeholder",
    "example",
    "changeme",
    "insert_key_here",
)


def _extract_json(text: str) -> Optional[dict]:
    """Extract the first valid JSON object from arbitrary model output."""
    if not text:
        return None

    stripped = re.sub(r"```(?:json)?\s*(.*?)\s*```", r"\1", text, flags=re.DOTALL).strip()
    for candidate in (stripped, text):
        try:
            parsed = json.loads(candidate)
            return parsed if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            pass

    start = text.find("{")
    if start == -1:
        return None

    depth = 0
    in_string = False
    escaped = False
    for i, ch in enumerate(text[start:], start):
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    parsed = json.loads(text[start:i + 1])
                    return parsed if isinstance(parsed, dict) else None
                except json.JSONDecodeError:
                    return None
    return None


def _valid_key(value: Optional[str]) -> bool:
    if not value:
        return False
    value = value.strip()
    if len(value) <= 10:
        return False
    lowered = value.lower()
    return not any(pattern in lowered for pattern in _PLACEHOLDER_PATTERNS)


def _safe_int_env(name: str, default: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _safe_float_env(name: str, default: float) -> float:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = float(raw)
    except ValueError:
        return default
    return max(0.0, min(value, 1.0))


class AIResponse(BaseModel):
    """Strict AI response consumed by deterministic execution policy gates."""

    reasoning: str = Field(..., min_length=1, description="AI analysis")
    suggested_command: str = Field(..., description="Command proposed for policy review")
    risk_level: Literal["low", "medium", "high"]
    target_info: Optional[Dict[str, Any]] = None
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    attack_phase: Literal[
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


class KMN_AI_Connector:
    """AI connector for Ollama, DeepSeek, NVIDIA NIM, and Gemini."""

    def __init__(
        self,
        provider: str = None,
        api_key: Optional[str] = None,
        local_model: Optional[str] = None,
        ollama_url: Optional[str] = None,
        api_model: Optional[str] = None,
    ):
        load_dotenv(override=True)

        configured_provider = (os.getenv("AI_PROVIDER") or "").strip().lower()
        requested_provider = (provider or configured_provider or "").strip().lower()
        requested_provider = _PROVIDER_ALIASES.get(requested_provider, requested_provider)

        # Preserve the historical behavior: if no provider is explicitly selected,
        # only a valid DeepSeek key may auto-select the cloud path. NVIDIA/Gemini
        # require AI_PROVIDER to be set so a newly-added secret can never silently
        # change data-routing behavior.
        deepseek_key = api_key or os.getenv("DEEPSEEK_API_KEY") or os.getenv("OPENAI_API_KEY")
        if not requested_provider:
            requested_provider = "api" if _valid_key(deepseek_key) else "local"

        if requested_provider not in {"local", "api", "nvidia", "gemini"}:
            logger.warning("Unknown AI provider '%s'; falling back to local Ollama.", requested_provider)
            requested_provider = "local"

        key_by_provider = {
            "api": deepseek_key,
            "nvidia": api_key or os.getenv("NVIDIA_API_KEY"),
            "gemini": api_key or os.getenv("GEMINI_API_KEY"),
        }

        if requested_provider in _CLOUD_PROVIDERS:
            candidate_key = key_by_provider[requested_provider]
            if not _valid_key(candidate_key):
                logger.warning(
                    "%s provider selected without a valid API key; falling back to local Ollama.",
                    requested_provider,
                )
                self.provider = "local"
                self.api_key = None
            else:
                self.provider = requested_provider
                self.api_key = candidate_key.strip()
        else:
            self.provider = "local"
            self.api_key = None

        ollama_base = (
            ollama_url or os.getenv("OLLAMA_URL") or "http://localhost:11434"
        ).strip().rstrip("/")
        if ollama_base.endswith("/api/generate"):
            ollama_base = ollama_base[: -len("/api/generate")].rstrip("/")
        self.ollama_url = f"{ollama_base}/api/generate"

        self.local_model = local_model or os.getenv("OLLAMA_MODEL") or "deepseek-r1:8b"
        self.deepseek_api_url = "https://api.deepseek.com/chat/completions"
        self.nvidia_api_url = "https://integrate.api.nvidia.com/v1/chat/completions"
        self.gemini_api_url = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"

        if self.provider == "nvidia":
            self.api_model = api_model or os.getenv("NVIDIA_MODEL") or "z-ai/glm-5.2"
            self.cloud_api_url = self.nvidia_api_url
            context_env = "NVIDIA_CONTEXT_WINDOW"
            context_default = 1_000_000
        elif self.provider == "gemini":
            self.api_model = api_model or os.getenv("GEMINI_MODEL") or "gemini-3.6-flash"
            self.cloud_api_url = self.gemini_api_url
            context_env = "GEMINI_CONTEXT_WINDOW"
            context_default = 131_072
        elif self.provider == "api":
            self.api_model = api_model or os.getenv("DEEPSEEK_MODEL") or "deepseek-chat"
            self.cloud_api_url = self.deepseek_api_url
            context_env = "DEEPSEEK_CONTEXT_WINDOW"
            context_default = 131_072
        else:
            self.api_model = api_model or os.getenv("DEEPSEEK_MODEL") or "deepseek-chat"
            self.cloud_api_url = self.deepseek_api_url
            context_env = "OLLAMA_CONTEXT_WINDOW"
            context_default = 8_192

        self.context_window = _safe_int_env(context_env, context_default)
        self.max_output_tokens = _safe_int_env("AI_MAX_OUTPUT_TOKENS", 2_000)
        self.temperature = _safe_float_env("AI_TEMPERATURE", 0.7)

        logger.info(
            "Initialized AI connector — provider=%s model=%s context_window=%s",
            self.provider,
            self.local_model if self.provider == "local" else self.api_model,
            self.context_window,
        )

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        return max(1, len(text) // 4)

    def _budget_for_output(self) -> int:
        cw = self.context_window
        if cw < 4_000:
            return 800
        if cw < 8_000:
            return 2_000
        if cw < 16_000:
            return 5_000
        return 12_000

    def _select_system_prompt(self, custom: Optional[str] = None) -> str:
        if custom:
            return custom
        from .prompts import SYSTEM_PROMPT, SYSTEM_PROMPT_COMPACT

        if self.provider in _CLOUD_PROVIDERS:
            return SYSTEM_PROMPT
        return SYSTEM_PROMPT_COMPACT if self.context_window < 8_000 else SYSTEM_PROMPT

    def _memory_block(self, memory: Optional[str], budget: Optional[int] = None) -> str:
        if not memory:
            return ""
        if budget is None:
            cw = self.context_window
            if cw < 4_000:
                budget = 600
            elif cw < 8_000:
                budget = 1_600
            elif cw < 16_000:
                budget = 4_000
            else:
                budget = 10_000
        trimmed = memory[:budget]
        if len(memory) > budget:
            trimmed += "\n... [memory trimmed for context budget]"
        return (
            "\n\n<<<UNTRUSTED_SESSION_MEMORY>>>\n"
            + trimmed
            + "\n<<<END_UNTRUSTED_SESSION_MEMORY>>>"
        )

    def _prepare_prompt(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        memory: Optional[str] = None,
    ) -> str:
        system = self._select_system_prompt(system_prompt)
        full_prompt = (
            f"{system}"
            f"{self._memory_block(memory)}"
            f"\n\nCurrent Context:\n{prompt}"
            f"\n\nRespond with valid raw JSON only — no markdown, no extra text."
        )
        estimated = self._estimate_tokens(full_prompt)
        usable = int(self.context_window * 0.80)
        if estimated > usable:
            logger.warning(
                "Prompt estimated at %s tokens but usable budget is %s tokens (context_window=%s).",
                estimated,
                usable,
                self.context_window,
            )
        return full_prompt

    def ask_ai_local(
        self,
        prompt: str,
        session_id: Optional[str] = None,
        memory: Optional[str] = None,
    ) -> Optional[AIResponse]:
        del session_id
        try:
            payload = {
                "model": self.local_model,
                "prompt": self._prepare_prompt(prompt, memory=memory),
                "stream": False,
                "options": {
                    "temperature": self.temperature,
                    "top_p": 0.9,
                    "top_k": 40,
                    "num_ctx": self.context_window,
                },
            }
            response = requests.post(self.ollama_url, json=payload, timeout=120)
            response.raise_for_status()
            response_text = response.json().get("response", "")
            ai_data = _extract_json(response_text)
            if ai_data is None:
                logger.error(
                    "Could not extract valid JSON from Ollama response (model=%s): %s",
                    self.local_model,
                    response_text[:500],
                )
                return None
            try:
                return AIResponse(**ai_data)
            except Exception as exc:
                logger.error("AIResponse validation failed: %s | data=%s", exc, ai_data)
                return None
        except requests.exceptions.RequestException as exc:
            logger.error("Local AI request failed: %s", exc)
            raise ConnectionError(f"Failed to connect to local Ollama: {exc}") from exc

    def _cloud_messages(self, prompt: str, memory: Optional[str]) -> list[dict[str, str]]:
        from .prompts import SYSTEM_PROMPT

        user_content = (
            f"{self._memory_block(memory, 10_000)}"
            f"\n\nCurrent Context:\n{prompt}"
            f"\n\nRespond with valid raw JSON only — no markdown, no extra text."
        )
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]

    def _cloud_payload(self, messages: list[dict[str, str]], temperature: float) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": self.api_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": self.max_output_tokens,
        }
        # DeepSeek's API supports the JSON response-format hint used by the
        # original implementation. NVIDIA and Gemini vary by model, so those
        # providers rely on the strict prompt plus the robust JSON extractor.
        if self.provider == "api":
            payload["response_format"] = {"type": "json_object"}
        return payload

    async def _post_cloud_chat(self, payload: dict[str, Any], timeout: float = 60.0) -> str:
        if not self.api_key:
            raise ValueError(f"{self.provider} API key is required for cloud provider")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(self.cloud_api_url, json=payload, headers=headers)
                response.raise_for_status()
                result = response.json()
                return result["choices"][0]["message"]["content"]
        except httpx.HTTPStatusError as exc:
            logger.error(
                "%s API returned HTTP %s for model=%s",
                self.provider,
                exc.response.status_code,
                self.api_model,
            )
            raise ConnectionError(
                f"{self.provider} API returned HTTP {exc.response.status_code}"
            ) from exc
        except (httpx.RequestError, KeyError, TypeError, ValueError) as exc:
            logger.error("%s API request failed for model=%s: %s", self.provider, self.api_model, exc)
            raise ConnectionError(f"Failed to connect to {self.provider} API: {exc}") from exc

    async def ask_ai_api(
        self,
        prompt: str,
        session_id: Optional[str] = None,
        memory: Optional[str] = None,
    ) -> Optional[AIResponse]:
        """Query the configured cloud provider.

        The method name is retained for backward compatibility; it now serves
        DeepSeek, NVIDIA NIM, and Gemini.
        """
        del session_id
        if self.provider not in _CLOUD_PROVIDERS:
            raise ValueError("ask_ai_api requires a cloud provider")

        text = await self._post_cloud_chat(
            self._cloud_payload(self._cloud_messages(prompt, memory), self.temperature)
        )
        ai_data = _extract_json(text)
        if ai_data is None:
            logger.error(
                "Could not extract valid JSON from %s response (model=%s): %s",
                self.provider,
                self.api_model,
                text[:500],
            )
            return None
        try:
            return AIResponse(**ai_data)
        except Exception as exc:
            logger.error("AIResponse validation failed: %s | data=%s", exc, ai_data)
            return None

    def ask_ai(self, prompt: str, session_id: Optional[str] = None) -> Optional[AIResponse]:
        if self.provider in _CLOUD_PROVIDERS:
            try:
                asyncio.get_running_loop()
            except RuntimeError:
                return asyncio.run(self.ask_ai_api(prompt, session_id))
            raise RuntimeError(
                "KMN_AI_Connector.ask_ai() is synchronous and cannot be called from "
                "inside a running event loop. Use 'await ask_ai_async(...)' instead."
            )
        return self.ask_ai_local(prompt, session_id)

    async def ask_ai_async(
        self,
        prompt: str,
        session_id: Optional[str] = None,
        memory: Optional[str] = None,
    ) -> Optional[AIResponse]:
        if self.provider in _CLOUD_PROVIDERS:
            return await self.ask_ai_api(prompt, session_id, memory)

        loop = asyncio.get_running_loop()
        with ThreadPoolExecutor() as executor:
            return await loop.run_in_executor(
                executor,
                lambda: self.ask_ai_local(prompt, session_id, memory),
            )

    async def ask_raw_async(self, system_prompt: str, user_prompt: str) -> Optional[Any]:
        try:
            if self.provider in _CLOUD_PROVIDERS:
                return await self._ask_raw_api(system_prompt, user_prompt)

            loop = asyncio.get_running_loop()
            with ThreadPoolExecutor() as executor:
                return await loop.run_in_executor(
                    executor,
                    lambda: self._ask_raw_local(system_prompt, user_prompt),
                )
        except Exception as exc:
            logger.warning("ask_raw_async failed (non-fatal): %s", exc)
            return None

    async def _ask_raw_api(self, system_prompt: str, user_prompt: str) -> Optional[Any]:
        if not self.api_key:
            return None
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        text = await self._post_cloud_chat(self._cloud_payload(messages, 0.3))
        return self._extract_json(text)

    def _ask_raw_local(self, system_prompt: str, user_prompt: str) -> Optional[Any]:
        payload = {
            "model": self.local_model,
            "prompt": f"{system_prompt}\n\n{user_prompt}",
            "stream": False,
            "options": {"temperature": 0.3, "num_ctx": self.context_window},
        }
        response = requests.post(self.ollama_url, json=payload, timeout=60)
        response.raise_for_status()
        return self._extract_json(response.json().get("response", ""))

    @staticmethod
    def _extract_json(text: str) -> Optional[Any]:
        """Best-effort JSON extraction for raw non-AIResponse tasks."""
        text = (text or "").strip()
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.MULTILINE).strip()
        match = re.search(r"(\[.*\]|\{.*\})", text, re.DOTALL)
        if match:
            text = match.group(1)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            logger.warning("ask_raw_async: failed to parse JSON from model response: %s", text[:200])
            return None


def get_ai_connector(provider: str = "local", api_key: Optional[str] = None) -> KMN_AI_Connector:
    """Factory function kept for backward compatibility."""
    return KMN_AI_Connector(provider=provider, api_key=api_key)
