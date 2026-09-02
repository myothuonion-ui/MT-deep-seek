"""Policy-gated, task-aware model routing.

Routing is disabled by default and preserves the operator's active provider.
Cross-provider routing requires explicit enablement plus an allowlist. Provider
credentials are never accepted, copied, or returned by this module.
"""

from __future__ import annotations

import os
from typing import Any, Mapping, Optional, Sequence


TASK_PROFILES: dict[str, dict[str, Any]] = {
    "scoper": {
        "purpose": "authorization and scope policy",
        "reasoning": "deterministic-first",
        "recommended_context_tokens": 8_000,
    },
    "mapper": {
        "purpose": "attack-surface and contract mapping",
        "reasoning": "balanced",
        "recommended_context_tokens": 16_000,
    },
    "code_reviewer": {
        "purpose": "white-box source review",
        "reasoning": "code-strong",
        "recommended_context_tokens": 32_000,
    },
    "strategist": {
        "purpose": "hypothesis and dependency planning",
        "reasoning": "strong",
        "recommended_context_tokens": 32_000,
    },
    "tactical": {
        "purpose": "next bounded action proposal",
        "reasoning": "balanced",
        "recommended_context_tokens": 16_000,
    },
    "verifier": {
        "purpose": "independent critique and proof review",
        "reasoning": "strong",
        "recommended_context_tokens": 24_000,
    },
    "reporter": {
        "purpose": "evidence-grounded reporting",
        "reasoning": "long-context",
        "recommended_context_tokens": 32_000,
    },
}
_SENSITIVITY = {"standard", "confidential", "restricted"}
_PRIVACY_RANK = {"cloud": 1, "gateway": 2, "local": 3}
_MAX_ESTIMATED_CONTEXT = 250_000


class ModelRoutingPolicyError(ValueError):
    """Raised when a route would violate configuration or privacy policy."""


def _enabled(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _split_csv(value: Optional[str]) -> set[str]:
    return {
        item.strip().lower()
        for item in str(value or "").split(",")
        if item.strip()
    }


def _privacy_allows(privacy: str, sensitivity: str) -> bool:
    rank = _PRIVACY_RANK.get(str(privacy).lower(), 0)
    required = {"standard": 1, "confidential": 2, "restricted": 3}[sensitivity]
    return rank >= required


class ModelRouter:
    """Select a configured provider without touching provider credentials."""

    def __init__(
        self,
        providers: Sequence[Mapping[str, Any]],
        active_provider: str,
        *,
        enabled: bool = False,
        auto_select: bool = False,
        allowed_providers: Optional[Sequence[str]] = None,
        explicit_routes: Optional[Mapping[str, str]] = None,
    ):
        self.providers = {
            str(item.get("code") or "").strip().lower(): dict(item)
            for item in providers
            if isinstance(item, Mapping) and item.get("code")
        }
        self.active_provider = str(active_provider or "").strip().lower()
        if self.active_provider not in self.providers:
            raise ModelRoutingPolicyError("active provider is not in the provider catalog")
        self.enabled = bool(enabled)
        self.auto_select = bool(auto_select)
        configured_allowed = {
            str(item).strip().lower()
            for item in (allowed_providers or [])
            if str(item).strip()
        }
        self.allowed_providers = configured_allowed or {self.active_provider}
        self.allowed_providers.add(self.active_provider)
        unknown = self.allowed_providers.difference(self.providers)
        if unknown:
            raise ModelRoutingPolicyError(
                "unknown allowed provider(s): " + ", ".join(sorted(unknown))
            )
        self.explicit_routes = {
            str(role).strip().lower(): str(provider).strip().lower()
            for role, provider in (explicit_routes or {}).items()
            if str(role).strip() and str(provider).strip()
        }
        unknown_roles = self.explicit_routes.keys() - TASK_PROFILES.keys()
        if unknown_roles:
            raise ModelRoutingPolicyError(
                "unknown routed role(s): " + ", ".join(sorted(unknown_roles))
            )

    @classmethod
    def from_environment(
        cls,
        providers: Sequence[Mapping[str, Any]],
        active_provider: str,
    ) -> "ModelRouter":
        routes = {}
        for role in TASK_PROFILES:
            provider = os.getenv(f"MODEL_ROUTE_{role.upper()}", "").strip()
            if provider:
                routes[role] = provider
        return cls(
            providers,
            active_provider,
            enabled=_enabled(os.getenv("MODEL_ROUTING_ENABLED")),
            auto_select=_enabled(os.getenv("MODEL_ROUTING_AUTO_SELECT")),
            allowed_providers=sorted(
                _split_csv(os.getenv("MODEL_ROUTING_ALLOWED_PROVIDERS"))
            ),
            explicit_routes=routes,
        )

    def public_status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "auto_select": self.auto_select,
            "active_provider": self.active_provider,
            "allowed_providers": sorted(self.allowed_providers),
            "explicit_routes": dict(sorted(self.explicit_routes.items())),
            "configured_providers": sorted(
                code
                for code, item in self.providers.items()
                if bool(item.get("configured"))
            ),
            "credentials_exposed": False,
            "roles": TASK_PROFILES,
        }

    def _candidate(self, provider: str, sensitivity: str) -> Optional[dict[str, Any]]:
        item = self.providers.get(provider)
        if not item or provider not in self.allowed_providers:
            return None
        if not bool(item.get("configured")):
            return None
        if not _privacy_allows(str(item.get("privacy") or "cloud"), sensitivity):
            return None
        return item

    def route(
        self,
        role: str,
        *,
        sensitivity: str = "standard",
        estimated_context_tokens: int = 0,
        independent_of: Optional[str] = None,
    ) -> dict[str, Any]:
        role = str(role or "").strip().lower()
        sensitivity = str(sensitivity or "").strip().lower()
        independent_of = str(independent_of or "").strip().lower() or None
        if role not in TASK_PROFILES:
            raise ModelRoutingPolicyError(f"unsupported task role: {role!r}")
        if sensitivity not in _SENSITIVITY:
            raise ModelRoutingPolicyError(
                "sensitivity must be standard, confidential, or restricted"
            )
        try:
            context_tokens = int(estimated_context_tokens)
        except (TypeError, ValueError) as exc:
            raise ModelRoutingPolicyError(
                "estimated_context_tokens must be an integer"
            ) from exc
        if context_tokens < 0 or context_tokens > _MAX_ESTIMATED_CONTEXT:
            raise ModelRoutingPolicyError(
                f"estimated_context_tokens must be 0..{_MAX_ESTIMATED_CONTEXT}"
            )

        active = self.providers[self.active_provider]
        if not self.enabled:
            selected = active
            source = "routing-disabled-active-provider"
            policy_enforced = False
        else:
            explicit = self.explicit_routes.get(role)
            if explicit:
                selected = self._candidate(explicit, sensitivity)
                if selected is None:
                    raise ModelRoutingPolicyError(
                        f"explicit route for {role} is unavailable or violates policy"
                    )
                source = "explicit-role-route"
            else:
                selected = self._candidate(self.active_provider, sensitivity)
                source = "active-provider"
                if self.auto_select and role == "verifier":
                    alternatives = [
                        self._candidate(code, sensitivity)
                        for code in sorted(self.allowed_providers)
                        if code != (independent_of or self.active_provider)
                    ]
                    selected = next((item for item in alternatives if item), selected)
                    if selected and selected.get("code") != self.active_provider:
                        source = "independent-verifier-auto-route"
                if selected is None:
                    raise ModelRoutingPolicyError(
                        "no configured allowed provider satisfies the privacy policy"
                    )
            policy_enforced = True

        selected_code = str(selected.get("code"))
        selected_privacy = str(selected.get("privacy") or "cloud")
        independent = bool(independent_of and selected_code != independent_of)
        return {
            "schema": 1,
            "role": role,
            "task_profile": TASK_PROFILES[role],
            "provider": selected_code,
            "model": str(selected.get("model") or ""),
            "provider_kind": str(selected.get("kind") or ""),
            "provider_configured": bool(selected.get("configured")),
            "privacy": selected_privacy,
            "sensitivity": sensitivity,
            "route_source": source,
            "routing_enabled": self.enabled,
            "policy_enforced": policy_enforced,
            "privacy_compatible": _privacy_allows(selected_privacy, sensitivity),
            "independent_of": independent_of,
            "independent": independent,
            "estimated_context_tokens": context_tokens,
            "context_capacity": "operator-configured-not-probed",
            "runtime_probed": False,
            "credentials_exposed": False,
        }
