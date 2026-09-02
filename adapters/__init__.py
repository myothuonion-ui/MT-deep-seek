"""Policy-gated integrations for external security tools and skill packs."""

from .base import AdapterError, AdapterPolicyError, AdapterResult, AdapterUnavailableError
from .bbot import BBOTAdapter
from .claude_bughunter import ClaudeBugHunterAdapter
from .nuclei import NucleiAdapter
from .playwright_browser import PlaywrightBrowserAdapter

__all__ = [
    "AdapterError",
    "AdapterPolicyError",
    "AdapterResult",
    "AdapterUnavailableError",
    "BBOTAdapter",
    "ClaudeBugHunterAdapter",
    "NucleiAdapter",
    "PlaywrightBrowserAdapter",
]
