"""Claude methodology routing tests."""

import os

from core.skill_router import ClaudeSkillRouter


class _FakeAdapter:
    pinned_commit = "fixture-commit"

    def list_skills(self, query="", limit=500):
        return [
            {"name": "idor-authorization-testing", "description": "API object authorization and IDOR"},
            {"name": "sql-injection", "description": "SQL database injection checks"},
            {"name": "subdomain-enumeration", "description": "DNS reconnaissance and discovery"},
            {"name": "report-writing", "description": "Evidence and remediation reporting"},
        ][:limit]

    def read_skill(self, name):
        return {
            "name": name,
            "content": "---\ntitle: fixture\n---\n# Method\n\n" + (name + " safe methodology. ") * 80,
            "source_commit": self.pinned_commit,
        }


class _UnavailableAdapter(_FakeAdapter):
    def list_skills(self, query="", limit=500):
        raise RuntimeError("bundle missing")


def test_skill_router_selects_relevant_bounded_content_with_provenance():
    router = ClaudeSkillRouter(
        adapter=_FakeAdapter(),
        max_skills=2,
        max_excerpt_chars=420,
    )
    result = router.route({
        "objective": "Test API object authorization and IDOR",
        "stage": "web_application",
        "services": [{"service": "http", "port": 443}],
        "vulnerabilities": ["broken access control"],
    })
    assert result["enabled"] is True
    assert result["source_commit"] == "fixture-commit"
    assert result["selected_skills"][0]["name"] == "idor-authorization-testing"
    assert len(result["selected_skills"]) <= 2
    assert all(len(item["excerpt"]) <= 420 for item in result["selected_skills"])
    assert "title: fixture" not in result["selected_skills"][0]["excerpt"]
    assert any("untrusted" in item.lower() for item in result["guardrails"])


def test_skill_router_can_be_disabled_without_reading_bundle():
    previous = os.environ.get("CLAUDE_SKILL_ROUTING")
    os.environ["CLAUDE_SKILL_ROUTING"] = "false"
    try:
        result = ClaudeSkillRouter(adapter=_UnavailableAdapter()).route({
            "objective": "API authorization",
            "stage": "web_application",
        })
        assert result["enabled"] is False
        assert "disabled" in result["reason"]
    finally:
        if previous is None:
            os.environ.pop("CLAUDE_SKILL_ROUTING", None)
        else:
            os.environ["CLAUDE_SKILL_ROUTING"] = previous


def test_skill_router_bundle_failure_is_non_fatal_and_fail_closed():
    result = ClaudeSkillRouter(adapter=_UnavailableAdapter()).route({
        "objective": "API authorization",
        "stage": "web_application",
    })
    assert result["enabled"] is False
    assert result["selected_skills"] == []
    assert "unavailable" in result["reason"]
