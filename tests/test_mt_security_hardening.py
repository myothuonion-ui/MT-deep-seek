import os
from pydantic import ValidationError

from ai.connector import AIResponse, KMN_AI_Connector
from core.validators import is_allowlisted_command, is_target_in_scope
from core.threat_intel import _url_is_public
from core.report_generator import _display_secret


def test_ai_response_schema_is_strict():
    try:
        AIResponse(reasoning="x", suggested_command="echo ok", risk_level="HIGH", confidence=2, attack_phase="reconnaissance")
        assert False, "invalid enum/range should fail"
    except ValidationError:
        pass

def test_explicit_local_provider_beats_stale_api_key():
    old = os.environ.get("DEEPSEEK_API_KEY")
    os.environ["DEEPSEEK_API_KEY"] = "sk-real-looking-stale-key-123456789"
    try:
        c = KMN_AI_Connector(provider="local")
        assert c.provider == "local"
        assert c.api_key is None
    finally:
        if old is None:
            os.environ.pop("DEEPSEEK_API_KEY", None)
        else:
            os.environ["DEEPSEEK_API_KEY"] = old

def test_scope_is_deny_by_default():
    old = os.environ.pop("ALLOW_UNSCOPED_TARGETS", None)
    try:
        assert not is_target_in_scope("8.8.8.8", "")
    finally:
        if old is not None:
            os.environ["ALLOW_UNSCOPED_TARGETS"] = old

def test_full_auto_does_not_bypass_interpreter_gate():
    old = os.environ.get("FULL_AUTO_MODE")
    os.environ["FULL_AUTO_MODE"] = "true"
    try:
        assert is_allowlisted_command("python3 -c 'print(1)'") is not None
    finally:
        if old is None:
            os.environ.pop("FULL_AUTO_MODE", None)
        else:
            os.environ["FULL_AUTO_MODE"] = old

def test_report_secrets_mask_by_default():
    old = os.environ.pop("INCLUDE_SECRETS_IN_REPORTS", None)
    try:
        assert _display_secret("hunter2") == "********"
    finally:
        if old is not None:
            os.environ["INCLUDE_SECRETS_IN_REPORTS"] = old

def test_ssrf_guard_blocks_local_addresses():
    assert not _url_is_public("http://127.0.0.1/admin")
    assert not _url_is_public("http://169.254.169.254/latest/meta-data/")
