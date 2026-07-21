"""
test_native.py — Tests for the native OpenAI / Anthropic tool-use adapter.
"""
import json
from unittest.mock import MagicMock

import pytest

from toolguard.adapters.native import guard_tool_calls, _extract_call, _build_error_result
from toolguard.client import ToolGuard
from toolguard.types import Decision, EvaluationResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(decision: str, reason: str = "", suggested: str = "") -> EvaluationResult:
    return EvaluationResult(
        decision=decision,
        action_taken=decision,
        decision_reason=reason,
        suggested_response=suggested,
    )


def _make_client(decisions: list[str]) -> MagicMock:
    """Return a client whose evaluate_raw() returns decisions in order."""
    client = MagicMock(spec=ToolGuard)
    client.evaluate_raw.side_effect = [_make_result(d) for d in decisions]
    return client


# ---------------------------------------------------------------------------
# OpenAI shape
# ---------------------------------------------------------------------------

OPENAI_ALLOW_CALL = {
    "id": "call_abc",
    "type": "function",
    "function": {
        "name": "search",
        "arguments": '{"query": "hello"}',
    },
}

OPENAI_DENY_CALL = {
    "id": "call_xyz",
    "type": "function",
    "function": {
        "name": "issue_refund",
        "arguments": '{"amount": 1000}',
    },
}


class TestOpenAIShape:
    def test_allowed_in_allowed_list(self):
        client = _make_client(["allowed"])
        allowed, denied = guard_tool_calls([OPENAI_ALLOW_CALL], client, provider="openai")
        assert len(allowed) == 1
        assert len(denied) == 0
        assert allowed[0]["call"] is OPENAI_ALLOW_CALL

    def test_denied_in_denied_list(self):
        client = _make_client(["denied"])
        allowed, denied = guard_tool_calls([OPENAI_DENY_CALL], client, provider="openai")
        assert len(allowed) == 0
        assert len(denied) == 1
        assert denied[0]["call"] is OPENAI_DENY_CALL

    def test_denied_tool_result_shape(self):
        client = _make_client(["denied"])
        _, denied = guard_tool_calls([OPENAI_DENY_CALL], client, provider="openai")
        tr = denied[0]["tool_result"]
        assert "tool_call_id" in tr
        assert tr["tool_call_id"] == "call_xyz"
        assert tr["role"] == "tool"
        assert "content" in tr

    def test_mixed_allow_deny(self):
        client = _make_client(["allowed", "denied"])
        calls = [OPENAI_ALLOW_CALL, OPENAI_DENY_CALL]
        allowed, denied = guard_tool_calls(calls, client, provider="openai")
        assert len(allowed) == 1
        assert len(denied) == 1

    def test_parameters_parsed_from_json_string(self):
        client = _make_client(["allowed"])
        guard_tool_calls([OPENAI_ALLOW_CALL], client, provider="openai")
        client.evaluate_raw.assert_called_once_with(
            tool_name="search",
            parameters={"query": "hello"},
            tool_group="",
        )

    def test_tool_group_from_map(self):
        client = _make_client(["allowed"])
        guard_tool_calls(
            [OPENAI_ALLOW_CALL],
            client,
            provider="openai",
            tool_groups={"search": "read_ops"},
        )
        client.evaluate_raw.assert_called_once_with(
            tool_name="search",
            parameters={"query": "hello"},
            tool_group="read_ops",
        )

    def test_escalated_goes_to_denied_list(self):
        client = _make_client(["escalated"])
        allowed, denied = guard_tool_calls([OPENAI_DENY_CALL], client, provider="openai")
        assert len(denied) == 1
        assert denied[0]["result"].decision == "escalated"

    def test_flagged_goes_to_allowed_list(self):
        """flagged = recorded near-miss; execution proceeds."""
        client = _make_client(["flagged"])
        allowed, denied = guard_tool_calls([OPENAI_ALLOW_CALL], client, provider="openai")
        assert len(allowed) == 1
        assert len(denied) == 0


# ---------------------------------------------------------------------------
# Anthropic shape
# ---------------------------------------------------------------------------

ANTHROPIC_ALLOW_CALL = {
    "type": "tool_use",
    "id": "toolu_01",
    "name": "search",
    "input": {"query": "hello"},
}

ANTHROPIC_DENY_CALL = {
    "type": "tool_use",
    "id": "toolu_02",
    "name": "issue_refund",
    "input": {"amount": 1000},
}


class TestAnthropicShape:
    def test_allowed_in_allowed_list(self):
        client = _make_client(["allowed"])
        allowed, denied = guard_tool_calls([ANTHROPIC_ALLOW_CALL], client, provider="anthropic")
        assert len(allowed) == 1
        assert len(denied) == 0

    def test_denied_in_denied_list(self):
        client = _make_client(["denied"])
        allowed, denied = guard_tool_calls([ANTHROPIC_DENY_CALL], client, provider="anthropic")
        assert len(denied) == 1

    def test_denied_tool_result_shape(self):
        client = _make_client(["denied"])
        _, denied = guard_tool_calls([ANTHROPIC_DENY_CALL], client, provider="anthropic")
        tr = denied[0]["tool_result"]
        assert tr["type"] == "tool_result"
        assert tr["tool_use_id"] == "toolu_02"
        assert tr["is_error"] is True
        assert "content" in tr

    def test_parameters_passed_from_input(self):
        client = _make_client(["allowed"])
        guard_tool_calls([ANTHROPIC_ALLOW_CALL], client, provider="anthropic")
        client.evaluate_raw.assert_called_once_with(
            tool_name="search",
            parameters={"query": "hello"},
            tool_group="",
        )

    def test_suggested_response_in_tool_result(self):
        result = _make_result("denied", suggested="Please reduce the refund amount.")
        client = MagicMock(spec=ToolGuard)
        client.evaluate_raw.return_value = result

        _, denied = guard_tool_calls([ANTHROPIC_DENY_CALL], client, provider="anthropic")
        tr = denied[0]["tool_result"]
        assert tr["content"] == "Please reduce the refund amount."


# ---------------------------------------------------------------------------
# Provider validation
# ---------------------------------------------------------------------------

class TestValidation:
    def test_invalid_provider_raises(self):
        client = MagicMock(spec=ToolGuard)
        with pytest.raises(ValueError, match="provider must be"):
            guard_tool_calls([], client, provider="bedrock")

    def test_empty_list_returns_empty(self):
        client = MagicMock(spec=ToolGuard)
        allowed, denied = guard_tool_calls([], client)
        assert allowed == []
        assert denied == []


# ---------------------------------------------------------------------------
# _extract_call helper
# ---------------------------------------------------------------------------

class TestExtractCall:
    def test_openai_dict(self):
        tool_name, params, call_id = _extract_call(OPENAI_ALLOW_CALL, "openai")
        assert tool_name == "search"
        assert params == {"query": "hello"}
        assert call_id == "call_abc"

    def test_anthropic_dict(self):
        tool_name, params, call_id = _extract_call(ANTHROPIC_ALLOW_CALL, "anthropic")
        assert tool_name == "search"
        assert params == {"query": "hello"}
        assert call_id == "toolu_01"

    def test_openai_bad_json_arguments(self):
        call = {
            "id": "c1",
            "type": "function",
            "function": {"name": "tool", "arguments": "not-json"},
        }
        tool_name, params, call_id = _extract_call(call, "openai")
        assert tool_name == "tool"
        assert params == {"_raw": "not-json"}
