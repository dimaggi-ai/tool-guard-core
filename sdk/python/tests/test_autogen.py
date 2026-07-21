"""
test_autogen.py — Tests for the AutoGen adapter (guarded / register_guarded).
"""
from unittest.mock import MagicMock

import pytest

from toolguard.adapters.autogen import guarded, register_guarded
from toolguard.client import ToolGuard
from toolguard.errors import ToolDenied, ToolEscalated
from toolguard.types import Decision, EvaluationResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(decision: str, suggested_response: str = "") -> EvaluationResult:
    return EvaluationResult(
        decision=decision,
        action_taken=decision,
        decision_reason=f"{decision} by policy",
        suggested_response=suggested_response,
    )


def _make_client(decision: str, suggested: str = "") -> MagicMock:
    client = MagicMock(spec=ToolGuard)
    result = _make_result(decision, suggested)
    if decision == "denied":
        client.evaluate.side_effect = ToolDenied("denied", result=result)
    elif decision == "escalated":
        client.evaluate.side_effect = ToolEscalated("escalated", result=result)
    else:
        client.evaluate.return_value = result
    return client


# ---------------------------------------------------------------------------
# guarded() decorator
# ---------------------------------------------------------------------------

class TestGuarded:
    def test_allowed_calls_underlying_function(self):
        client = _make_client("allowed")
        real_fn = MagicMock(return_value={"status": "ok"})

        wrapped = guarded(client, tool_name="do_thing", tool_group="ops")(real_fn)
        result = wrapped(item="widget", count=3)

        real_fn.assert_called_once_with(item="widget", count=3)
        assert result == {"status": "ok"}

    def test_denied_does_not_call_function(self):
        client = _make_client("denied")
        real_fn = MagicMock(return_value="should not run")

        wrapped = guarded(client, "issue_refund", "monetary_outflow")(real_fn)
        result = wrapped(amount=1000)

        real_fn.assert_not_called()
        assert result["error"] == "denied"

    def test_escalated_does_not_call_function(self):
        client = _make_client("escalated")
        real_fn = MagicMock()

        wrapped = guarded(client, "approve_payment")(real_fn)
        result = wrapped(amount=500)

        real_fn.assert_not_called()
        assert result["error"] == "escalated"

    def test_denied_returns_suggested_response(self):
        client = _make_client("denied", suggested="Please reduce the amount.")
        real_fn = MagicMock()
        wrapped = guarded(client, "issue_refund")(real_fn)
        result = wrapped(amount=5000)
        assert result["suggested_response"] == "Please reduce the amount."

    def test_evaluate_called_with_kwargs_as_params(self):
        client = _make_client("allowed")
        real_fn = MagicMock(return_value="ok")

        wrapped = guarded(client, "search", "data")(real_fn)
        wrapped(query="test", limit=10)

        client.evaluate.assert_called_once_with(
            tool_name="search",
            parameters={"query": "test", "limit": 10},
            tool_group="data",
        )

    def test_preserves_function_metadata(self):
        client = _make_client("allowed")

        def my_tool(x: int) -> int:
            """My tool docstring."""
            return x

        wrapped = guarded(client, "my_tool")(my_tool)
        assert wrapped.__name__ == "my_tool"
        assert wrapped.__doc__ == "My tool docstring."

    def test_empty_tool_group_allowed(self):
        """tool_group defaults to empty string if not specified."""
        client = _make_client("allowed")
        real_fn = MagicMock(return_value="ok")
        wrapped = guarded(client, "search")(real_fn)
        wrapped()
        client.evaluate.assert_called_once_with(
            tool_name="search",
            parameters={},
            tool_group="",
        )


# ---------------------------------------------------------------------------
# register_guarded helper
# ---------------------------------------------------------------------------

class TestRegisterGuarded:
    def test_register_guarded_wraps_function(self):
        client = _make_client("allowed")
        real_fn = MagicMock(return_value="result")

        wrapped = register_guarded(client, "my_tool", "group", real_fn)
        r = wrapped(val=1)
        assert r == "result"
        real_fn.assert_called_once_with(val=1)

    def test_register_guarded_requires_func(self):
        client = _make_client("allowed")
        with pytest.raises(ValueError, match="func is required"):
            register_guarded(client, "my_tool")
