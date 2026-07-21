"""
test_mcp.py — Tests for the MCP adapter.
"""
from unittest.mock import MagicMock

import pytest

from toolguard.adapters.mcp import guard_mcp_tool
from toolguard.client import ToolGuard
from toolguard.errors import ToolDenied, ToolEscalated
from toolguard.types import Decision, EvaluationResult, Framework, IntegrationType


def _make_result(decision: str) -> EvaluationResult:
    return EvaluationResult(
        decision=decision,
        action_taken=decision,
        decision_reason=f"{decision} by policy",
    )


def _make_client(decision: str) -> MagicMock:
    client = MagicMock(spec=ToolGuard)
    client.framework = "sdk"
    client.integration_type = "sdk"
    result = _make_result(decision)
    if decision == "denied":
        client.evaluate.side_effect = ToolDenied("denied", result=result)
    elif decision == "escalated":
        client.evaluate.side_effect = ToolEscalated("escalated", result=result)
    else:
        client.evaluate.return_value = result
    return client


class TestGuardMcpTool:
    def test_allowed_call_executes_handler(self):
        client = _make_client("allowed")
        real_handler = MagicMock(return_value={"result": "ok"})

        decorated = guard_mcp_tool(client, tool_group="data")(real_handler)
        result = decorated("search", {"query": "hello"})

        real_handler.assert_called_once_with("search", {"query": "hello"})
        assert result == {"result": "ok"}

    def test_denied_raises_tool_denied(self):
        client = _make_client("denied")
        real_handler = MagicMock()

        decorated = guard_mcp_tool(client)(real_handler)

        with pytest.raises(ToolDenied):
            decorated("delete_records", {"table": "users"})

        real_handler.assert_not_called()

    def test_escalated_raises_tool_escalated(self):
        client = _make_client("escalated")
        real_handler = MagicMock()

        decorated = guard_mcp_tool(client)(real_handler)

        with pytest.raises(ToolEscalated):
            decorated("approve_payment", {"amount": 5000})

        real_handler.assert_not_called()

    def test_framework_stamped_as_mcp(self):
        client = MagicMock(spec=ToolGuard)
        client.framework = "sdk"
        client.integration_type = "sdk"
        client.evaluate = MagicMock(return_value=_make_result("allowed"))

        guard_mcp_tool(client)
        assert client.framework == Framework.MCP
        assert client.integration_type == IntegrationType.MCP_PROXY

    def test_evaluate_called_with_correct_args(self):
        client = _make_client("allowed")

        @guard_mcp_tool(client, tool_group="storage")
        def my_handler(tool_name: str, parameters: dict, **kwargs):
            return {}

        my_handler("read_file", {"path": "/data/file.txt"})

        client.evaluate.assert_called_once_with(
            tool_name="read_file",
            parameters={"path": "/data/file.txt"},
            tool_group="storage",
        )

    def test_none_parameters_defaults_to_empty_dict(self):
        client = _make_client("allowed")
        received_params = []

        @guard_mcp_tool(client)
        def handler(tool_name, parameters, **kwargs):
            received_params.append(parameters)
            return {}

        handler("search", None)
        assert received_params[0] == {}

    def test_extra_kwargs_passed_through(self):
        client = _make_client("allowed")
        received_kwargs = []

        @guard_mcp_tool(client)
        def handler(tool_name, parameters, **kwargs):
            received_kwargs.append(kwargs)
            return {}

        handler("search", {"q": "x"}, session_id="s1", user="u1")
        assert received_kwargs[0] == {"session_id": "s1", "user": "u1"}

    def test_default_tool_group_is_mcp(self):
        """Default tool_group when not specified is 'mcp'."""
        client = _make_client("allowed")

        @guard_mcp_tool(client)
        def handler(tool_name, parameters, **kwargs):
            return {}

        handler("tool", {"x": 1})
        client.evaluate.assert_called_once_with(
            tool_name="tool",
            parameters={"x": 1},
            tool_group="mcp",
        )

    def test_preserves_function_name(self):
        client = _make_client("allowed")

        @guard_mcp_tool(client)
        def call_tool(tool_name, parameters, **kwargs):
            """Docstring."""
            return {}

        assert call_tool.__name__ == "call_tool"
        assert call_tool.__doc__ == "Docstring."
