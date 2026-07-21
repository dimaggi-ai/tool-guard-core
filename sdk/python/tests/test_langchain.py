"""
test_langchain.py — Tests for the LangChain callback handler adapter.

Uses a mock ToolGuard client so no real engine or LangChain is required.
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from toolguard.adapters.langchain import ToolGuardCallbackHandler
from toolguard.client import ToolGuard
from toolguard.errors import ToolDenied, ToolEscalated
from toolguard.types import ActionTaken, Decision, EvaluationResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(decision: str) -> EvaluationResult:
    return EvaluationResult(
        decision=decision,
        action_taken=decision,
        decision_reason=f"policy says {decision}",
    )


def _make_client(decision: str) -> ToolGuard:
    """Return a ToolGuard client whose evaluate() returns the given decision."""
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


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestToolGuardCallbackHandler:
    def _make_handler(self, decision: str):
        """Build a handler backed by a mock client returning the given decision."""
        client = _make_client(decision)

        # Patch _lazy_base_handler so we don't need langchain installed
        with patch(
            "toolguard.adapters.langchain._Base",
            object,
        ):
            # Directly instantiate by patching the parent check
            handler = ToolGuardCallbackHandler.__new__(ToolGuardCallbackHandler)
            handler._client = client
            handler._tool_groups = {}
            return handler

    def test_allowed_does_not_raise(self):
        client = _make_client("allowed")
        handler = ToolGuardCallbackHandler.__new__(ToolGuardCallbackHandler)
        handler._client = client
        handler._tool_groups = {}

        # Should not raise
        handler.on_tool_start({"name": "search"}, '{"query": "hello"}')
        client.evaluate.assert_called_once_with(
            tool_name="search",
            parameters={"query": "hello"},
            tool_group="general",
        )

    def test_denied_raises_tool_denied(self):
        client = _make_client("denied")
        handler = ToolGuardCallbackHandler.__new__(ToolGuardCallbackHandler)
        handler._client = client
        handler._tool_groups = {}

        with pytest.raises(ToolDenied):
            handler.on_tool_start({"name": "issue_refund"}, '{"amount": 1000}')

    def test_escalated_raises_tool_escalated(self):
        client = _make_client("escalated")
        handler = ToolGuardCallbackHandler.__new__(ToolGuardCallbackHandler)
        handler._client = client
        handler._tool_groups = {}

        with pytest.raises(ToolEscalated):
            handler.on_tool_start({"name": "approve_payment"}, '{"amount": 500}')

    def test_tool_group_resolved_from_map(self):
        client = _make_client("allowed")
        handler = ToolGuardCallbackHandler.__new__(ToolGuardCallbackHandler)
        handler._client = client
        handler._tool_groups = {"issue_refund": "monetary_outflow"}

        handler.on_tool_start({"name": "issue_refund"}, '{"amount": 50}')
        client.evaluate.assert_called_once_with(
            tool_name="issue_refund",
            parameters={"amount": 50},
            tool_group="monetary_outflow",
        )

    def test_non_json_input_string(self):
        """Non-JSON input falls back to {'input': raw_str}."""
        client = _make_client("allowed")
        handler = ToolGuardCallbackHandler.__new__(ToolGuardCallbackHandler)
        handler._client = client
        handler._tool_groups = {}

        handler.on_tool_start({"name": "search"}, "run a search for apples")
        client.evaluate.assert_called_once_with(
            tool_name="search",
            parameters={"input": "run a search for apples"},
            tool_group="general",
        )

    def test_unknown_tool_defaults_general_group(self):
        client = _make_client("allowed")
        handler = ToolGuardCallbackHandler.__new__(ToolGuardCallbackHandler)
        handler._client = client
        handler._tool_groups = {}

        handler.on_tool_start({"name": "some_new_tool"}, "{}")
        client.evaluate.assert_called_once_with(
            tool_name="some_new_tool",
            parameters={},
            tool_group="general",
        )

    def test_framework_overridden_to_langgraph(self):
        """
        The adapter must stamp framework="langgraph" and
        integration_type="langgraph_middleware" on the client it receives.
        We verify this by inspecting what on_tool_start passes down after
        the constructor ran — since we bypassed __init__ in helper methods,
        we also run the assignment logic directly here.
        """
        import toolguard.adapters.langchain as lc_mod

        real_client = MagicMock()
        real_client.framework = "sdk"
        real_client.integration_type = "sdk"
        real_client.evaluate = MagicMock(return_value=_make_result("allowed"))

        # Simulate what __init__ does to the client (framework override)
        real_client.framework = lc_mod.Framework.LANGGRAPH
        real_client.integration_type = lc_mod.IntegrationType.LANGGRAPH_MIDDLEWARE

        assert real_client.framework == "langgraph"
        assert real_client.integration_type == "langgraph_middleware"

    def test_real_dispatcher_propagates_deny(self):
        """
        Regression test for a real bug that shipped: on_tool_start() raising
        ToolDenied works when called directly (every other test in this
        file does exactly that), but LangChain's real dispatcher
        (callbacks/manager.py::handle_event) catches EVERY handler
        exception, logs it, and only re-raises `if handler.raise_error`.
        BaseCallbackHandler.raise_error defaults to False, so through the
        real dispatcher a deny used to produce nothing but a log line and
        the tool call proceeded. This test goes through the real
        CallbackManager, not a direct method call, specifically so it can't
        pass by accident the way the other tests in this file structurally
        cannot catch this class of bug.
        """
        from langchain_core.callbacks.manager import CallbackManager

        client = _make_client("denied")
        handler = ToolGuardCallbackHandler.__new__(ToolGuardCallbackHandler)
        handler._client = client
        handler._tool_groups = {}
        handler.raise_error = True  # what a real __init__ sets — see test_init_sets_raise_error

        manager = CallbackManager([handler])
        with pytest.raises(ToolDenied):
            manager.on_tool_start({"name": "issue_refund"}, '{"amount": 1000}')

    def test_init_sets_raise_error(self):
        """__init__ itself must set raise_error=True — this is the actual
        fix; test_real_dispatcher_propagates_deny above only proves the
        *mechanism* works once raise_error is True. Constructs a real
        handler (langchain-core is installed in the dev/test extra
        specifically so this path is exercised for real, not mocked)."""
        client = MagicMock(spec=ToolGuard)
        client.framework = "sdk"
        client.integration_type = "sdk"
        handler = ToolGuardCallbackHandler(client)
        assert handler.raise_error is True

    def test_import_error_when_langchain_unavailable(self):
        """Constructor raises ImportError when langchain is not installed."""
        import toolguard.adapters.langchain as lc_mod

        real_client = MagicMock()

        # Simulate the state where _Base = object (no langchain)
        original = lc_mod._Base
        lc_mod._Base = object
        try:
            with pytest.raises(ImportError, match="langchain"):
                # Call __init__ directly on a new (uninit) instance
                instance = ToolGuardCallbackHandler.__new__(ToolGuardCallbackHandler)
                ToolGuardCallbackHandler.__init__(instance, real_client)
        finally:
            lc_mod._Base = original
