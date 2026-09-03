"""
toolguard.adapters.langchain — LangChain / LangGraph callback handler.

Intercepts ``on_tool_start`` before LangChain executes a tool. If the
policy engine denies or escalates the call, the handler raises
:exc:`~toolguard.errors.ToolDenied` / :exc:`~toolguard.errors.ToolEscalated`,
which stops the chain immediately.

framework / integration_type stamped on every envelope:
  framework        = "langgraph"
  integration_type = "langgraph_middleware"

Install (not yet on PyPI — from a clone of this repo):
    pip install "./tool-guard-core/sdk/python[langchain]"
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional

from toolguard.client import ToolGuard
from toolguard.errors import ToolDenied, ToolEscalated
from toolguard.types import Framework, IntegrationType

# ---------------------------------------------------------------------------
# Lazy import of BaseCallbackHandler — LangChain is an optional dependency.
# The class falls back to ``object`` so the module can be imported without
# langchain installed; a clear ImportError is raised only when the handler
# is actually instantiated (and therefore used).
# ---------------------------------------------------------------------------
try:
    from langchain_core.callbacks.base import BaseCallbackHandler as _Base
except ImportError:
    try:
        from langchain.callbacks.base import BaseCallbackHandler as _Base  # type: ignore
    except ImportError:
        _Base = object  # type: ignore


class ToolGuardCallbackHandler(_Base):  # type: ignore[misc]
    """
    LangChain ``BaseCallbackHandler`` that evaluates every tool call with
    the Tool Guard policy engine before LangChain executes it.

    Drop-in usage::

        from toolguard import ToolGuard
        from toolguard.adapters.langchain import ToolGuardCallbackHandler

        client = ToolGuard(mode="proxy", proxy_url="http://localhost:9090",
                           agent_id="lc-agent", org_id="acme")
        handler = ToolGuardCallbackHandler(client)

        chain = MyChain(..., callbacks=[handler])

    Parameters
    ----------
    client : ToolGuard
        Pre-configured :class:`~toolguard.client.ToolGuard` instance.
        ``framework`` and ``integration_type`` are overridden automatically
        to ``"langgraph"`` / ``"langgraph_middleware"``.
    tool_groups : dict, optional
        Mapping of ``tool_name → tool_group`` so the envelope carries the
        correct ``tool_group``.  Unknown tools default to ``"general"``.
    """

    def __init__(
        self,
        client: ToolGuard,
        tool_groups: Optional[Dict[str, str]] = None,
    ) -> None:
        if _Base is object:
            raise ImportError(
                "langchain-core (or langchain) is required: "
                'pip install "./tool-guard-core/sdk/python[langchain]" '
                "(not yet on PyPI — install from a clone of this repo)"
            )
        super().__init__()
        # BaseCallbackHandler.raise_error defaults to False — LangChain's
        # dispatcher (callbacks/manager.py::handle_event) catches EVERY
        # exception a handler raises, logs it as a warning, and only
        # re-raises `if handler.raise_error`. Without this, on_tool_start
        # raising ToolDenied/ToolEscalated below produces nothing but a log
        # line and the tool executes anyway — the handler's entire purpose
        # silently doesn't happen. Verified against the installed
        # langchain-core wheel, not assumed from the docs.
        self.raise_error = True
        client.framework = Framework.LANGGRAPH
        client.integration_type = IntegrationType.LANGGRAPH_MIDDLEWARE
        self._client = client
        self._tool_groups = tool_groups or {}

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """
        Called by LangChain before a tool runs.

        Parses the tool input string into a dict and evaluates it.
        Raises :exc:`~toolguard.errors.ToolDenied` or
        :exc:`~toolguard.errors.ToolEscalated` to abort execution.
        """
        tool_name = serialized.get("name", "unknown")
        tool_group = self._tool_groups.get(tool_name, "general")

        # Parse input: LangChain passes either a JSON string or a raw str.
        try:
            parameters = json.loads(input_str)
            if not isinstance(parameters, dict):
                parameters = {"input": input_str}
        except (json.JSONDecodeError, TypeError):
            parameters = {"input": str(input_str)}

        # evaluate() raises ToolDenied / ToolEscalated automatically.
        self._client.evaluate(
            tool_name=tool_name,
            parameters=parameters,
            tool_group=tool_group,
        )
