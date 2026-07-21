"""
toolguard.adapters.mcp — Thin guard wrapper for MCP tool handlers.

Wraps any ``CallTool``-style function with a pre-execution policy check.
This is the Python-side complement to the Go MCP example in
``docs/integration.md`` section 3.1.

framework / integration_type stamped on every envelope:
  framework        = "mcp"
  integration_type = "mcp_proxy"

Usage::

    from toolguard import ToolGuard
    from toolguard.adapters.mcp import guard_mcp_tool

    client = ToolGuard(mode="proxy", proxy_url="http://localhost:9090",
                       agent_id="my-mcp-server", org_id="acme")

    @guard_mcp_tool(client, tool_group="data_access")
    def call_tool(tool_name: str, parameters: dict, **kwargs) -> dict:
        return TOOLS[tool_name](**parameters)
"""
from __future__ import annotations

import functools
from typing import Any, Callable, Dict, Optional

from toolguard.client import ToolGuard
from toolguard.errors import ToolDenied, ToolEscalated
from toolguard.types import Framework, IntegrationType


def guard_mcp_tool(
    client: ToolGuard,
    tool_group: str = "mcp",
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator factory that wraps an MCP ``call_tool`` handler with a
    pre-execution Tool Guard policy check.

    The decorated function signature should be::

        def call_tool(tool_name: str, parameters: dict, **kwargs) -> Any: ...

    Parameters
    ----------
    client : ToolGuard
        Pre-configured client.  ``framework`` and ``integration_type`` are
        overridden to ``"mcp"`` / ``"mcp_proxy"`` automatically.
    tool_group : str
        Tool group to stamp on every envelope.  Defaults to ``"mcp"``.
    """
    # Override framework stamps for MCP
    client.framework = Framework.MCP
    client.integration_type = IntegrationType.MCP_PROXY

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(
            tool_name: str,
            parameters: Optional[Dict[str, Any]] = None,
            **kwargs: Any,
        ) -> Any:
            params = parameters or {}
            # evaluate() raises on deny/escalate
            client.evaluate(
                tool_name=tool_name,
                parameters=params,
                tool_group=tool_group,
            )
            return func(tool_name, params, **kwargs)

        return wrapper

    return decorator
