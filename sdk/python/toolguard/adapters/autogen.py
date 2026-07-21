"""
toolguard.adapters.autogen — AutoGen / generic function-calling guard.

Provides a ``guarded`` decorator that wraps any callable (an AutoGen tool
function) and evaluates it with the Tool Guard policy engine before running
the real function.  If denied or escalated, the wrapper returns an error
dict (never raises) so AutoGen's conversation loop can surface the refusal
to the LLM.

framework / integration_type stamped on every envelope:
  framework        = "sdk"
  integration_type = "sdk"

Install (not yet on PyPI — from a clone of this repo):
    pip install "./tool-guard-core/sdk/python[autogen]"    # also installs pyautogen
"""
from __future__ import annotations

import functools
from typing import Any, Callable, Dict, Optional

from toolguard.client import ToolGuard
from toolguard.errors import ToolDenied, ToolEscalated


def guarded(
    client: ToolGuard,
    tool_name: str,
    tool_group: str = "",
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator factory that evaluates a function-calling tool before it runs.

    Usage::

        from toolguard import ToolGuard
        from toolguard.adapters.autogen import guarded

        guard = ToolGuard(mode="proxy", proxy_url="http://localhost:9090",
                          agent_id="autogen-agent", org_id="acme")

        @guarded(guard, tool_name="issue_refund", tool_group="monetary_outflow")
        def issue_refund(order_id: str, amount: float) -> dict:
            ...  # real implementation

        # Register with AutoGen:
        assistant.register_for_execution(name="issue_refund")(issue_refund)

    Parameters
    ----------
    client : ToolGuard
        Pre-configured :class:`~toolguard.client.ToolGuard` instance.
    tool_name : str
        Tool name stamped on the envelope (should match the function name
        as seen by the LLM).
    tool_group : str
        Tool group stamped on the envelope.

    Returns
    -------
    Callable
        A decorator; apply it to the tool function.
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Collect kwargs as parameters (what AutoGen passes)
            parameters: Dict[str, Any] = dict(kwargs)
            if args:
                # positional args are unusual in AutoGen but handle gracefully
                parameters["_args"] = list(args)

            try:
                client.evaluate(
                    tool_name=tool_name,
                    parameters=parameters,
                    tool_group=tool_group,
                )
            except ToolDenied as exc:
                return {
                    "error": "denied",
                    "reason": str(exc),
                    "suggested_response": getattr(
                        exc.result, "suggested_response", ""
                    ) if exc.result else "",
                }
            except ToolEscalated as exc:
                return {
                    "error": "escalated",
                    "reason": str(exc),
                    "suggested_response": getattr(
                        exc.result, "suggested_response", ""
                    ) if exc.result else "",
                }
            return func(*args, **kwargs)

        return wrapper

    return decorator


def register_guarded(
    client: ToolGuard,
    tool_name: str,
    tool_group: str = "",
    func: Optional[Callable[..., Any]] = None,
) -> Callable[..., Any]:
    """
    Helper for AutoGen's ``register_for_execution`` pattern.

    Usage::

        assistant.register_for_execution(name="issue_refund")(
            register_guarded(guard, "issue_refund", "monetary_outflow", real_refund)
        )
    """
    if func is None:
        raise ValueError("func is required")
    return guarded(client, tool_name, tool_group)(func)
