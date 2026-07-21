"""
toolguard.adapters.native — Native OpenAI and Anthropic tool-use loop guard.

When you receive tool_call / tool_use blocks from the model, do NOT execute
them directly.  Call ``guard_tool_calls`` first.  It returns two lists:

  - ``allowed``  — safe to execute; feed results back to the model.
  - ``denied``   — must NOT execute; return a ``tool_result`` with
                   ``is_error=True`` and the ``suggested_response`` so the
                   model adapts.

Supports both provider shapes automatically:

OpenAI ``tool_calls`` item::

    {
      "id": "call_abc",
      "type": "function",
      "function": {
        "name": "issue_refund",
        "arguments": "{\"amount\": 1000}"   # JSON string
      }
    }

Anthropic ``content`` item (type == "tool_use")::

    {
      "type": "tool_use",
      "id": "toolu_01",
      "name": "issue_refund",
      "input": {"amount": 1000}             # already parsed dict
    }

framework / integration_type stamped on every envelope:
  framework        = "sdk"
  integration_type = "sdk"

Install (not yet on PyPI — from a clone of this repo):
    pip install "./tool-guard-core/sdk/python[openai]"       # for OpenAI shapes
    pip install "./tool-guard-core/sdk/python[anthropic]"    # for Anthropic shapes
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from toolguard.client import ToolGuard
from toolguard.errors import ToolDenied, ToolEscalated
from toolguard.types import ActionTaken, EvaluationResult


def guard_tool_calls(
    tool_calls: List[Any],
    client: ToolGuard,
    provider: str = "openai",
    tool_groups: Optional[Dict[str, str]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Evaluate a list of tool calls from a native LLM response.

    Returns ``(allowed, denied)`` where:

    - ``allowed``  — dicts with keys ``call`` (original), ``result``
      (:class:`~toolguard.types.EvaluationResult`).
    - ``denied``   — dicts with keys ``call``, ``result``,
      ``tool_result`` (ready to return to the model as an error).

    Parameters
    ----------
    tool_calls : list
        List of tool call objects from the LLM response.
    client : ToolGuard
        Pre-configured :class:`~toolguard.client.ToolGuard` instance.
    provider : "openai" | "anthropic"
        Shape of the tool call objects.
    tool_groups : dict, optional
        Mapping of ``tool_name → tool_group``.
    """
    if provider not in ("openai", "anthropic"):
        raise ValueError(f"provider must be 'openai' or 'anthropic', got {provider!r}")

    tool_groups = tool_groups or {}
    allowed: List[Dict[str, Any]] = []
    denied: List[Dict[str, Any]] = []

    for call in tool_calls:
        tool_name, parameters, call_id = _extract_call(call, provider)
        tool_group = tool_groups.get(tool_name, "")

        result = client.evaluate_raw(
            tool_name=tool_name,
            parameters=parameters,
            tool_group=tool_group,
        )

        # Branch on action_taken, not decision — same reasoning as
        # ToolGuard.evaluate() (see client.py): in shadow mode the engine
        # keeps decision="denied"/"escalated" (what WOULD have happened)
        # but action_taken="allowed_shadow" (what actually happened).
        # Branching on `decision` would block tool execution in a
        # shadow-mode deployment, which shadow mode exists specifically to
        # never do.
        #
        # Any action_taken value NOT in this known-safe set — including a
        # future engine value this SDK version doesn't recognize yet —
        # fails closed (treated as denied) rather than falling through to
        # allowed by default.
        if result.action_taken in (
            ActionTaken.ALLOWED,
            ActionTaken.ALLOWED_SHADOW,
            ActionTaken.FLAGGED,
        ):
            allowed.append({"call": call, "result": result})
        else:
            tool_result = _build_error_result(call_id, result, provider)
            denied.append({"call": call, "result": result, "tool_result": tool_result})

    return allowed, denied


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _extract_call(
    call: Any, provider: str
) -> Tuple[str, Dict[str, Any], str]:
    """
    Extract (tool_name, parameters, call_id) from a provider-shaped object.
    """
    if provider == "openai":
        # dict-like or object with .function.name / .function.arguments
        if isinstance(call, dict):
            fn = call.get("function", {})
            tool_name = fn.get("name", "")
            args_str = fn.get("arguments", "{}")
            call_id = call.get("id", "")
        else:
            # openai SDK objects (ChatCompletionMessageToolCall)
            fn = getattr(call, "function", None)
            tool_name = getattr(fn, "name", "") if fn else ""
            args_str = getattr(fn, "arguments", "{}") if fn else "{}"
            call_id = getattr(call, "id", "")

        try:
            parameters = json.loads(args_str) if isinstance(args_str, str) else args_str
            if not isinstance(parameters, dict):
                parameters = {"_raw": parameters}
        except (json.JSONDecodeError, TypeError):
            parameters = {"_raw": args_str}

    else:  # anthropic
        if isinstance(call, dict):
            tool_name = call.get("name", "")
            parameters = call.get("input", {})
            call_id = call.get("id", "")
        else:
            # anthropic SDK ToolUseBlock
            tool_name = getattr(call, "name", "")
            parameters = getattr(call, "input", {}) or {}
            call_id = getattr(call, "id", "")

        if not isinstance(parameters, dict):
            parameters = {"_raw": parameters}

    return tool_name, parameters, call_id


def _build_error_result(
    call_id: str,
    result: EvaluationResult,
    provider: str,
) -> Dict[str, Any]:
    """
    Build the error ``tool_result`` dict to return to the model so it adapts
    without the caller having to execute the denied tool.
    """
    message = result.suggested_response or result.decision_reason or result.decision

    if provider == "openai":
        return {
            "tool_call_id": call_id,
            "role": "tool",
            "content": message,
            # The OpenAI API does not have a native is_error flag on tool
            # results; the content string surfacing the reason is sufficient.
        }
    else:  # anthropic
        return {
            "type": "tool_result",
            "tool_use_id": call_id,
            "is_error": True,
            "content": message,
        }
