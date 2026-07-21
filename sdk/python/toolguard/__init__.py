"""
toolguard — Python SDK for Tool Guard Core.

Universal AI agent governance: evaluate any tool call against configurable
policies before it executes.  Drop-in adapters for LangChain, AutoGen,
native OpenAI/Anthropic tool use, and MCP.

Quick start::

    from toolguard import ToolGuard, ToolDenied

    guard = ToolGuard(
        mode="proxy",
        proxy_url="http://localhost:9090",
        agent_id="my-agent",
        org_id="acme",
    )

    try:
        result = guard.evaluate("issue_refund", {"amount": 1000})
    except ToolDenied as exc:
        print("Blocked:", exc)
"""
from toolguard.client import ToolGuard
from toolguard.errors import ToolDenied, ToolEscalated, ToolGuardError
from toolguard.types import (
    ActionEnvelope,
    ActionTaken,
    AgentBudgetContext,
    AgentVelocityContext,
    Citation,
    Decision,
    EnvelopeContext,
    EvaluationResult,
    Framework,
    IntegrationType,
    JustificationContext,
    PolicyMode,
    RuleResult,
    SessionStateContext,
    VerifiedContext,
)

__version__ = "1.0.0"

__all__ = [
    # Client
    "ToolGuard",
    # Errors
    "ToolGuardError",
    "ToolDenied",
    "ToolEscalated",
    # Core types
    "ActionEnvelope",
    "EvaluationResult",
    "Decision",
    "ActionTaken",
    "PolicyMode",
    "Framework",
    "IntegrationType",
    "EnvelopeContext",
    "VerifiedContext",
    "SessionStateContext",
    "AgentBudgetContext",
    "AgentVelocityContext",
    "JustificationContext",
    "Citation",
    "RuleResult",
]
