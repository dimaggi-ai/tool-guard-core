"""
toolguard.errors — exceptions raised by the SDK on denied / escalated decisions.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from toolguard.types import EvaluationResult


class ToolGuardError(Exception):
    """Base class for all Tool Guard SDK errors."""

    def __init__(self, message: str, result: "EvaluationResult | None" = None) -> None:
        super().__init__(message)
        self.result = result


class ToolDenied(ToolGuardError):
    """
    Raised by :meth:`ToolGuard.evaluate` when the policy engine returns
    ``decision = "denied"``.

    The ``result`` attribute carries the full :class:`~toolguard.types.EvaluationResult`
    including ``decision_reason``, ``primary_citation``, and ``suggested_response``.
    """


class ToolEscalated(ToolGuardError):
    """
    Raised by :meth:`ToolGuard.evaluate` when the policy engine returns
    ``decision = "escalated"``.

    The tool call must not proceed until a human approves the escalation.
    """
