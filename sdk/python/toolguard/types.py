"""
toolguard.types — Python dataclasses that mirror pkg/domain JSON contracts.

Field names are EXACT copies of the Go ``json:"..."`` struct tags so that
SDK-produced envelopes round-trip through ``tg`` and ``tg-proxy`` without
any translation.

Go source references:
  pkg/domain/envelope.go  — ActionEnvelope, EnvelopeContext, *Context helpers
  pkg/domain/trace.go     — EvaluationResult, DecisionTrace, RuleResult, Citation
  pkg/domain/policy.go    — PolicyMode, Effect, Citation (shared)
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# String-constant namespaces (mirror Go consts verbatim)
# ---------------------------------------------------------------------------

class Decision:
    """pkg/domain.Decision — wire values for policy decisions."""
    ALLOWED = "allowed"
    DENIED = "denied"
    ESCALATED = "escalated"
    FLAGGED = "flagged"


class ActionTaken:
    """pkg/domain.ActionTaken — what actually happened (differs in shadow mode)."""
    ALLOWED = "allowed"
    DENIED = "denied"
    ESCALATED = "escalated"
    FLAGGED = "flagged"
    ALLOWED_SHADOW = "allowed_shadow"


class PolicyMode:
    """pkg/domain.PolicyMode."""
    SHADOW = "shadow"
    ENFORCEMENT = "enforcement"


class Framework:
    """framework field values on ActionEnvelope."""
    MCP = "mcp"
    LANGGRAPH = "langgraph"
    SDK = "sdk"
    UNKNOWN = "unknown"


class IntegrationType:
    """integration_type field values on ActionEnvelope."""
    MCP_PROXY = "mcp_proxy"
    LANGGRAPH_MIDDLEWARE = "langgraph_middleware"
    SDK = "sdk"


# ---------------------------------------------------------------------------
# EnvelopeContext nested types  (pkg/domain/envelope.go)
# ---------------------------------------------------------------------------

@dataclass
class AgentBudgetContext:
    """context.verified.agent_budget — tracks agent spending authority."""
    total_limit: float = 0.0
    used_today: float = 0.0
    remaining: float = 0.0
    transactions_today: int = 0

    def to_dict(self) -> dict:
        return {
            "total_limit": self.total_limit,
            "used_today": self.used_today,
            "remaining": self.remaining,
            "transactions_today": self.transactions_today,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AgentBudgetContext":
        return cls(
            total_limit=d.get("total_limit", 0.0),
            used_today=d.get("used_today", 0.0),
            remaining=d.get("remaining", 0.0),
            transactions_today=d.get("transactions_today", 0),
        )


@dataclass
class AgentVelocityContext:
    """context.verified.agent_velocity — tracks transaction rate and LLM-cost burn."""
    monetary_count_1h: int = 0
    monetary_sum_1h: float = 0.0
    monetary_count_24h: int = 0
    monetary_sum_24h: float = 0.0
    token_count_1h: int = 0
    token_count_24h: int = 0
    llm_cost_usd_1h: float = 0.0
    llm_cost_usd_24h: float = 0.0

    def to_dict(self) -> dict:
        return {
            "monetary_count_1h": self.monetary_count_1h,
            "monetary_sum_1h": self.monetary_sum_1h,
            "monetary_count_24h": self.monetary_count_24h,
            "monetary_sum_24h": self.monetary_sum_24h,
            "token_count_1h": self.token_count_1h,
            "token_count_24h": self.token_count_24h,
            "llm_cost_usd_1h": self.llm_cost_usd_1h,
            "llm_cost_usd_24h": self.llm_cost_usd_24h,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AgentVelocityContext":
        return cls(
            monetary_count_1h=d.get("monetary_count_1h", 0),
            monetary_sum_1h=d.get("monetary_sum_1h", 0.0),
            monetary_count_24h=d.get("monetary_count_24h", 0),
            monetary_sum_24h=d.get("monetary_sum_24h", 0.0),
            token_count_1h=d.get("token_count_1h", 0),
            token_count_24h=d.get("token_count_24h", 0),
            llm_cost_usd_1h=d.get("llm_cost_usd_1h", 0.0),
            llm_cost_usd_24h=d.get("llm_cost_usd_24h", 0.0),
        )


@dataclass
class JustificationContext:
    """context.verified.justification — verified business reason."""
    reason_code: str = ""
    verified: bool = False
    verification_source: str = ""
    verification_details: str = ""

    def to_dict(self) -> dict:
        d: dict = {"reason_code": self.reason_code, "verified": self.verified}
        if self.verification_source:
            d["verification_source"] = self.verification_source
        if self.verification_details:
            d["verification_details"] = self.verification_details
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "JustificationContext":
        return cls(
            reason_code=d.get("reason_code", ""),
            verified=d.get("verified", False),
            verification_source=d.get("verification_source", ""),
            verification_details=d.get("verification_details", ""),
        )


@dataclass
class VerifiedContext:
    """
    context.verified — system-enriched fields from the database.

    All fields are optional (omitempty in Go); only non-zero values are
    serialised to keep the envelope wire size small.
    """
    customer_tier: str = ""
    customer_account_age_days: int = 0
    customer_lifetime_value: float = 0.0
    customer_order_count: int = 0
    order_total: float = 0.0
    order_age_days: int = 0
    order_currency: str = ""
    customer_id: str = ""
    order_id: str = ""
    order_item_count: int = 0
    product_category: str = ""
    product_category_avg_price: float = 0.0
    return_request_reason: str = ""
    return_request_status: str = ""
    economic_value_impact: float = 0.0
    rolling_24h_total: float = 0.0
    rolling_24h_count: int = 0
    rolling_7d_total: float = 0.0
    rolling_7d_count: int = 0
    agent_budget: Optional[AgentBudgetContext] = None
    agent_velocity: Optional[AgentVelocityContext] = None
    justification: Optional[JustificationContext] = None
    content_risk: str = ""
    content_categories: List[str] = field(default_factory=list)
    content_classifier_tier: str = ""
    counter_agent_risk: str = ""
    counter_agent_categories: List[str] = field(default_factory=list)
    counter_agent_reasoning: str = ""

    def to_dict(self) -> dict:
        d: dict = {}
        if self.customer_tier:
            d["customer_tier"] = self.customer_tier
        if self.customer_account_age_days:
            d["customer_account_age_days"] = self.customer_account_age_days
        if self.customer_lifetime_value:
            d["customer_lifetime_value"] = self.customer_lifetime_value
        if self.customer_order_count:
            d["customer_order_count"] = self.customer_order_count
        if self.order_total:
            d["order_total"] = self.order_total
        if self.order_age_days:
            d["order_age_days"] = self.order_age_days
        if self.order_currency:
            d["order_currency"] = self.order_currency
        if self.customer_id:
            d["customer_id"] = self.customer_id
        if self.order_id:
            d["order_id"] = self.order_id
        if self.order_item_count:
            d["order_item_count"] = self.order_item_count
        if self.product_category:
            d["product_category"] = self.product_category
        if self.product_category_avg_price:
            d["product_category_avg_price"] = self.product_category_avg_price
        if self.return_request_reason:
            d["return_request_reason"] = self.return_request_reason
        if self.return_request_status:
            d["return_request_status"] = self.return_request_status
        if self.economic_value_impact:
            d["economic_value_impact"] = self.economic_value_impact
        if self.rolling_24h_total:
            d["rolling_24h_total"] = self.rolling_24h_total
        if self.rolling_24h_count:
            d["rolling_24h_count"] = self.rolling_24h_count
        if self.rolling_7d_total:
            d["rolling_7d_total"] = self.rolling_7d_total
        if self.rolling_7d_count:
            d["rolling_7d_count"] = self.rolling_7d_count
        if self.agent_budget is not None:
            d["agent_budget"] = self.agent_budget.to_dict()
        if self.agent_velocity is not None:
            d["agent_velocity"] = self.agent_velocity.to_dict()
        if self.justification is not None:
            d["justification"] = self.justification.to_dict()
        if self.content_risk:
            d["content_risk"] = self.content_risk
        if self.content_categories:
            d["content_categories"] = self.content_categories
        if self.content_classifier_tier:
            d["content_classifier_tier"] = self.content_classifier_tier
        if self.counter_agent_risk:
            d["counter_agent_risk"] = self.counter_agent_risk
        if self.counter_agent_categories:
            d["counter_agent_categories"] = self.counter_agent_categories
        if self.counter_agent_reasoning:
            d["counter_agent_reasoning"] = self.counter_agent_reasoning
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "VerifiedContext":
        ab = d.get("agent_budget")
        av = d.get("agent_velocity")
        jc = d.get("justification")
        return cls(
            customer_tier=d.get("customer_tier", ""),
            customer_account_age_days=d.get("customer_account_age_days", 0),
            customer_lifetime_value=d.get("customer_lifetime_value", 0.0),
            customer_order_count=d.get("customer_order_count", 0),
            order_total=d.get("order_total", 0.0),
            order_age_days=d.get("order_age_days", 0),
            order_currency=d.get("order_currency", ""),
            customer_id=d.get("customer_id", ""),
            order_id=d.get("order_id", ""),
            order_item_count=d.get("order_item_count", 0),
            product_category=d.get("product_category", ""),
            product_category_avg_price=d.get("product_category_avg_price", 0.0),
            return_request_reason=d.get("return_request_reason", ""),
            return_request_status=d.get("return_request_status", ""),
            economic_value_impact=d.get("economic_value_impact", 0.0),
            rolling_24h_total=d.get("rolling_24h_total", 0.0),
            rolling_24h_count=d.get("rolling_24h_count", 0),
            rolling_7d_total=d.get("rolling_7d_total", 0.0),
            rolling_7d_count=d.get("rolling_7d_count", 0),
            agent_budget=AgentBudgetContext.from_dict(ab) if ab else None,
            agent_velocity=AgentVelocityContext.from_dict(av) if av else None,
            justification=JustificationContext.from_dict(jc) if jc else None,
            content_risk=d.get("content_risk", ""),
            content_categories=d.get("content_categories", []),
            content_classifier_tier=d.get("content_classifier_tier", ""),
            counter_agent_risk=d.get("counter_agent_risk", ""),
            counter_agent_categories=d.get("counter_agent_categories", []),
            counter_agent_reasoning=d.get("counter_agent_reasoning", ""),
        )


@dataclass
class SessionStateContext:
    """context.session_state — maintained by the proxy across turns."""
    cumulative_amount: float = 0.0
    actions_in_session: int = 0
    escalations_in_session: int = 0
    denied_in_session: int = 0
    tool_sequence: List[str] = field(default_factory=list)
    amount_trajectory: List[float] = field(default_factory=list)

    def to_dict(self) -> dict:
        d: dict = {
            "cumulative_amount": self.cumulative_amount,
            "actions_in_session": self.actions_in_session,
            "escalations_in_session": self.escalations_in_session,
            "denied_in_session": self.denied_in_session,
        }
        if self.tool_sequence:
            d["tool_sequence"] = self.tool_sequence
        if self.amount_trajectory:
            d["amount_trajectory"] = self.amount_trajectory
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "SessionStateContext":
        return cls(
            cumulative_amount=d.get("cumulative_amount", 0.0),
            actions_in_session=d.get("actions_in_session", 0),
            escalations_in_session=d.get("escalations_in_session", 0),
            denied_in_session=d.get("denied_in_session", 0),
            tool_sequence=d.get("tool_sequence", []),
            amount_trajectory=d.get("amount_trajectory", []),
        )


@dataclass
class EnvelopeContext:
    """
    context — organizes all context fields by trust level.

    json tag: "context"
    """
    verified: VerifiedContext = field(default_factory=VerifiedContext)
    session_state: SessionStateContext = field(default_factory=SessionStateContext)
    agent_supplied: Optional[Any] = None  # raw JSON-serializable (omitempty)

    def to_dict(self) -> dict:
        d: dict = {
            "verified": self.verified.to_dict(),
            "session_state": self.session_state.to_dict(),
        }
        if self.agent_supplied is not None:
            d["agent_supplied"] = self.agent_supplied
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "EnvelopeContext":
        return cls(
            verified=VerifiedContext.from_dict(d.get("verified", {})),
            session_state=SessionStateContext.from_dict(d.get("session_state", {})),
            agent_supplied=d.get("agent_supplied"),
        )


# ---------------------------------------------------------------------------
# ActionEnvelope (pkg/domain/envelope.go)
# ---------------------------------------------------------------------------

@dataclass
class ActionEnvelope:
    """
    Mirrors pkg/domain.ActionEnvelope (spec: 01_Action_Envelope_v0).

    JSON field names are verbatim copies of the Go ``json:"..."`` struct tags.
    The envelope is the wire format sent to ``tg evaluate`` (via a temp file)
    or to ``tg-proxy POST /evaluate``.
    """
    # Identity
    envelope_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    agent_id: str = ""
    session_id: str = ""
    org_id: str = ""

    # Agent metadata (omitempty in Go)
    agent_version: str = ""
    framework: str = Framework.SDK        # "mcp" | "langgraph" | "sdk" | "unknown"
    turn_number: int = 0
    department: str = ""

    # Action
    tool_name: str = ""
    tool_server: str = ""                 # MCP server ID or endpoint (omitempty)
    tool_group: str = ""
    parameters: Optional[Any] = None     # raw JSON value (omitempty)
    parameters_redacted: Optional[Any] = None  # (omitempty)

    # Context
    context: EnvelopeContext = field(default_factory=EnvelopeContext)

    # Source metadata (omitempty in Go)
    integration_type: str = IntegrationType.SDK  # "mcp_proxy"|"langgraph_middleware"|"sdk"
    proxy_version: str = ""
    tls_verified: bool = False

    def to_dict(self) -> dict:
        """Serialize to a dict matching the Go JSON wire format exactly."""
        d: dict = {
            "envelope_id": self.envelope_id,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "org_id": self.org_id,
            "tool_name": self.tool_name,
            "tool_group": self.tool_group,
            "context": self.context.to_dict(),
        }
        # omitempty fields — only include when non-zero/non-empty
        if self.agent_version:
            d["agent_version"] = self.agent_version
        if self.framework:
            d["framework"] = self.framework
        if self.turn_number:
            d["turn_number"] = self.turn_number
        if self.department:
            d["department"] = self.department
        if self.tool_server:
            d["tool_server"] = self.tool_server
        if self.parameters is not None:
            d["parameters"] = self.parameters
        if self.parameters_redacted is not None:
            d["parameters_redacted"] = self.parameters_redacted
        if self.integration_type:
            d["integration_type"] = self.integration_type
        if self.proxy_version:
            d["proxy_version"] = self.proxy_version
        if self.tls_verified:
            d["tls_verified"] = self.tls_verified
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ActionEnvelope":
        return cls(
            envelope_id=d.get("envelope_id", str(uuid.uuid4())),
            timestamp=d.get("timestamp", datetime.now(timezone.utc).isoformat()),
            agent_id=d.get("agent_id", ""),
            session_id=d.get("session_id", ""),
            org_id=d.get("org_id", ""),
            agent_version=d.get("agent_version", ""),
            framework=d.get("framework", Framework.SDK),
            turn_number=d.get("turn_number", 0),
            department=d.get("department", ""),
            tool_name=d.get("tool_name", ""),
            tool_server=d.get("tool_server", ""),
            tool_group=d.get("tool_group", ""),
            parameters=d.get("parameters"),
            parameters_redacted=d.get("parameters_redacted"),
            context=EnvelopeContext.from_dict(d.get("context", {})),
            integration_type=d.get("integration_type", IntegrationType.SDK),
            proxy_version=d.get("proxy_version", ""),
            tls_verified=d.get("tls_verified", False),
        )


# ---------------------------------------------------------------------------
# EvaluationResult and supporting types  (pkg/domain/trace.go:165)
# ---------------------------------------------------------------------------

@dataclass
class Citation:
    """
    Mirrors pkg/domain.Citation — links a rule to a source document.

    json field names: document_id, document_title, section, page, line, excerpt
    """
    document_id: str = ""
    document_title: str = ""
    section: str = ""
    page: int = 0
    line: int = 0
    excerpt: str = ""

    def to_dict(self) -> dict:
        d: dict = {"document_id": self.document_id, "excerpt": self.excerpt}
        if self.document_title:
            d["document_title"] = self.document_title
        if self.section:
            d["section"] = self.section
        if self.page:
            d["page"] = self.page
        if self.line:
            d["line"] = self.line
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Citation":
        return cls(
            document_id=d.get("document_id", ""),
            document_title=d.get("document_title", ""),
            section=d.get("section", ""),
            page=d.get("page", 0),
            line=d.get("line", 0),
            excerpt=d.get("excerpt", ""),
        )


@dataclass
class RuleResult:
    """
    Mirrors pkg/domain.RuleResult — outcome of evaluating one rule.

    json field names: rule_id, rule_name, policy_id, policy_version,
                      matched, effect, severity, citation, details
    """
    rule_id: str = ""
    rule_name: str = ""
    policy_id: str = ""
    policy_version: int = 0
    matched: bool = False
    effect: str = ""
    severity: str = ""
    citation: Citation = field(default_factory=Citation)
    details: str = ""

    def to_dict(self) -> dict:
        d: dict = {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "policy_id": self.policy_id,
            "matched": self.matched,
            "effect": self.effect,
            "citation": self.citation.to_dict(),
        }
        if self.policy_version:
            d["policy_version"] = self.policy_version
        if self.severity:
            d["severity"] = self.severity
        if self.details:
            d["details"] = self.details
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "RuleResult":
        return cls(
            rule_id=d.get("rule_id", ""),
            rule_name=d.get("rule_name", ""),
            policy_id=d.get("policy_id", ""),
            policy_version=d.get("policy_version", 0),
            matched=d.get("matched", False),
            effect=d.get("effect", ""),
            severity=d.get("severity", ""),
            citation=Citation.from_dict(d.get("citation", {})),
            details=d.get("details", ""),
        )


@dataclass
class EvaluationResult:
    """
    Mirrors pkg/domain.EvaluationResult (trace.go:165).

    This is what ``tg evaluate`` prints to stdout (JSON) and what
    ``tg-proxy POST /evaluate`` returns in the response body.

    json field names: decision, action_taken, decision_reason, effective_mode,
                      policies_matched, rules_evaluated, rules_triggered,
                      rule_results, applied_rule_results, primary_citation,
                      applied_primary_citation, is_near_miss, suggested_response
    """
    decision: str = Decision.ALLOWED          # "allowed"|"denied"|"escalated"|"flagged"
    action_taken: str = ActionTaken.ALLOWED   # "allowed"|"denied"|"escalated"|"flagged"|"allowed_shadow"
    decision_reason: str = ""
    effective_mode: str = PolicyMode.ENFORCEMENT
    policies_matched: int = 0
    rules_evaluated: int = 0
    rules_triggered: int = 0
    rule_results: List[RuleResult] = field(default_factory=list)
    applied_rule_results: List[RuleResult] = field(default_factory=list)
    primary_citation: Optional[Citation] = None
    applied_primary_citation: Optional[Citation] = None
    is_near_miss: bool = False
    suggested_response: str = ""

    def to_dict(self) -> dict:
        d: dict = {
            "decision": self.decision,
            "action_taken": self.action_taken,
            "effective_mode": self.effective_mode,
            "policies_matched": self.policies_matched,
            "rules_evaluated": self.rules_evaluated,
            "rules_triggered": self.rules_triggered,
            "rule_results": [r.to_dict() for r in self.rule_results],
            "applied_rule_results": [r.to_dict() for r in self.applied_rule_results],
            "is_near_miss": self.is_near_miss,
        }
        if self.decision_reason:
            d["decision_reason"] = self.decision_reason
        if self.primary_citation is not None:
            d["primary_citation"] = self.primary_citation.to_dict()
        if self.applied_primary_citation is not None:
            d["applied_primary_citation"] = self.applied_primary_citation.to_dict()
        if self.suggested_response:
            d["suggested_response"] = self.suggested_response
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "EvaluationResult":
        # "decision" and "action_taken" are always present on a real
        # response — the engine never omits them. Silently defaulting a
        # missing field to ALLOWED (the old behavior) meant a malformed or
        # unexpected response body — wrong shape, truncated body, a future
        # API change this SDK version doesn't know about — parsed as a
        # real "allowed" decision instead of surfacing the problem. Raise
        # instead: the caller (evaluate_raw/evaluate) has no principled
        # decision to fall back to here either.
        missing = [k for k in ("decision", "action_taken") if k not in d]
        if missing:
            raise ValueError(
                f"malformed EvaluationResult: missing {missing} "
                f"in response body: {d!r}"
            )
        pc = d.get("primary_citation")
        applied_pc = d.get("applied_primary_citation")
        return cls(
            decision=d["decision"],
            action_taken=d["action_taken"],
            decision_reason=d.get("decision_reason", ""),
            effective_mode=d.get("effective_mode", PolicyMode.ENFORCEMENT),
            policies_matched=d.get("policies_matched", 0),
            rules_evaluated=d.get("rules_evaluated", 0),
            rules_triggered=d.get("rules_triggered", 0),
            rule_results=[RuleResult.from_dict(r) for r in d.get("rule_results", [])],
            applied_rule_results=[
                RuleResult.from_dict(r) for r in d.get("applied_rule_results", [])
            ],
            primary_citation=Citation.from_dict(pc) if pc else None,
            applied_primary_citation=(
                Citation.from_dict(applied_pc) if applied_pc else None
            ),
            is_near_miss=d.get("is_near_miss", False),
            suggested_response=d.get("suggested_response", ""),
        )
