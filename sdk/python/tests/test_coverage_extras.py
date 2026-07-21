"""
test_coverage_extras.py — Additional tests targeting uncovered paths
to push coverage above 90%.

Covers:
- types.py: AgentBudget/Velocity/Justification from_dict, VerifiedContext
  with all optional fields set, EnvelopeContext agent_supplied, ActionEnvelope
  all paths.
- client.py: fallback result when stdout is empty/bad, policy_file missing,
  proxy ImportError path.
- adapters/native.py: SDK object (non-dict) paths.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from toolguard.adapters.native import _extract_call, _build_error_result, guard_tool_calls
from toolguard.client import ToolGuard
from toolguard.errors import ToolDenied, ToolEscalated
from toolguard.types import (
    ActionEnvelope,
    AgentBudgetContext,
    AgentVelocityContext,
    Citation,
    Decision,
    EnvelopeContext,
    EvaluationResult,
    JustificationContext,
    RuleResult,
    SessionStateContext,
    VerifiedContext,
)


# ---------------------------------------------------------------------------
# AgentBudgetContext round-trip
# ---------------------------------------------------------------------------

class TestAgentBudgetRoundTrip:
    def test_from_dict_full(self):
        d = {"total_limit": 1000.0, "used_today": 300.0, "remaining": 700.0, "transactions_today": 5}
        ab = AgentBudgetContext.from_dict(d)
        assert ab.total_limit == 1000.0
        assert ab.used_today == 300.0
        assert ab.remaining == 700.0
        assert ab.transactions_today == 5

    def test_from_dict_empty(self):
        ab = AgentBudgetContext.from_dict({})
        assert ab.total_limit == 0.0
        assert ab.transactions_today == 0


# ---------------------------------------------------------------------------
# AgentVelocityContext round-trip
# ---------------------------------------------------------------------------

class TestAgentVelocityRoundTrip:
    def test_from_dict_full(self):
        d = {
            "monetary_count_1h": 10,
            "monetary_sum_1h": 5000.0,
            "monetary_count_24h": 50,
            "monetary_sum_24h": 25000.0,
            "token_count_1h": 1000,
            "token_count_24h": 8000,
            "llm_cost_usd_1h": 0.5,
            "llm_cost_usd_24h": 4.0,
        }
        av = AgentVelocityContext.from_dict(d)
        assert av.monetary_count_1h == 10
        assert av.monetary_sum_1h == 5000.0
        assert av.llm_cost_usd_24h == 4.0

    def test_to_dict_round_trip(self):
        av = AgentVelocityContext(
            monetary_count_1h=3, monetary_sum_1h=1500.0, llm_cost_usd_1h=0.15
        )
        restored = AgentVelocityContext.from_dict(av.to_dict())
        assert restored.monetary_count_1h == 3
        assert restored.monetary_sum_1h == 1500.0
        assert restored.llm_cost_usd_1h == 0.15


# ---------------------------------------------------------------------------
# JustificationContext
# ---------------------------------------------------------------------------

class TestJustificationContext:
    def test_to_dict_with_all_fields(self):
        jc = JustificationContext(
            reason_code="return_approved",
            verified=True,
            verification_source="order_db",
            verification_details="return_request ORD-123 status=approved",
        )
        d = jc.to_dict()
        assert d["reason_code"] == "return_approved"
        assert d["verified"] is True
        assert d["verification_source"] == "order_db"
        assert d["verification_details"] == "return_request ORD-123 status=approved"

    def test_from_dict_full(self):
        d = {
            "reason_code": "rc1",
            "verified": False,
            "verification_source": "crm_db",
            "verification_details": "detail",
        }
        jc = JustificationContext.from_dict(d)
        assert jc.reason_code == "rc1"
        assert jc.verified is False
        assert jc.verification_source == "crm_db"

    def test_to_dict_minimal(self):
        """Empty optional fields should not appear in dict."""
        jc = JustificationContext(reason_code="rc", verified=True)
        d = jc.to_dict()
        assert "verification_source" not in d
        assert "verification_details" not in d


# ---------------------------------------------------------------------------
# VerifiedContext — hit all omitempty paths
# ---------------------------------------------------------------------------

class TestVerifiedContextFull:
    def test_all_scalar_fields(self):
        vc = VerifiedContext(
            customer_tier="gold",
            customer_account_age_days=365,
            customer_lifetime_value=9999.99,
            customer_order_count=50,
            order_total=500.0,
            order_age_days=5,
            order_currency="USD",
            customer_id="cust-1",
            order_id="ord-1",
            order_item_count=3,
            product_category="electronics",
            product_category_avg_price=299.99,
            return_request_reason="damaged",
            return_request_status="approved",
            economic_value_impact=500.0,
            rolling_24h_total=1000.0,
            rolling_24h_count=5,
            rolling_7d_total=7000.0,
            rolling_7d_count=30,
            content_risk="low",
            content_categories=["general"],
            content_classifier_tier="t1",
            counter_agent_risk="medium",
            counter_agent_categories=["financial"],
            counter_agent_reasoning="LLM flagged potential fraud",
        )
        d = vc.to_dict()
        assert d["customer_tier"] == "gold"
        assert d["customer_account_age_days"] == 365
        assert d["customer_lifetime_value"] == 9999.99
        assert d["customer_order_count"] == 50
        assert d["order_total"] == 500.0
        assert d["order_age_days"] == 5
        assert d["order_currency"] == "USD"
        assert d["customer_id"] == "cust-1"
        assert d["order_id"] == "ord-1"
        assert d["order_item_count"] == 3
        assert d["product_category"] == "electronics"
        assert d["product_category_avg_price"] == 299.99
        assert d["return_request_reason"] == "damaged"
        assert d["return_request_status"] == "approved"
        assert d["economic_value_impact"] == 500.0
        assert d["rolling_24h_total"] == 1000.0
        assert d["rolling_24h_count"] == 5
        assert d["rolling_7d_total"] == 7000.0
        assert d["rolling_7d_count"] == 30
        assert d["content_risk"] == "low"
        assert d["content_categories"] == ["general"]
        assert d["content_classifier_tier"] == "t1"
        assert d["counter_agent_risk"] == "medium"
        assert d["counter_agent_categories"] == ["financial"]
        assert d["counter_agent_reasoning"] == "LLM flagged potential fraud"

    def test_from_dict_with_nested(self):
        d = {
            "customer_tier": "silver",
            "agent_budget": {"total_limit": 500.0, "used_today": 100.0, "remaining": 400.0, "transactions_today": 2},
            "agent_velocity": {"monetary_count_1h": 1, "monetary_sum_1h": 100.0,
                               "monetary_count_24h": 5, "monetary_sum_24h": 500.0,
                               "token_count_1h": 0, "token_count_24h": 0,
                               "llm_cost_usd_1h": 0.0, "llm_cost_usd_24h": 0.0},
            "justification": {"reason_code": "approved", "verified": True},
        }
        vc = VerifiedContext.from_dict(d)
        assert vc.customer_tier == "silver"
        assert vc.agent_budget is not None
        assert vc.agent_budget.total_limit == 500.0
        assert vc.agent_velocity is not None
        assert vc.agent_velocity.monetary_count_1h == 1
        assert vc.justification is not None
        assert vc.justification.reason_code == "approved"


# ---------------------------------------------------------------------------
# EnvelopeContext — agent_supplied
# ---------------------------------------------------------------------------

class TestEnvelopeContextAgentSupplied:
    def test_agent_supplied_included_when_set(self):
        ctx = EnvelopeContext(agent_supplied={"custom": "value"})
        d = ctx.to_dict()
        assert d["agent_supplied"] == {"custom": "value"}

    def test_agent_supplied_absent_when_none(self):
        ctx = EnvelopeContext()
        d = ctx.to_dict()
        assert "agent_supplied" not in d

    def test_from_dict_with_agent_supplied(self):
        d = {
            "verified": {},
            "session_state": {"cumulative_amount": 0, "actions_in_session": 0,
                               "escalations_in_session": 0, "denied_in_session": 0},
            "agent_supplied": {"hint": "xyz"},
        }
        ctx = EnvelopeContext.from_dict(d)
        assert ctx.agent_supplied == {"hint": "xyz"}


# ---------------------------------------------------------------------------
# SessionStateContext
# ---------------------------------------------------------------------------

class TestSessionStateContextExtra:
    def test_trajectory_included_when_set(self):
        sc = SessionStateContext(
            amount_trajectory=[100.0, 200.0, 300.0],
        )
        d = sc.to_dict()
        assert d["amount_trajectory"] == [100.0, 200.0, 300.0]

    def test_trajectory_absent_when_empty(self):
        sc = SessionStateContext()
        d = sc.to_dict()
        assert "amount_trajectory" not in d
        assert "tool_sequence" not in d


# ---------------------------------------------------------------------------
# ActionEnvelope — more from_dict paths
# ---------------------------------------------------------------------------

class TestActionEnvelopeFromDict:
    def test_missing_fields_get_defaults(self):
        env = ActionEnvelope.from_dict({})
        assert env.agent_id == ""
        assert env.framework == "sdk"
        assert env.integration_type == "sdk"

    def test_parameters_none_when_absent(self):
        env = ActionEnvelope.from_dict({"tool_name": "search"})
        assert env.parameters is None

    def test_parameters_redacted_present(self):
        env = ActionEnvelope.from_dict({
            "parameters_redacted": {"amount": "REDACTED"},
        })
        assert env.parameters_redacted == {"amount": "REDACTED"}


# ---------------------------------------------------------------------------
# Citation
# ---------------------------------------------------------------------------

class TestCitationExtra:
    def test_page_line_absent_when_zero(self):
        c = Citation(document_id="d", excerpt="x")
        d = c.to_dict()
        assert "page" not in d
        assert "line" not in d
        assert "section" not in d
        assert "document_title" not in d

    def test_from_dict_defaults(self):
        c = Citation.from_dict({})
        assert c.document_id == ""
        assert c.excerpt == ""
        assert c.page == 0


# ---------------------------------------------------------------------------
# RuleResult
# ---------------------------------------------------------------------------

class TestRuleResultExtra:
    def test_from_dict_full(self):
        d = {
            "rule_id": "r1",
            "rule_name": "Cap rule",
            "policy_id": "pol1",
            "policy_version": 2,
            "matched": True,
            "effect": "deny",
            "severity": "high",
            "citation": {"document_id": "d1", "excerpt": "x"},
            "details": "amount 1000 > 500",
        }
        rr = RuleResult.from_dict(d)
        assert rr.rule_id == "r1"
        assert rr.policy_version == 2
        assert rr.severity == "high"
        assert rr.details == "amount 1000 > 500"

    def test_to_dict_omits_optional_when_zero(self):
        rr = RuleResult(rule_id="r", matched=False, effect="allow")
        d = rr.to_dict()
        assert "policy_version" not in d
        assert "severity" not in d
        assert "details" not in d


# ---------------------------------------------------------------------------
# Client — fallback / edge paths
# ---------------------------------------------------------------------------

class TestClientEdgePaths:
    def _make_cli_client(self, tmp_path):
        p = tmp_path / "p.yaml"
        p.write_text("policy_id: p\nstatus: approved\nmode: enforcement\n"
                     "scope:\n  tool_names: []\nrules: []\n")
        return ToolGuard(
            mode="cli",
            policy_file=str(p),
            agent_id="a",
            org_id="o",
        )

    def test_fallback_when_stdout_empty_exit_0(self, tmp_path):
        """Empty stdout with exit 0 → allowed fallback."""
        client = self._make_cli_client(tmp_path)
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = ""
        proc.stderr = ""
        with patch("subprocess.run", return_value=proc):
            result = client.evaluate_raw("search", {})
        assert result.decision == Decision.ALLOWED

    def test_fallback_when_stdout_invalid_json_exit_3(self, tmp_path):
        """Invalid JSON stdout with exit 3 → denied fallback."""
        client = self._make_cli_client(tmp_path)
        proc = MagicMock()
        proc.returncode = 3
        proc.stdout = "not-json"
        proc.stderr = ""
        with patch("subprocess.run", return_value=proc):
            result = client.evaluate_raw("issue_refund", {"amount": 1000})
        assert result.decision == Decision.DENIED

    def test_policy_file_not_found_returns_allowed(self, tmp_path):
        """If policy_file doesn't exist, _resolve_policy_files returns []."""
        client = ToolGuard(
            mode="cli",
            policy_file="/nonexistent/policy.yaml",
            agent_id="a",
            org_id="o",
        )
        result = client.evaluate_raw("search", {})
        assert result.decision == Decision.ALLOWED

    def test_proxy_mode_raises_on_http_error(self):
        """httpx HTTPStatusError propagates from _evaluate_proxy."""
        import httpx
        client = ToolGuard(
            mode="proxy",
            proxy_url="http://localhost:9090",
            agent_id="a",
            org_id="o",
        )
        mock_resp = MagicMock()
        mock_resp.json.return_value = {}
        mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "503", request=MagicMock(), response=MagicMock()
        )
        with patch("httpx.post", return_value=mock_resp):
            with pytest.raises(httpx.HTTPStatusError):
                client.evaluate_raw("search", {})

    def test_yml_extension_also_discovered(self, tmp_path):
        """Both .yaml and .yml files are discovered."""
        (tmp_path / "a.yml").write_text("policy_id: a\nstatus: approved\nmode: enforcement\n"
                                        "scope:\n  tool_names: []\nrules: []\n")
        client = ToolGuard(mode="cli", policy_dir=str(tmp_path), agent_id="a", org_id="o")
        proc = MagicMock()
        proc.returncode = 0
        proc.stdout = json.dumps({
            "decision": "allowed", "action_taken": "allowed",
            "effective_mode": "enforcement",
            "policies_matched": 0, "rules_evaluated": 0,
            "rules_triggered": 0, "rule_results": [], "is_near_miss": False,
        })
        proc.stderr = ""
        with patch("subprocess.run", return_value=proc):
            result = client.evaluate_raw("search", {})
        assert result.decision == Decision.ALLOWED


# ---------------------------------------------------------------------------
# Native adapter — object (non-dict) provider shapes
# ---------------------------------------------------------------------------

class TestNativeNonDictShapes:
    def test_openai_object_shape(self):
        """Supports openai SDK object (ChatCompletionMessageToolCall)."""
        fn_obj = MagicMock()
        fn_obj.name = "search"
        fn_obj.arguments = '{"query": "test"}'

        call_obj = MagicMock()
        call_obj.function = fn_obj
        call_obj.id = "call_999"
        call_obj.__class__.__name__ = "ChatCompletionMessageToolCall"

        # Override isinstance check — dict check will fail, fall to else
        # The code checks `isinstance(call, dict)` — since call_obj is a MagicMock
        # it's not a dict, so it goes to the object path.
        tool_name, params, call_id = _extract_call(call_obj, "openai")
        assert tool_name == "search"
        assert params == {"query": "test"}
        assert call_id == "call_999"

    def test_anthropic_object_shape(self):
        """Supports anthropic SDK ToolUseBlock object."""
        call_obj = MagicMock()
        call_obj.name = "issue_refund"
        call_obj.input = {"amount": 100}
        call_obj.id = "toolu_99"

        tool_name, params, call_id = _extract_call(call_obj, "anthropic")
        assert tool_name == "issue_refund"
        assert params == {"amount": 100}
        assert call_id == "toolu_99"

    def test_build_error_result_decision_reason_fallback(self):
        """When suggested_response is empty, decision_reason is used."""
        result = EvaluationResult(
            decision="denied",
            action_taken="denied",
            decision_reason="Amount exceeds cap",
            suggested_response="",
        )
        tr = _build_error_result("call_1", result, "openai")
        assert tr["content"] == "Amount exceeds cap"

    def test_build_error_result_decision_fallback(self):
        """When both are empty, decision itself is used."""
        result = EvaluationResult(
            decision="denied",
            action_taken="denied",
            decision_reason="",
            suggested_response="",
        )
        tr = _build_error_result("call_1", result, "anthropic")
        assert tr["content"] == "denied"

    def test_anthropic_non_dict_non_object_input(self):
        """Anthropic input that is not a dict gets wrapped."""
        call = {
            "type": "tool_use",
            "id": "t1",
            "name": "tool",
            "input": ["not", "a", "dict"],  # unexpected shape
        }
        tool_name, params, call_id = _extract_call(call, "anthropic")
        assert tool_name == "tool"
        assert params == {"_raw": ["not", "a", "dict"]}

    def test_guard_tool_calls_with_object_shapes(self):
        """guard_tool_calls handles object-shaped tool calls."""
        fn_obj = MagicMock()
        fn_obj.name = "search"
        fn_obj.arguments = '{"q": "hello"}'
        call_obj = MagicMock()
        call_obj.function = fn_obj
        call_obj.id = "c1"

        client = MagicMock(spec=ToolGuard)
        client.evaluate_raw.return_value = EvaluationResult(
            decision=Decision.ALLOWED, action_taken=Decision.ALLOWED
        )

        allowed, denied = guard_tool_calls([call_obj], client, provider="openai")
        assert len(allowed) == 1
        assert len(denied) == 0
