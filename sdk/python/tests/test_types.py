"""
test_types.py — JSON round-trip tests for toolguard.types.

Verifies that Python dataclasses produce / consume JSON with EXACTLY the field
names the Go engine expects (read from pkg/domain/envelope.go and
pkg/domain/trace.go).
"""
import json

import pytest

from toolguard.types import (
    ActionEnvelope,
    ActionTaken,
    AgentBudgetContext,
    AgentVelocityContext,
    Citation,
    Decision,
    DecisionReceipt,
    EnvelopeContext,
    Escalation,
    EscalationState,
    EvaluationResult,
    Framework,
    IntegrationType,
    JustificationContext,
    PolicyMode,
    RuleResult,
    SessionStateContext,
    VerifiedContext,
)


def test_escalation_state_constants_match_server_contract():
    assert {
        EscalationState.PENDING,
        EscalationState.APPROVED,
        EscalationState.DENIED,
        EscalationState.EXPIRED,
        EscalationState.INDETERMINATE,
    } == {"pending", "approved", "denied", "expired", "indeterminate"}


# ---------------------------------------------------------------------------
# ActionEnvelope
# ---------------------------------------------------------------------------

class TestActionEnvelopeFieldNames:
    """Field names must match Go json tags verbatim."""

    def test_identity_fields(self):
        env = ActionEnvelope(
            envelope_id="env-001",
            agent_id="agent-1",
            session_id="sess-1",
            org_id="org-1",
        )
        d = env.to_dict()
        assert "envelope_id" in d
        assert "agent_id" in d
        assert "session_id" in d
        assert "org_id" in d
        assert "timestamp" in d

    def test_action_fields(self):
        env = ActionEnvelope(
            tool_name="issue_refund",
            tool_group="monetary_outflow",
        )
        d = env.to_dict()
        assert d["tool_name"] == "issue_refund"
        assert d["tool_group"] == "monetary_outflow"

    def test_framework_and_integration_type(self):
        env = ActionEnvelope(
            framework=Framework.LANGGRAPH,
            integration_type=IntegrationType.LANGGRAPH_MIDDLEWARE,
        )
        d = env.to_dict()
        assert d["framework"] == "langgraph"
        assert d["integration_type"] == "langgraph_middleware"

    def test_sdk_defaults(self):
        env = ActionEnvelope()
        d = env.to_dict()
        assert d["framework"] == "sdk"
        assert d["integration_type"] == "sdk"

    def test_parameters_is_inline_json(self):
        """parameters must be a JSON-serializable object (not a string)."""
        env = ActionEnvelope(parameters={"amount": 500})
        d = env.to_dict()
        assert d["parameters"] == {"amount": 500}
        # Verify it round-trips through json.dumps/loads without extra escaping
        serialized = json.dumps(d)
        parsed = json.loads(serialized)
        assert parsed["parameters"]["amount"] == 500

    def test_context_field_names(self):
        env = ActionEnvelope()
        d = env.to_dict()
        ctx = d["context"]
        assert "verified" in ctx
        assert "session_state" in ctx

    def test_omitempty_fields_absent_when_zero(self):
        """omitempty fields must not appear in the dict when zero/empty."""
        env = ActionEnvelope()
        d = env.to_dict()
        assert "agent_version" not in d
        assert "turn_number" not in d
        assert "tool_server" not in d
        assert "parameters_redacted" not in d
        assert "tls_verified" not in d

    def test_omitempty_fields_present_when_set(self):
        env = ActionEnvelope(
            agent_version="1.2.3",
            turn_number=5,
            tool_server="mcp://server",
            tls_verified=True,
        )
        d = env.to_dict()
        assert d["agent_version"] == "1.2.3"
        assert d["turn_number"] == 5
        assert d["tool_server"] == "mcp://server"
        assert d["tls_verified"] is True

    def test_round_trip_from_dict(self):
        original = ActionEnvelope(
            envelope_id="env-rt",
            agent_id="a1",
            session_id="s1",
            org_id="o1",
            tool_name="search",
            tool_group="read",
            parameters={"query": "hello"},
            framework=Framework.MCP,
            integration_type=IntegrationType.MCP_PROXY,
        )
        d = original.to_dict()
        restored = ActionEnvelope.from_dict(d)
        assert restored.envelope_id == original.envelope_id
        assert restored.agent_id == original.agent_id
        assert restored.tool_name == original.tool_name
        assert restored.framework == "mcp"
        assert restored.integration_type == "mcp_proxy"
        assert restored.parameters == {"query": "hello"}


# ---------------------------------------------------------------------------
# VerifiedContext
# ---------------------------------------------------------------------------

class TestVerifiedContext:
    def test_empty_dict_when_all_zero(self):
        vc = VerifiedContext()
        d = vc.to_dict()
        # All fields are omitempty; empty VerifiedContext → empty dict
        assert d == {}

    def test_nested_agent_budget(self):
        vc = VerifiedContext(
            agent_budget=AgentBudgetContext(
                total_limit=1000.0,
                used_today=200.0,
                remaining=800.0,
                transactions_today=3,
            )
        )
        d = vc.to_dict()
        assert "agent_budget" in d
        ab = d["agent_budget"]
        assert ab["total_limit"] == 1000.0
        assert ab["remaining"] == 800.0
        assert ab["transactions_today"] == 3

    def test_nested_agent_velocity(self):
        vc = VerifiedContext(
            agent_velocity=AgentVelocityContext(
                monetary_count_1h=5,
                monetary_sum_1h=2500.0,
            )
        )
        d = vc.to_dict()
        av = d["agent_velocity"]
        assert av["monetary_count_1h"] == 5
        assert av["monetary_sum_1h"] == 2500.0
        assert av["llm_cost_usd_1h"] == 0.0

    def test_round_trip(self):
        original = VerifiedContext(
            customer_tier="gold",
            rolling_24h_total=9000.0,
            rolling_24h_count=18,
        )
        restored = VerifiedContext.from_dict(original.to_dict())
        assert restored.customer_tier == "gold"
        assert restored.rolling_24h_total == 9000.0
        assert restored.rolling_24h_count == 18


# ---------------------------------------------------------------------------
# SessionStateContext
# ---------------------------------------------------------------------------

class TestSessionStateContext:
    def test_field_names(self):
        sc = SessionStateContext(
            cumulative_amount=500.0,
            actions_in_session=10,
            tool_sequence=["search", "issue_refund"],
        )
        d = sc.to_dict()
        assert d["cumulative_amount"] == 500.0
        assert d["actions_in_session"] == 10
        assert d["tool_sequence"] == ["search", "issue_refund"]

    def test_round_trip(self):
        original = SessionStateContext(
            escalations_in_session=2,
            denied_in_session=1,
        )
        restored = SessionStateContext.from_dict(original.to_dict())
        assert restored.escalations_in_session == 2
        assert restored.denied_in_session == 1


# ---------------------------------------------------------------------------
# EvaluationResult
# ---------------------------------------------------------------------------

class TestEvaluationResult:
    """field names must match Go trace.go:165 EvaluationResult verbatim."""

    def test_field_names(self):
        result = EvaluationResult(
            decision=Decision.DENIED,
            action_taken=ActionTaken.DENIED,
            decision_reason="over cap",
            effective_mode=PolicyMode.ENFORCEMENT,
            policies_matched=1,
            rules_evaluated=2,
            rules_triggered=1,
            is_near_miss=False,
        )
        d = result.to_dict()
        assert d["decision"] == "denied"
        assert d["action_taken"] == "denied"
        assert d["decision_reason"] == "over cap"
        assert d["effective_mode"] == "enforcement"
        assert d["policies_matched"] == 1
        assert d["rules_evaluated"] == 2
        assert d["rules_triggered"] == 1
        assert d["is_near_miss"] is False

    def test_decision_values_are_lowercase(self):
        """Wire format uses lowercase per Go domain constants."""
        assert Decision.ALLOWED == "allowed"
        assert Decision.DENIED == "denied"
        assert Decision.ESCALATED == "escalated"
        assert Decision.FLAGGED == "flagged"

    def test_action_taken_shadow(self):
        assert ActionTaken.ALLOWED_SHADOW == "allowed_shadow"

    def test_rule_results_nested(self):
        result = EvaluationResult(
            decision=Decision.DENIED,
            action_taken=ActionTaken.DENIED,
            rule_results=[
                RuleResult(
                    rule_id="r1",
                    rule_name="Amount cap",
                    policy_id="pol-1",
                    matched=True,
                    effect="deny",
                    citation=Citation(
                        document_id="doc-1",
                        excerpt="$500 cap",
                    ),
                )
            ],
        )
        d = result.to_dict()
        rr = d["rule_results"][0]
        assert rr["rule_id"] == "r1"
        assert rr["matched"] is True
        assert rr["citation"]["document_id"] == "doc-1"
        assert rr["citation"]["excerpt"] == "$500 cap"

    def test_primary_citation_field_name(self):
        result = EvaluationResult(
            primary_citation=Citation(document_id="d1", excerpt="x")
        )
        d = result.to_dict()
        assert "primary_citation" in d
        assert d["primary_citation"]["document_id"] == "d1"

    def test_applied_provenance_field_names(self):
        applied_rule = RuleResult(
            rule_id="enforce-r1",
            rule_name="Enforced escalation",
            policy_id="enforce-pol",
            matched=True,
            effect="escalate",
            citation=Citation(document_id="enforce-doc", excerpt="Needs approval"),
        )
        result = EvaluationResult(
            applied_rule_results=[applied_rule],
            applied_primary_citation=Citation(
                document_id="enforce-doc", excerpt="Needs approval"
            ),
        )
        d = result.to_dict()
        assert d["applied_rule_results"][0]["policy_id"] == "enforce-pol"
        assert d["applied_primary_citation"]["document_id"] == "enforce-doc"

    def test_v070_positional_constructor_compatibility(self):
        """0.8 additive fields must not rebind the published 0.7 signature."""
        citation = Citation(document_id="legacy-doc", excerpt="Legacy citation")
        rule = RuleResult(rule_id="legacy-rule", matched=True, effect="deny")
        result = EvaluationResult(
            Decision.DENIED,
            ActionTaken.DENIED,
            "legacy reason",
            PolicyMode.ENFORCEMENT,
            1,
            2,
            1,
            [rule],
            citation,
            True,
            "legacy guidance",
        )

        assert result.primary_citation is citation
        assert result.is_near_miss is True
        assert result.suggested_response == "legacy guidance"
        assert result.applied_rule_results == []
        assert result.applied_primary_citation is None
        assert result.to_dict()["primary_citation"]["document_id"] == "legacy-doc"

    def test_suggested_response_field_name(self):
        result = EvaluationResult(suggested_response="Please reduce the amount.")
        d = result.to_dict()
        assert d["suggested_response"] == "Please reduce the amount."

    def test_round_trip_from_dict(self):
        """Simulate deserializing what tg-proxy or tg evaluate returns."""
        wire = {
            "decision": "denied",
            "action_taken": "denied",
            "decision_reason": "Denied by: [rule-amount-cap]",
            "effective_mode": "enforcement",
            "policies_matched": 1,
            "rules_evaluated": 2,
            "rules_triggered": 1,
            "rule_results": [
                {
                    "rule_id": "rule-amount-cap",
                    "rule_name": "Amount cap",
                    "policy_id": "pol-refund",
                    "matched": True,
                    "effect": "deny",
                    "citation": {"document_id": "sop-001", "excerpt": "No refund >$500"},
                }
            ],
            "applied_rule_results": [
                {
                    "rule_id": "rule-amount-cap",
                    "rule_name": "Amount cap",
                    "policy_id": "pol-refund",
                    "matched": True,
                    "effect": "deny",
                    "citation": {"document_id": "sop-001", "excerpt": "No refund >$500"},
                }
            ],
            "primary_citation": {"document_id": "sop-001", "excerpt": "No refund >$500"},
            "applied_primary_citation": {"document_id": "sop-001", "excerpt": "No refund >$500"},
            "is_near_miss": False,
        }
        result = EvaluationResult.from_dict(wire)
        assert result.decision == "denied"
        assert result.action_taken == "denied"
        assert result.policies_matched == 1
        assert result.rules_triggered == 1
        assert len(result.rule_results) == 1
        assert result.rule_results[0].rule_id == "rule-amount-cap"
        assert len(result.applied_rule_results) == 1
        assert result.applied_rule_results[0].policy_id == "pol-refund"
        assert result.primary_citation is not None
        assert result.primary_citation.document_id == "sop-001"
        assert result.applied_primary_citation is not None
        assert result.applied_primary_citation.document_id == "sop-001"

    def test_sample_envelope_go_contract(self):
        """
        Parse a minimal sample envelope the Go side would emit (from examples/).
        This is the shape of examples/call_over_cap.json passed through ActionEnvelope.
        """
        go_wire = {
            "agent_id": "support-agent-v2",
            "session_id": "sess-001",
            "org_id": "acme",
            "tool_name": "issue_refund",
            "tool_group": "monetary_outflow",
            "parameters": {"amount": 1000, "reason": "Goodwill credit"},
        }
        env = ActionEnvelope.from_dict(go_wire)
        assert env.agent_id == "support-agent-v2"
        assert env.tool_name == "issue_refund"
        assert env.tool_group == "monetary_outflow"
        assert env.parameters["amount"] == 1000
        # context defaults must be present in output
        d = env.to_dict()
        assert "context" in d
        assert "verified" in d["context"]
        assert "session_state" in d["context"]


# ---------------------------------------------------------------------------
# Citation
# ---------------------------------------------------------------------------

class TestCitation:
    def test_field_names(self):
        c = Citation(
            document_id="SOC2-CTRL-5",
            document_title="SOC 2 Controls",
            section="4.2",
            page=12,
            line=3,
            excerpt="Monetary transactions exceeding $500...",
        )
        d = c.to_dict()
        assert d["document_id"] == "SOC2-CTRL-5"
        assert d["document_title"] == "SOC 2 Controls"
        assert d["section"] == "4.2"
        assert d["page"] == 12
        assert d["line"] == 3
        assert d["excerpt"] == "Monetary transactions exceeding $500..."

    def test_round_trip(self):
        original = Citation(document_id="d1", excerpt="cap rule")
        restored = Citation.from_dict(original.to_dict())
        assert restored.document_id == "d1"
        assert restored.excerpt == "cap rule"


# ---------------------------------------------------------------------------
# DecisionReceipt and receipt-bearing proxy responses
# ---------------------------------------------------------------------------

_WIRE_RECEIPT = {
    "receipt_version": "1",
    "trace_id": "trc-001",
    "trace_hash": "sha256:" + "ab" * 32,
    "hash_algorithm": "sha256",
    "canonical_trace_version": "v2",
    "integrity_model": "hash-chain",
    "decision": "denied",
    "action_taken": "denied",
    "timestamp": "2026-08-25T00:00:00Z",
    "issuer": "proxy-instance-7",
    "receipt_uri": "urn:tool-guard:trace:v2:sha256:" + "ab" * 32,
}


class TestDecisionReceipt:
    def test_wire_fields_round_trip(self):
        receipt = DecisionReceipt.from_dict(_WIRE_RECEIPT)
        assert receipt.to_dict() == _WIRE_RECEIPT

    def test_optional_issuer_is_omitted(self):
        wire = dict(_WIRE_RECEIPT)
        wire.pop("issuer")
        receipt = DecisionReceipt.from_dict(wire)
        assert receipt.issuer == ""
        assert "issuer" not in receipt.to_dict()

    def test_unknown_future_fields_are_ignored(self):
        receipt = DecisionReceipt.from_dict(
            dict(_WIRE_RECEIPT, future_metadata={"new": True})
        )
        assert receipt.receipt_uri == _WIRE_RECEIPT["receipt_uri"]


class TestEvaluationResultReceipt:
    def test_absent_receipt_stays_absent(self):
        result = EvaluationResult.from_dict(
            {"decision": "allowed", "action_taken": "allowed"}
        )
        assert result.decision_receipt is None
        assert "decision_receipt" not in result.to_dict()

    def test_nested_receipt_round_trip(self):
        result = EvaluationResult.from_dict(
            {
                "decision": "denied",
                "action_taken": "denied",
                "decision_receipt": _WIRE_RECEIPT,
            }
        )
        assert result.decision_receipt is not None
        assert result.decision_receipt.trace_hash == _WIRE_RECEIPT["trace_hash"]
        assert result.to_dict()["decision_receipt"] == _WIRE_RECEIPT

    def test_non_object_receipt_is_ignored_without_changing_decision(self):
        result = EvaluationResult.from_dict(
            {
                "decision": "allowed",
                "action_taken": "allowed",
                "decision_receipt": "malformed",
            }
        )
        assert result.decision == "allowed"
        assert result.decision_receipt is None


class TestEscalationReceipt:
    def test_resolution_receipt_round_trip(self):
        wire = {
            "id": "esc-1",
            "state": "approved",
            "created_at": "2026-08-25T00:00:00Z",
            "expires_at": "2026-08-25T00:15:00Z",
            "resolved_at": "2026-08-25T00:01:00Z",
            "approver": "operator",
            "envelope": {},
            "decision": {"decision": "escalated", "action_taken": "escalated"},
            "resolution_receipt": _WIRE_RECEIPT,
        }
        escalation = Escalation.from_dict(wire)
        assert escalation.resolution_receipt is not None
        assert escalation.resolution_receipt.receipt_uri == _WIRE_RECEIPT["receipt_uri"]
        assert escalation.to_dict()["resolution_receipt"] == _WIRE_RECEIPT

    def test_pending_resolution_receipt_is_absent(self):
        escalation = Escalation.from_dict(
            {
                "id": "esc-pending",
                "state": "pending",
                "envelope": {},
                "decision": {"decision": "escalated", "action_taken": "escalated"},
            }
        )
        assert escalation.resolution_receipt is None
