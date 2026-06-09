package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// TrustLevel indicates who provided the data and how much it can be trusted.
type TrustLevel string

const (
	TrustVerified      TrustLevel = "verified"       // System-enriched from DB
	TrustSessionState  TrustLevel = "session_state"  // Proxy-maintained across turns
	TrustAgentSupplied TrustLevel = "agent_supplied" // Agent-provided, never for enforcement
)

// ActionEnvelope captures every agent tool call enriched with verified context.
// Spec: 01_Action_Envelope_v0
type ActionEnvelope struct {
	// Identity
	EnvelopeID string    `json:"envelope_id"`
	Timestamp  time.Time `json:"timestamp"`
	AgentID    string    `json:"agent_id"`
	SessionID  string    `json:"session_id"`
	OrgID      string    `json:"org_id"`

	// Agent metadata
	AgentVersion string `json:"agent_version,omitempty"`
	Framework    string `json:"framework,omitempty"` // mcp, langgraph, sdk, unknown
	TurnNumber   int    `json:"turn_number,omitempty"`
	Department   string `json:"department,omitempty"`

	// Action
	ToolName           string          `json:"tool_name"`
	ToolServer         string          `json:"tool_server,omitempty"` // MCP server ID or endpoint
	ToolGroup          string          `json:"tool_group"`
	Parameters         json.RawMessage `json:"parameters,omitempty"`
	ParametersRedacted json.RawMessage `json:"parameters_redacted,omitempty"`

	// Context
	Context EnvelopeContext `json:"context"`

	// Source metadata
	IntegrationType string `json:"integration_type,omitempty"` // mcp_proxy, langgraph_middleware, sdk
	ProxyVersion    string `json:"proxy_version,omitempty"`
	TLSVerified     bool   `json:"tls_verified,omitempty"`

	// Integrity
	Integrity *EnvelopeIntegrity `json:"integrity,omitempty"`
}

// EnvelopeIntegrity provides tamper-detection for the envelope itself.
type EnvelopeIntegrity struct {
	Hash     string `json:"hash,omitempty"`      // SHA-256 of envelope content
	SignedBy string `json:"signed_by,omitempty"` // Proxy instance ID
}

// EnvelopeContext contains all context fields, organized by trust level.
type EnvelopeContext struct {
	Verified      VerifiedContext     `json:"verified"`
	SessionState  SessionStateContext `json:"session_state"`
	AgentSupplied json.RawMessage     `json:"agent_supplied,omitempty"`
}

// VerifiedContext contains system-enriched fields from the database.
type VerifiedContext struct {
	// Customer/order context
	CustomerTier           string  `json:"customer_tier,omitempty"`
	CustomerAccountAgeDays int     `json:"customer_account_age_days,omitempty"`
	CustomerLifetimeValue  float64 `json:"customer_lifetime_value,omitempty"`
	CustomerOrderCount     int     `json:"customer_order_count,omitempty"`
	OrderTotal             float64 `json:"order_total,omitempty"`
	OrderAge               int     `json:"order_age_days,omitempty"`
	OrderCurrency          string  `json:"order_currency,omitempty"`
	CustomerID             string  `json:"customer_id,omitempty"`
	OrderID                string  `json:"order_id,omitempty"`

	// Order details (semantic fraud detection)
	OrderItemCount          int     `json:"order_item_count,omitempty"`
	ProductCategory         string  `json:"product_category,omitempty"`
	ProductCategoryAvgPrice float64 `json:"product_category_avg_price,omitempty"`

	// Return details
	ReturnRequestReason string `json:"return_request_reason,omitempty"`
	ReturnRequestStatus string `json:"return_request_status,omitempty"` // pending, approved, rejected

	// Economic equivalence
	EconomicValueImpact float64 `json:"economic_value_impact,omitempty"`

	// Rolling totals (cross-session)
	Rolling24hTotal float64 `json:"rolling_24h_total,omitempty"`
	Rolling24hCount int     `json:"rolling_24h_count,omitempty"`
	Rolling7dTotal  float64 `json:"rolling_7d_total,omitempty"`
	Rolling7dCount  int     `json:"rolling_7d_count,omitempty"`

	// Agent budget
	AgentBudget *AgentBudgetContext `json:"agent_budget,omitempty"`

	// Agent velocity
	AgentVelocity *AgentVelocityContext `json:"agent_velocity,omitempty"`

	// Justification
	Justification *JustificationContext `json:"justification,omitempty"`

	// Content classification
	ContentRisk           string   `json:"content_risk,omitempty"`
	ContentCategories     []string `json:"content_categories,omitempty"`
	ContentClassifierTier string   `json:"content_classifier_tier,omitempty"`

	// Counter-agent classification
	CounterAgentRisk       string   `json:"counter_agent_risk,omitempty"`
	CounterAgentCategories []string `json:"counter_agent_categories,omitempty"`
	CounterAgentReasoning  string   `json:"counter_agent_reasoning,omitempty"`
}

// AgentBudgetContext tracks agent spending authority.
type AgentBudgetContext struct {
	TotalLimit        float64 `json:"total_limit"`
	UsedToday         float64 `json:"used_today"`
	Remaining         float64 `json:"remaining"`
	TransactionsToday int     `json:"transactions_today"`
}

// AgentVelocityContext tracks agent transaction rate and LLM-cost burn.
//
// MonetaryCount/Sum buckets are aggregated from decision_traces.amount and
// power the $-velocity rules (refund caps, 24h ledger ceilings).
//
// TokenCount and LLMCostUSD buckets are aggregated from decision_traces
// agent_tokens_in/out + agent_llm_cost_usd columns — populated by the proxy
// when the upstream LLM response carries usage headers. They power token-
// spend velocity rules (e.g. retry-loop cost ceiling). These are the AGENT's
// LLM usage, NOT Tool Guard's internal hybrid-eval model usage.
type AgentVelocityContext struct {
	MonetaryCount1h  int     `json:"monetary_count_1h"`
	MonetarySum1h    float64 `json:"monetary_sum_1h"`
	MonetaryCount24h int     `json:"monetary_count_24h"`
	MonetarySum24h   float64 `json:"monetary_sum_24h"`

	TokenCount1h  int     `json:"token_count_1h"`
	TokenCount24h int     `json:"token_count_24h"`
	LLMCostUSD1h  float64 `json:"llm_cost_usd_1h"`
	LLMCostUSD24h float64 `json:"llm_cost_usd_24h"`
}

// JustificationContext tracks verified business reason.
type JustificationContext struct {
	ReasonCode          string `json:"reason_code"`
	Verified            bool   `json:"verified"`
	VerificationSource  string `json:"verification_source,omitempty"`  // order_db, crm_db, manual
	VerificationDetails string `json:"verification_details,omitempty"` // e.g. "return_request ORD-123 status=approved"
}

// SessionStateContext is maintained by the proxy across turns in a session.
type SessionStateContext struct {
	CumulativeAmount     float64   `json:"cumulative_amount"`
	ActionsInSession     int       `json:"actions_in_session"`
	EscalationsInSession int       `json:"escalations_in_session"`
	DeniedInSession      int       `json:"denied_in_session"`
	ToolSequence         []string  `json:"tool_sequence,omitempty"`
	AmountTrajectory     []float64 `json:"amount_trajectory,omitempty"`
}

// AmountError is returned when the amount field has an invalid type.
type AmountError struct {
	Message string
}

func (e *AmountError) Error() string { return e.Message }

// Amount extracts the monetary amount from the envelope parameters.
// Returns an error if the field is present but cannot be coerced to a
// non-negative number.
//
// Numeric coercion semantics — agent SDKs serialise numbers
// inconsistently:
//   - JSON number (10000, 10000.50)                     → parsed directly
//   - JSON string that parses as a number ("10000.00")  → parsed via
//     strconv. The CHANGELOG promises this; closes the
//     string-amount-bypass class where a hostile envelope sends
//     "amount":"99999999" and the threshold rule reads 0.
//   - Empty string ("") → 0 with NO error (legitimate "no monetary
//     value" — fields that don't apply to non-monetary tools).
//   - Anything else (object, array, bool, unparseable string) → error.
//     The caller decides whether to fail closed or accept 0.
//
// Negative amounts are rejected with an error so a hostile
// "amount": -1 cannot trip a `gt`-threshold off by sign confusion.
func (e *ActionEnvelope) Amount() (float64, error) {
	if e.Parameters == nil {
		return 0, nil
	}
	dec := json.NewDecoder(bytes.NewReader(e.Parameters))
	dec.UseNumber()
	var params map[string]interface{}
	if err := dec.Decode(&params); err != nil {
		// Parameters is not a JSON object — typically it's an array,
		// a string, a number, or a bool. A hostile envelope can use
		// this shape to dodge an amount-cap policy: the previous
		// implementation returned (0, nil), the engine stored 0, and
		// every `gt amount` rule silently allowed. Now we return an
		// error so FlattenEnvelope's sentinel-substitute path fires
		// and amount-cap rules deny.
		return 0, &AmountError{Message: fmt.Sprintf("parameters is not a JSON object (got %T-shaped payload): %v", params, err)}
	}
	v, ok := params["amount"]
	if !ok {
		return 0, nil
	}
	switch a := v.(type) {
	case json.Number:
		f, err := a.Float64()
		if err != nil {
			return 0, &AmountError{Message: fmt.Sprintf("invalid amount number: %s", a)}
		}
		if f < 0 {
			return 0, &AmountError{Message: fmt.Sprintf("negative amount not allowed: %.2f", f)}
		}
		return f, nil
	case float64:
		if a < 0 {
			return 0, &AmountError{Message: fmt.Sprintf("negative amount not allowed: %.2f", a)}
		}
		return a, nil
	case string:
		trimmed := a
		// Allow common leading/trailing whitespace; reject everything
		// else as a non-numeric input.
		for len(trimmed) > 0 && (trimmed[0] == ' ' || trimmed[0] == '\t') {
			trimmed = trimmed[1:]
		}
		for len(trimmed) > 0 && (trimmed[len(trimmed)-1] == ' ' || trimmed[len(trimmed)-1] == '\t') {
			trimmed = trimmed[:len(trimmed)-1]
		}
		if trimmed == "" {
			return 0, nil
		}
		f, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return 0, &AmountError{Message: fmt.Sprintf("amount must be a number, got string %q", a)}
		}
		if f < 0 {
			return 0, &AmountError{Message: fmt.Sprintf("negative amount not allowed: %.2f", f)}
		}
		return f, nil
	default:
		return 0, &AmountError{Message: fmt.Sprintf("amount must be a number, got %T", v)}
	}
}
