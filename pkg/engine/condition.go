package engine

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
)

// EvalCondition evaluates a condition tree against a flattened field
// map. Returns true if the rule should fire (apply its Effect).
func EvalCondition(cond domain.Condition, fields map[string]interface{}) bool {
	fired, _ := EvalConditionWithDetail(cond, fields)
	return fired
}

// EvalConditionWithDetail is the same as EvalCondition but also
// returns a short diagnostic string describing WHY the rule fired
// (e.g. "sql_classify: postgres parse: unclosed block comment").
// Used by the evaluator to populate RuleResult.Details so operators
// can see classifier-level reasons in the audit chain.
func EvalConditionWithDetail(cond domain.Condition, fields map[string]interface{}) (bool, string) {
	// Branch: AND. When the AND fires (all subs true) carry through
	// the most informative detail from any sub — the operator wants to
	// see WHY the sql_classify leaf fired, not silence because the
	// outer eq matched first.
	if len(cond.And) > 0 {
		var firstDetail string
		for _, sub := range cond.And {
			fired, detail := EvalConditionWithDetail(sub, fields)
			if !fired {
				return false, detail
			}
			if firstDetail == "" && detail != "" {
				firstDetail = detail
			}
		}
		return true, firstDetail
	}

	// Branch: OR
	if len(cond.Or) > 0 {
		for _, sub := range cond.Or {
			if fired, detail := EvalConditionWithDetail(sub, fields); fired {
				return true, detail
			}
		}
		return false, ""
	}

	// Branch: NOT
	if cond.Not != nil {
		fired, _ := EvalConditionWithDetail(*cond.Not, fields)
		return !fired, ""
	}

	// Leaf: SQL-classify — surfaces classifier diagnostics so
	// operators can see "postgres parse: unclosed block comment"
	// in the audit chain.
	if cond.SQLClassify != nil {
		return evalSQLClassifyWithDetail(cond.SQLClassify, fields)
	}

	if cond.PathClassify != nil {
		return evalPathClassify(cond.PathClassify, fields), ""
	}

	if cond.ShellClassify != nil {
		return evalShellClassify(cond.ShellClassify, fields), ""
	}

	if cond.LLMClassify != nil {
		return evalLLMClassifyWithDetail(cond.LLMClassify, fields)
	}

	if !cond.IsLeaf() {
		return true, "" // empty condition matches everything
	}

	return evalLeaf(cond.Field, cond.Operator, cond.Value, fields), ""
}

// evalSQLClassify is the bool-only wrapper for callers that don't
// care about diagnostic detail (existing tests). Prefer
// evalSQLClassifyWithDetail in the evaluator hot path so the audit
// chain sees the WHY.
func evalSQLClassify(s *domain.SQLClassify, fields map[string]interface{}) bool {
	fired, _ := evalSQLClassifyWithDetail(s, fields)
	return fired
}

// evalSQLClassifyWithDetail returns (fired, reason).
//
// fired: true when the SQL at fields[s.Field] violates any Require
// predicate OR the classifier cannot make a confident judgement.
//
// reason: short human-readable explanation surfaced through
// RuleResult.Details. Always populated when fired=true; empty when
// the rule passes.
func evalSQLClassifyWithDetail(s *domain.SQLClassify, fields map[string]interface{}) (bool, string) {
	raw, ok := resolveField(s.Field, fields)
	if !ok {
		return true, fmt.Sprintf("sql_classify field %q missing", s.Field)
	}
	sql, ok := raw.(string)
	if !ok {
		return true, fmt.Sprintf("sql_classify field %q is not a string (%T)", s.Field, raw)
	}
	cl, err := sqlguard.Classify(s.Dialect, sql)
	if err != nil {
		return true, fmt.Sprintf("sql_classify(%s): %v", s.Dialect, err)
	}

	if len(s.Require.DeniedTopLevelKinds) > 0 {
		for _, k := range cl.TopLevelKinds {
			ku := strings.ToUpper(string(k))
			for _, d := range s.Require.DeniedTopLevelKinds {
				if strings.EqualFold(d, ku) {
					return true, fmt.Sprintf("sql_classify: top-level %s is in denied set", ku)
				}
			}
		}
	}
	if len(s.Require.TopLevelKinds) > 0 {
		if cl.StmtCount != 1 || len(cl.TopLevelKinds) != 1 {
			return true, fmt.Sprintf("sql_classify: multi-stmt input (%d statements) not permitted", cl.StmtCount)
		}
		want := strings.ToUpper(string(cl.TopLevelKinds[0]))
		permitted := false
		for _, k := range s.Require.TopLevelKinds {
			if strings.EqualFold(k, want) {
				permitted = true
				break
			}
		}
		if !permitted {
			return true, fmt.Sprintf("sql_classify: top-level %s not in %v", want, s.Require.TopLevelKinds)
		}
		if cl.MutatesViaCTE && allReadOnlyKinds(s.Require.TopLevelKinds) {
			return true, "sql_classify: SELECT with modifying CTE (INSERT/UPDATE/DELETE/MERGE in WITH clause)"
		}
	}
	if s.Require.NoDynamicSQL && cl.UsesDynamicSQL {
		return true, "sql_classify: dynamic SQL (DO/EXECUTE/CALL/PREPARE) not permitted"
	}
	if s.Require.NoProgramExec && cl.UsesProgram {
		return true, "sql_classify: program-exec primitive (COPY FROM PROGRAM, xp_cmdshell, ...) not permitted"
	}
	if fn, bad := cl.HasDisallowedFunction(s.Require.AllowedFunctions); bad {
		return true, fmt.Sprintf("sql_classify: function %q not in allowed_functions", fn)
	}
	if s.Require.NoFunctions && len(cl.Functions) > 0 {
		return true, fmt.Sprintf("sql_classify: function call(s) %v present, no_functions=true", cl.Functions)
	}

	if t, bad := cl.HasDeniedTable(s.Require.DeniedTables); bad {
		return true, fmt.Sprintf("sql_classify: table %q matches denied_tables prefix", t)
	}
	if t, bad := cl.HasTableOutsideAllowed(s.Require.AllowedTables); bad {
		return true, fmt.Sprintf("sql_classify: table %q is not in allowed_tables", t)
	}

	if len(s.Require.DeniedFunctionClasses) > 0 || len(s.Require.AllowedFunctionClasses) > 0 {
		reg := sqlguard.CurrentRegistry()
		if reg == nil {
			return true, "sql_classify: function-class predicate set but no tools.yaml registry loaded"
		}
		for _, fn := range cl.Functions {
			for _, deniedClass := range s.Require.DeniedFunctionClasses {
				if reg.FunctionInClass(fn, deniedClass) {
					return true, fmt.Sprintf("sql_classify: function %q is in denied class %q", fn, deniedClass)
				}
			}
		}
		if len(s.Require.AllowedFunctionClasses) > 0 {
			for _, fn := range cl.Functions {
				ok := false
				for _, allowedClass := range s.Require.AllowedFunctionClasses {
					if reg.FunctionInClass(fn, allowedClass) {
						ok = true
						break
					}
				}
				if !ok {
					return true, fmt.Sprintf("sql_classify: function %q is in no allowed class", fn)
				}
			}
		}
	}

	return false, ""
}

// allReadOnlyKinds reports whether every kind in the require list is a
// read-only statement type. Used by evalSQLClassify to decide whether
// the MutatesViaCTE flag should be treated as a violation.
func allReadOnlyKinds(kinds []string) bool {
	for _, k := range kinds {
		switch strings.ToUpper(k) {
		case "SELECT":
			// read-only
		default:
			return false
		}
	}
	return true
}

// evalLeaf evaluates a single field comparison.
func evalLeaf(field string, op domain.Operator, value interface{}, fields map[string]interface{}) bool {
	fieldVal, exists := resolveField(field, fields)
	if !exists {
		return false
	}

	switch op {
	case domain.OpEq:
		return compareEq(fieldVal, value)
	case domain.OpNeq:
		return !compareEq(fieldVal, value)
	case domain.OpGt:
		return compareNumeric(fieldVal, value) > 0
	case domain.OpGte:
		return compareNumeric(fieldVal, value) >= 0
	case domain.OpLt:
		return compareNumeric(fieldVal, value) < 0
	case domain.OpLte:
		return compareNumeric(fieldVal, value) <= 0
	case domain.OpIn:
		return compareIn(fieldVal, value)
	case domain.OpContains:
		return compareContains(fieldVal, value)
	case domain.OpRegex:
		return compareRegex(fieldVal, value)
	case domain.OpGtField:
		// Compare fieldVal > value of another field
		otherField, ok := value.(string)
		if !ok {
			return false
		}
		otherVal, exists := resolveField(otherField, fields)
		if !exists {
			return false
		}
		return compareNumeric(fieldVal, otherVal) > 0
	case domain.OpLtField:
		otherField, ok := value.(string)
		if !ok {
			return false
		}
		otherVal, exists := resolveField(otherField, fields)
		if !exists {
			return false
		}
		return compareNumeric(fieldVal, otherVal) < 0
	default:
		return false
	}
}

// resolveField resolves a dot-notation field path against the fields map.
func resolveField(path string, fields map[string]interface{}) (interface{}, bool) {
	// Try exact match first
	if v, ok := fields[path]; ok {
		return v, true
	}

	// Try dot-notation traversal
	parts := strings.Split(path, ".")
	var current interface{} = fields
	for _, part := range parts {
		switch m := current.(type) {
		case map[string]interface{}:
			v, ok := m[part]
			if !ok {
				return nil, false
			}
			current = v
		default:
			return nil, false
		}
	}
	return current, true
}

// compareEq checks equality with type coercion.
func compareEq(a, b interface{}) bool {
	// Normalize both to comparable types
	an := toFloat64(a)
	bn := toFloat64(b)
	if an != nil && bn != nil {
		return *an == *bn
	}

	as := fmt.Sprintf("%v", a)
	bs := fmt.Sprintf("%v", b)
	return as == bs
}

// compareNumeric returns -1, 0, or 1 for numeric comparison.
func compareNumeric(a, b interface{}) int {
	an := toFloat64(a)
	bn := toFloat64(b)
	if an == nil || bn == nil {
		return 0
	}
	if *an < *bn {
		return -1
	}
	if *an > *bn {
		return 1
	}
	return 0
}

// compareIn checks if the field value is in a list.
func compareIn(fieldVal, listVal interface{}) bool {
	var list []interface{}
	switch v := listVal.(type) {
	case []interface{}:
		list = v
	case []string:
		for _, s := range v {
			list = append(list, s)
		}
	case string:
		// Try JSON array
		if err := json.Unmarshal([]byte(v), &list); err != nil {
			return false
		}
	default:
		return false
	}

	for _, item := range list {
		if compareEq(fieldVal, item) {
			return true
		}
	}
	return false
}

// compareContains checks if a string field contains the value.
func compareContains(fieldVal, value interface{}) bool {
	fs := fmt.Sprintf("%v", fieldVal)
	vs := fmt.Sprintf("%v", value)
	return strings.Contains(fs, vs)
}

// compareRegex checks if a string field matches a regex. The compile
// goes through the process-global regexCache so the common case is a
// sync.Map.Load instead of a fresh Compile per evaluation.
func compareRegex(fieldVal, value interface{}) bool {
	fs := fmt.Sprintf("%v", fieldVal)
	pattern := fmt.Sprintf("%v", value)
	re, err := compiledRegex(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(fs)
}

// toFloat64 converts a value to float64 if possible.
func toFloat64(v interface{}) *float64 {
	var f float64
	switch n := v.(type) {
	case float64:
		f = n
	case float32:
		f = float64(n)
	case int:
		f = float64(n)
	case int64:
		f = float64(n)
	case int32:
		f = float64(n)
	case json.Number:
		var err error
		f, err = n.Float64()
		if err != nil {
			return nil
		}
	case string:
		var err error
		f, err = strconv.ParseFloat(strings.TrimSpace(n), 64)
		if err != nil {
			return nil
		}
	default:
		return nil
	}
	return &f
}

// FlattenEnvelope converts an ActionEnvelope into a flat field map for condition evaluation.
func FlattenEnvelope(env *domain.ActionEnvelope) map[string]interface{} {
	fields := make(map[string]interface{})

	// Identity
	fields["envelope_id"] = env.EnvelopeID
	fields["agent_id"] = env.AgentID
	fields["session_id"] = env.SessionID
	fields["org_id"] = env.OrgID
	fields["tool_name"] = env.ToolName
	fields["tool_group"] = env.ToolGroup

	// Extract amount from parameters. If the envelope sends a
	// malformed amount (`"amount": "abc"`, `"amount": {}`, negative
	// value, etc.), Amount() returns an error and we substitute a
	// sentinel that is larger than any plausible monetary cap. The
	// result: every `field: amount, operator: gt, value: <cap>` rule
	// fires, which is the fail-closed semantic. A hostile envelope
	// that tries to dodge an amount-cap by sending an unparseable
	// value now gets caught.
	amt, err := env.Amount()
	if err != nil {
		// 1e18 is one quintillion — well above any legitimate
		// monetary action, well below math.MaxFloat64 so it
		// participates in normal float comparisons without overflow.
		fields["amount"] = 1e18
	} else {
		fields["amount"] = amt
	}

	// Parameters as nested map
	if env.Parameters != nil {
		var params map[string]interface{}
		if err := json.Unmarshal(env.Parameters, &params); err == nil {
			for k, v := range params {
				fields["parameters."+k] = v
			}
		}
	}

	// Agent metadata
	fields["agent_version"] = env.AgentVersion
	fields["framework"] = env.Framework
	fields["turn_number"] = env.TurnNumber
	fields["department"] = env.Department
	fields["tool_server"] = env.ToolServer

	// Verified context
	v := env.Context.Verified
	fields["context.verified.customer_tier"] = v.CustomerTier
	fields["context.verified.customer_account_age_days"] = v.CustomerAccountAgeDays
	fields["context.verified.customer_lifetime_value"] = v.CustomerLifetimeValue
	fields["context.verified.customer_order_count"] = v.CustomerOrderCount
	fields["context.verified.order_total"] = v.OrderTotal
	fields["context.verified.order_age_days"] = v.OrderAge
	fields["context.verified.order_currency"] = v.OrderCurrency
	fields["context.verified.customer_id"] = v.CustomerID
	fields["context.verified.order_id"] = v.OrderID
	fields["context.verified.order_item_count"] = v.OrderItemCount
	fields["context.verified.product_category"] = v.ProductCategory
	fields["context.verified.product_category_avg_price"] = v.ProductCategoryAvgPrice
	fields["context.verified.return_request_reason"] = v.ReturnRequestReason
	fields["context.verified.return_request_status"] = v.ReturnRequestStatus
	fields["context.verified.economic_value_impact"] = v.EconomicValueImpact
	fields["context.verified.rolling_24h_total"] = v.Rolling24hTotal
	fields["context.verified.rolling_24h_count"] = v.Rolling24hCount
	fields["context.verified.rolling_7d_total"] = v.Rolling7dTotal
	fields["context.verified.rolling_7d_count"] = v.Rolling7dCount

	if v.AgentBudget != nil {
		fields["context.verified.agent_budget.total_limit"] = v.AgentBudget.TotalLimit
		fields["context.verified.agent_budget.used_today"] = v.AgentBudget.UsedToday
		fields["context.verified.agent_budget.remaining"] = v.AgentBudget.Remaining
		fields["context.verified.agent_budget.transactions_today"] = v.AgentBudget.TransactionsToday
	}

	if v.AgentVelocity != nil {
		fields["context.verified.agent_velocity.monetary_count_1h"] = v.AgentVelocity.MonetaryCount1h
		fields["context.verified.agent_velocity.monetary_sum_1h"] = v.AgentVelocity.MonetarySum1h
		fields["context.verified.agent_velocity.monetary_count_24h"] = v.AgentVelocity.MonetaryCount24h
		fields["context.verified.agent_velocity.monetary_sum_24h"] = v.AgentVelocity.MonetarySum24h
		fields["context.verified.agent_velocity.token_count_1h"] = v.AgentVelocity.TokenCount1h
		fields["context.verified.agent_velocity.token_count_24h"] = v.AgentVelocity.TokenCount24h
		fields["context.verified.agent_velocity.llm_cost_usd_1h"] = v.AgentVelocity.LLMCostUSD1h
		fields["context.verified.agent_velocity.llm_cost_usd_24h"] = v.AgentVelocity.LLMCostUSD24h
	}

	if v.Justification != nil {
		fields["context.verified.justification.reason_code"] = v.Justification.ReasonCode
		fields["context.verified.justification.verified"] = v.Justification.Verified
		fields["context.verified.justification.verification_source"] = v.Justification.VerificationSource
		fields["context.verified.justification.verification_details"] = v.Justification.VerificationDetails
	}

	// Content classification (join once, reuse for aliases)
	contentCats := strings.Join(v.ContentCategories, ",")
	fields["context.verified.content_risk"] = v.ContentRisk
	fields["context.verified.content_categories"] = contentCats
	fields["context.verified.content_classifier_tier"] = v.ContentClassifierTier
	fields["content.risk_level"] = v.ContentRisk
	fields["content.categories"] = contentCats

	// Counter-agent classification (join once, reuse for aliases)
	counterCats := strings.Join(v.CounterAgentCategories, ",")
	fields["context.verified.counter_agent_risk"] = v.CounterAgentRisk
	fields["context.verified.counter_agent_categories"] = counterCats
	fields["counter_agent.risk"] = v.CounterAgentRisk
	fields["counter_agent.categories"] = counterCats
	fields["counter_agent.reasoning"] = v.CounterAgentReasoning

	// Session state
	s := env.Context.SessionState
	fields["context.session_state.cumulative_amount"] = s.CumulativeAmount
	fields["context.session_state.actions_in_session"] = s.ActionsInSession
	fields["context.session_state.escalations_in_session"] = s.EscalationsInSession
	fields["context.session_state.denied_in_session"] = s.DeniedInSession

	// Agent-supplied context (untrusted — used for flagging, not enforcement decisions)
	if env.Context.AgentSupplied != nil {
		var agentCtx map[string]interface{}
		if err := json.Unmarshal(env.Context.AgentSupplied, &agentCtx); err == nil {
			for k, val := range agentCtx {
				fields["context.agent_supplied."+k] = val
			}
		}
	}

	return fields
}
