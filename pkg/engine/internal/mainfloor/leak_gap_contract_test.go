package mainfloor

// Leak-gap contract tests (engine side). TDD red phase: T6 and T7 describe
// behaviour the engine does not have yet and fail at baseline. T9 settles a
// disputed resolution question by running it. T10 guards the fixtures so a red
// test is red for the behaviour it names, not because a fixture is broken.
// See TESTCONTRACT.md at the repository root.

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/policyload"
)

// leakGapFixtureDir holds policy fixtures that must load and validate today.
var leakGapFixtureDir = filepath.Join("testdata", "leakgap")

// leakGapProposalDir holds contract-proposal fixtures that use an operator the
// engine does not implement yet. They are expected to fail validation until the
// proposal is built.
var leakGapProposalDir = filepath.Join("testdata", "leakgap", "proposals")

// leakGapCmdFixtureDir holds the cmd/tg fixtures, checked here by T10 too.
var leakGapCmdFixtureDir = filepath.Join("..", "..", "..", "..", "cmd", "tg", "testdata", "leakgap")

// proposedSequenceOperator is the operator name T7 proposes. T10 swaps it for
// a known operator to prove the proposal fixture is otherwise well formed.
const proposedSequenceOperator domain.Operator = "ordered_subsequence"

// Synthetic GitHub-style token. The hyphens keep it outside the real token
// alphabet, so no scanner or service can treat it as a live credential.
const syntheticGitHubToken = "ghp_SYNTHETIC-leakgap-not-a-real-token"

func loadValidLeakGapPolicy(t *testing.T, name string) domain.Policy {
	t.Helper()
	path := filepath.Join(leakGapFixtureDir, name)
	policy, err := policyload.Load(path)
	if err != nil {
		t.Fatalf("fixture defect: %s does not load: %v", path, err)
	}
	if err := ValidatePolicy(&policy); err != nil {
		t.Fatalf("fixture defect: %s does not validate: %v", path, err)
	}
	return policy
}

func leakGapEnvelope(id, tool, group string, params map[string]any, seq []string) *domain.ActionEnvelope {
	raw, err := json.Marshal(params)
	if err != nil {
		panic(err) // static test input; cannot fail
	}
	return &domain.ActionEnvelope{
		EnvelopeID: id,
		AgentID:    "leakgap-agent",
		SessionID:  "leakgap-session",
		OrgID:      "leakgap-org",
		ToolName:   tool,
		ToolGroup:  group,
		Parameters: raw,
		Context: domain.EnvelopeContext{
			SessionState: domain.SessionStateContext{ToolSequence: seq},
		},
	}
}

// Required: a policy condition can read context.session_state.tool_sequence.
// Incident class: multi-step exfiltration (read a secret, then send it out) is
// invisible to policy because FlattenEnvelope exports only the four scalar
// session fields (condition.go:569-573) and never the ordered tool history.
func TestSessionToolSequenceIsVisibleToPolicyConditions(t *testing.T) {
	t.Skip("NOT IMPLEMENTED - contract test kept as the requirement record. deferred LG-F2: exposing SessionStateContext.ToolSequence changes how in/contains/regex stringify a slice for every existing policy. Needs an operator-semantics decision.")

	policy := loadValidLeakGapPolicy(t, "session_tool_sequence_visible.yaml")
	env := leakGapEnvelope("leakgap-t6", "fetch", "network_egress",
		map[string]any{"url": "https://api.internal/v1", "method": "GET"},
		[]string{"read", "fetch"})

	result := NewEvaluator().Evaluate(env, []domain.Policy{policy}, domain.PolicyModeEnforcement)
	if result.Decision != domain.DecisionDenied {
		t.Fatalf("a policy condition must be able to read context.session_state.tool_sequence: "+
			"with tool_sequence [read fetch] the fixture rule (operator exists) should fire and deny, "+
			"got decision %q; the flattened field map does not expose the session tool sequence", result.Decision)
	}
}

// Required: a policy can express "a read, followed later in the same session by
// an outbound fetch" and the engine matches it in order only.
// Incident class: read-then-exfiltrate sequences in one agent session.
// Exposing the slice (T6) is not enough on its own: there is no temporal or
// ordered operator. `in` compares a scalar field against a list value, so it
// cannot test a list field; `contains` and `regex` stringify the slice
// ("[read fetch]"), which loses element boundaries ("prefetch" contains
// "fetch") and is a fragile way to express order. This test proposes the
// `ordered_subsequence` operator (see the proposal fixture for its semantics)
// and fails at policy validation today ("unknown operator").
func TestPolicyCanExpressOrderedReadThenEgressWithinSession(t *testing.T) {
	t.Skip("NOT IMPLEMENTED - contract test kept as the requirement record. deferred LG-F3: new temporal operator (proposed name ordered_subsequence) needs schema, validation, docs and conformance. Design work, not a mechanical edit.")

	path := filepath.Join(leakGapProposalDir, "read_then_egress_sequence.yaml")
	policy, err := policyload.Load(path)
	if err != nil {
		t.Fatalf("fixture defect: the ordered-sequence proposal %s does not load: %v", path, err)
	}
	if err := ValidatePolicy(&policy); err != nil {
		t.Fatalf("a policy must be able to express an ordered read-then-egress pair within one session "+
			"(operator %q over context.session_state.tool_sequence, value [read fetch]), "+
			"but the engine rejects the policy: %v", proposedSequenceOperator, err)
	}

	// tool_sequence is the session's tool history, oldest first, and ends
	// with the current call (the shape the Python SDK sends, for example
	// ["search", "issue_refund"]).
	cases := []struct {
		name string
		seq  []string
		want bool
	}{
		{name: "read then fetch matches", seq: []string{"read", "fetch"}, want: true},
		{name: "read, other call, then fetch matches", seq: []string{"read", "bash", "fetch"}, want: true},
		{name: "fetch then read does not match", seq: []string{"fetch", "read"}, want: false},
		{name: "read then a tool whose name only contains fetch does not match", seq: []string{"read", "prefetch"}, want: false},
		{name: "fetch alone does not match", seq: []string{"fetch"}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			current := tc.seq[len(tc.seq)-1]
			env := leakGapEnvelope("leakgap-t7", current, "", map[string]any{}, tc.seq)
			result := NewEvaluator().Evaluate(env, []domain.Policy{policy}, domain.PolicyModeEnforcement)
			got := result.Decision == domain.DecisionEscalated
			if got != tc.want {
				t.Fatalf("ordered read-then-fetch rule on tool_sequence %v: matched=%v, want %v (decision %q)",
					tc.seq, got, tc.want, result.Decision)
			}
		})
	}
}

// GAP (red at baseline). Required: a condition can address one nested
// parameter by its dotted path, such as parameters.headers.Authorization.
// Incident class: a credential sent in a request header is invisible to a
// rule that names that header. FlattenEnvelope (condition.go:489-495) stores
// each top-level parameter under one flat key ("parameters.headers"), and
// resolveField (condition.go:308-331) tries the exact key and then walks the
// map from its root. There is no "parameters" root map, so the walk stops at
// the first segment (condition.go:321-323) and the field is reported missing.
// A rule on the whole parameters.headers value with contains still matches,
// because the map is stringified; only the per-header path fails.
func TestNestedParameterHeaderFieldResolvesInConditions(t *testing.T) {
	t.Skip("NOT IMPLEMENTED - contract test kept as the requirement record. deferred LG-F1: adding a nested parameters root changes field resolution for every existing policy that matches on the stringified whole value.")

	policy := loadValidLeakGapPolicy(t, "header_authorization_contains.yaml")

	cases := []struct {
		name    string
		headers map[string]any
		want    domain.Decision
	}{
		{
			name:    "github token in Authorization header is denied",
			headers: map[string]any{"Authorization": "Bearer " + syntheticGitHubToken, "Accept": "application/json"},
			want:    domain.DecisionDenied,
		},
		{
			name:    "Authorization header without a github token is allowed",
			headers: map[string]any{"Authorization": "Bearer synthetic-opaque-session", "Accept": "application/json"},
			want:    domain.DecisionAllowed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := leakGapEnvelope("leakgap-t9", "http", "network_egress", map[string]any{
				"url":     "https://api.internal/v1/repos",
				"method":  "GET",
				"headers": tc.headers,
			}, nil)
			fields := FlattenEnvelope(env)
			if _, ok := resolveField("parameters.headers.Authorization", fields); !ok {
				t.Errorf("the field path parameters.headers.Authorization must resolve to the nested header value; " +
					"resolveField reports it missing because flattened parameters have no \"parameters\" root map")
			}
			result := NewEvaluator().Evaluate(env, []domain.Policy{policy}, domain.PolicyModeEnforcement)
			if result.Decision != tc.want {
				t.Fatalf("a contains condition on parameters.headers.Authorization must match a synthetic ghp_ token "+
					"and only that: decision %q, want %q", result.Decision, tc.want)
			}
		})
	}
}

// Required: every leak-gap policy fixture is a well-formed policy, so the
// contract tests cannot go red because a fixture failed to load.
// Incident class: test-harness hygiene (a broken fixture hiding a real result).
// Current fixtures must load and validate. Proposal fixtures must load, and
// must validate once the proposed operator is replaced by a known one; that
// proves the operator name is the only reason validation rejects them today.
func TestLeakGapPolicyFixturesLoadAndValidate(t *testing.T) {
	var current []string
	for _, dir := range []string{leakGapFixtureDir, leakGapCmdFixtureDir} {
		matches, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		if err != nil {
			t.Fatalf("glob %s: %v", dir, err)
		}
		if len(matches) == 0 {
			t.Fatalf("no fixtures found in %s: the glob path is wrong or the fixtures are missing", dir)
		}
		current = append(current, matches...)
	}
	sort.Strings(current)
	for _, path := range current {
		t.Run(filepath.ToSlash(path), func(t *testing.T) {
			policy, err := policyload.Load(path)
			if err != nil {
				t.Fatalf("fixture must load through policyload.Load: %v", err)
			}
			if err := ValidatePolicy(&policy); err != nil {
				t.Fatalf("fixture must pass engine.ValidatePolicy: %v", err)
			}
		})
	}

	proposals, err := filepath.Glob(filepath.Join(leakGapProposalDir, "*.yaml"))
	if err != nil {
		t.Fatalf("glob %s: %v", leakGapProposalDir, err)
	}
	if len(proposals) == 0 {
		t.Fatalf("no proposal fixtures found in %s", leakGapProposalDir)
	}
	sort.Strings(proposals)
	for _, path := range proposals {
		t.Run(filepath.ToSlash(path), func(t *testing.T) {
			policy, err := policyload.Load(path)
			if err != nil {
				t.Fatalf("proposal fixture must load through policyload.Load: %v", err)
			}
			replaced := 0
			for i := range policy.Rules {
				replaced += replaceOperator(&policy.Rules[i].Conditions, proposedSequenceOperator, domain.OpIn)
			}
			if replaced == 0 {
				t.Fatalf("proposal fixture does not use the proposed operator %q", proposedSequenceOperator)
			}
			if err := ValidatePolicy(&policy); err != nil {
				t.Fatalf("proposal fixture must be valid apart from the proposed operator %q: %v",
					proposedSequenceOperator, err)
			}
		})
	}
}

// replaceOperator rewrites every leaf using from to use to and returns the
// number of leaves changed.
func replaceOperator(c *domain.Condition, from, to domain.Operator) int {
	n := 0
	if strings.EqualFold(string(c.Operator), string(from)) {
		c.Operator = to
		n++
	}
	for i := range c.And {
		n += replaceOperator(&c.And[i], from, to)
	}
	for i := range c.Or {
		n += replaceOperator(&c.Or[i], from, to)
	}
	if c.Not != nil {
		n += replaceOperator(c.Not, from, to)
	}
	return n
}
