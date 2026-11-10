package main

// -escalate-as decides how a policy escalation is returned to the harness.
// Measured 2026-11-09: Codex CLI 0.166.0 ran a tool call the hook answered
// "ask" to, so on that harness an escalate rule stops nothing unless the hook
// returns "deny" instead. These tests pin the conversion and its limits.

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	escalateAsGitPayload    = `{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}`
	escalateAsRmPayload     = `{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"}}`
	escalateAsLsPayload     = `{"tool_name":"Bash","tool_input":{"command":"ls -la"}}`
	escalateAsAgyGitPayload = `{"toolCall":{"name":"run_command","args":{"CommandLine":"git push origin main"}}}`
)

func TestHookEscalateAsDefaultKeepsAsk(t *testing.T) {
	pol := writeHookPolicy(t, hookAskPolicy)
	out, code := runHookStr(t, escalateAsGitPayload, "-policy", pol)
	if code != 0 {
		t.Fatalf("hook must exit 0, got %d", code)
	}
	if got := hookDecision(t, out); got != "ask" {
		t.Fatalf("without -escalate-as an escalation must stay ask, got %q; output=%s", got, out)
	}
}

func TestHookEscalateAsAskIsExplicitDefault(t *testing.T) {
	pol := writeHookPolicy(t, hookAskPolicy)
	out, _ := runHookStr(t, escalateAsGitPayload, "-policy", pol, "-escalate-as", "ask")
	if got := hookDecision(t, out); got != "ask" {
		t.Fatalf("-escalate-as ask must return ask, got %q; output=%s", got, out)
	}
}

func TestHookEscalateAsDenyConvertsEscalation(t *testing.T) {
	pol := writeHookPolicy(t, hookAskPolicy)
	out, code := runHookStr(t, escalateAsGitPayload, "-policy", pol, "-escalate-as", "deny")
	if code != 0 {
		t.Fatalf("hook must exit 0, got %d", code)
	}
	dec, reason := hookDecisionReason(t, out)
	if dec != "deny" {
		t.Fatalf("-escalate-as deny must return deny for an escalated call, got %q; output=%s", dec, out)
	}
	if !strings.Contains(reason, "-escalate-as deny") {
		t.Errorf("the reason must say the escalation was converted, got %q", reason)
	}
	if !strings.Contains(reason, "git needs review") {
		t.Errorf("the reason must keep the rule's own text, got %q", reason)
	}
}

func TestHookEscalateAsDenyLeavesAllowAndDenyAlone(t *testing.T) {
	ask := writeHookPolicy(t, hookAskPolicy)
	out, _ := runHookStr(t, escalateAsLsPayload, "-policy", ask, "-escalate-as", "deny")
	if got := hookDecision(t, out); got != "allow" {
		t.Errorf("-escalate-as deny must not touch an allowed call, got %q", got)
	}
	deny := writeHookPolicy(t, hookDenyPolicy)
	out, _ = runHookStr(t, escalateAsRmPayload, "-policy", deny, "-escalate-as", "deny")
	dec, reason := hookDecisionReason(t, out)
	if dec != "deny" {
		t.Errorf("a denied call must stay denied, got %q", dec)
	}
	if strings.Contains(reason, "-escalate-as") {
		t.Errorf("a real denial must not be labelled as a converted escalation, got %q", reason)
	}
}

func TestHookEscalateAsUnknownValueFailsSafeToDeny(t *testing.T) {
	pol := writeHookPolicy(t, hookAskPolicy)
	out, _ := runHookStr(t, escalateAsGitPayload, "-policy", pol, "-escalate-as", "prompt")
	if got := hookDecision(t, out); got != "deny" {
		t.Fatalf("an unrecognised -escalate-as value must fail safe to deny, got %q; output=%s", got, out)
	}
}

func TestHookEscalateAsDenyAppliesBeforeAntigravityEscalation(t *testing.T) {
	pol := writeHookPolicy(t, strings.Replace(hookAskPolicy, "tool_names: [bash]", "tool_names: [bash, run_command]", 1))
	decode := func(out string) string {
		t.Helper()
		var agy struct {
			Decision string `json:"decision"`
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &agy); err != nil {
			t.Fatalf("antigravity dialect must emit a top-level decision: %v; output=%s", err, out)
		}
		return agy.Decision
	}
	out, _ := runHookStr(t, escalateAsAgyGitPayload, "-policy", pol)
	if got := decode(out); got != "force_ask" {
		t.Fatalf("baseline: an Antigravity escalation must be force_ask, got %q", got)
	}
	out, _ = runHookStr(t, escalateAsAgyGitPayload, "-policy", pol, "-escalate-as", "deny")
	if got := decode(out); got != "deny" {
		t.Fatalf("-escalate-as deny must win over -antigravity-escalation, got %q; output=%s", got, out)
	}
	out, _ = runHookStr(t, escalateAsAgyGitPayload, "-policy", pol, "-escalate-as", "deny", "-antigravity-escalation", "ask")
	if got := decode(out); got != "deny" {
		t.Fatalf("-escalate-as deny must win over -antigravity-escalation ask, got %q; output=%s", got, out)
	}
}

func TestHookUsageNamesEveryDecisionFlag(t *testing.T) {
	for _, flagName := range []string{
		"-dialect", "-antigravity-escalation", "-escalate-as",
		"-fail-closed-groups", "-audit-log",
	} {
		if !strings.Contains(hookUsage, flagName) {
			t.Errorf("tg hook -h does not mention %s", flagName)
		}
	}
}
