package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

// cmdHook is a first-class PreToolUse guard for coding agents (Claude Code,
// Codex, Antigravity). It replaces the hand-rolled jq shell adapters in
// examples/coding-agent-guard/hooks with one binary that speaks the hook
// JSON contract directly.
//
// Contract:
//
//	stdin  : {"tool_name":"Bash","tool_input":{"command":"...","file_path":"...","path":"..."}}
//	stdout : {"hookSpecificOutput":{"hookEventName":"PreToolUse",
//	          "permissionDecision":"deny|ask|allow","permissionDecisionReason":"..."}}
//	exit   : ALWAYS 0 — a PreToolUse hook signals via JSON, never via exit code.
//
// Decision mapping: engine `denied` → deny, `escalated` → ask, everything
// else → allow.
//
// Fail-open by default: any internal error (unparseable stdin, policy load
// failure, eval panic) emits allow so a tooling glitch never wedges the
// machine. -fail-closed flips that to deny; -fail-closed-tools denies ONLY
// for the named tools on error (the careful-operator default — deny a
// destructive Bash on error, but don't wedge on a Read glitch).
//
// -protect-paths / -protect-self apply the SAME unconditional protected-path
// deny that tg-proxy applies, BEFORE policy evaluation. A policy cannot turn
// it off (the point: the agent can edit the policy, but not these flags).
func cmdHook(args []string) int {
	return runHook(args, os.Stdin, os.Stdout)
}

// runHook is the testable inner implementation of cmdHook. It accepts an
// explicit stdin reader and stdout writer so unit tests can drive it without
// spawning a process. cmdHook is the thin public entry point that passes
// os.Stdin / os.Stdout.
func runHook(args []string, stdin io.Reader, stdout io.Writer) int {
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // hooks stay quiet; we signal via JSON on stdout
	policyDir := fs.String("policy-dir", "", "directory of *.yaml/*.yml policies (mutually exclusive with -policy)")
	policyFile := fs.String("policy", "", "single policy YAML (mutually exclusive with -policy-dir)")
	modeStr := fs.String("mode", "enforcement", "shadow | enforcement")
	agentID := fs.String("agent-id", "coding-agent", "agent_id recorded on the synthesized envelope")
	failClosed := fs.Bool("fail-closed", false, "on internal error, emit deny instead of allow")
	failClosedTools := fs.String("fail-closed-tools", "", "comma list of tool names to fail CLOSED for on internal error (others fail open); overrides -fail-closed's global behavior")
	protectPaths := fs.String("protect-paths", "", "comma list of path prefixes; a write-capable tool targeting one is denied BEFORE policy eval, unconditionally")
	protectSelf := fs.Bool("protect-self", false, "shorthand: also protect the policy dir/file and $HOME/.claude from writes")

	parseErr := fs.Parse(args)

	failTools := csvSet(*failClosedTools)
	// failDecide picks the on-error decision for a given tool name.
	failDecide := func(tool string) (string, string) {
		if len(failTools) > 0 {
			if failTools[strings.ToLower(tool)] {
				return "deny", fmt.Sprintf("Tool Guard hook could not evaluate; failing closed for tool %q (-fail-closed-tools)", tool)
			}
			return "allow", ""
		}
		if *failClosed {
			return "deny", "Tool Guard hook could not evaluate; failing closed (-fail-closed)"
		}
		return "allow", ""
	}

	if parseErr != nil {
		// A flag misconfiguration (or -h) can't be evaluated. -h prints a
		// short usage; anything else fails open so a broken invocation never
		// wedges the agent.
		if errors.Is(parseErr, flag.ErrHelp) {
			fmt.Fprint(os.Stderr, hookUsage)
			return 0
		}
		d, reason := failDecide("")
		emitHookDecisionTo(stdout, d, reason)
		return 0
	}

	raw, _ := io.ReadAll(stdin)

	var in hookInput
	if err := json.Unmarshal(raw, &in); err != nil {
		// Unparseable stdin: we don't know the tool, so -fail-closed-tools
		// can't match — that intentionally fails open (don't wedge on a
		// glitch we can't attribute to a destructive tool).
		d, reason := failDecide("")
		emitHookDecisionTo(stdout, d, reason)
		return 0
	}

	tool := strings.ToLower(strings.TrimSpace(in.ToolName))
	if tool == "" {
		tool = "bash"
	}

	env := hookEnvelope(tool, in, *agentID)

	// ── Protected paths (Feature B) — BEFORE policy eval, unconditional ──
	protectList := splitCSVPaths(*protectPaths)
	if *protectSelf {
		protectList = append(selfProtectPaths(*policyDir, *policyFile), protectList...)
	}
	if violated, reason := engine.ViolatesProtectedPaths(env, protectList); violated {
		emitHookDecisionTo(stdout, "deny", reason)
		return 0
	}

	// A policy source is required to evaluate. Missing one is an operator
	// config error, not a runtime error — treat it as internal-error so the
	// fail-open/closed policy applies. (Protected paths above still ran.)
	if *policyDir == "" && *policyFile == "" {
		d, reason := failDecide(tool)
		emitHookDecisionTo(stdout, d, reason)
		return 0
	}

	mode := domain.PolicyModeEnforcement
	if *modeStr == "shadow" {
		mode = domain.PolicyModeShadow
	}

	dec, reason := evalHook(*policyDir, *policyFile, env, mode, failDecide)
	emitHookDecisionTo(stdout, dec, reason)
	return 0
}

// evalHook loads the policy set and evaluates env, recovering from any panic
// so the hook can never crash the agent. On load failure or panic it returns
// the fail-open/closed decision for env.ToolName.
func evalHook(policyDir, policyFile string, env *domain.ActionEnvelope, mode domain.PolicyMode, failDecide func(string) (string, string)) (dec string, reason string) {
	defer func() {
		if r := recover(); r != nil {
			dec, reason = failDecide(env.ToolName)
			if reason == "" && dec == "deny" {
				reason = fmt.Sprintf("Tool Guard hook panicked during evaluation: %v", r)
			}
		}
	}()

	policies, err := loadPolicySet(policyDir, policyFile)
	if err != nil || len(policies) == 0 {
		return failDecide(env.ToolName)
	}

	result := engine.NewEvaluator().Evaluate(env, policies, mode)
	switch result.Decision {
	case domain.DecisionDenied:
		return "deny", hookReason(result)
	case domain.DecisionEscalated:
		return "ask", hookReason(result)
	default:
		return "allow", ""
	}
}

// hookReason prefers the primary citation excerpt (the "why" an auditor
// wants) and falls back to the engine's decision reason.
func hookReason(r *domain.EvaluationResult) string {
	if r.PrimaryCitation != nil && r.PrimaryCitation.Excerpt != "" {
		return r.PrimaryCitation.Excerpt
	}
	return r.DecisionReason
}

// hookInput is the PreToolUse stdin object. Only the fields the engine maps
// are decoded; extra fields are ignored.
type hookInput struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command  string `json:"command"`
		FilePath string `json:"file_path"`
		Path     string `json:"path"`
	} `json:"tool_input"`
}

// hookEnvelope maps a PreToolUse object onto an ActionEnvelope. Parameters
// carry only the non-empty {command, file_path, path} fields.
func hookEnvelope(tool string, in hookInput, agentID string) *domain.ActionEnvelope {
	params := map[string]string{}
	if in.ToolInput.Command != "" {
		params["command"] = in.ToolInput.Command
	}
	if in.ToolInput.FilePath != "" {
		params["file_path"] = in.ToolInput.FilePath
	}
	if in.ToolInput.Path != "" {
		params["path"] = in.ToolInput.Path
	}
	pj, _ := json.Marshal(params)

	return &domain.ActionEnvelope{
		EnvelopeID: fmt.Sprintf("hook-%d", time.Now().UnixNano()),
		Timestamp:  time.Now().UTC(),
		AgentID:    agentID,
		SessionID:  "tg-hook",
		OrgID:      "local",
		ToolName:   tool,
		ToolGroup:  hookToolGroup(tool),
		Parameters: pj,
	}
}

// hookToolGroup is a small heuristic so tool_groups-scoped policies match:
// shell-executing tools → "shell", file tools → "filesystem", else "shell".
func hookToolGroup(tool string) string {
	switch tool {
	case "write", "edit", "notebookedit", "multiedit", "read", "create":
		return "filesystem"
	default:
		return "shell"
	}
}

// selfProtectPaths expands -protect-self to the policy source location plus
// the coding-agent config dir ($HOME/.claude). Keeping this general: it
// protects the directory the policies live in (whether given via -policy-dir
// or the dir of -policy) so the agent can't rewrite the rules guarding it.
func selfProtectPaths(policyDir, policyFile string) []string {
	var out []string
	if policyDir != "" {
		out = append(out, filepath.Clean(policyDir))
	}
	if policyFile != "" {
		out = append(out, filepath.Dir(filepath.Clean(policyFile)))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		out = append(out, filepath.Join(home, ".claude"))
	}
	return out
}

// hookOutput is the PreToolUse response shape the harness reads.
type hookOutput struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	} `json:"hookSpecificOutput"`
}

// emitHookDecisionTo writes the hook JSON to w. It never returns an error
// to the caller — a hook must always exit 0.
func emitHookDecisionTo(w io.Writer, decision, reason string) {
	var out hookOutput
	out.HookSpecificOutput.HookEventName = "PreToolUse"
	out.HookSpecificOutput.PermissionDecision = decision
	out.HookSpecificOutput.PermissionDecisionReason = reason
	_ = json.NewEncoder(w).Encode(out)
}

// emitHookDecision is the os.Stdout-bound variant kept for any callers
// outside runHook (currently none, but exported as a convenience so
// future shell-adapter helpers can use it without threading a writer).
func emitHookDecision(decision, reason string) {
	emitHookDecisionTo(os.Stdout, decision, reason)
}

// csvSet parses a comma list into a lowercased set.
func csvSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" {
			out[part] = true
		}
	}
	return out
}

// splitCSVPaths parses a comma list of paths, trimming blanks. Paths are
// left as-is (ViolatesProtectedPaths cleans them).
func splitCSVPaths(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

const hookUsage = `tg hook — PreToolUse guard for coding agents

Usage:
  tg hook (-policy-dir DIR | -policy FILE) [-mode shadow|enforcement]
          [-agent-id NAME] [-fail-closed] [-fail-closed-tools bash,write,edit]
          [-protect-paths P1,P2] [-protect-self]

Reads ONE PreToolUse JSON object on stdin, evaluates it, and writes a
hookSpecificOutput permissionDecision (deny|ask|allow) to stdout. Always
exits 0.
`
