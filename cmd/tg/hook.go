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
	"github.com/dimaggi-ai/tool-guard-core/pkg/policyload"
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
// Decision mapping (on the engine's action_taken, not its decision — the
// two differ in shadow mode): `denied` → deny, `escalated` → ask,
// everything else (including `allowed_shadow`) → allow.
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
	var protectPath repeatablePathFlag
	fs.Var(&protectPath, "protect-path", "path prefix denied before policy eval; repeat for multiple paths")
	protectSelf := fs.Bool("protect-self", false, "shorthand: also protect the policy dir/file and $HOME/.claude from writes")
	auditLog := fs.String("audit-log", "", "append each hook decision to this SHA-256 hash-chained JSONL log (tamper-evident, verify with `tg verify`); empty disables")
	unknownToolsDeny := fs.Bool("unknown-tools-deny", false, "deny any tool_name not declared in scope.tool_names of some loaded ENFORCEMENT policy (closes the tool-name-spoofing/new-tool-goes-ungoverned class); mirrors tg-proxy's -unknown-tools-deny")

	parseErr := fs.Parse(args)

	failTools := csvSet(*failClosedTools)
	// failDecide picks the on-error decision for a KNOWN tool name.
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
	// failUnattributable is the on-error decision when we CANNOT identify the
	// tool (unreadable / oversized / malformed stdin, or a flag parse error).
	// If ANY fail-closed mode is engaged, deny: an unparseable PreToolUse
	// payload cannot be proven non-destructive, and the operator explicitly
	// asked for destructive calls to fail closed. Pure default (no fail-closed
	// flags) still fails open so a transient glitch never wedges the agent.
	failUnattributable := func(why string) (string, string) {
		if *failClosed || len(failTools) > 0 {
			return "deny", fmt.Sprintf("Tool Guard hook could not read/parse the tool call (%s); failing closed (fail-closed engaged)", why)
		}
		return "allow", ""
	}

	if parseErr != nil {
		// A flag misconfiguration (or -h) can't be evaluated. -h prints a
		// short usage; anything else is an unattributable error.
		if errors.Is(parseErr, flag.ErrHelp) {
			fmt.Fprint(os.Stderr, hookUsage)
			return 0
		}
		d, reason := failUnattributable("flag parse error")
		emitHookDecisionTo(stdout, d, reason)
		return 0
	}

	// Cap stdin (a PreToolUse payload is small; an oversized one is either a
	// bug or an attempt to exhaust memory) and surface read errors instead of
	// silently treating a partial read as valid.
	const maxHookStdin = 1 << 20 // 1 MiB
	raw, rerr := io.ReadAll(io.LimitReader(stdin, maxHookStdin+1))
	if rerr != nil {
		d, reason := failUnattributable("stdin read error")
		emitHookDecisionTo(stdout, d, reason)
		return 0
	}
	if len(raw) > maxHookStdin {
		d, reason := failUnattributable("oversized stdin")
		emitHookDecisionTo(stdout, d, reason)
		return 0
	}

	var in hookInput
	if err := json.Unmarshal(raw, &in); err != nil {
		// Unparseable stdin: we don't know the tool. Fail closed if any
		// fail-closed mode is engaged (can't prove it's non-destructive),
		// else fail open.
		d, reason := failUnattributable("malformed JSON")
		emitHookDecisionTo(stdout, d, reason)
		return 0
	}

	tool := strings.ToLower(strings.TrimSpace(in.ToolName))
	if tool == "" {
		tool = "bash"
	}

	env := hookEnvelope(tool, in, *agentID)
	auditPolicyHash, _ := policyload.PolicySetHash(nil)

	// emitAudited emits the decision and, when -audit-log is set, appends it
	// to the hash chain (best-effort — an audit failure never changes the
	// decision). Used for every decision that has a real envelope.
	emitAudited := func(dec, reason string, result *domain.EvaluationResult) {
		emitHookDecisionTo(stdout, dec, reason)
		if *auditLog != "" {
			appendHookAuditBestEffort(os.Stderr, *auditLog, env, result, dec, reason, auditPolicyHash)
		}
	}

	// ── Protected paths (Feature B) — BEFORE policy eval, unconditional ──
	protectList := append(splitCSVPaths(*protectPaths), protectPath...)
	if *protectSelf {
		protectList = append(selfProtectPaths(*policyDir, *policyFile), protectList...)
	}
	if violated, reason := engine.ViolatesProtectedPaths(env, protectList); violated {
		emitAudited("deny", reason, nil)
		return 0
	}

	// A policy source is required to evaluate. Missing one is an operator
	// config error, not a runtime error — treat it as internal-error so the
	// fail-open/closed policy applies. (Protected paths above still ran.)
	if *policyDir == "" && *policyFile == "" {
		d, reason := failDecide(tool)
		emitAudited(d, reason, nil)
		return 0
	}

	mode := domain.PolicyModeEnforcement
	if *modeStr == "shadow" {
		mode = domain.PolicyModeShadow
	}

	dec, reason, result, auditPolicyHash := evalHook(*policyDir, *policyFile, env, mode, failDecide, *unknownToolsDeny)
	emitAudited(dec, reason, result)
	return 0
}

// evalHook loads the policy set and evaluates env, recovering from any panic
// so the hook can never crash the agent. On load failure or panic it returns
// the fail-open/closed decision for env.ToolName.
func evalHook(policyDir, policyFile string, env *domain.ActionEnvelope, mode domain.PolicyMode, failDecide func(string) (string, string), unknownToolsDeny bool) (dec string, reason string, result *domain.EvaluationResult, policySetHash string) {
	policySetHash, _ = policyload.PolicySetHash(nil)
	defer func() {
		if r := recover(); r != nil {
			dec, reason = failDecide(env.ToolName)
			result = nil
			if reason == "" && dec == "deny" {
				reason = fmt.Sprintf("Tool Guard hook panicked during evaluation: %v", r)
			}
		}
	}()

	policies, err := loadPolicySet(policyDir, policyFile)
	if err != nil || len(policies) == 0 {
		// Say so on stderr, always: in the default fail-open configuration
		// this branch means NO policy is enforced for this call, and with
		// strict decoding a single stale field in one file fails the whole
		// set. A silent allow here turns a working deny into nothing on
		// upgrade; Claude Code surfaces hook stderr, so the operator at
		// least sees why.
		if err != nil {
			fmt.Fprintf(os.Stderr, "tg hook: policy load failed — no policy enforced for this call: %v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, "tg hook: no policies loaded — no policy enforced for this call")
		}
		dec, reason = failDecide(env.ToolName)
		return dec, reason, nil, policySetHash
	}
	policySetHash, err = policyload.PolicySetHash(policies)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tg hook: policy-set hash failed — no policy enforced for this call: %v\n", err)
		dec, reason = failDecide(env.ToolName)
		return dec, reason, nil, policySetHash
	}

	// Tool-name spoof guard, evaluated BEFORE the engine call so a denied
	// unknown tool never needs the engine to have matched anything — same
	// ordering and semantics as tg-proxy's -unknown-tools-deny (see
	// engine.ToolNameKnown's doc comment for why shadow-mode policies don't
	// count). Closes the coverage gap where tg-proxy had this gate and tg
	// hook — the actual coding-agent enforcement point — did not.
	if unknownToolsDeny && !engine.ToolNameKnown(env.ToolName, policies) {
		return "deny", fmt.Sprintf("tool_name %q is not declared in scope.tool_names of any loaded ENFORCEMENT policy (-unknown-tools-deny)", env.ToolName), nil, policySetHash
	}

	result = engine.NewEvaluator().Evaluate(env, policies, mode)
	// Branches on ActionTaken (what actually happened), NOT Decision (what
	// would have happened). In shadow mode the engine reports
	// Decision=denied/escalated alongside ActionTaken=allowed_shadow — the
	// call is never actually meant to be blocked. Switching on Decision
	// here made `tg hook -mode shadow` silently enforce every policy,
	// since a PreToolUse "deny" IS enforced by the calling agent regardless
	// of what the engine's own mode label says. Same bug class as the SDK's
	// decision-vs-action_taken fixes (see docs/REVIEW-PROCESS.md pillar 1)
	// — found here by an adversarial review pass that specifically went
	// looking for it after the SDK fixes landed.
	switch result.ActionTaken {
	case domain.ActionDenied:
		return "deny", hookReason(result), result, policySetHash
	case domain.ActionEscalated:
		return "ask", hookReason(result), result, policySetHash
	default:
		return "allow", "", result, policySetHash
	}
}

// hookReason explains the applied action, not a stricter shadow-only raw
// decision. In a mixed set, AppliedPrimaryCitation names the rule that really
// blocked or escalated the call; PrimaryCitation may belong to telemetry.
func hookReason(r *domain.EvaluationResult) string {
	if r.AppliedPrimaryCitation != nil && r.AppliedPrimaryCitation.Excerpt != "" {
		return r.AppliedPrimaryCitation.Excerpt
	}
	if ((r.ActionTaken == domain.ActionDenied && r.Decision == domain.DecisionDenied) ||
		(r.ActionTaken == domain.ActionEscalated && r.Decision == domain.DecisionEscalated)) &&
		r.PrimaryCitation != nil && r.PrimaryCitation.Excerpt != "" {
		return r.PrimaryCitation.Excerpt
	}
	return r.DecisionReason
}

// hookInput is the PreToolUse stdin object. tool_input is kept raw so the
// FULL parameter set (command, file_path, path, and any arrays / nested edit
// objects) flows into the envelope — cherry-picking three fields would let an
// array-of-paths write slip past protected-path checks.
type hookInput struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

// hookEnvelope maps a PreToolUse object onto an ActionEnvelope, forwarding the
// entire tool_input as parameters. Falls back to an empty object when
// tool_input is absent or not a JSON object.
func hookEnvelope(tool string, in hookInput, agentID string) *domain.ActionEnvelope {
	params := json.RawMessage(`{}`)
	if len(in.ToolInput) > 0 {
		var probe map[string]interface{}
		if json.Unmarshal(in.ToolInput, &probe) == nil {
			params = in.ToolInput
		}
	}

	return &domain.ActionEnvelope{
		EnvelopeID: fmt.Sprintf("hook-%d", time.Now().UnixNano()),
		Timestamp:  time.Now().UTC(),
		AgentID:    agentID,
		SessionID:  "tg-hook",
		OrgID:      "local",
		ToolName:   tool,
		ToolGroup:  hookToolGroup(tool),
		Parameters: params,
	}
}

// hookToolGroup is a small heuristic so tool_groups-scoped policies match.
// Keep write and network capabilities distinct from read-only filesystem
// tools: grouping them together would make a write-classifier policy evaluate
// (and fail closed) on harmless reads.
func hookToolGroup(tool string) string {
	switch tool {
	case "write", "edit", "notebookedit", "apply_patch", "multiedit", "create":
		return "filesystem_writes"
	case "read":
		return "filesystem"
	case "http", "fetch", "webfetch":
		return "network_egress"
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

// repeatablePathFlag preserves paths exactly, including commas. The legacy
// -protect-paths comma list remains supported for hand-written invocations,
// while generated integrations use repeatable -protect-path flags so valid
// filesystem names cannot be split accidentally.
type repeatablePathFlag []string

func (p *repeatablePathFlag) String() string {
	return strings.Join(*p, ",")
}

func (p *repeatablePathFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("protected path cannot be empty")
	}
	*p = append(*p, value)
	return nil
}

const hookUsage = `tg hook — PreToolUse guard for coding agents

Usage:
  tg hook (-policy-dir DIR | -policy FILE) [-mode shadow|enforcement]
          [-agent-id NAME] [-fail-closed] [-fail-closed-tools bash,write,edit]
          [-protect-path PATH ...] [-protect-paths P1,P2]
          [-protect-self] [-unknown-tools-deny]

Reads ONE PreToolUse JSON object on stdin, evaluates it, and writes a
hookSpecificOutput permissionDecision (deny|ask|allow) to stdout. Always
exits 0.

RECOMMENDED for any enforcing deployment: pass -fail-closed-tools (or
-fail-closed). Without one, an internal error (unparseable stdin, a policy
load failure, an evaluator panic) fails OPEN — allow — by default, so a
tooling glitch never wedges the agent, but that also means the error is
never denied either. That default suits local dev; it is not what you want
once this hook is actually enforcing policy.
`
