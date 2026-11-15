package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
	"github.com/dimaggi-ai/tool-guard-core/pkg/policyload"
	"sort"
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
	// hookChildArg is internal: only the supervisor passes it.
	if len(args) > 0 && args[0] == hookChildArg {
		return runHook(args[1:], os.Stdin, os.Stdout)
	}
	if hookDispatchRequested(args) {
		return superviseHook(os.Stdin, os.Stdout, os.Stderr, hookSuperviseTimeout, hookChildCommand(args), args...)
	}
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
	failClosedGroups := fs.String("fail-closed-groups", "", "comma list of tool groups (shell, filesystem_writes, filesystem, network_egress) to fail CLOSED for on internal error; a tool name the hook does not recognise is in group shell. A tool fails closed when its name is in -fail-closed-tools OR its group is listed here")
	escalateAs := fs.String("escalate-as", "ask", "how a policy escalation is returned to the harness: ask (default) | deny. Use deny for a harness measured to run a call the hook answered ask to, or for an unattended run where nobody can answer a prompt. Any other value is treated as deny")
	agyEscalation := fs.String("antigravity-escalation", "force_ask", "how an escalation is expressed to Antigravity: force_ask (default; the Antigravity hooks documentation says it prompts even where an \"Always Allow\" rule exists, which ask does not; not measured here) | ask (the harness's own value). Antigravity CLI started with --dangerously-skip-permissions ran the call after either value in the release run. See docs/support-matrix.md.")
	dialectStr := fs.String("dialect", "auto", "hook payload and output dialect: auto | claude | antigravity. auto reads the input shape")
	protectPaths := fs.String("protect-paths", "", "comma list of path prefixes; a write-capable tool targeting one is denied BEFORE policy eval, unconditionally")
	var protectPath repeatablePathFlag
	fs.Var(&protectPath, "protect-path", "path prefix denied before policy eval; repeat for multiple paths")
	protectSelf := fs.Bool("protect-self", false, "shorthand: also protect the policy dir/file and $HOME/.claude from writes")
	auditLog := fs.String("audit-log", "", "append each hook decision to this SHA-256 hash-chained JSONL log (tamper-evident, verify with `tg verify`); empty disables")
	unknownToolsDeny := fs.Bool("unknown-tools-deny", false, "deny any tool_name not declared in scope.tool_names of some loaded ENFORCEMENT policy (closes the tool-name-spoofing/new-tool-goes-ungoverned class); mirrors tg-proxy's -unknown-tools-deny")
	dispatch := fs.String("dispatch", "", "gh_read: after policy evaluation allows a Bash call, allow verified gh reads; validated literal pwd/ls return no decision in the claude dialect and ask in other dialects; everything else asks and every internal error denies")

	parseErr := fs.Parse(args)
	// Until input is decoded, auto has no known harness. Include both
	// contracts on early errors so either harness receives the decision.
	dialect := *dialectStr
	if dialect != dialectClaude && dialect != dialectAntigravity {
		dialect = dialectBoth
	}

	failTools := csvSet(*failClosedTools)
	failGroups := csvSet(*failClosedGroups)
	dispatching := *dispatch != "" || hookDispatchRequested(args)
	var env *domain.ActionEnvelope
	auditPolicyHash, _ := policyload.PolicySetHash(nil)
	// Dispatch records the decision before output and denies on audit failure.
	// Other calls preserve the best-effort audit behavior.
	emitAudited := func(dec, reason string, result *domain.EvaluationResult) {
		if dispatching && *auditLog != "" {
			auditEnv := env
			if auditEnv == nil {
				auditEnv = hookEnvelope("", hookInput{}, *agentID)
			}
			if err := appendHookAudit(*auditLog, auditEnv, result, dec, reason, auditPolicyHash); err != nil {
				fmt.Fprintf(os.Stderr, "tg hook: audit append failed under -dispatch; denying: %v\n", err)
				dec, reason = "deny", "Tool Guard hook could not write its audit record; failing closed (-dispatch)"
			}
		}
		emitHookDecisionDialect(stdout, dialect, *agyEscalation, dec, reason)
		if !dispatching && env != nil && *auditLog != "" {
			appendHookAuditBestEffort(os.Stderr, *auditLog, env, result, dec, reason, auditPolicyHash)
		}
	}
	if dispatching {
		// A panic outside evalHook (dispatch, audit) must still deny. If the
		// supervisor is skipped, nothing else would turn it into a decision.
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "tg hook: panic under -dispatch; denying: %v\n", r)
				emitAudited("deny", "Tool Guard hook failed internally; failing closed (-dispatch)", nil)
			}
		}()
	}
	// failDecide picks the on-error decision for a KNOWN tool name.
	failDecide := func(tool string) (string, string) {
		if dispatching {
			return "deny", fmt.Sprintf("Tool Guard hook could not evaluate; failing closed for tool %q (-dispatch)", tool)
		}
		if len(failTools) > 0 || len(failGroups) > 0 {
			lt := strings.ToLower(tool)
			if failTools[lt] {
				return "deny", fmt.Sprintf("Tool Guard hook could not evaluate; failing closed for tool %q (-fail-closed-tools)", tool)
			}
			if group := hookToolGroup(lt); failGroups[group] {
				return "deny", fmt.Sprintf("Tool Guard hook could not evaluate; failing closed for tool %q in group %q (-fail-closed-groups)", tool, group)
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
		if dispatching || *failClosed || len(failTools) > 0 || len(failGroups) > 0 {
			return "deny", fmt.Sprintf("Tool Guard hook could not read/parse the tool call (%s); failing closed (fail-closed engaged)", why)
		}
		return "allow", ""
	}

	if parseErr != nil {
		// A flag misconfiguration (or -h) can't be evaluated. -h prints a
		// short usage; anything else is an unattributable error.
		if errors.Is(parseErr, flag.ErrHelp) && !dispatching {
			fmt.Fprint(os.Stderr, hookUsage)
			return 0
		}
		// On a parse error the parsed flags cannot be trusted: Go's flag
		// package stops at the FIRST unrecognised flag, so a fail-closed flag
		// written after one was never parsed, and the hook would fail open on
		// the very error path the operator asked it to fail closed on. Scan
		// the raw argument list instead: a mistyped flag must not be able to
		// disarm fail-closed.
		dialect = argsHookDialect(args)
		if argsRequestFailClosed(args) {
			emitAudited("deny", "Tool Guard hook could not parse its command-line flags (flag parse error); a -fail-closed flag appears in the argument list, so failing closed", nil)
			return 0
		}
		d, reason := failUnattributable("flag parse error")
		emitAudited(d, reason, nil)
		return 0
	}
	// The dispatcher replaces the default allow for Bash, so it is only
	// meaningful when decisions are enforced.
	if dispatching && (*dispatch != "gh_read" || *modeStr != "enforcement") {
		emitAudited("deny", "Tool Guard hook -dispatch requires the value gh_read and -mode enforcement; failing closed", nil)
		return 0
	}

	// Cap stdin (a PreToolUse payload is small; an oversized one is either a
	// bug or an attempt to exhaust memory) and surface read errors instead of
	// silently treating a partial read as valid.
	const maxHookStdin = 1 << 20 // 1 MiB
	raw, rerr := io.ReadAll(io.LimitReader(stdin, maxHookStdin+1))
	if rerr != nil {
		d, reason := failUnattributable("stdin read error")
		emitAudited(d, reason, nil)
		return 0
	}
	if len(raw) > maxHookStdin {
		d, reason := failUnattributable("oversized stdin")
		emitAudited(d, reason, nil)
		return 0
	}

	var in hookInput
	if err := json.Unmarshal(raw, &in); err != nil {
		// Unparseable stdin: we don't know the tool. Fail closed if any
		// fail-closed mode is engaged (can't prove it's non-destructive),
		// else fail open.
		d, reason := failUnattributable("malformed JSON")
		emitAudited(d, reason, nil)
		return 0
	}

	// Antigravity dialect: a toolCall object instead of tool_name/tool_input.
	// Decoded here so every downstream stage (tool group, protected paths,
	// policy conditions, audit) sees one canonical envelope.
	if in.ToolCall != nil {
		if rawIn := bytes.TrimSpace(in.ToolInput); strings.TrimSpace(in.ToolName) != "" || (len(rawIn) > 0 && string(rawIn) != "null") {
			// Two tool calls in one payload: which one the harness runs
			// is not known.
			d, reason := failUnattributable("the payload holds a toolCall object and tool_name or tool_input")
			dialect = resolveHookDialect(*dialectStr, true)
			emitAudited(d, reason, nil)
			return 0
		}
		in.ToolName = in.ToolCall.Name
		in.ToolInput = in.ToolCall.Args
	}

	dialect = resolveHookDialect(*dialectStr, in.ToolCall != nil)

	tool := strings.ToLower(strings.TrimSpace(in.ToolName))
	if tool == "" {
		// No usable tool_name. The payload is not in the PreToolUse shape this
		// hook understands — another harness's hook contract, or an empty
		// object. Defaulting it to "bash" invented an identity for a call we
		// cannot see and let it be evaluated as a shell command, so it goes
		// down the same unattributable path as malformed input.
		d, reason := failUnattributable("no tool_name field; payload format not recognised")
		emitAudited(d, reason, nil)
		return 0
	}

	env = hookEnvelope(tool, in, *agentID)
	// Alias families (Path/path/file_path, Content/text/content,
	// CommandLine/script/command) can carry more than one distinct value in a
	// single call, and which one a harness will act on is not knowable from the
	// payload. Canonicalising one value and parking the rest on keys no policy
	// reads produced allow decisions for a protected path and for a credential,
	// measured 2026-11-09. So every candidate is evaluated, and the strictest
	// decision wins: the guard does not have to know which spelling the harness
	// honours, because all of them are checked.
	variants, truncatedVariants := hookParamVariants(hookParams(in))
	envs := hookVariantEnvelopes(env, variants)
	// An apply_patch call holds its files in the patch text. Each file gets
	// an envelope with a path parameter, and these replace the envelope
	// without one.
	patchEnvs, patchDeny, isPatch := applyPatchEnvelopes(env, in.Cwd)
	if isPatch && patchDeny == "" {
		envs = nil
		truncatedVariants = false
		for _, pe := range patchEnvs {
			v, trunc := hookParamVariants(pe.Parameters)
			truncatedVariants = truncatedVariants || trunc
			envs = append(envs, hookVariantEnvelopes(pe, v)...)
		}
	}

	// A tool input that is not an object, or a command that is not a
	// string (or a string array for apply_patch), cannot be evaluated. Before,
	// such a call got an empty parameter object and was allowed.
	if why := hookInputMalformed(in); why != "" && !(dispatching && tool == "bash" && dispatchCommandMalformed(in)) {
		if d, reason := failDecide(tool); d == "deny" {
			emitAudited(d, reason+": "+why, nil)
			return 0
		}
	}

	// ── Protected paths (Feature B) — BEFORE policy eval, unconditional ──
	protectList := append(splitCSVPaths(*protectPaths), protectPath...)
	if *protectSelf {
		protectList = append(selfProtectPaths(*policyDir, *policyFile), protectList...)
	}
	if patchDeny != "" {
		emitAudited("deny", "Tool Guard: "+patchDeny, nil)
		return 0
	}
	for _, e := range envs {
		if violated, reason := engine.ViolatesProtectedPaths(withHarnessCwd(e, in.Cwd), protectList); violated {
			emitAudited("deny", reason, nil)
			return 0
		}
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

	dec, reason, result, auditPolicyHash := evalHook(*policyDir, *policyFile, envs, truncatedVariants, mode, failDecide, *unknownToolsDeny)
	if dispatching && tool == "bash" && dec == "allow" {
		dec, reason = dispatchBashEnvelopes(envs, truncatedVariants)
		if dec == hookNoDecision && dialect != dialectClaude {
			dec, reason = "ask", "Tool Guard dispatch: this dialect requires an explicit decision for an unrelated command"
		}
		result = dispatchedResult(result, dec, reason)
	}
	if truncatedVariants {
		// Say so in the answer the operator and the model see: a decision that
		// sampled only part of the candidate set must not read as complete.
		reason = strings.TrimRight(reason, "\n") + fmt.Sprintf(
			"\n(parameter-spelling limit: more than %d distinct alias values, so not every spelling could be evaluated)",
			maxHookParamVariants)
	}
	if *escalateAs != "ask" && *escalateAs != "deny" {
		fmt.Fprintf(os.Stderr, "tg hook: -escalate-as %q is not ask or deny; treating it as deny\n", *escalateAs)
	}
	dec, reason = applyEscalateAs(*escalateAs, dec, reason)
	emitAudited(dec, reason, result)
	return 0
}

// hookNoDecision is the decision value for a proven unrelated command. The
// hook writes no permissionDecision, so the client's own permission rules
// apply. The audit record keeps the engine result with this reason.
const hookNoDecision = ""

// dispatchCommandMalformed permits the dispatcher to ask about an invalid
// command value. Malformed values in other parameter families still deny.
func dispatchCommandMalformed(in hookInput) bool {
	var params map[string]json.RawMessage
	if json.Unmarshal(in.ToolInput, &params) != nil || params == nil {
		return false
	}
	invalid := false
	for key, value := range params {
		if commandAliasNames[normParamName(key)] {
			var command string
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) || json.Unmarshal(value, &command) != nil {
				invalid = true
			}
			delete(params, key)
		}
	}
	in.ToolInput, _ = json.Marshal(params)
	return invalid && hookInputMalformed(in) == ""
}

// dispatchBashEnvelopes checks every alias candidate. An ask outranks no
// decision, which outranks allow. An incomplete candidate set always asks.
func dispatchBashEnvelopes(envs []*domain.ActionEnvelope, truncated bool) (string, string) {
	if truncated || len(envs) == 0 {
		return "ask", "Tool Guard dispatch: command alias candidates are incomplete"
	}
	decision, reason := "allow", ""
	for _, env := range envs {
		d, why := dispatchBash(env)
		if d == "ask" {
			return d, why
		}
		if d == hookNoDecision || decision == "allow" {
			decision, reason = d, why
		}
	}
	return decision, reason
}

// dispatchedResult returns a copy of the engine result that records the
// dispatcher's outcome: an ask is recorded as escalated, and every outcome
// carries the dispatch reason. Rule results and citations are unchanged.
func dispatchedResult(result *domain.EvaluationResult, dec, reason string) *domain.EvaluationResult {
	if result == nil {
		return nil
	}
	r := *result
	if dec == "ask" {
		r.Decision, r.ActionTaken = domain.DecisionEscalated, domain.ActionEscalated
	}
	r.DecisionReason = reason
	return &r
}

// dispatchBash runs only after protected paths and every loaded enforcing
// rule allowed the call. Verified reads allow, proven unrelated commands get
// no decision, and everything else asks.
func dispatchBash(env *domain.ActionEnvelope) (string, string) {
	var params map[string]interface{}
	cmd, ok := "", false
	if json.Unmarshal(env.Parameters, &params) == nil {
		cmd, ok = params["command"].(string)
	}
	if !ok {
		return "ask", "Tool Guard dispatch: command is missing or not a string"
	}
	switch class, why := engine.ClassifyCommand(cmd); class {
	case engine.CommandVerifiedRead:
		return "allow", "Tool Guard dispatch: " + why
	case engine.CommandProvenUnrelated:
		return hookNoDecision, "Tool Guard dispatch: " + why + "; no decision, client permissions apply"
	default:
		return "ask", "Tool Guard dispatch: " + why
	}
}

// evalHook loads the policy set and evaluates env, recovering from any panic
// so the hook can never crash the agent. On load failure or panic it returns
// the fail-open/closed decision for env.ToolName.
// evalHook decides one tool call. envs carries the base envelope first and one
// copy per alias candidate; the strictest decision across all of them wins, and
// aliasLimitTruncated says the candidate list was cut off by the reviewable
// limit, which must escalate rather than allow.
func evalHook(policyDir, policyFile string, envs []*domain.ActionEnvelope, aliasLimitTruncated bool, mode domain.PolicyMode, failDecide func(string) (string, string), unknownToolsDeny bool) (dec string, reason string, result *domain.EvaluationResult, policySetHash string) {
	env := envs[0]
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

	result = evaluateHookEnvelopes(envs, policies, mode)
	if aliasLimitTruncated {
		// More distinct parameter spellings than the reviewable limit: the
		// strictest decision found so far is permissive, and an unexamined
		// spelling could be the harmful one. Hold it for a human instead of
		// pretending the sampled set was the whole truth.
		if rankHookAction(result.ActionTaken) < rankHookAction(domain.ActionEscalated) {
			// The candidate set was cut off and the strictest decision found is
			// still permissive: an unexamined spelling could be the harmful one,
			// so hold it for a human rather than report allow.
			result.ActionTaken = domain.ActionEscalated
			result.Decision = domain.DecisionEscalated
		}
	}
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

// applyEscalateAs returns an escalation as a denial when the operator asked
// for that with -escalate-as deny. Only the decision "ask" is converted, so an
// allow and a real deny pass through unchanged. Every value other than the
// literal "ask" converts: a mistyped value must not leave an escalation as a
// prompt that a harness may ignore. In the release run of 2026-11-10, headless
// Codex CLI 0.166.0 did not run a call the hook answered ask to (3 of 3
// runs). The Codex wrapper of the example still defaults to deny.
func applyEscalateAs(flagVal, dec, reason string) (string, string) {
	if dec != "ask" || flagVal == "ask" {
		return dec, reason
	}
	return "deny", "Escalation returned as a denial (-escalate-as deny): " + reason
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

// argsHookDialect reads explicit dialect flags even after a flag parse error.
// The last occurrence wins, as in flag.Parse. An absent, auto, invalid or
// missing value leaves the harness unknown and requires both contracts.
func argsHookDialect(args []string) string {
	dialect := dialectBoth
	for i := 0; i < len(args); i++ {
		if args[i] == "--" {
			break
		}
		name, value, hasValue := strings.Cut(args[i], "=")
		if name != "-dialect" && name != "--dialect" {
			continue
		}
		if !hasValue && i+1 < len(args) {
			i++
			value = args[i]
		}
		dialect = dialectBoth
		if value == dialectClaude || value == dialectAntigravity {
			dialect = value
		}
	}
	return dialect
}

// argsRequestFailClosed reports whether any fail-closed flag appears in the
// raw argument list, with a single or double dash and with or without "=".
// It exists for the flag-parse-error path only, where the parsed values
// cannot be trusted because Go stops parsing at the first unknown flag.
func argsRequestFailClosed(args []string) bool {
	for _, a := range args {
		name := strings.TrimPrefix(strings.TrimPrefix(a, "--"), "-")
		if name == "" {
			continue
		}
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		if name == "fail-closed" || name == "fail-closed-tools" || name == "fail-closed-groups" {
			return true
		}
	}
	return false
}

// hookInput is the PreToolUse stdin object. tool_input is kept raw so the
// FULL parameter set (command, file_path, path, and any arrays / nested edit
// objects) flows into the envelope — cherry-picking three fields would let an
// array-of-paths write slip past protected-path checks.
type hookInput struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	// Cwd is the working directory the harness reports for the call. Only
	// the apply_patch reading uses it, to place a relative path.
	Cwd string `json:"cwd"`

	// Antigravity CLI 1.5.3 sends a different shape entirely, captured from a
	// real install on 2026-11-09:
	//   {"toolCall":{"name":"write_file","args":{"Path":"...","Content":"..."}}}
	// Arg names are PascalCase. The web documentation names these
	// tools write_to_file / TargetFile; the shipped CLI emits write_file /
	// Path, which is why this comes from a capture and not from the docs.
	ToolCall *struct {
		Name string          `json:"name"`
		Args json.RawMessage `json:"args"`
	} `json:"toolCall"`
}

// UnmarshalJSON preserves the distinction between an absent typed field and
// JSON null, which encoding/json otherwise accepts as a zero string or pointer.
func (in *hookInput) UnmarshalJSON(raw []byte) error {
	type plain hookInput
	var decoded plain
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for key, value := range fields {
		switch strings.ToLower(key) {
		case "tool_name", "cwd", "toolcall":
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return fmt.Errorf("%s must not be null", key)
			}
		}
		if strings.EqualFold(key, "toolCall") {
			var call map[string]json.RawMessage
			if err := json.Unmarshal(value, &call); err != nil {
				return err
			}
			for name, v := range call {
				if strings.EqualFold(name, "name") && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
					return fmt.Errorf("toolCall.name must not be null")
				}
			}
		}
	}
	*in = hookInput(decoded)
	return nil
}

// pathAliasNames and contentAliasNames are the parameter names harnesses use
// for the same two things a policy matches on: the file being written, and
// its new content. Matching is on the normalised name (case-folded, with
// '_', '-', ' ' and '.' removed), so TargetFile, target_file and filePath all
// normalise to "targetfile". This list is deliberately generic rather than a
// per-harness whitelist: it encodes naming style, not knowledge of any one
// vendor's schema, so it keeps working for a harness nobody has captured yet.
var pathAliasNames = map[string]bool{
	"path": true, "filepath": true, "file": true, "filename": true, "targetfile": true,
	"targetpath": true, "abspath": true, "absolutepath": true, "filetopatch": true,
}

// commandAliasNames covers shell tools that name the command string something
// other than "command". Antigravity CLI 1.5.3 emits "CommandLine" (captured
// 2026-11-09). Without this the shell classifier and the protected-path scan
// never see the command, so every such call escalates and no redirection is
// checked.
var commandAliasNames = map[string]bool{
	// "command" is here for a key in another letter case (Command, COMMAND).
	"command":     true,
	"commandline": true, "cmdline": true, "cmd": true, "script": true,
	"shellcommand": true, "commandstring": true, "terminalcommand": true,
	"bashcommand": true,
}

var contentAliasNames = map[string]bool{
	"contents": true, "text": true, "filecontent": true, "newcontent": true,
	"newstring": true, "content": true,
}

// normalizeHookParams adds the canonical parameter names policies match on
// (file_path, content) when the caller used a different name for the same
// thing, and only when the canonical name is absent. A payload that already
// carries file_path is returned untouched.
//
// Without this, a policy that matches parameters.file_path is inert against
// every harness that names the field differently, which is exactly the
// silently-uncovered-write CTO review D3 requires to be closed.
// When one alias family carries several DIFFERENT values, for example
// {"Path":"AGENTS.md","Filename":"plain.txt"}, every distinct value is exposed
// under a distinct canonical key rather than one of them being chosen. Random
// choice is not acceptable: the previous version ranged over a Go map, so
// identical calls got different results and identical bytes could be denied
// and allowed. Choosing by priority is unsafe in the other
// direction: if the policy-relevant value loses, a write to a protected file
// rides in under an innocuous alias. Keys are visited in sorted order, and
// candidates land on `file_path` then `path` then `target_file` (only keys not
// already present), all of which the shipped policies already match.
func normalizeHookParams(raw json.RawMessage) json.RawMessage {
	var m map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil || len(m) == 0 {
		return raw
	}
	norm := func(k string) string {
		var b strings.Builder
		for _, r := range k {
			switch r {
			case '_', '-', ' ', '.':
			default:
				b.WriteRune(unicode.ToLower(r))
			}
		}
		return b.String()
	}
	// Sorted by literal key name, so both the candidate order and the
	// ambiguity report never depend on Go map iteration order.
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Free canonical keys a policy already matches, in the order candidates
	// take them. Never overwrites a key the caller sent.
	freeKeys := map[string][]string{
		"file_path": {"file_path", "path", "target_file", "file_path_2", "file_path_3"},
		"content":   {"content", "text", "file_content", "content_2", "content_3"},
		"command":   {"command", "cmd", "command_line", "command_2", "command_3"},
	}
	addAlias := func(target string, aliases map[string]bool) {
		// The literal key, not the normalised one: a policy matches
		// parameters.content, so a payload carrying "Content" still needs the
		// canonical spelling added.
		if _, ok := m[target]; ok {
			return
		}
		// Candidate keys in sorted order, deduplicated by value so two aliases
		// naming the same file contribute one entry.
		type cand struct {
			key string
			val json.RawMessage
		}
		var cands []cand
		seenVal := map[string]bool{}
		for _, k := range keys {
			if !aliases[norm(k)] {
				continue
			}
			if seenVal[string(m[k])] {
				continue
			}
			seenVal[string(m[k])] = true
			cands = append(cands, cand{k, m[k]})
		}
		placed := 0
		for _, free := range freeKeys[target] {
			if placed >= len(cands) {
				break
			}
			if _, taken := m[free]; taken {
				continue
			}
			m[free] = cands[placed].val
			placed++
		}
	}
	addAlias("file_path", pathAliasNames)
	addAlias("content", contentAliasNames)
	addAlias("command", commandAliasNames)
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

// hookEnvelope maps a PreToolUse object onto an ActionEnvelope, forwarding the
// entire tool_input as parameters. Falls back to an empty object when
// tool_input is absent or not a JSON object.
func hookEnvelope(tool string, in hookInput, agentID string) *domain.ActionEnvelope {
	return &domain.ActionEnvelope{
		EnvelopeID: fmt.Sprintf("hook-%d", time.Now().UnixNano()),
		Timestamp:  time.Now().UTC(),
		AgentID:    agentID,
		SessionID:  "tg-hook",
		OrgID:      "local",
		ToolName:   tool,
		ToolGroup:  hookToolGroup(tool),
		Parameters: hookParams(in),
	}
}

// hookParams returns the parameter object the engine evaluates: the harness's
// tool input with alias families canonicalised. It is exported through
// hookEnvelope and used directly by the caller that builds alias variants, so
// variants start from the SAME object the base decision was made on. Starting
// them from the raw payload instead dropped the other family's canonical key and
// made the engine look at a call shape the harness never sends, which produced
// denials no real call would get.
func hookParams(in hookInput) json.RawMessage {
	params := json.RawMessage(`{}`)
	if len(in.ToolInput) > 0 {
		var probe map[string]interface{}
		if json.Unmarshal(in.ToolInput, &probe) == nil {
			params = normalizeHookParams(in.ToolInput)
		}
	}
	return params
}

// hookInputMalformed returns why the tool input cannot be evaluated, or "".
// It rejects non-object input and non-string values in typed alias families.
// Only apply_patch accepts a command array, and every element must be a string.
func hookInputMalformed(in hookInput) string {
	raw := bytes.TrimSpace(in.ToolInput)
	if len(raw) == 0 || string(raw) == "null" {
		return "the tool input is not a JSON object"
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "the tool input is not a JSON object"
	}
	for k, v := range obj {
		name := normParamName(k)
		isDirectory := name == "cwd" || name == "workdir" || name == "workingdir" || name == "workingdirectory"
		if commandAliasNames[name] || pathAliasNames[name] || contentAliasNames[name] || isDirectory {
			if k == "command" && strings.EqualFold(strings.TrimSpace(in.ToolName), "apply_patch") && bytes.HasPrefix(bytes.TrimSpace(v), []byte("[")) {
				var elements []json.RawMessage
				if json.Unmarshal(v, &elements) == nil {
					for _, element := range elements {
						var s string
						if bytes.Equal(bytes.TrimSpace(element), []byte("null")) || json.Unmarshal(element, &s) != nil {
							return fmt.Sprintf("the %s in the tool input is not a string array", k)
						}
					}
					continue
				}
			}
			var s string
			if bytes.Equal(bytes.TrimSpace(v), []byte("null")) || json.Unmarshal(v, &s) != nil {
				return fmt.Sprintf("the %s in the tool input is not a string", k)
			}
		}
	}
	return ""
}

// normParamName is a parameter name in lower case without "_", "-", "." and
// blanks, the form the alias lists are written in.
func normParamName(k string) string {
	var b strings.Builder
	for _, r := range k {
		switch r {
		case '_', '-', ' ', '.':
		default:
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// withHarnessCwd returns the envelope for the protected-path check: a copy
// with the working directory the harness reports as the parameter "cwd",
// which the check reads a relative path under. The envelope is returned as
// it is when the harness reports no absolute directory or the tool input
// has a "cwd" of its own.
func withHarnessCwd(e *domain.ActionEnvelope, cwd string) *domain.ActionEnvelope {
	if e == nil || !strings.HasPrefix(cwd, "/") {
		return e
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(e.Parameters, &m) != nil {
		return e
	}
	if _, has := m["cwd"]; has {
		return e
	}
	if m == nil {
		m = map[string]json.RawMessage{}
	}
	v, _ := json.Marshal(cwd)
	m["cwd"] = v
	b, err := json.Marshal(m)
	if err != nil {
		return e
	}
	c := *e
	c.Parameters = b
	return &c
}

// hookToolGroup is a small heuristic so tool_groups-scoped policies match.
// Keep write and network capabilities distinct from read-only filesystem
// tools: grouping them together would make a write-classifier policy evaluate
// (and fail closed) on harmless reads.
func hookToolGroup(tool string) string {
	switch tool {
	case "write", "edit", "notebookedit", "apply_patch", "multiedit", "create":
		return "filesystem_writes"
	// Write-capable tool names of the Gemini CLI and Antigravity tool
	// contracts. Without these the
	// default bucket is "shell", so a tool-group-scoped policy such as
	// coding-agent-context-files never sees the write at all.
	case "write_file", "write_to_file", "replace", "replace_file_content", "multi_replace_file_content":
		return "filesystem_writes"
	case "read", "read_file", "view_file":
		return "filesystem"
	case "http", "fetch", "webfetch", "web_fetch", "read_url_content":
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
		PermissionDecision       string `json:"permissionDecision,omitempty"`
		PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
	} `json:"hookSpecificOutput"`
}

// emitHookDecisionTo writes the hook JSON to w. It never returns an error
// to the caller — a hook must always exit 0.
// Hook dialects. The input shape and the output contract differ per harness,
// and emitting the wrong output contract is not a cosmetic bug: the Gemini
// CLI documentation states malformed hook stdout defaults to Allow, so a
// Claude-shaped answer handed to a harness that expects a top-level "decision"
// is a silent fail-open.
const (
	dialectClaude      = "claude"
	dialectAntigravity = "antigravity"
	dialectBoth        = "both"
)

// resolveHookDialect picks the output contract. An explicit -dialect wins;
// otherwise the input shape decides.
func resolveHookDialect(flagVal string, hasToolCall bool) string {
	switch flagVal {
	case dialectClaude, dialectAntigravity:
		return flagVal
	}
	if hasToolCall {
		return dialectAntigravity
	}
	return dialectClaude
}

// emitHookDecisionDialect writes the decision in the named dialect.
// Antigravity CLI 1.5.3 reads a top-level {"decision","reason"} object, with
// decision one of allow | deny | ask | force_ask, per the hooks.md shipped
// with that CLI. Claude Code and Codex read hookSpecificOutput.permissionDecision.
// resolveAntigravityEscalation maps our "ask" onto "force_ask", the stricter
// of the two approval values Antigravity CLI reads. Measurements. The 1.5.3 runs were local and
// their records are not in the repository. The 1.5.4 runs are in
// docs/evidence/harness-manifest.json.
//
//	1.5.3, headless, no --dangerously-skip-permissions, four runs:
//	  "force_ask" -> the write was refused in 4 of 4 runs; a write the hook
//	                 allowed landed in 3 of the 4
//	1.5.4, headless, with --dangerously-skip-permissions, three runs each:
//	  "ask"       -> the command ran in 3 of 3
//	  "force_ask" -> the command ran in 3 of 3
//
// No retained record shows "ask" without the flag. With the flag neither
// value stops a call; use -escalate-as deny there. -antigravity-escalation ask
// restores "ask" for an interactive operator who wants the "Always Allow"
// cache respected.
func resolveAntigravityEscalation(flagVal, decision string) string {
	if decision != "ask" {
		return decision
	}
	if flagVal == "ask" {
		return "ask"
	}
	return "force_ask"
}

func emitHookDecisionDialect(w io.Writer, dialect, escalationDecision, decision, reason string) {
	if dialect == dialectAntigravity {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"decision": resolveAntigravityEscalation(escalationDecision, decision),
			"reason":   reason,
		})
		return
	}
	if dialect == dialectBoth {
		var out struct {
			hookOutput
			Decision string `json:"decision"`
			Reason   string `json:"reason"`
		}
		out.Decision = resolveAntigravityEscalation(escalationDecision, decision)
		out.Reason = reason
		out.HookSpecificOutput.HookEventName = "PreToolUse"
		out.HookSpecificOutput.PermissionDecision = decision
		out.HookSpecificOutput.PermissionDecisionReason = reason
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	emitHookDecisionTo(w, decision, reason)
}

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
          [-agent-id NAME] [-dialect auto|claude|antigravity]
          [-escalate-as ask|deny] [-antigravity-escalation force_ask|ask]
          [-fail-closed] [-fail-closed-tools bash,write,edit]
          [-fail-closed-groups shell,filesystem_writes,network_egress]
          [-protect-path PATH ...] [-protect-paths P1,P2]
          [-protect-self] [-unknown-tools-deny] [-audit-log FILE] [-dispatch gh_read]

Reads ONE PreToolUse JSON object on stdin, evaluates it, and writes one
decision to stdout. Always exits 0.

  -dialect claude       hookSpecificOutput.permissionDecision: deny|ask|allow
                        (Claude Code, Codex CLI)
  -dialect antigravity  top-level {"decision","reason"}: deny|force_ask|ask|allow
                        (Antigravity CLI)
  -dialect auto         default: antigravity when stdin carries a toolCall
                        object, claude otherwise

  -escalate-as deny     return a policy escalation as deny. Use it for a
                        harness that runs a call answered ask (see
                        docs/support-matrix.md) and for unattended runs.
  -antigravity-escalation ask
                        emit ask instead of force_ask in the antigravity
                        dialect. Started with
                        --dangerously-skip-permissions, Antigravity CLI ran
                        the call after either value.

RECOMMENDED for any enforcing deployment: pass -fail-closed-tools (or
-fail-closed). Without one, an internal error (unparseable stdin, a policy
load failure, an evaluator panic) fails OPEN — allow — by default, so a
tooling glitch never wedges the agent, but that also means the error is
never denied either. That default suits local dev; it is not what you want
once this hook is actually enforcing policy.

-dispatch gh_read (enforcement mode only) changes what an allowed Bash call
returns: a verified gh read allows; a validated literal pwd or ls returns no
decision in the claude dialect so the client's permission rules apply.
Other dialects ask for pwd or ls, and every other command asks in all
dialects. Load it without a broad rule that escalates gh commands, because
escalate outranks allow. Every internal error then denies for every tool,
and the hook runs its evaluation in a supervised child process: a crash,
timeout, non-zero exit or malformed child output denies.
`

// maxHookParamVariants bounds how many alias candidates one call can raise.
// Bounded so a hostile payload cannot make the hook evaluate an unbounded
// number of envelopes; beyond the limit the decision escalates rather than
// claiming the sampled subset was complete.
const maxHookParamVariants = 16

// hookParamVariants returns one parameters object per distinct value in each
// alias family, with that value placed on the canonical key the policies read.
// The base object is NOT included (the caller already evaluates it). The second
// return is true when candidates exceeded the limit and were truncated.
func hookParamVariants(raw json.RawMessage) ([]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil || len(m) == 0 {
		return nil, false
	}
	norm := func(k string) string {
		var b strings.Builder
		for _, r := range k {
			switch r {
			case '_', '-', ' ', '.':
			default:
				b.WriteRune(unicode.ToLower(r))
			}
		}
		return b.String()
	}
	families := []struct {
		canonical string
		aliases   map[string]bool
	}{
		{"file_path", pathAliasNames},
		{"content", contentAliasNames},
		{"command", commandAliasNames},
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []json.RawMessage
	seen := map[string]bool{}
	total := 0
	for _, fam := range families {
		base := hookAliasValueKey(m[fam.canonical])
		seenValues := map[string]bool{}
		for _, k := range keys {
			if !fam.aliases[norm(k)] {
				continue
			}
			v := m[k]
			value := hookAliasValueKey(v)
			if value == base {
				continue
			}
			if seenValues[value] {
				continue
			}
			seenValues[value] = true
			total++
			if len(out) >= maxHookParamVariants {
				continue
			}
			mm := make(map[string]json.RawMessage, len(m)+1)
			for kk, vv := range m {
				mm[kk] = vv
			}
			mm[fam.canonical] = v
			b, err := json.Marshal(mm)
			if err != nil || seen[string(b)] {
				continue
			}
			seen[string(b)] = true
			out = append(out, b)
		}
	}
	return out, total > maxHookParamVariants
}

// hookAliasValueKey compares decoded strings, so JSON escape spellings do not
// consume the variant limit. Other types retain their JSON identity; malformed
// typed values are still rejected by hookInputMalformed when failing closed.
func hookAliasValueKey(raw json.RawMessage) string {
	var s string
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '"' && json.Unmarshal(trimmed, &s) == nil {
		return "string:" + s
	}
	return "json:" + string(trimmed)
}

// hookVariantEnvelopes copies the base envelope once per candidate parameter
// set. Tool name, group, agent and session stay identical: only the parameters
// differ, which is exactly the ambiguity being resolved.
func hookVariantEnvelopes(base *domain.ActionEnvelope, variants []json.RawMessage) []*domain.ActionEnvelope {
	out := []*domain.ActionEnvelope{base}
	for i, v := range variants {
		e := *base
		e.Parameters = v
		e.EnvelopeID = fmt.Sprintf("%s-alias-%d", base.EnvelopeID, i+1)
		out = append(out, &e)
	}
	return out
}

// rankHookAction orders engine outcomes by how protective they are, so the
// strictest of several alias evaluations wins. Shadow-mode actions rank as the
// least protective because they do not stop anything.
func rankHookAction(a domain.ActionTaken) int {
	switch a {
	case domain.ActionDenied:
		return 3
	case domain.ActionEscalated:
		return 2
	default:
		return 0
	}
}

// evaluateHookEnvelopes evaluates every alias variant and returns the strictest
// result. One candidate denied is enough: the guard cannot know which spelling
// the harness will act on.
func evaluateHookEnvelopes(envs []*domain.ActionEnvelope, policies []domain.Policy, mode domain.PolicyMode) *domain.EvaluationResult {
	ev := engine.NewEvaluator()
	best := ev.Evaluate(envs[0], policies, mode)
	for _, e := range envs[1:] {
		r := ev.Evaluate(e, policies, mode)
		if rankHookAction(r.ActionTaken) > rankHookAction(best.ActionTaken) {
			best = r
		}
	}
	return best
}
