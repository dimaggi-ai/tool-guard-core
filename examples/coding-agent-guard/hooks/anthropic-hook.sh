#!/usr/bin/env bash
# Tool Guard — PreToolUse adapter for Claude Code and OpenAI Codex.
#
# Claude Code and Codex speak the same PreToolUse hook protocol:
#   stdin : {"tool_name":"Bash","tool_input":{"command":"<shell command>"}, ...}
#   block : exit code 2, with a human-readable reason on stderr
#   allow : exit code 0
#
# This adapter pipes the proposed command through Tool Guard Core
# (`tg evaluate`) against ../policy.yaml and turns the engine decision into
# the agent's block signal:
#
#   denied    -> exit 2   (never run)
#   escalated -> exit 2   (hold for manual human approval)
#   allowed   -> exit 0   (let the agent run it)
#
# Fail CLOSED by default: if the guard cannot produce a decision (missing
# tg/jq, unreadable input, no engine output) it BLOCKS the command rather than
# letting it through — a broken security guard must never silently disable
# itself. A tool call with no command to evaluate is out of scope, not an
# error, and is allowed. Set TG_FAIL=open to allow-on-error instead (if you
# would rather a tooling glitch never wedge your agent).
#
# Overridable via env: TG_BIN (path to tg), TG_POLICY (path to policy.yaml).

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TG="${TG_BIN:-$here/../../../bin/tg}"
POLICY="${TG_POLICY:-$here/../policy.yaml}"
FAIL="${TG_FAIL:-closed}"

fail() {
  if [ "$FAIL" = open ]; then exit 0; fi
  echo "🛑 Tool Guard could not evaluate this command and is failing CLOSED — it was blocked." >&2
  echo "   Build tg (make build) and install jq, or set TG_FAIL=open to allow on guard errors." >&2
  exit 2
}

command -v jq >/dev/null 2>&1 || fail
[ -x "$TG" ] || fail

input="$(cat)"
printf '%s' "$input" | jq -e . >/dev/null 2>&1 || fail   # unreadable call -> fail closed
# Normalize the command to a single string: argv arrays (["rm","-rf","/"]) are
# joined with spaces so the engine sees the real command, not its Go %v render.
cmd="$(printf '%s' "$input" | jq -r '((.tool_input.command // .tool_input.cmd) // empty) | if type=="array" then (map(tostring)|join(" ")) else tostring end' 2>/dev/null)"
[ -z "$cmd" ] && exit 0   # well-formed call with no command — out of scope, nothing to guard

call="$(mktemp)" || fail
trap 'rm -f "$call"' EXIT
jq -nc --arg cmd "$cmd" '{agent_id:"coding-agent",session_id:"toolguard-hook",org_id:"local",
  tool_name:"bash",tool_group:"shell",parameters:{command:$cmd}}' > "$call" 2>/dev/null || fail

# tg evaluate exits non-zero when it denies/escalates (it is an enforcement
# tool), so we do NOT gate on its exit code — we read the decision from its
# JSON. An empty/unparseable decision is the real "internal error" signal.
out="$("$TG" evaluate -policy "$POLICY" -call "$call" -mode enforcement 2>/dev/null)"
decision="$(printf '%s' "$out" | jq -r '.decision' 2>/dev/null)"
reason="$(printf '%s' "$out" | jq -r '.primary_citation.excerpt // .decision_reason // empty' 2>/dev/null)"
[ -n "$decision" ] || fail

case "$decision" in
  denied)
    echo "🚫 Tool Guard DENIED this command (policy: pol-coding-agent-guard). It was not run." >&2
    [ -n "$reason" ] && echo "   reason: $reason" >&2
    exit 2 ;;
  escalated)
    echo "✋ Tool Guard: this command needs MANUAL human approval (policy: pol-coding-agent-guard) before it can run." >&2
    [ -n "$reason" ] && echo "   reason: $reason" >&2
    exit 2 ;;
  *)
    exit 0 ;;
esac
