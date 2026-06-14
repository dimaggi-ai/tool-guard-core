#!/usr/bin/env bash
# Tool Guard — PreToolUse adapter for the Google Antigravity CLI (agy).
#
# Antigravity's hook protocol differs from Claude/Codex: it does NOT use exit
# codes for the decision — it reads a JSON object from the hook's stdout.
#   stdin  : {"toolCall":{"name":"run_command","args":{"CommandLine":"<cmd>"}}, ...}
#   decide : print {"decision":"allow"|"deny"|"ask","reason":"..."} on stdout
#
# Same Tool Guard Core engine, same ../policy.yaml — only this thin
# stdin/stdout adapter changes. The four engine effects map cleanly onto
# Antigravity's three decisions:
#
#   denied    -> {"decision":"deny"}   (never run)
#   escalated -> {"decision":"ask"}    (Antigravity asks the human to confirm)
#   allowed   -> {"decision":"allow"}  (let the agent run it)
#
# Fail CLOSED by default: any internal error (missing tg/jq, unreadable input,
# no engine output) prints {"decision":"deny"} rather than allowing — a broken
# security guard must never silently disable itself. A tool call with no command
# to evaluate is out of scope, not an error, and is allowed. Set TG_FAIL=open to
# allow-on-error instead.
#
# Overridable via env: TG_BIN (path to tg), TG_POLICY (path to policy.yaml).

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TG="${TG_BIN:-$here/../../../bin/tg}"
POLICY="${TG_POLICY:-$here/../policy.yaml}"
FAIL="${TG_FAIL:-closed}"

allow() { printf '{"decision":"allow"}\n'; exit 0; }              # out of scope / permitted
gate()  { jq -nc --arg d "$1" --arg r "$2" '{decision:$d,reason:$r}'; exit 0; }  # safe-escaped
fail()  {
  if [ "$FAIL" = open ]; then printf '{"decision":"allow"}\n'; exit 0; fi
  # printf with a static literal so this works even when jq is the missing piece.
  printf '%s\n' '{"decision":"deny","reason":"Tool Guard could not evaluate this command and is failing closed. Build tg and install jq, or set TG_FAIL=open to allow on guard errors."}'
  exit 0
}

command -v jq >/dev/null 2>&1 || fail
[ -x "$TG" ] || fail

input="$(cat)"
printf '%s' "$input" | jq -e . >/dev/null 2>&1 || fail   # unreadable call -> fail closed
# Antigravity puts the shell command at toolCall.args.CommandLine; accept a few
# aliases so the adapter survives minor schema drift, and normalize argv arrays
# to a single string so the engine sees the real command.
cmd="$(printf '%s' "$input" | jq -r '((.toolCall.args.CommandLine // .toolCall.args.command // .toolCall.args.cmd // .tool_input.command) // empty) | if type=="array" then (map(tostring)|join(" ")) else tostring end' 2>/dev/null)"
[ -z "$cmd" ] && allow   # well-formed call with no command — out of scope, nothing to guard

call="$(mktemp)" || fail
trap 'rm -f "$call"' EXIT
jq -nc --arg cmd "$cmd" '{agent_id:"antigravity",session_id:"toolguard-hook",org_id:"local",
  tool_name:"bash",tool_group:"shell",parameters:{command:$cmd}}' > "$call" 2>/dev/null || fail

# tg evaluate exits non-zero when it denies/escalates (it is an enforcement
# tool), so we read the decision from its JSON rather than gating on exit code.
out="$("$TG" evaluate -policy "$POLICY" -call "$call" -mode enforcement 2>/dev/null)"
decision="$(printf '%s' "$out" | jq -r '.decision' 2>/dev/null)"
[ -n "$decision" ] || fail
reason="$(printf '%s' "$out" | jq -r '.primary_citation.excerpt // .decision_reason // "blocked by pol-coding-agent-guard"' 2>/dev/null)"

case "$decision" in
  denied)    gate deny "Tool Guard DENIED this command (pol-coding-agent-guard): $reason" ;;
  escalated) gate ask  "Tool Guard: this command needs manual human approval (pol-coding-agent-guard): $reason" ;;
  *)         allow ;;
esac
