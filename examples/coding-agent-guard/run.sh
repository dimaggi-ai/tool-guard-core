#!/usr/bin/env bash
#
# run.sh — drive a batch of shell commands through the Tool Guard hook
# adapters for all three coding agents and show the decision each agent would
# make, WITHOUT needing a live agent session.
#
# It feeds each command to the adapters exactly as Claude Code, Codex and
# Antigravity would (same stdin JSON shape per agent) and reports:
#   * Claude Code / Codex  -> the adapter's exit code (2 = blocked, 0 = allowed)
#   * Antigravity          -> the adapter's stdout decision (deny/ask/allow)
#
# This is the deterministic, LLM-free proof that one policy.yaml gates all
# three agents. No Docker, no network, no API key.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
TG="$ROOT/bin/tg"
HOOKS="$HERE/hooks"

command -v jq >/dev/null 2>&1 || { echo "this demo needs 'jq' on PATH"; exit 2; }

if [ ! -x "$TG" ]; then
  echo "→ building tg (one-time) ..."
  ( cd "$ROOT" && CGO_ENABLED=0 go build -o bin/tg ./cmd/tg )
fi
export TG_BIN="$TG"

# The battery of commands an agent might propose. Mix of catastrophic,
# review-worthy, and benign.
CMDS=(
  'rm -rf /'
  'rm -r -f /'
  'rm --recursive --force /'
  'rm -fR /home'
  'rm -rf /tmp/scratch/build'
  'rm -rf $HOME/projects'
  'git push origin main --force'
  'git clean -fdx'
  'ls -la /home'
  'go test ./...'
)

anthropic_decision() { # $1=cmd -> prints DENY/ESCALATE/ALLOW based on exit code
  local env rc
  env="$(jq -nc --arg c "$1" '{tool_name:"Bash",tool_input:{command:$c}}')"
  set +e
  printf '%s' "$env" | "$HOOKS/anthropic-hook.sh" >/dev/null 2>&1
  rc=$?
  set -e
  case "$rc" in
    2) echo "BLOCK (exit 2)" ;;
    0) echo "allow (exit 0)" ;;
    *) echo "err  (exit $rc)" ;;
  esac
}

antigravity_decision() { # $1=cmd -> prints the stdout decision
  local env
  env="$(jq -nc --arg c "$1" '{toolCall:{name:"run_command",args:{CommandLine:$c}}}')"
  printf '%s' "$env" | "$HOOKS/antigravity-hook.sh" 2>/dev/null | jq -r '.decision'
}

engine_decision() { # $1=cmd -> raw engine decision, for reference
  local call
  call="$(mktemp)"
  jq -nc --arg c "$1" '{agent_id:"x",session_id:"x",org_id:"local",tool_name:"bash",tool_group:"shell",parameters:{command:$c}}' > "$call"
  "$TG" evaluate -policy "$HERE/policy.yaml" -call "$call" -mode enforcement 2>/dev/null | jq -r '.decision'
  rm -f "$call"
}

printf '\n  Tool Guard — one policy, three coding agents\n'
printf '  policy: %s\n\n' "$HERE/policy.yaml"
printf '  %-34s %-12s %-18s %-14s\n' "COMMAND" "ENGINE" "Claude/Codex" "Antigravity"
printf '  %-34s %-12s %-18s %-14s\n' "----------------------------------" "------------" "------------------" "--------------"
for c in "${CMDS[@]}"; do
  printf '  %-34s %-12s %-18s %-14s\n' "$c" "$(engine_decision "$c")" "$(anthropic_decision "$c")" "$(antigravity_decision "$c")"
done
printf '\n  deny = never runs · escalate/ask = held for a human · allow = passes through\n\n'
