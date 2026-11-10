#!/usr/bin/env bash
# guard-hook.sh HARNESS: the one PreToolUse hook that install.sh wires into
# every harness. HARNESS is claude, codex or antigravity. It selects the output
# dialect and the escalation handling that docs/support-matrix.md records for
# that harness. The harness config files call the zero-argument wrappers next
# to this file (claude-code-hook.sh, codex-hook.sh, antigravity-cli-hook.sh).
#
# The script always exits 0 and always prints one JSON decision. When it cannot
# run tg, or tg prints no decision, it prints a deny in the dialect the harness
# reads.
#
# Environment (all optional):
#   TG_BIN               tg binary             default <repo>/bin/tg
#   TG_POLICIES          policy directory      default ../policies (five files)
#   TG_POLICY_FILE       one policy file; when set it replaces TG_POLICIES
#   TG_STATE_DIR         state directory       default $HOME/.tool-guard
#   TG_AUDIT_LOG         audit log file        default $TG_STATE_DIR/hook-audit-<UTC date>.jsonl
#   TG_PROTECT_FILE      protected paths, one absolute path per line
#                                              default $TG_STATE_DIR/protect-paths
#   TG_PROTECT_BASELINE  0 turns off the built-in protected paths
#   TG_ESCALATE_AS       ask or deny; default ask for claude and antigravity,
#                        deny for codex
#   TG_AGY_ESCALATION    force_ask or ask: the word an escalation takes in
#                        the antigravity dialect; default force_ask
#   TG_UNKNOWN_TOOLS_DENY  1 denies a tool that no loaded policy names
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
harness="${1:-}"

TG_BIN="${TG_BIN:-$here/../../../bin/tg}"
TG_POLICIES="${TG_POLICIES:-$here/../policies}"
TG_STATE_DIR="${TG_STATE_DIR:-$HOME/.tool-guard}"
TG_AUDIT_LOG="${TG_AUDIT_LOG:-$TG_STATE_DIR/hook-audit-$(date -u +%Y-%m-%d).jsonl}"
TG_PROTECT_FILE="${TG_PROTECT_FILE:-$TG_STATE_DIR/protect-paths}"

case "$harness" in
  claude)
    dialect=claude
    escalate="${TG_ESCALATE_AS:-ask}"
    ;;
  codex)
    dialect=claude
    escalate="${TG_ESCALATE_AS:-deny}"
    ;;
  antigravity)
    dialect=antigravity
    escalate="${TG_ESCALATE_AS:-ask}"
    ;;
  *)
    dialect=unknown
    escalate=deny
    ;;
esac

# static_deny REASON: answer without tg. REASON must contain no double quote
# and no backslash, because it is placed in JSON without escaping.
static_deny() {
  cat >/dev/null
  echo "guard-hook: $1" >&2
  case "$dialect" in
    antigravity)
      printf '{"decision":"deny","reason":"%s"}\n' "$1"
      ;;
    claude)
      printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$1"
      ;;
    *)
      printf '{"decision":"deny","reason":"%s","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$1" "$1"
      ;;
  esac
  exit 0
}

if [ "$dialect" = unknown ]; then
  static_deny "Tool Guard hook could not run: first argument must be claude, codex or antigravity"
fi
if [ ! -x "$TG_BIN" ]; then
  static_deny "Tool Guard hook could not run: tg binary missing (set TG_BIN)"
fi

args=(hook)
if [ -n "${TG_POLICY_FILE:-}" ]; then
  [ -f "$TG_POLICY_FILE" ] || static_deny "Tool Guard hook could not run: policy file missing (TG_POLICY_FILE)"
  args+=(-policy "$TG_POLICY_FILE")
else
  [ -d "$TG_POLICIES" ] || static_deny "Tool Guard hook could not run: policy directory missing (TG_POLICIES)"
  args+=(-policy-dir "$TG_POLICIES")
fi

args+=(-mode enforcement -dialect "$dialect" -escalate-as "$escalate")
if [ "$dialect" = antigravity ] && [ -n "${TG_AGY_ESCALATION:-}" ]; then
  args+=(-antigravity-escalation "$TG_AGY_ESCALATION")
fi
if [ "${TG_UNKNOWN_TOOLS_DENY:-0}" = 1 ]; then
  args+=(-unknown-tools-deny)
fi
args+=(-fail-closed-tools bash,powershell,write,edit,notebookedit)
args+=(-fail-closed-groups shell,filesystem_writes,network_egress)

if mkdir -p "$(dirname "$TG_AUDIT_LOG")" 2>/dev/null; then
  args+=(-audit-log "$TG_AUDIT_LOG")
fi

protect=()
if [ "${TG_PROTECT_BASELINE:-1}" != 0 ]; then
  protect+=("$here" "$TG_STATE_DIR" "$TG_BIN")
  protect+=("${CLAUDE_CONFIG_DIR:-$HOME/.claude}/settings.json")
  protect+=("${CODEX_HOME:-$HOME/.codex}/hooks.json")
  protect+=("$HOME/.gemini/config/hooks.json")
  if [ -n "${TG_POLICY_FILE:-}" ]; then
    protect+=("$TG_POLICY_FILE")
  else
    protect+=("$TG_POLICIES")
  fi
fi
if [ -f "$TG_PROTECT_FILE" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ''|'#'*) continue ;;
    esac
    protect+=("$line")
  done < "$TG_PROTECT_FILE"
fi
if [ "${#protect[@]}" -gt 0 ]; then
  for p in "${protect[@]}"; do
    args+=(-protect-path "$p")
  done
fi

# tg hook always exits 0 and prints one decision. A binary at TG_BIN that exits
# non-zero, prints nothing, or prints text with no decision would leave the
# harness without an answer, and a harness that reads no answer runs the tool.
out="$("$TG_BIN" "${args[@]}")"
rc=$?
if [ "$dialect" = antigravity ]; then
  want='"decision":"'
else
  want='"permissionDecision":"'
fi
if [ "$rc" -ne 0 ] || [ "${out#*"$want"}" = "$out" ]; then
  static_deny "Tool Guard hook could not run: tg printed no decision"
fi
printf '%s\n' "$out"
exit 0
