#!/usr/bin/env bash
#
# install.sh — wire the Tool Guard hook into one or more coding agents on this
# machine. Idempotent; backs up any file it touches.
#
#   ./install.sh                 # install for every agent found on PATH
#   ./install.sh claude          # Claude Code only
#   ./install.sh codex           # OpenAI Codex only
#   ./install.sh antigravity     # Google Antigravity (agy) only
#   ./install.sh claude codex     # any subset
#
# Uninstall is the reverse: restore the .bak file the installer wrote, or run
# ./install.sh --uninstall <agent...>.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
HOOK_DIR="$HERE/hooks"
PROTECT=()      # --protect PATH: an absolute path the hook denies writes to
STATE_DIR="${TG_STATE_DIR:-$HOME/.tool-guard}"
PROTECT_FILE="${TG_PROTECT_FILE:-$STATE_DIR/protect-paths}"
TG="$ROOT/bin/tg"

command -v jq >/dev/null 2>&1 || { echo "install.sh needs 'jq' on PATH"; exit 2; }

UNINSTALL=0
TARGETS=()
ARGS=("$@"); i=0
while [ "$i" -lt "${#ARGS[@]}" ]; do
  a="${ARGS[$i]}"
  case "$a" in
    --uninstall) UNINSTALL=1 ;;
    --protect)
      i=$((i+1))
      [ "$i" -lt "${#ARGS[@]}" ] || { echo "--protect needs a path"; exit 2; }
      PROTECT+=("${ARGS[$i]}")
      ;;
    claude|codex|antigravity) TARGETS+=("$a") ;;
    *) echo "unknown arg: $a (want: claude codex antigravity --protect PATH --uninstall)"; exit 2 ;;
  esac
  i=$((i+1))
done

# Default: auto-detect installed agents.
if [ "${#TARGETS[@]}" -eq 0 ]; then
  command -v claude >/dev/null 2>&1 && TARGETS+=("claude")
  command -v codex  >/dev/null 2>&1 && TARGETS+=("codex")
  command -v agy    >/dev/null 2>&1 && TARGETS+=("antigravity")
  [ "${#TARGETS[@]}" -eq 0 ] && { echo "no supported agent (claude/codex/agy) found on PATH"; exit 1; }
fi

# The harness config stores the hook command as one bare absolute path. Whether
# each harness passes that string to a shell was not measured, so a path that
# would need quoting is refused instead of written.
case "$HOOK_DIR" in
  *[[:space:]]*|*'"'*|*"'"*|*'\'*|*'$'*)
    echo "install.sh cannot install from a path containing whitespace, a quote, a backslash or a dollar sign:"
    echo "  $HOOK_DIR"
    echo "Move the repository to a path without those characters and run install.sh again."
    exit 2
    ;;
esac

# --protect paths go into one file that hooks/guard-hook.sh reads on every call.
record_protect_paths() {
  [ "${#PROTECT[@]}" -gt 0 ] || return 0
  local pth
  for pth in "${PROTECT[@]}"; do
    case "$pth" in
      /*) ;;
      *) echo "--protect needs an absolute path, got: $pth"; exit 2 ;;
    esac
    case "$pth" in
      *$'\n'*) echo "--protect rejects a path containing a newline"; exit 2 ;;
    esac
  done
  mkdir -p "$(dirname "$PROTECT_FILE")"
  touch "$PROTECT_FILE"
  for pth in "${PROTECT[@]}"; do
    grep -Fxq -- "$pth" "$PROTECT_FILE" || printf '%s\n' "$pth" >> "$PROTECT_FILE"
  done
  echo "✓ protected paths recorded in $PROTECT_FILE"
}

# Build tg once so the hook has something to call.
if [ ! -x "$TG" ]; then
  echo "→ building tg ..."
  ( cd "$ROOT" && CGO_ENABLED=0 go build -o bin/tg ./cmd/tg )
fi

# Back up once — never overwrite an existing backup, so the very first
# (pristine) version is what --uninstall restores even after repeat installs.
backup() {
  [ -f "$1" ] || return 0
  [ -f "$1.bak-toolguard" ] && return 0
  cp -p "$1" "$1.bak-toolguard" && echo "  backed up $1 -> $1.bak-toolguard"
}

install_claude() {
  local f="$HOME/.claude/settings.json"
  local hook="$HOOK_DIR/claude-code-hook.sh"
  mkdir -p "$(dirname "$f")"
  [ -f "$f" ] || echo '{}' > "$f"
  backup "$f"
  # Append our matcher block to .hooks.PreToolUse, removing any prior copy of
  # the same command so re-running is a no-op.
  local tmp; tmp="$(mktemp)"
  jq --arg cmd "$hook" --arg dir "$HOOK_DIR/" '
    .hooks //= {} | .hooks.PreToolUse //= []
    | .hooks.PreToolUse |= ( map( .hooks |= ( map(select((.command // "") | contains($dir) | not)) ) )
                             | map(select((.hooks // []) | length > 0)) )
    | .hooks.PreToolUse += [ { matcher:"", hooks:[ { type:"command", command:$cmd } ] } ]
  ' "$f" > "$tmp" && mv "$tmp" "$f"
  echo "✓ Claude Code: PreToolUse(all tools) -> $hook"
  echo "  $f"
}

install_codex() {
  local f="$HOME/.codex/hooks.json"
  local hook="$HOOK_DIR/codex-hook.sh"
  mkdir -p "$(dirname "$f")"
  [ -f "$f" ] || echo '{}' > "$f"
  backup "$f"
  # Same shape as Claude's PreToolUse array; merge ours in, drop prior copies.
  local tmp; tmp="$(mktemp)"
  jq --arg cmd "$hook" --arg dir "$HOOK_DIR/" '
    .hooks //= {}
    | .hooks.PreToolUse //= []
    | .hooks.PreToolUse |= ( map( .hooks |= ( map(select((.command // "") | contains($dir) | not)) ) )
                       | map(select((.hooks // []) | length > 0)) )
    | .hooks.PreToolUse += [ { matcher:"",
        hooks:[ { type:"command", command:$cmd, timeout:30, statusMessage:"Tool Guard policy check" } ] } ]
  ' "$f" > "$tmp" && mv "$tmp" "$f"
  echo "✓ Codex: PreToolUse(all tools) -> $hook"
  echo "  $f"
  # Measured against Codex CLI 0.166.0: a hooks.json that Codex has not been
  # made to trust is never invoked, the command runs, and Codex prints nothing
  # about it. Writing the file is not the last step.
  echo "  Codex will not run this hook until you make it trust it: start codex,"
  echo "  review and accept the hook when prompted. An untrusted hooks.json gives"
  echo "  no protection and no error (measured on 0.166.0)."
}

install_antigravity() {
  local f="$HOME/.gemini/config/hooks.json"
  local hook="$HOOK_DIR/antigravity-cli-hook.sh"
  mkdir -p "$(dirname "$f")"
  [ -f "$f" ] || echo '{}' > "$f"
  backup "$f"
  # Named-hook map: set only our key, leaving any other hooks intact.
  local tmp; tmp="$(mktemp)"
  jq --arg cmd "$hook" '
    ."toolguard-coding-agent-guard" = { PreToolUse: [ { matcher:"*",
      hooks:[ { command:$cmd } ] } ] }
  ' "$f" > "$tmp" && mv "$tmp" "$f"
  echo "✓ Antigravity: PreToolUse(all tools) -> $hook"
  echo "  $f"
}

uninstall_one() {
  local f="$1"
  if [ -f "$f.bak-toolguard" ]; then
    mv "$f.bak-toolguard" "$f"; echo "↩ restored $f"
  elif [ -f "$f" ]; then
    rm -f "$f"; echo "↩ removed $f (no backup existed)"
  fi
}

[ "$UNINSTALL" -eq 1 ] || record_protect_paths

for t in "${TARGETS[@]}"; do
  if [ "$UNINSTALL" -eq 1 ]; then
    case "$t" in
      claude)      uninstall_one "$HOME/.claude/settings.json" ;;
      codex)       uninstall_one "$HOME/.codex/hooks.json" ;;
      antigravity) uninstall_one "$HOME/.gemini/config/hooks.json" ;;
    esac
  else
    case "$t" in
      claude)      install_claude ;;
      codex)       install_codex ;;
      antigravity) install_antigravity ;;
    esac
  fi
done

if [ "$UNINSTALL" -eq 0 ]; then
  echo
  echo "Done. Each harness now calls its wrapper in $HOOK_DIR"
  echo "The wrappers run 'tg hook' with the five policies in $HERE/policies"
  echo
  echo "Check it against the harness you run:"
  echo "  ./examples/coding-agent-guard/verify-harnesses.sh   (needs the CLIs, makes paid model calls)"
  echo "  ./examples/coding-agent-guard/run.sh                (offline: prints the decision each wrapper returns)"
  echo
  echo "What a harness does with a decision differs by harness and by version."
  echo "docs/support-matrix.md lists what was measured and on which version."
  echo "The Codex wrapper returns an escalation as a denial. The other two wrappers"
  echo "return it as a request for approval. To change that for one harness, set"
  echo "TG_ESCALATE_AS=deny or TG_ESCALATE_AS=ask in the environment the harness runs in."
fi
