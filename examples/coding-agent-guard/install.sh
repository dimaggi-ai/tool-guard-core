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
TG="$ROOT/bin/tg"

command -v jq >/dev/null 2>&1 || { echo "install.sh needs 'jq' on PATH"; exit 2; }

UNINSTALL=0
TARGETS=()
for a in "$@"; do
  case "$a" in
    --uninstall) UNINSTALL=1 ;;
    claude|codex|antigravity) TARGETS+=("$a") ;;
    *) echo "unknown arg: $a (want: claude codex antigravity --uninstall)"; exit 2 ;;
  esac
done

# Default: auto-detect installed agents.
if [ "${#TARGETS[@]}" -eq 0 ]; then
  command -v claude >/dev/null 2>&1 && TARGETS+=("claude")
  command -v codex  >/dev/null 2>&1 && TARGETS+=("codex")
  command -v agy    >/dev/null 2>&1 && TARGETS+=("antigravity")
  [ "${#TARGETS[@]}" -eq 0 ] && { echo "no supported agent (claude/codex/agy) found on PATH"; exit 1; }
fi

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
  local hook="$HOOK_DIR/anthropic-hook.sh"
  mkdir -p "$(dirname "$f")"
  [ -f "$f" ] || echo '{}' > "$f"
  backup "$f"
  # Append our matcher block to .hooks.PreToolUse, removing any prior copy of
  # the same command so re-running is a no-op.
  local tmp; tmp="$(mktemp)"
  jq --arg cmd "$hook" '
    .hooks //= {} | .hooks.PreToolUse //= []
    | .hooks.PreToolUse |= ( map( .hooks |= ( map(select(.command != $cmd)) ) )
                             | map(select((.hooks // []) | length > 0)) )
    | .hooks.PreToolUse += [ { matcher:"Bash", hooks:[ { type:"command", command:$cmd } ] } ]
  ' "$f" > "$tmp" && mv "$tmp" "$f"
  echo "✓ Claude Code: PreToolUse(Bash) -> $hook"
  echo "  $f"
}

install_codex() {
  local f="$HOME/.codex/hooks.json"
  local hook="$HOOK_DIR/anthropic-hook.sh"
  mkdir -p "$(dirname "$f")"
  [ -f "$f" ] || echo '{}' > "$f"
  backup "$f"
  # Same shape as Claude's PreToolUse array; merge ours in, drop prior copies.
  local tmp; tmp="$(mktemp)"
  jq --arg cmd "$hook" '
    .PreToolUse //= []
    | .PreToolUse |= ( map( .hooks |= ( map(select(.command != $cmd)) ) )
                       | map(select((.hooks // []) | length > 0)) )
    | .PreToolUse += [ { matcher:"^Bash$",
        hooks:[ { type:"command", command:$cmd, timeout:30, statusMessage:"Tool Guard policy check" } ] } ]
  ' "$f" > "$tmp" && mv "$tmp" "$f"
  echo "✓ Codex: PreToolUse(^Bash$) -> $hook"
  echo "  $f"
}

install_antigravity() {
  local f="$HOME/.gemini/config/hooks.json"
  local hook="$HOOK_DIR/antigravity-hook.sh"
  mkdir -p "$(dirname "$f")"
  [ -f "$f" ] || echo '{}' > "$f"
  backup "$f"
  # Named-hook map: set only our key, leaving any other hooks intact.
  local tmp; tmp="$(mktemp)"
  jq --arg cmd "$hook" '
    ."toolguard-coding-agent-guard" = { PreToolUse: [ { matcher:"run_command",
      hooks:[ { command:$cmd } ] } ] }
  ' "$f" > "$tmp" && mv "$tmp" "$f"
  echo "✓ Antigravity: PreToolUse(run_command) -> $hook"
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
  echo "Done. Try it: ask your agent to run 'rm -rf /tmp/x' or 'git push' and watch Tool Guard step in."
  echo "Verify offline first with:  ./run.sh"
fi
