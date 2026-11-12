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
# Uninstall: ./install.sh --uninstall <agent...> restores the .bak-toolguard
# file the installer wrote. Without that file it removes its own entry.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
HOOK_DIR="$HERE/hooks"
PROTECT=()      # --protect PATH: an absolute path the hook denies writes to
STATE_DIR="${TG_STATE_DIR:-$HOME/.tool-guard}"
PROTECT_FILE="${TG_PROTECT_FILE:-$STATE_DIR/protect-paths}"
TG="$ROOT/bin/tg"
# Claude Code and Codex read their config from these directories when the
# variables are set; hooks/guard-hook.sh protects the same paths.
CLAUDE_F="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/settings.json"
CODEX_F="${CODEX_HOME:-$HOME/.codex}/hooks.json"
AGY_F="$HOME/.gemini/config/hooks.json"

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

# Create the config file when it is missing and keep a backup of the first
# version.
prepare_config() {
  mkdir -p "$(dirname "$1")"
  [ -f "$1" ] || echo '{}' > "$1"
  backup "$1"
}

# Stop in the check pass when the installer could not write a config file or
# its backup: the path is a link to a file that does not exist, or the first
# existing directory above it is not a directory the installer can write to.
check_target_path() {
  local f="$1" what="$2" d
  if [ -L "$f" ] && [ ! -e "$f" ]; then
    echo "install.sh: $f is a symbolic link to a file that does not exist."
    echo "  No config file was changed and no hook was installed."
    exit 1
  fi
  if [ -e "$f" ] && [ ! -f "$f" ]; then
    echo "install.sh: $f is not a regular file."
    echo "  No config file was changed and no hook was installed."
    exit 1
  fi
  d="$(dirname "$f")"
  while [ ! -e "$d" ] && [ ! -L "$d" ]; do d="$(dirname "$d")"; done
  if [ ! -d "$d" ] || [ ! -w "$d" ] || [ ! -x "$d" ]; then
    echo "install.sh: cannot write $what in $d. It is not a directory this user can write to."
    echo "  No config file was changed and no hook was installed."
    exit 1
  fi
}

# The installer runs every edit twice. The first pass (CHECK_ONLY=1) computes
# each result and writes nothing, so a config file the installer cannot edit
# stops the run before any config file is changed. The second pass writes.
CHECK_ONLY=0

# Run one jq program on a config file. When jq fails, or its output is not
# one JSON object, the file is not changed and the installer stops: a success
# line must not follow a failed edit. The result is written into the file, so
# its mode stays and a symbolic link stays a link.
apply_jq() {
  local f="$1"; shift
  local tmp src
  if [ "$CHECK_ONLY" -eq 1 ]; then
    check_target_path "$f" "the config file and its backup"
  fi
  tmp="$(mktemp)"; src="$(mktemp)"
  # A missing file and a file of 0 bytes are read as the empty object.
  if [ -s "$f" ]; then cat "$f" > "$src"; else echo '{}' > "$src"; fi
  if ! jq "$@" "$src" > "$tmp" || ! jq -e -s 'length == 1 and (.[0] | type) == "object"' "$tmp" >/dev/null 2>&1; then
    rm -f "$tmp" "$src"
    echo "install.sh: could not update $f. No config file was changed and no hook was installed."
    echo "  It must hold one JSON object. A \"hooks\" value must be an object, \"hooks.PreToolUse\" must be an array, and each PreToolUse entry must be an object."
    exit 1
  fi
  rm -f "$src"
  if [ -e "$f" ] && [ ! -w "$f" ]; then
    rm -f "$tmp"
    echo "install.sh: $f is not writable. No config file was changed and no hook was installed."
    exit 1
  fi
  if [ "$CHECK_ONLY" -eq 0 ]; then
    cat "$tmp" > "$f"
  fi
  rm -f "$tmp"
}

# jq text shared by the Claude Code and Codex edits: stop when
# hooks.PreToolUse exists and is not an array.
PRETOOLUSE_ARRAY='if (.hooks.PreToolUse | type) != "array" then error("hooks.PreToolUse is not an array") else . end'

install_claude() {
  local f="$CLAUDE_F"
  local hook="$HOOK_DIR/claude-code-hook.sh"
  # The Claude Code settings reference lists "disableAllHooks" as turning off
  # hooks (read 2026-11-10).
  # A hook written into such a file would not run, so the installer stops.
  if [ -s "$f" ] && jq -e 'type == "object" and .disableAllHooks == true' "$f" >/dev/null 2>&1; then
    echo "install.sh: $f sets \"disableAllHooks\" to true. Claude Code documents that"
    echo "  setting as turning off hooks. Remove it and run install.sh again."
    echo "  No config file was changed and no hook was installed."
    exit 1
  fi
  [ "$CHECK_ONLY" -eq 1 ] || prepare_config "$f"
  # Append our matcher block to .hooks.PreToolUse, removing any prior copy of
  # the same command so re-running is a no-op.
  apply_jq "$f" --arg cmd "$hook" --arg dir "$HOOK_DIR/" '
    .hooks //= {} | .hooks.PreToolUse //= [] | '"$PRETOOLUSE_ARRAY"'
    | .hooks.PreToolUse |= ( map( if (.hooks | type) == "array" then .hooks |= ( map(select((.command // "") | contains($dir) | not)) ) else . end )
                             | map(select(((.hooks | type) != "array") or (.hooks | length > 0))) )
    | .hooks.PreToolUse += [ { matcher:"", hooks:[ { type:"command", command:$cmd } ] } ]
  '
  [ "$CHECK_ONLY" -eq 0 ] || return 0
  echo "✓ Claude Code: PreToolUse(all tools) -> $hook"
  echo "  $f"
}

install_codex() {
  local f="$CODEX_F"
  local hook="$HOOK_DIR/codex-hook.sh"
  # install.sh up to 0.8.x wrote its entry under a top-level PreToolUse key.
  # Codex CLI 0.166.0 rejects a hooks.json with that key and loads no hook
  # (one interactive start, 2026-11-10). The key is removed when every entry
  # under it is from this installer. Another entry is not ours to move or
  # delete, so the installer stops before it changes the file.
  if [ -f "$f" ] && jq -e 'type == "object" and has("PreToolUse")' "$f" >/dev/null 2>&1 &&
     ! jq -e --arg dir "$HOOK_DIR/" '
         (.PreToolUse | type) == "array"
         and (.PreToolUse | all( type == "object" and (.hooks | type) == "array" and (.hooks | length) > 0
                                 and (.hooks | all( type == "object" and ((.command // "") | contains($dir)) )) ))
       ' "$f" >/dev/null 2>&1; then
    echo "install.sh: $f has a top-level PreToolUse key with an entry that is not"
    echo "  from this installer. Codex CLI 0.166.0 rejects such a file and loads no"
    echo "  hook. Move that entry under \"hooks\" and run install.sh again."
    echo "  No config file was changed and no hook was installed."
    exit 1
  fi
  [ "$CHECK_ONLY" -eq 1 ] || prepare_config "$f"
  # Same shape as Claude's PreToolUse array; merge ours in, drop prior copies.
  apply_jq "$f" --arg cmd "$hook" --arg dir "$HOOK_DIR/" '
    del(.PreToolUse)
    | .hooks //= {}
    | .hooks.PreToolUse //= [] | '"$PRETOOLUSE_ARRAY"'
    | .hooks.PreToolUse |= ( map( if (.hooks | type) == "array" then .hooks |= ( map(select((.command // "") | contains($dir) | not)) ) else . end )
                       | map(select(((.hooks | type) != "array") or (.hooks | length > 0))) )
    | .hooks.PreToolUse += [ { matcher:"",
        hooks:[ { type:"command", command:$cmd, timeout:30, statusMessage:"Tool Guard policy check" } ] } ]
  '
  [ "$CHECK_ONLY" -eq 0 ] || return 0
  echo "✓ Codex: PreToolUse(all tools) -> $hook"
  echo "  $f"
  # Measured against Codex CLI 0.166.0: codex exec does not call a hook from
  # a hooks.json that Codex has not been made to trust, the command runs, and
  # codex exec prints nothing about it. Writing the file is not the last step.
  echo "  Codex will not run this hook until you make it trust it: start codex,"
  echo "  review and accept the hook when prompted. An untrusted hooks.json gives"
  echo "  no protection, and codex exec prints no error (measured on 0.166.0)."
}

install_antigravity() {
  local f="$AGY_F"
  local hook="$HOOK_DIR/antigravity-cli-hook.sh"
  [ "$CHECK_ONLY" -eq 1 ] || prepare_config "$f"
  # Named-hook map: set only our key, leaving any other hooks intact.
  apply_jq "$f" --arg cmd "$hook" '
    ."toolguard-coding-agent-guard" = { PreToolUse: [ { matcher:"*",
      hooks:[ { command:$cmd } ] } ] }
  '
  [ "$CHECK_ONLY" -eq 0 ] || return 0
  echo "✓ Antigravity: PreToolUse(all tools) -> $hook"
  echo "  $f"
  echo "  Not measured: the release run used a workspace .agents/hooks.json. No run"
  echo "  shows that Antigravity CLI reads the file above. See docs/support-matrix.md."
}

# Without a backup the installer does not know the first version of the
# file. It removes its own entry and keeps everything else. It never deletes
# the file.
uninstall_one() {
  local f="$1" tmp
  if [ -f "$f.bak-toolguard" ]; then
    # Written into the file, so a symbolic link stays a link.
    if { cat "$f.bak-toolguard" > "$f"; } 2>/dev/null; then
      echo "↩ restored $f"
      if ! rm -f "$f.bak-toolguard" 2>/dev/null; then
        echo "✗ $f.bak-toolguard could not be removed. $f was restored." >&2
        UNINSTALL_FAILED=1
      fi
    else
      echo "✗ $f could not be written, so it was not restored. The copy is still at $f.bak-toolguard." >&2
      UNINSTALL_FAILED=1
    fi
  elif [ -s "$f" ]; then
    tmp="$(mktemp)"
    if jq --arg dir "$HOOK_DIR/" '
         if type != "object" then error("not an object") else . end
         | del(."toolguard-coding-agent-guard")
         | if (.hooks | type) == "object" and (.hooks.PreToolUse | type) == "array" then
             .hooks.PreToolUse |= ( map( if type == "object" and (.hooks | type) == "array"
                                         then .hooks |= map(select(((type == "object") and ((.command // "") | contains($dir))) | not))
                                         else . end )
                                    | map(select((type != "object") or ((.hooks | type) != "array") or (.hooks | length > 0))) )
           else . end
       ' "$f" > "$tmp" 2>/dev/null && [ -w "$f" ]; then
      if cmp -s "$tmp" "$f" || [ "$(jq -cS . "$tmp")" = "$(jq -cS . "$f")" ]; then
        echo "↩ no backup of $f exists and it holds no Tool Guard entry. The file was not changed."
      else
        cat "$tmp" > "$f"
        echo "↩ no backup of $f exists. Removed the Tool Guard entry and kept the rest of the file."
      fi
    else
      echo "✗ no backup of $f exists and the file could not be edited. The file was not changed." >&2
      UNINSTALL_FAILED=1
    fi
    rm -f "$tmp"
  fi
}

install_targets() {
  local t
  for t in "${TARGETS[@]}"; do
    case "$t" in
      claude)      install_claude ;;
      codex)       install_codex ;;
      antigravity) install_antigravity ;;
    esac
  done
}

if [ "$UNINSTALL" -eq 1 ]; then
  for t in "${TARGETS[@]}"; do
    case "$t" in
      claude)      uninstall_one "$CLAUDE_F" ;;
      codex)       uninstall_one "$CODEX_F" ;;
      antigravity) uninstall_one "$AGY_F" ;;
    esac
  done
  [ "${UNINSTALL_FAILED:-0}" -eq 0 ] || exit 1
else
  # Check every target first, then write.
  CHECK_ONLY=1; install_targets
  if [ "${#PROTECT[@]}" -gt 0 ]; then
    check_target_path "$PROTECT_FILE" "the protected-paths file"
  fi
  CHECK_ONLY=0
  record_protect_paths
  install_targets
fi

if [ "$UNINSTALL" -eq 0 ]; then
  echo
  echo "Done. Each harness config now names its wrapper in $HOOK_DIR"
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
