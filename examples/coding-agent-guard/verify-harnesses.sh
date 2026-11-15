#!/usr/bin/env bash
# verify-harnesses.sh: run the shipped hook wrappers under the real coding
# harnesses (Claude Code, Codex CLI, Antigravity CLI) and record what each
# harness did with every decision. It makes paid model calls.
#
# The work is done by verify_harnesses.py next to this file. Its header lists
# the environment variables, the exit status values, what is kept as evidence
# and how sign-in files are handled.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v python3 >/dev/null 2>&1; then
  echo "verify-harnesses: python3 is required" >&2
  exit 2
fi
exec python3 "$here/verify_harnesses.py" "$@"
