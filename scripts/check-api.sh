#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
baseline="$repo_root/api/go-api.current"
module="github.com/dimaggi-ai/tool-guard-core"
apidiff_version="v0.0.0-20260824195058-e88cd73687aa"

cd "$repo_root"

if [[ "${1:-}" == "--update" ]]; then
  go run "golang.org/x/exp/cmd/apidiff@${apidiff_version}" -m -w "$baseline" "$module"
  echo "Updated $baseline"
  echo "Review the intended API change and its release notes before committing."
  exit 0
fi

if [[ ! -s "$baseline" ]]; then
  echo "ERROR: missing API baseline: $baseline" >&2
  echo "Run 'make api-update' only after the API change has been reviewed." >&2
  exit 1
fi

report="$(mktemp "${TMPDIR:-/tmp}/toolguard-apidiff.XXXXXX")"
diagnostics="$(mktemp "${TMPDIR:-/tmp}/toolguard-apidiff-stderr.XXXXXX")"
trap 'rm -f "$report" "$diagnostics"' EXIT

if ! go run "golang.org/x/exp/cmd/apidiff@${apidiff_version}" -m "$baseline" "$module" >"$report" 2>"$diagnostics"; then
	cat "$diagnostics" >&2
	cat "$report" >&2
	exit 1
fi

if [[ -s "$report" ]]; then
  echo "ERROR: exported Go API differs from api/go-api.current:" >&2
  cat "$report" >&2
  echo >&2
  echo "If intentional, document the compatibility impact, obtain review, then run 'make api-update'." >&2
  exit 1
fi

echo "OK: exported Go API matches api/go-api.current"
