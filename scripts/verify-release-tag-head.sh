#!/usr/bin/env bash
set -euo pipefail

tag_ref="${1:?usage: verify-release-tag-head.sh TAG_REF [MAIN_REF] [TAG_NAME]}"
main_ref="${2:-origin/main}"
tag_name="${3:-$tag_ref}"

# Peel either an annotated-tag object or a direct commit SHA. GitHub normally
# supplies the commit for a tag push, but accepting both shapes keeps the
# invariant explicit and independently testable.
tag_commit="$(git rev-parse "${tag_ref}^{commit}")"
main_commit="$(git rev-parse "${main_ref}^{commit}")"

if [[ "${tag_commit}" != "${main_commit}" ]]; then
  echo "::error::Tag ${tag_name} resolves to ${tag_commit}, but ${main_ref} is ${main_commit}." >&2
  echo "::error::The reviewed release commit must be main's exact HEAD before tagging — see RELEASING.md." >&2
  exit 1
fi

echo "OK: ${tag_name} resolves to ${main_ref} HEAD ${main_commit}."
