#!/usr/bin/env bash
set -euo pipefail

tag_ref="${1:?usage: verify-release-tag-head.sh TAG_REF [MAIN_REF] [TAG_NAME]}"
main_ref="${2:-origin/main}"
tag_name="${3:-$tag_ref}"
mode="${4:-exact}"

# Peel either an annotated-tag object or a direct commit SHA. GitHub normally
# supplies the commit for a tag push, but accepting both shapes keeps the
# invariant explicit and independently testable.
tag_commit="$(git rev-parse "${tag_ref}^{commit}")"
main_commit="$(git rev-parse "${main_ref}^{commit}")"

if [[ "${tag_commit}" == "${main_commit}" ]]; then
  echo "OK: ${tag_name} resolves to ${main_ref} HEAD ${main_commit}."
  exit 0
fi

if [[ "${mode}" == "allow-main-advance" ]] && git merge-base --is-ancestor "${tag_commit}" "${main_commit}"; then
  echo "OK: ${tag_name} remains at ${tag_commit}; ${main_ref} advanced to descendant ${main_commit} during draft recovery."
  exit 0
fi

if [[ "${mode}" != "exact" && "${mode}" != "allow-main-advance" ]]; then
  echo "::error::Unknown release tag-head verification mode ${mode}." >&2
  exit 2
fi

if [[ "${tag_commit}" != "${main_commit}" ]]; then
  echo "::error::Tag ${tag_name} resolves to ${tag_commit}, but ${main_ref} is ${main_commit}." >&2
  if [[ "${mode}" == "allow-main-advance" ]]; then
    echo "::error::Draft recovery only permits main to advance as a descendant of the immutable release tag." >&2
  else
    echo "::error::The reviewed release commit must be main's exact HEAD before tagging — see RELEASING.md." >&2
  fi
  exit 1
fi
