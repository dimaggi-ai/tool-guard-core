#!/usr/bin/env bash
set -euo pipefail

candidate_ref="${1:-HEAD}"
candidate_commit="$(git rev-parse "${candidate_ref}^{commit}")"

while IFS= read -r tag; do
  [[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
  tag_commit="$(git rev-parse "${tag}^{commit}")"
  if [[ "${tag_commit}" != "${candidate_commit}" ]]; then
    echo "${tag}"
    exit 0
  fi
done < <(git tag --merged "${candidate_commit}" --sort=-version:refname)

echo "no distinct stable release tag is reachable from ${candidate_ref} (${candidate_commit})" >&2
exit 1
