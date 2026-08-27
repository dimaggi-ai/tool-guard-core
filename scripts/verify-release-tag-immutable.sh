#!/usr/bin/env bash
set -euo pipefail

event_ref="${1:?usage: verify-release-tag-immutable.sh EVENT_REF TAG_REF [TAG_NAME]}"
tag_ref="${2:?missing TAG_REF}"
tag_name="${3:-$tag_ref}"

event_commit="$(git rev-parse "${event_ref}^{commit}")"
tag_commit="$(git rev-parse "${tag_ref}^{commit}")"
if [[ "${tag_commit}" != "${event_commit}" ]]; then
  echo "::error::${tag_name} moved from workflow commit ${event_commit} to ${tag_commit}; refusing publication." >&2
  exit 1
fi
echo "OK: ${tag_name} remains immutable at ${event_commit}."
