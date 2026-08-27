#!/usr/bin/env bash
set -euo pipefail

event_ref="${1:?usage: verify-release-workflow-state.sh EVENT_REF MAIN_REF TAG_NAME RUN_ATTEMPT RELEASE_STATE}"
main_ref="${2:?missing MAIN_REF}"
tag_name="${3:?missing TAG_NAME}"
run_attempt="${4:?missing RUN_ATTEMPT}"
release_state="${5:?missing RELEASE_STATE (missing|draft|public)}"

if [[ ! "${run_attempt}" =~ ^[1-9][0-9]*$ ]]; then
  echo "::error::GITHUB_RUN_ATTEMPT must be a positive integer, got ${run_attempt}." >&2
  exit 2
fi
case "${release_state}" in
  missing|draft|public) ;;
  *)
    echo "::error::Unknown release state ${release_state}; expected missing, draft, or public." >&2
    exit 2
    ;;
esac

tag_ref="refs/tags/${tag_name}"
tag_commit="$(git rev-parse "${tag_ref}^{commit}")"
event_commit="$(git rev-parse "${event_ref}^{commit}")"
if [[ "${tag_commit}" != "${event_commit}" ]]; then
  echo "::error::${tag_name} moved from workflow commit ${event_commit} to ${tag_commit}." >&2
  exit 1
fi

mode=exact
if (( run_attempt > 1 )); then
  case "${release_state}" in
    draft)
      mode=allow-main-advance
      echo "Resuming existing draft for immutable tag ${tag_name}"
      ;;
    public)
      echo "::error::${tag_name} is already public; refusing release-workflow recovery." >&2
      exit 1
      ;;
    missing) ;;
  esac
fi

exec bash scripts/verify-release-tag-head.sh "${tag_ref}" "${main_ref}" "${tag_name}" "${mode}"
