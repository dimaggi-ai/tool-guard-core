#!/usr/bin/env bash
# Snapshot the policies/ directory exactly as it existed at a release tag
# into testdata/policy-compat/<tag>/, for TestPolicyCompat. Run after
# tagging a release (see RELEASING.md). Idempotent: re-running for an
# existing tag overwrites the snapshot with the same bytes.
set -euo pipefail

tag="${1:?usage: scripts/snapshot-policies.sh <tag> (e.g. v0.7.0)}"
root="$(git rev-parse --show-toplevel)"
dest="$root/testdata/policy-compat/$tag"

git rev-parse -q --verify "refs/tags/$tag" >/dev/null || {
  echo "error: tag $tag does not exist" >&2
  exit 1
}

mkdir -p "$dest"
git ls-tree -r --name-only "$tag" -- policies/ | grep -v 'README\.md$' | while read -r f; do
  git show "$tag:$f" > "$dest/$(basename "$f")"
done

echo "snapshotted $(ls "$dest" | wc -l | tr -d ' ') policies from $tag into ${dest#"$root"/}"
