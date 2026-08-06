#!/usr/bin/env bash
# Snapshot the policies/ directory into testdata/policy-compat/<version>/,
# for TestPolicyCompat. Run BEFORE tagging the release (see RELEASING.md):
# the tag-triggered release workflow runs the test suite at the tag, and
# TestPolicyCompatCoverage requires the tag's own snapshot to exist there —
# so the snapshot must be committed before the tag is placed, taken from
# the commit that will be tagged.
#
#   scripts/snapshot-policies.sh vX.Y.Z          # from the vX.Y.Z tag (backfill)
#   scripts/snapshot-policies.sh vX.Y.Z HEAD     # pre-tag: from the release commit
#
# The destination is rebuilt from empty, so a re-run is an exact snapshot
# with no stale leftovers.
set -euo pipefail

version="${1:?usage: scripts/snapshot-policies.sh <version> [ref] (e.g. vX.Y.Z HEAD)}"
ref="${2:-$version}"
root="$(git rev-parse --show-toplevel)"
dest="$root/testdata/policy-compat/$version"

git rev-parse -q --verify "$ref^{commit}" >/dev/null || {
  echo "error: ref $ref does not resolve to a commit" >&2
  exit 1
}

rm -rf "$dest"
mkdir -p "$dest"
git ls-tree -r --name-only "$ref" -- policies/ | grep -v 'README\.md$' | while read -r f; do
  git show "$ref:$f" > "$dest/$(basename "$f")"
done

echo "snapshotted $(ls "$dest" | wc -l | tr -d ' ') policies from $ref into ${dest#"$root"/}"
