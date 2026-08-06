# Policy compatibility snapshots

Each `<version>/` directory here is an exact copy of `policies/*.yaml` as
it existed at that git tag — taken with `git show <tag>:policies/<file>`,
not hand-written. `TestPolicyCompat` (`cmd/tg/policy_compat_test.go`)
re-runs the conformance corpus (`testdata/conformance/*.json`) against
these frozen snapshots instead of the live `policies/` directory, and
asserts the exact same decision comes out.

This is the **behavioral** half of the "frozen policy schema" item on
the public 1.0 roadmap. The structural half — `schema_version` on policy
YAML, enforced strictly at parse time, with migration guidance for
removed fields — ships in 0.7.0 (#15/#17). These snapshots are the
complementary net: they fail loudly if a future engine or loader change
would silently change how an old, unmodified policy file *behaves*,
which no parse-time check can catch. Snapshots from pre-0.7.0 tags
deliberately carry no `schema_version` — loading them exercises the
omitted-version-is-v1 compatibility path.

## Adding a snapshot for a release

**Before tagging** (see `RELEASING.md` — the tag's own CI requires its
snapshot, so the snapshot commit must be the commit that gets tagged),
snapshot the policies from the release commit:

```bash
scripts/snapshot-policies.sh vX.Y.Z HEAD
```

To backfill a snapshot for an already-existing tag, omit the ref:
`scripts/snapshot-policies.sh vX.Y.Z` reads from the tag itself.

`TestPolicyCompat` picks up any new `<version>/` directory automatically
— no test code changes needed. A case is skipped for a version whose
snapshot doesn't contain that policy's filename yet (the policy didn't
exist at that tag) rather than failing.

Forgetting the snapshot is no longer silent: `TestPolicyCompatCoverage`
(same file) fails when any release tag from v0.2.0 on has no snapshot
directory, when a snapshot is missing a policy that its tag shipped,
when a snapshot file's bytes differ from what the tag shipped, or when
a snapshot contains a file its tag never shipped.
It compares against `git tag` / `git ls-tree`, so it needs a checkout
with tags (CI fetches them via `fetch-tags` in `ci.yml`; a tag-less
clone skips with a message instead of passing vacuously).
