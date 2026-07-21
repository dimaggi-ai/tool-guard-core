# Policy compatibility snapshots

Each `<version>/` directory here is an exact copy of `policies/*.yaml` as
it existed at that git tag — taken with `git show <tag>:policies/<file>`,
not hand-written. `TestPolicyCompat` (`cmd/tg/policy_compat_test.go`)
re-runs the conformance corpus (`testdata/conformance/*.json`) against
these frozen snapshots instead of the live `policies/` directory, and
asserts the exact same decision comes out.

This is a **partial** implementation of the "frozen policy schema" item
on the public 1.0 roadmap: there is no version field on policy YAML, no
migration step, and no compatibility guarantee enforced at parse time —
just a regression net that fails loudly if a future engine or loader
change would silently change how an old, unmodified policy file behaves.
Full schema versioning is still open.

## Adding a snapshot after a release

After tagging a release (see `RELEASING.md`), snapshot the policies as
they shipped at that tag:

```bash
mkdir -p testdata/policy-compat/vX.Y.Z
for f in $(git ls-tree -r --name-only vX.Y.Z -- policies/ | grep -v README.md); do
  git show "vX.Y.Z:$f" > "testdata/policy-compat/vX.Y.Z/$(basename "$f")"
done
```

`TestPolicyCompat` picks up any new `<version>/` directory automatically
— no test code changes needed. A case is skipped for a version whose
snapshot doesn't contain that policy's filename yet (the policy didn't
exist at that tag) rather than failing.
