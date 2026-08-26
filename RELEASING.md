# Releasing Tool Guard Core

This is the exact, required order. Tagging out of this order is how
`v0.3.0` shipped a working GitHub Release while `main` — and every
`blob/main/...` link the Release page itself points to (CHANGELOG.md,
Release-Notes.md, README) — still showed the *previous* version for
two days. `release.yml` now has a CI guard that refuses to publish a
release whose tag isn't reachable from `main`, but don't rely on the
guard catching it after the fact — do it right the first time.

## The order

1. **Land all release work on `main`.** Either merge directly, or if
   the work happened on a long-lived `release/vX.Y.Z` branch, merge
   (or fast-forward) that branch into `main` **and push `main`** —
   before the next step, not after:
   ```bash
   git checkout main
   git merge --ff-only release/vX.Y.Z   # or a real merge if history diverged
   git push origin main
   ```
   If `--ff-only` refuses, `main` and the release branch have
   diverged — resolve that with a real merge/rebase before continuing.
   Don't tag a branch that isn't `main`.

2. **Snapshot the policies from the release commit — BEFORE tagging.**
   The tag-triggered release workflow runs the test suite at the tag,
   and `TestPolicyCompatCoverage` requires the tag's own snapshot to
   exist in that tree — a snapshot committed after tagging can never
   reach the immutable tag, and every release would fail before
   GoReleaser. So the snapshot commit must be the commit you tag:
   ```bash
   scripts/snapshot-policies.sh vX.Y.Z HEAD
   git add testdata/policy-compat/vX.Y.Z
   git commit -m "test: policy-compat snapshot for vX.Y.Z"
   git push origin main
   ```

3. **Tag `main`'s new HEAD:**
   ```bash
   git tag -a vX.Y.Z -m "Tool Guard Core vX.Y.Z"
   ```

4. **Push the tag** (this triggers `.github/workflows/release.yml`,
   which builds, runs GoReleaser, and publishes the GitHub Release +
   container image + SBOMs, then attests build provenance and
   cosign-signs the container manifests — the workflow verifies the
   signatures before going green):
   ```bash
   git push origin vX.Y.Z
   ```

5. **Watch the Release workflow.** Its first real step verifies the
   tag is reachable from `origin/main` and fails immediately, before
   any build/publish work, if it isn't. If it fails: `main` is behind
   the tag — go back to step 1, fast-forward `main`, push it, then
   either re-run the workflow for the same tag or delete and re-push
   the tag once `main` is caught up.

## Before tagging at all

- `CHANGELOG.md` has a dated `## [X.Y.Z]` section (promoted out of
  `## [Unreleased]`), and its link footer has a `[X.Y.Z]:
  .../compare/vPREV...vX.Y.Z` entry.
- `Release-Notes.md` has a matching `## X.Y.Z — date` section, in the
  same style as the existing entries, with every command in it
  actually run and confirmed to work as written.
- `README.md`'s "Known limitations" callout and any version-specific
  prose are current.
- `go build ./... && go vet ./... && go test ./... -race -count=1` is
  green, fresh, at the exact commit being tagged — not "was green
  earlier this session."
- No `v X.Y.Z` tag already exists locally or on `origin`
  (`git tag --list vX.Y.Z`).
- The Python distributions build cleanly and derive the same version from the
  tag: `python -m build --outdir dist/python sdk/python`, then
  `python scripts/verify-python-dist.py dist/python --expected-version X.Y.Z`.
- PyPI trusted publishing is configured for distribution `toolguard-core`,
  repository `dimaggi-ai/tool-guard-core`, workflow `release.yml`, and GitHub
  environment `pypi`. This is a one-time maintainer-side PyPI configuration;
  the workflow intentionally has no long-lived upload token.
- `make api-check` is green. If the release intentionally changes the exported
  Go API, the compatibility impact and baseline refresh followed the process in
  `docs/api-stability.md`.
- Any change to policy evaluation, the policy loader, the SDK, audit
  integrity, or a release workflow in this release has been run through
  the internal review checklist in `docs/REVIEW-PROCESS.md` — as a
  multi-model **panel review** (see "Panel review" there), run on each
  qualifying PR **before it merged**, with the disposition table posted
  as a top-level PR comment (or, for work landed without a PR, recorded
  in that document's findings log) — and log-worthy findings added to
  the findings log, not left only in PR comments.

After the release workflow succeeds, verify the SDK from a clean environment:

```bash
python3 -m venv /tmp/toolguard-install-check
/tmp/toolguard-install-check/bin/pip install "toolguard-core==X.Y.Z"
/tmp/toolguard-install-check/bin/python -c "import toolguard"
```

## Why this exists

`release.yml`'s tag-push trigger only ever looked at the tag — never
at whether `main` had caught up to it. A tag on a branch that never
got merged into `main` still builds and publishes a completely valid
GitHub Release (binaries, SBOMs, container image, changelog excerpt —
all correct, all from the right commit). The only thing wrong is
everything a visitor sees by default: the repo homepage, `git clone`
with no branch specified, and the Release page's own links to
`blob/main/CHANGELOG.md` / `blob/main/Release-Notes.md` — all still
serving the prior release. The CI guard in `release.yml` turns that
from a silent, easy-to-miss gap into a hard failure on the next
release attempt.
