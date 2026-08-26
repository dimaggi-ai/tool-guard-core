# Pre-release review process

This is an **internal** adversarial-review checklist, run by a maintainer
(or a maintainer using an AI reviewer) before tagging a release with any
security- or correctness-relevant change. It is not an independent or
third-party review — nothing here should ever be described publicly as
"independently reviewed" or "audited." It's a repeatable process for
catching the class of bug that unit tests miss because they encode the
same assumption the implementation made, formalized after this pattern
found real, shipped issues in the SDK ahead of the 0.5.0 release (see
"Findings log" below).

## Why this exists

A reviewer who only reads the code the author points them at will confirm
what the author already believes. The passes below exist to counter that:
each one targets a different way a change can look correct in isolation
and still be wrong in a real deployment.

## Per-pillar checklist

Run against any change touching policy evaluation, the policy loader,
the SDK, audit integrity, or a release workflow. Not every pillar applies to every
change — judge relevance, but default to running all of them for
anything touching the decision path.

1. **Decision vs. audit-trail correctness.** Does the change branch on
   `decision` (what policy says would happen) or `action_taken` (what
   actually happened)? In shadow mode these differ on purpose
   (`decision=denied`, `action_taken=allowed_shadow`) — any caller that
   branches on `decision` alone will enforce through a code path that
   shadow mode exists specifically to never enforce through. Grep every
   new branch point for this before shipping it.

2. **Allowlist vs. denylist posture.** For anything gating a tool call
   (an unrecognized decision string, exit code, severity level,
   response field), does an *unrecognized* value fail safe (deny/raise)
   or fail open (allow)? A denylist that doesn't recognize a new value
   added later silently passes it through. Prefer an explicit allowlist
   of known-safe values wherever the safe/unsafe cost is asymmetric.

3. **Real dispatcher, not a direct call.** For any adapter/integration
   that hooks a third-party framework's callback or hook system, is at
   least one test going through the framework's *real* dispatcher
   (e.g. `CallbackManager(...).on_tool_start(...)`), not just invoking
   the handler method directly? A direct call can pass while the real
   dispatcher silently swallows the same exception (this is exactly how
   the LangChain adapter's `raise_error` gap survived 8 passing direct
   tests before 0.5.0).

4. **Fail-closed on the unhappy path.** For any exit code / HTTP status
   / parse failure not explicitly enumerated, does the code raise
   (fail-closed) rather than default to an allowed decision? "We'll
   never see that code" is not a justification — enumerate what happens
   when it's wrong.

5. **Claim honesty.** Does any doc, CHANGELOG entry, comment, or CI step
   name added by this change claim something stronger than what was
   built? Concretely: "provenance" is not "reproducible builds";
   "conformance corpus" is not "exhaustive"; a self-review pass run by
   the maintainer is not "independent." Say exactly what exists.

6. **CI coverage, not just local coverage.** Does the new test actually
   run in CI (the right job, the right OS matrix, the right trigger —
   PR vs. nightly vs. release), or does it only run when someone
   remembers to invoke it locally? Check the workflow YAML, don't
   assume.

## Panel review (multi-model)

For release-bound changes touching policy evaluation, the policy loader,
the SDK, audit integrity, or a release workflow, the per-pillar
checklist above is run as a **panel**: several frontier models from
different vendors, each with a distinct brief, reviewing the same change
in parallel. The panel runs **on the pull request, before merge** — its
disposition stamp is a merge prerequisite for qualifying PRs (enforced
by maintainer practice, not by CI), and the pre-tag checklist in
`RELEASING.md` verifies it happened. This is still
maintainer-run review, not independent third-party review — the same
honesty rule as everything else in this document (pillar 5).

The seats and why they differ:

- **Release engineer** (repo access, may execute): walks changed
  workflows/process files as a timeline — what runs at the tag, what is
  immutable when — and reproduces suspicions with real commands.
- **Adversarial verifier** (repo access, may execute): reports nothing
  unreproduced and clears nothing unprobed; builds live probes and
  publishes a "checked and cleared" list alongside findings, which
  removes most of the panel's false positives.
- **Cold reader** (diff only, deliberately no repo access): represents a
  future outside contributor. Anything it cannot verify from the diff it
  reports as a finding ("cannot verify from diff"), dispositioned like
  any other — when such a finding recurs, the usual fix is making the
  change self-evident, not refuting the reader.
- **Second reader** (diff only): fast independent pass over the same
  diff; where it independently agrees with the cold reader, a real gap
  is near-certain.

A strategy/positioning pass (product framing, claim boundaries) may also
run; it is advisory and sits outside the verdict contract below.

Panel mechanics:

- Every reviewing seat returns `VERDICT: APPROVE | APPROVE-WITH-NITS |
  REQUEST-CHANGES` plus ranked findings with file:line, severity, and a
  concrete fix. `REQUEST-CHANGES` means at least one finding must be
  dispositioned before merge; `APPROVE-WITH-NITS` means the findings are
  minor and may be declined with reason; `APPROVE` means none.
- There is no vote. The maintainer synthesizes the verdicts,
  **verifies every finding before acting**, and dispositions each one:
  fixed / refuted-with-evidence / declined-with-reason /
  deferred-to-issue. Deferral is not available to blocker or major
  findings. A single-source finding from a diff-only seat is
  corroborated before a fix lands, or the stamp records why not.
  Conflicts between seats are resolved by evidence and recorded in the
  disposition table.
- The disposition table is posted as a top-level PR comment ("stamp"),
  so the record of what was found, what was refuted, and why is public
  next to the change (see PRs #24/#25 for the format; stamps are keyed
  by reviewer, and seat assignment is per-run). Findings that meet the
  bar for the findings log below are logged there as well — the stamp
  is additional to the log, never a substitute.

First run (2026-08-06, the 0.7.0 PRs) caught a release-pipeline
deadlock, a silent enforcement collapse in `tg hook`, and a
multi-document YAML loader bypass — and refuted eight plausible-sounding
findings that would otherwise have driven unnecessary churn. Both halves
are the point: real bugs fixed, and churn kept out of the tree. The
catches are logged below.

## Findings log

Entries here are load-bearing history, not a changelog duplicate — they
record what the checklist above was built to catch, so future review
passes have real precedent instead of a starting from scratch.

- **2026-07 · SDK, pre-0.5.0.** LangChain adapter never set
  `raise_error = True`; LangChain's real dispatcher catches every
  handler exception and only re-raises if that flag is set, so a DENY
  produced a log line and the tool ran anyway. Found by an adversarial
  review pass, not by the 8 existing direct-call unit tests (all of
  which passed against the bug). → pillar 3.
- **2026-07 · SDK, pre-0.5.0.** `client.py::evaluate()` and
  `native.py::guard_tool_calls()` both branched on `decision` instead of
  `action_taken`, independently, in two different adapters — a
  shadow-mode deployment would have enforced through the SDK. → pillar
  1.
- **2026-07 · SDK, pre-0.5.0.** A re-verification pass on the pillar-1
  fix caught that the fix used a denylist (`decision not in
  ("denied", "escalated")` → allow) inconsistent with the allowlist
  pattern used elsewhere; unified on an explicit allowlist across all
  call sites. → pillar 2.
- **2026-07 · SDK, pre-0.5.0.** `_run_tg_evaluate` defaulted unrecognized
  exit codes / unparseable stdout to `Decision.ALLOWED`; changed to
  raise. `EvaluationResult.from_dict` defaulted missing `decision`/
  `action_taken` keys to `ALLOWED` the same way; changed to raise. →
  pillar 4.
- **2026-07 · release.yml, 1.0-roadmap provenance work.** Initial draft
  of the CHANGELOG entry for `actions/attest-build-provenance` needed an
  explicit correction to not imply "reproducible builds" — the config
  only proves provenance (these bytes came from this CI run), not
  bit-for-bit reproducibility. → pillar 5.
- **2026-07 · `cmd/tg/hook.go`, v0.5.0 pre-tag review.** After fixing the
  SDK's decision-vs-action_taken bug (pillar 1, two entries above), a
  review pass was specifically asked to check whether the same fix
  pattern held everywhere it needed to — it did not: `evalHook` branched
  on `Decision` instead of `ActionTaken`, so `tg hook -mode shadow`
  silently enforced every policy instead of only observing near-misses.
  This is the flagship coding-agent enforcement point, not a peripheral
  adapter, and it shipped drafted (pre-0.5.0) before the SDK work
  surfaced the bug class at all — a first review pass on the SDK alone
  would not have caught it. → pillar 1, and a reminder that pillar 1's
  "grep every new branch point" needs to mean the whole diff, not just
  the files the current change-set touched most.
- **2026-07 · v0.5.0 pre-tag review, general.** The first review pass on
  this exact tag was interrupted mid-run (background task killed) after
  confirming the conformance corpus was non-vacuous but before checking
  the CI wiring, the stress-test floor gating, or the SDK's remaining
  doc claims. A second, fresh pass (no memory of the first) caught the
  hook.go bug above plus five doc/metadata issues (a half-applied SDK
  version bump, stale PyPI-implying install instructions in five files,
  stale `decision`-based docstrings in `errors.py`, a contract test that
  could silently skip in CI, and a "verified against a real tg-proxy"
  claim with no automated test backing it — closed by adding
  `TestProxyShadowModeContract`). None of these were caught by the
  original SDK-focused review. → pillar 6, and evidence for why this
  checklist says "run against any change touching the decision path" —
  narrowly scoping a review to "the new SDK" missed a bug in existing
  code that the SDK's own fix pattern should have prompted a search for.

- **2026-08 · `cmd/tg/protect.go`, v0.6.0 pre-tag review.** A
  pre-tag review pass on the platform-native config-root change (issue
  #13) returned three blockers, all in the same class the checklist
  exists to catch — *state that outlives the code path that created
  it*. (1) `runProtect` resolved fresh default paths before loading
  prior state, so a re-`protect` after the native root came into
  existence silently abandoned an existing install's customized policy
  and started a second audit chain; fixed by pinning re-protect to the
  absolute `PolicyPath`/`AuditPath` recorded in managed state. (2)
  `status`/`unprotect` called the full resolver, which unconditionally
  required `os.UserHomeDir`, so both failed with an explicit `-config`
  when `HOME` was unset — reproduced independently by darwin CI, where
  `os.UserConfigDir` needs `$HOME`; fixed by giving those verbs a
  config-only resolver that performs no root resolution at all. (3) A
  failed platform-root lookup fell back to the legacy path without
  requiring it to exist, so an unset `%AppData%` or a relative
  `XDG_CONFIG_HOME` silently created a *fresh* install in the legacy
  location; fixed by requiring real install evidence (a `policies/` or
  `audit/` directory) and surfacing the resolution error otherwise.
  A follow-up pass then caught that the evidence check followed
  symlinks, so a symlinked legacy root or leaf still qualified —
  tightened to `Lstat`. → pillars 1 and 6, and a reminder that
  "reversible by construction" is a property of the *recorded state*,
  not of the resolver: any change to how default paths are computed
  must be checked against installs that recorded different ones.
  Each finding has its own regression test in
  `cmd/tg/protect_root_test.go`.

- **2026-08 · `RELEASING.md`/`release.yml`, 0.7.0 pre-merge panel.** The
  release checklist put the policy-compat snapshot step *after* the tag
  push, but the tag-triggered workflow runs the test suite at the tag
  and `TestPolicyCompatCoverage` requires the tag's own snapshot to
  exist in the tagged tree — every future release would have failed
  before GoReleaser. Caught by walking the release as a timeline rather
  than reading steps in isolation; the snapshot now happens before
  tagging, from the release commit. → pillar 6.

- **2026-08 · `cmd/tg/hook.go`, 0.7.0 pre-merge panel.** Strict policy
  decoding plus the hook's default fail-open meant one stale field in
  any policy file collapsed enforcement silently: the load failure
  dropped every policy, and `rm -rf /` went from **deny** to **allow**
  with empty stderr. The hook now reports the load failure and the
  offending file on stderr. The load-failure branch still fails open by
  design — the failure mode is now visible, not gone. → pillars 4
  and 2.

- **2026-08 · `pkg/policyload`, 0.7.0 pre-merge panel.** The YAML loader
  decoded only the first document of a multi-document stream, so a
  policy whose scope/rules sat after a `---` separator loaded as an
  empty permissive shell that `tg lint` accepted. Trailing documents
  are now a load error. → pillar 2: a shape the loader does not
  recognize must fail safe, not fail open.

- **2026-08 · v0.8.0 integrated release review.** Timeline and adversarial
  release probes found that ordinary green tests did not prove a retry-safe
  publication: the finalizer lacked explicit repository context, accepted any
  successful PyPI version endpoint rather than the exact built filenames and
  digests, and could not recover when promotion succeeded but its read-back
  failed. A second pass found that GoReleaser did not reuse its staged draft,
  prerelease-shaped tags could enter a workflow whose signature identity only
  accepted stable semver, and the changelog still described 0.8 as planned.
  The final adversarial pass also proved that HTTP 204 responses with no
  decision body and an empty audit report could pass the nightly stress gate.
  The workflow now checks release state transitions explicitly, clean rebuilds
  must produce identical Python artifacts, and the stress harness accepts only
  contract-valid 200/202 bodies while requiring the audit report to contain at
  least the corresponding candidate records. → pillars 2, 4, and 6.

## Where this fits in the release checklist

`RELEASING.md`'s "Before tagging at all" section should include running
this checklist — as a panel review for qualifying changes — for any
release containing a change to policy evaluation, the policy loader,
the SDK, audit integrity, or a release workflow. Add findings to the
log above rather than letting them live only in a PR description or
commit message.
