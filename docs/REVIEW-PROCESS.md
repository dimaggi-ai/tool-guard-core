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

Run against any change touching policy evaluation, the SDK, audit
integrity, or a release workflow. Not every pillar applies to every
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

## Where this fits in the release checklist

`RELEASING.md`'s "Before tagging at all" section should include running
this checklist for any release containing a decision-path, SDK, or
release-workflow change — add findings to the log above rather than
letting them live only in a PR description or commit message.
