# Conformance corpus

Each top-level `*.json` file in this directory is one executable case: one or
more policies, a real action envelope, and the exact result the engine must
produce. Policy-only test inputs live under `fixtures/` and do not count as
cases. Run the same gate CI uses with:

```bash
make conformance
```

Wired into `.github/workflows/ci.yml`'s existing 3-OS matrix
(ubuntu/macos/windows) — this corpus is the "green on every release and
platform" claim from the public 1.0 roadmap, made real rather than
aspirational. The v0.8.0 floor is 60 cases; add a focused case whenever a
policy, operator, mode, or documented boundary changes.

## Schema

```json
{
  "name": "unique-kebab-case-id",
  "description": "one sentence: what this case proves and why",
  "policy_file": "../../policies/<file>.yaml or fixtures/<file>.yaml",
  "mode": "enforcement",
  "envelope": { "tool_name": "...", "tool_group": "...", "parameters": {...}, "context": {...} },
  "expect": {
    "decision": "allowed|denied|escalated|flagged",
    "action_taken": "allowed|denied|escalated|flagged|allowed_shadow",
    "matched_rule_ids": ["optional", "exact", "matched-rule-set"]
  }
}
```

Use `policy_files` instead of `policy_file` when a composition property needs
multiple policies:

```json
"policy_files": ["../../policies/irreversibility_floor.yaml", "fixtures/allow_all.yaml"]
```

Exactly one selector is required. Paths must be relative to the case file and
cannot repeat.

If a case relies on policy content first introduced after older frozen
snapshots, declare the earliest compatible release explicitly:

```json
"policy_compat_since": "v0.5.0"
```

This only limits replay by `TestPolicyCompat`; it never skips current
conformance. Leave it absent when every snapshot containing that policy should
produce the same result.

The loader rejects unknown fields, trailing JSON, missing required values,
invalid modes/results, non-object `parameters`, duplicate policy paths, and
duplicate case IDs (`name`). Every non-allow result must declare
`expect.matched_rule_ids`; the harness compares the exact sorted set so a case
cannot stay green merely because a different rule produced the same top-level
decision.

`mode` is the call-site default passed to the engine. The corpus includes both
`enforcement` and `shadow`: an enforcement policy cannot be downgraded by a
shadow call site, while a matched shadow deny records `decision: denied` and
`action_taken: allowed_shadow`.

## Completeness rule

`TestConformanceCompleteness` (`cmd/tg/conformance_test.go`) fails when any of
these contracts drifts:

- fewer than 60 top-level cases;
- a duplicate case name or a name that differs from its filename;
- any reachable outcome class missing for a shipped `policies/*.yaml` file
  (default allow plus each enabled rule effect);
- any generic condition operator or AND/OR/NOT branch missing from matched
  cases;
- either call-site mode missing;
- any reversibility tier missing from irreversibility-floor cases; or
- no multi-policy case proving an irreversible escalation outranks a matched
  permissive allow.

Deleting a shipped policy's only outcome case therefore turns CI red and names
the missing policy and outcome.
