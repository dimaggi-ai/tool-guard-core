# Conformance corpus

Each `*.json` file in this directory is one case: a shipped policy from
`policies/` or an explicitly documented derived fixture from `fixtures/`, a
real envelope, and the exact decision and applied action the engine must
produce. Run with:

```bash
go test ./cmd/tg/ -run TestConformance -v
```

Wired into `.github/workflows/ci.yml`'s existing 3-OS matrix
(ubuntu/macos/windows) — this corpus is the "green on every release and
platform" claim from the public 1.0 roadmap, made real rather than
aspirational. It's a starting set, not exhaustive — add a case whenever a
policy's documented behavior changes, a new shipped policy lands, or a
derived fixture pins an engine contract that shipped policies do not isolate.
This keeps the corpus growing with the product instead of drifting from it.

## Schema

```json
{
  "name": "unique-kebab-case-id",
  "description": "one sentence: what this case proves and why",
  "policy_file": "../../policies/<file>.yaml or fixtures/<file>.yaml",
  "mode": "enforcement",
  "envelope": { "tool_name": "...", "tool_group": "...", "parameters": {...}, "context": {...} },
  "expect": { "decision": "allowed|denied|escalated|flagged", "action_taken": "allowed|denied|escalated|flagged|allowed_shadow" }
}
```

`mode` is the call-site default passed to the engine. A policy's own mode is
authoritative for its contribution: `mode: shadow` in YAML remains telemetry
under a call-site `enforcement` default, while `mode: enforcement` in YAML
cannot be downgraded by a call-site `shadow` value. The
`shadow_policy_under_enforcement_callsite.json` case pins the documented
single-policy staging workflow using a policy fixture whose only semantic
difference from the shipped refund-cap example is `mode: shadow`.

## Completeness rule

`TestConformanceCompleteness` (`cmd/tg/conformance_test.go`) fails when
any `policies/*.yaml` has zero cases here, when two cases share a name,
or when a case's `name` doesn't match its filename. A new shipped
policy therefore cannot land without at least one pinned
decision — the corpus can't silently drift from the policy set the way
it did between 0.5.0 and 0.6.0. One case is the floor, not the goal:
cover each outcome class the policy can actually produce.
