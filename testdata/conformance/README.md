# Conformance corpus

Each `*.json` file in this directory is one case: a shipped policy from
`policies/`, a real envelope, and the exact decision the engine must
produce. Run with:

```bash
go test ./cmd/tg/ -run TestConformance -v
```

Wired into `.github/workflows/ci.yml`'s existing 3-OS matrix
(ubuntu/macos/windows) — this corpus is the "green on every release and
platform" claim from the public 1.0 roadmap, made real rather than
aspirational. It's a starting set, not exhaustive — add a case whenever a
policy's documented behavior changes or a new shipped policy lands, so the
corpus grows with the product instead of drifting from it.

## Schema

```json
{
  "name": "unique-kebab-case-id",
  "description": "one sentence: what this case proves and why",
  "policy_file": "../../policies/<file>.yaml",
  "mode": "enforcement",
  "envelope": { "tool_name": "...", "tool_group": "...", "parameters": {...}, "context": {...} },
  "expect": { "decision": "allowed|denied|escalated|flagged", "action_taken": "allowed|denied|escalated|flagged|allowed_shadow" }
}
```

`mode` is the proxy-level default passed to the engine (see
`pkg/engine/evaluator.go`'s effective-mode resolution — a policy's own
`mode: enforcement` always escalates regardless of this value; a policy
can never be forced into shadow by this field alone if the policy itself
says enforcement). Every case here uses policies that hardcode
`mode: enforcement`, so this field is `"enforcement"` throughout — add a
shadow-mode case here if a shadow-mode example policy ever ships.

## Completeness rule

`TestConformanceCompleteness` (`cmd/tg/conformance_test.go`) fails when
any `policies/*.yaml` has zero cases here, when two cases share a name,
or when a case's `name` doesn't match its filename. A new shipped
policy therefore cannot land without at least one pinned
decision — the corpus can't silently drift from the policy set the way
it did between 0.5.0 and 0.6.0. One case is the floor, not the goal:
cover each outcome class the policy can actually produce.
