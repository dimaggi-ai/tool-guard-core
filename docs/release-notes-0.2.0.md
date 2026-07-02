# Tool Guard Core 0.2.0 — Release Notes

*Release date: 2026-07-02 · [Full changelog](../CHANGELOG.md#020--2026-07-02)*

Tool Guard Core 0.2.0 closes the one attack class 0.1.0's own battle-test
left open, adds a first-class way to guard coding agents, and makes the guard
able to protect itself. **No breaking changes** — every 0.1.0 policy and audit
chain evaluates and verifies identically, and every new behavior is opt-in.

The Enterprise boundary is unchanged: no cryptographic signing, no PII
redaction, no semantic classification beyond the existing opt-in
`llm_classify`. Everything below is deterministic and dependency-free.

## Highlights

- **Amount fragmentation is now mitigated.** `tg-proxy -velocity-track`
  computes rolling 1h/24h monetary windows so a policy can stop an agent that
  splits one large action into many small ones — the bypass 0.1.0 flagged as
  having "no shipped mitigation."
- **`tg hook`** — a single binary that guards Claude Code / Codex / Antigravity
  tool calls, replacing hand-rolled `jq` shell adapters.
- **`-protect-paths` / `-protect-self`** — self-protection that lives in
  operator flags, *outside* the editable policy, so an agent can't disable it
  by rewriting the rules. Adversarially reviewed and hardened.
- **Five new operators** and **`tg simulate`** for expressing and testing
  policies.

---

## 1. Velocity tracking — closes amount fragmentation

`tg-proxy -velocity-track` maintains a per-key sliding window of monetary
actions and injects the trailing 1h/24h sum + count into
`context.verified.agent_velocity.*` before evaluation. A policy then closes
the bypass with an ordinary threshold rule — no new condition type needed:

```yaml
conditions:
  field: context.verified.agent_velocity.monetary_sum_1h
  operator: gt
  value: 5000        # deny once the 1h refund total would cross $5k
```

- The injected sum **includes the prospective call**, so the rule denies the
  call that crosses the line; only calls that actually proceed are recorded.
- The proxy **never overwrites** a caller-supplied `agent_velocity` block — a
  real ledger stays authoritative.
- `-velocity-key-by agent_id|session_id|org_id` (default `agent_id`).
  Bounded, in-memory, does not survive a restart. New `tg_proxy_velocity_keys`
  metric. Example policy: [`policies/refund_velocity_cap.yaml`](../policies/refund_velocity_cap.yaml).

## 2. `tg hook` — guard a coding agent

A first-class PreToolUse guard that reads the hook JSON on stdin and emits a
permission decision — no `jq` plumbing:

```jsonc
// Claude Code settings.json
{ "hooks": { "PreToolUse": [ { "matcher": "*", "hooks": [ {
  "type": "command",
  "command": "tg hook -policy-dir /etc/tg/policies -protect-self -fail-closed-tools bash,write,edit,notebookedit"
} ] } ] } }
```

- Maps `denied → deny`, `escalated → ask`, else `allow`. Always exits 0.
- **Fail-open by default** so a glitch never wedges the agent. `-fail-closed`
  denies globally on error; `-fail-closed-tools` denies only for named tools.
  **Unattributable input** (malformed / oversized / unreadable stdin) fails
  **closed** when any fail-closed mode is engaged.
- Forwards the full `tool_input`, so array/nested path params are seen.

## 3. `-protect-paths` / `-protect-self` — self-protection

The insight from dogfooding: *protection written inside a policy is useless
because the agent can edit the policy.* So this deny lives in flags and runs
before — and independent of — policy evaluation:

```sh
tg-proxy -policy-dir /etc/tg/policies -audit-log /var/tg/audit.jsonl -protect-self
tg hook  -policy-dir /etc/tg/policies -protect-paths /etc/tg,$HOME/.claude
```

A write-capable tool targeting a protected prefix is denied (HTTP 403 in the
proxy, with the deny recorded in the hash-chained audit log). **Hardened after
an adversarial review:** paths on both sides are made absolute and
symlink-resolved, and array/nested params are extracted, closing relative-path
and symlink-traversal bypasses. Shell coverage is best-effort by design — the
robust control is scoping bash out or using `shell_classify`.

## 4. Five new operators

`not_in`, `not_contains`, `starts_with`, `ends_with`, `exists`. `not_in` /
`not_contains` **fail closed on a missing field**, so a deny-if-not-allowlisted
rule can't be dodged by omitting the field:

```yaml
# Deny any shell tool not on the approved list — without regex gymnastics.
conditions:
  and:
    - { field: tool_group, operator: eq, value: shell }
    - { field: tool_name, operator: not_in, value: [run_tests, build, lint] }
effect: deny
```

## 5. `tg simulate` — batch dry-run

See what a policy set would do to real traffic before deploying:

```sh
tg simulate -policy-dir policies -calls yesterdays-calls.jsonl
# decision breakdown + per-rule fire counts; -fail-on-deny gates CI; -json for machines
```

## 6. New lint heuristic

`writable-scope-no-self-protection` (warning) flags a policy whose scope admits
write-capable tools but has no `path_classify` guard — a nudge toward
`-protect-paths`.

---

## Upgrade notes

- **Drop-in.** No schema, CLI, or audit-format changes. Replace the binaries;
  existing policies load and existing audit chains still `tg verify`.
- **Everything new is opt-in.** `-velocity-track`, `-protect-paths`,
  `-protect-self`, and `tg hook`'s `-fail-closed*` all default off / fail-open.
  Adopt them deliberately.
- **New lint warning** may appear on write-scoped policies — it's advisory
  (never an error) and never blocks a load.

## What's unchanged

Still Enterprise-only (not in this repo): cryptographic signing, PII
redaction, multi-model ensemble classification, and compliance evidence packs.
See [oss-vs-enterprise.md](oss-vs-enterprise.md) for the precise boundary.

## Verifying the release

Binaries ship with `checksums.txt`; container images are multi-arch
(`linux/amd64`, `linux/arm64`). See the GitHub release page for digests.
