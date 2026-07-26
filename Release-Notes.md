# Tool Guard Core — Release Notes

Curated highlights and upgrade notes per release. For the exhaustive,
per-change record see [CHANGELOG.md](CHANGELOG.md).

---

## 0.5.2 — 2026-07-26

Bug-fix release. **No breaking changes; no new required config.**

### Highlights

- **`matchesScope`'s `tool_names` check is now case-insensitive.** A policy
  scoped to `tool_names: [bash]` previously never matched a call whose tool
  name arrived as `Bash` — different agent frameworks capitalize their own
  tool names inconsistently, and `tool_name` is untrusted, externally-sourced
  data. Found via a real dogfood deployment: an `enforcement`-mode policy
  with a `deny-rm-root` rule silently never fired against Claude Code's own
  `Bash` tool calls. `OrgIDs`/`AgentIDs` (real identifiers) and `ToolGroups`
  (operator-assigned constants) are unaffected and stay exact-match.

  **`-unknown-tools-deny`'s underlying check (`ToolNameKnown`) deliberately
  stays exact-match**, unlike the `matchesScope` fix above. Its whole job is
  telling apart "a name the operator explicitly declared" from "something
  else, fail closed" — and a case-varied spoof of a declared name (e.g.
  `DROP_TABLE` vs. a policy declaring `drop_table`) is exactly the kind of
  "something else" that fail-closed default exists to catch. This was
  caught before release by `make test-postgres-full`'s adversarial suite,
  which now passes 129/129 with zero bypasses.

- **CI fixes, unrelated to the above but caught in the same pass:** a
  Windows `gofmt` false-positive (missing `.gitattributes` → CRLF checkout
  → every file flagged) that had been silently failing `main` since 0.3.0
  across three releases undetected, and a Go toolchain bump to 1.25.12 for
  `GO-2026-5856` (a `crypto/tls` privacy-leak CVE).

### Upgrade notes

If you're relying on the previous exact-match behavior to deliberately
exclude a differently-cased tool name from a `matchesScope`-governed
policy, this release changes that — the fix makes that specific check
**strictly more permissive** (more calls now match an existing policy than
before), never less, so it cannot newly deny anything that was previously
allowed. Reconcile duplicate same-tool entries differing only by case in
your own `tool_names` lists; they're now redundant. `-unknown-tools-deny`
behavior is unchanged (still exact-match, as before this release).

---

## 0.5.0 — 2026-07-21

"The control holds" — Reliability, Accountability, and the first SDK. Makes
error paths and the audit trail behave the way an *enforcing* deployment
needs, ships a Python SDK for universal agent-framework coverage, and lands
partial progress on five items from the public 1.0 roadmap. **No breaking
changes.**

### Highlights

- **A per-request evaluator panic on `tg-proxy` now always denies and
  audits** instead of silently dropping the connection with zero record —
  the real gap before this release: there was no recovery around the
  engine call at all.
- **`tg-proxy` verifies the ENTIRE audit chain on startup, not just the
  tail**, and refuses to start if any link anywhere is broken. The old
  tail-only check could miss a tampered record buried mid-file whose own
  hash was still internally valid.
- **`tg hook -unknown-tools-deny`** — the coding-agent enforcement point
  finally has the same "deny anything not explicitly declared" posture
  `tg-proxy` already had.
- **Fixed: `tg hook -mode shadow` now actually only observes.** It was
  silently enforcing every policy instead — see "Upgrade notes" below if
  you use shadow mode on `tg hook` today.
- **A real, quote-aware shell tokenizer** replaces the old best-effort
  scanner behind `-protect-paths`. Quoting, command substitution, and
  variable-expansion evasions that the old scanner's own doc comment
  admitted to are now caught — or, where they genuinely can't be resolved
  offline, fail closed instead of silently passing through.
- **New: a Python SDK** (`sdk/python/`, package `toolguard`) — drop-in
  adapters for LangChain, AutoGen, native OpenAI/Anthropic tool use, and
  MCP, backed by either the CLI or `tg-proxy`. Pre-1.0 and not yet on
  PyPI (install from source); an adversarial review caught and fixed two
  real bugs before this shipped — see [CHANGELOG.md](CHANGELOG.md) for
  what they were and [sdk/python/README.md](sdk/python/README.md) for
  usage.
- **New: a public conformance corpus, a published throughput floor, a
  release provenance attestation, a policy-compatibility regression net,
  and a documented internal review process** — five partial steps toward
  the public 1.0 roadmap, each scoped honestly rather than claimed in
  full. Details in [CHANGELOG.md](CHANGELOG.md).

### Upgrade notes

- **Drop-in.** No schema, CLI, or audit-format changes to existing
  classifiers or the hook contract.
- **Behavior fix to know about if you use `tg hook -mode shadow`:**
  before this release, a shadow-mode policy on `tg hook` was actually
  enforced — every "would deny" became a real `permissionDecision: deny`
  the calling agent obeyed. If you were relying on shadow mode there to
  observe without blocking, it wasn't; after upgrading, it will. This is
  a correctness fix, not new behavior you're opting into, but it changes
  what happens at runtime for that one flag combination.
- **New default-on behavior to know about, unlike every prior release:**
  `tg-proxy` will now refuse to start if its existing audit log's hash
  chain is broken *anywhere*, not only at the tail. If you're upgrading a
  long-running deployment, this is the one thing worth checking before you
  restart — run `tg verify -file <your-audit-log>` first if you want to
  confirm ahead of time rather than find out at startup.
- Everything else is either strictly additive (`-unknown-tools-deny`, the
  SDK, the conformance/compat/stress/provenance tooling are all opt-in or
  CI-only, with zero runtime impact on an existing deployment) or a
  correctness fix in the direction of catching more, never less, than
  before (the panic recovery, the tokenizer).
- Recommended, not required: set `-fail-closed-tools` (or `-fail-closed`)
  on `tg hook` for any deployment meant to actually enforce policy — see
  [docs/getting-started.md](docs/getting-started.md).

## 0.4.0 — 2026-07-20

A correctness fix and a release-process fix — no new policy surface.
**No breaking changes.**

### Highlights

- **Path-prefix matching now works correctly on Windows.** `path_classify`,
  `write_classify`, `shell_classify`'s argv checks, and
  `-protect-self`/`-protect-paths` all compare canonicalized runtime paths
  against policy-authored prefixes. Before this fix, that comparison never
  matched on Windows — an allow-list failed closed (safe, but everything
  denied), while a **deny-list failed open, silently** (nothing it was
  supposed to block ever fired). Fixed with a normalization step gated on
  the operand actually looking like an absolute Windows path (drive-letter
  or UNC), so a literal `\` in a Unix filename is never mistaken for a
  separator. `windows-latest` is now in CI.
- **Releases can no longer ship while `main` is behind the tag.** A new
  `release.yml` guard refuses to publish unless the tag is reachable from
  `main` — see the new [RELEASING.md](RELEASING.md) for why this order
  matters and the exact required sequence.

### Upgrade notes

- **Drop-in.** No schema, CLI, or audit-format changes. Linux/macOS
  behavior is unchanged; only Windows path comparisons are affected, and
  only in the direction of correctness (deny-lists that were silently
  inert on Windows now fire).

---

## 0.3.0 — 2026-07-12

Extends the deterministic engine to the two surfaces our own machine-guard
audit log showed passing ungoverned — file writes and outbound HTTP — plus a
tamper-evident audit log for the coding-agent hook path and a coverage metric
to measure the gap this closes. **No breaking changes**; the Enterprise
boundary is unchanged (deny-only, no redaction/inference/signing).

### Highlights

- **`write_classify`** — governs file-writing tools (write / edit /
  notebookedit / apply_patch / multiedit): path allow/deny-lists, a
  runaway-write byte ceiling, and a literal-deny content regex.
- **`http_classify`** — governs the egress surface for http/fetch tools:
  host, scheme, method, and port allow/deny-lists.
- **`tg hook -audit-log`** — the coding-agent hook path now leaves a
  SHA-256 hash-chained, tamper-evident record of every decision.
- **`tg coverage`** — measures what fraction of an agent's real tool calls
  have any governing policy at all, with a `-min-coverage` CI gate.

### 1. `write_classify` — govern the file-write surface

```yaml
conditions:
  write_classify:
    require:
      allowed_path_prefixes: [/home/me/project/]
      denied_path_prefixes:  [/home/me/project/.git/, /etc/]
      max_bytes: 1048576
      denied_content_regex: ['(?i)BEGIN (RSA|OPENSSH) PRIVATE KEY']
effect: deny
```

- Reuses `path_classify`'s canonicalization (absolute + clean,
  component-boundary `*`/`**` wildcards) and the array/nested-edit path
  extraction, so a path buried in a batch edit or a nested `edits: [...]`
  shape is still seen.
- Symlink resolution is **always on** — a write through a symlinked
  directory is exactly the evasion this primitive exists to catch, so it
  isn't a configurable option.
- **Fail-closed**, precisely: every canonical candidate of a write target
  (the lexical path *and* the symlink-resolved path) must independently be
  under an allowed prefix. A write that only *looks* like it's inside the
  allowed root — because a symlink inside it points elsewhere — is denied,
  not silently permitted.
- `max_bytes` and `denied_content_regex` fail closed on any content that
  can't be read as a string (wrong type, or no content field present at
  all) — the predicate can't pass on bytes it can't see.

### 2. `http_classify` — govern the egress surface

```yaml
conditions:
  http_classify:
    require:
      allowed_hosts: [api.internal, .githubusercontent.com]
      denied_hosts:  [169.254.169.254]   # e.g. the cloud metadata endpoint
      allowed_schemes: [https]
      denied_ports: [22, 25]
effect: deny
```

- Host entries starting with `.` are suffix matches on a proper subdomain
  boundary (`.example.com` matches `api.example.com` and bare
  `example.com`, never `notexample.com` or `example.com.evil.test`).
- Reads `parameters.url` by default, the same convention `sql_classify`
  uses for `parameters.sql`.
- **Fail-closed** on a missing or unparseable URL whenever an allow-list
  (hosts/schemes/methods/ports) is set — an egress call whose destination
  can't be confirmed doesn't pass by default.

### 3. `tg hook -audit-log` — tamper-evident coding-agent audit

The hook path (`tg hook`, the PreToolUse guard for Claude Code / Codex /
Antigravity) now appends every decision to a SHA-256 hash-chained JSONL log,
verifiable offline with `tg verify` — the same guarantee `tg-proxy` already
had. Tail-read keeps each append O(1). Best-effort: an audit-write failure
never changes the returned decision.

### 4. `tg coverage` — measure what's actually governed

```sh
tg coverage -policy-dir policies -calls audit.jsonl -min-coverage 90
# coverage %, a per-tool breakdown, and the biggest ungoverned tools
```

Reads a JSONL of envelopes *or* decision traces, so it runs straight
against an existing audit log — no separate instrumentation. `-min-coverage
PCT` exits 3 for a CI gate; `-json` for machines. This is the metric the
whole release is about: pointed at our own audit log, it's what showed
file-writes and egress passing ungoverned in the first place, and confirms
both are governed now.

### 5. `not:` refusal extended to both new leaves

Both `write_classify` and `http_classify` are fail-closed classifiers and,
consistent with the four existing ones, are refused under a `not:` node —
negating a fail-closed check would flip it fail-open.

### Deferred

SQL-in-bash extraction — parsing SQL out of an opaque shell command string
is a false-negative machine that would create illusory safety. Left for a
later 0.3.x once there's a design that doesn't just move the bypass.

### Upgrade notes

- **Drop-in.** No schema, CLI, or audit-format changes to existing
  classifiers. Replace the binaries; existing policies load and existing
  audit chains still `tg verify`.
- **Everything new is opt-in** — a policy that doesn't reference
  `write_classify` or `http_classify` behaves identically to 0.2.0.

---

## 0.2.0 — 2026-07-02

Closes the one attack class 0.1.0's own battle-test left open, adds a
first-class way to guard coding agents, and makes the guard able to protect
itself. **No breaking changes** — every 0.1.0 policy and audit chain evaluates
and verifies identically, and every new behavior is opt-in.

The Enterprise boundary is unchanged: no cryptographic signing, no PII
redaction, no semantic classification beyond the existing opt-in
`llm_classify`. Everything below is deterministic and dependency-free.

### Highlights

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

### 1. Velocity tracking — closes amount fragmentation

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
  metric. Example policy: [`policies/refund_velocity_cap.yaml`](policies/refund_velocity_cap.yaml).

### 2. `tg hook` — guard a coding agent

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

### 3. `-protect-paths` / `-protect-self` — self-protection

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

### 4. Five new operators

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

### 5. `tg simulate` — batch dry-run

See what a policy set would do to real traffic before deploying:

```sh
tg simulate -policy-dir policies -calls yesterdays-calls.jsonl
# decision breakdown + per-rule fire counts; -fail-on-deny gates CI; -json for machines
```

### 6. New lint heuristic

`writable-scope-no-self-protection` (warning) flags a policy whose scope admits
write-capable tools but has no `path_classify` guard — a nudge toward
`-protect-paths`.

### Upgrade notes

- **Drop-in.** No schema, CLI, or audit-format changes. Replace the binaries;
  existing policies load and existing audit chains still `tg verify`.
- **Everything new is opt-in.** `-velocity-track`, `-protect-paths`,
  `-protect-self`, and `tg hook`'s `-fail-closed*` all default off / fail-open.
  Adopt them deliberately.
- **New lint warning** may appear on write-scoped policies — it's advisory
  (never an error) and never blocks a load.

---

## 0.1.0 — 2026-06-09

Initial public release: the deterministic core, the classifiers, tamper-evident
audit, the CLI, and the runtime proxy. Apache 2.0, no usage limits.

### Deterministic policy engine (`pkg/engine`)

- `Evaluator.Evaluate(envelope, policies, mode)` → decision + action taken +
  triggered rules + primary citation.
- Operators `eq`/`neq`/`gt`/`gte`/`lt`/`lte`/`in`/`contains`/`regex` plus
  field-to-field `gt_field`/`lt_field`; `and`/`or`/`not` condition trees;
  effects `allow`/`flag`/`escalate`/`deny` with a deterministic severity
  hierarchy; shadow mode; string→number coercion so a stringified amount can't
  dodge a threshold. Zero I/O, zero external dependencies.

### Deterministic classifiers — close whole bypass families

- **SQL** (`pkg/sqlguard`, four dialects) — `sql_classify`: top-level kinds,
  no-dynamic-SQL, no-program-exec, function/table allow-deny, function classes.
  Closes CTE-hidden DML (`WITH x AS (…) DELETE …`), dollar-quote, and
  function-exec smuggling.
- **Path** — `path_classify`: clean, absolute-only, canonical-prefix
  allow/deny, symlink resolution, shell-meta deny. Closes traversal and
  hostile-symlink bypasses.
- **Shell** — `shell_classify`: argv[0] allowlist, argv path/pattern deny,
  env-wrap deny (`env`/`sudo`/`chroot` re-launch). Closes shell-meta and
  env-wrap injection — the tool execs argv directly, never `sh -c`.
- **LLM (multimodal)** — `llm_classify`: opt-in local Gemma-class classifier
  for generative prompts (text or text+image); fail-closed on error / low
  confidence.

### Tamper-evident audit (`pkg/audit`)

- SHA-256 hash-chained decision traces with a canonical, byte-stable
  serialization; offline `tg verify` reports the first break — no database.
  The chain resumes cleanly across proxy restarts and rotation.

### CLI + runtime

- **`tg`** — `evaluate`, `verify`, `lint` (8 heuristics), `benchmark`, with a
  documented exit-code contract.
- **`tg-proxy`** — single-binary HTTP service: `POST /evaluate` plus
  `/healthz`, `/readyz`, `/policies`, `/metrics`, `/reload` (+ `SIGHUP`).
  Per-agent token-bucket rate limiting, a bounded escalation store with
  constant-time approver-token compare, audit rotation + three fsync modes,
  `-unknown-tools-deny`, and an envelope-depth cap.

### Battle-tested

- `cmd/battle-test` drives a real local LLM against the engine; canonical
  numbers in [docs/battle-test-results.md](docs/battle-test-results.md) —
  5/5 blocked on direct semantic smuggling, with tool-substitution and
  amount-fragmentation bypasses documented honestly (the latter is closed in
  0.2.0 above).

### Boundary from day one

Enterprise-only, not in this repo: cryptographic signing, PII redaction,
multi-model ensemble classification, and compliance evidence packs. See
[docs/oss-vs-enterprise.md](docs/oss-vs-enterprise.md).
