# Changelog

All notable changes to Tool Guard Core are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Nothing yet.

## [0.2.0] — 2026-07-02

Adds a rolling-window velocity mitigation for the one attack class the
0.1.0 battle-test left open (amount fragmentation), five new deterministic
operators, a batch policy-simulation verb, a first-class coding-agent hook
verb (`tg hook`), unconditional self-protection for policy files and audit
logs (`-protect-paths` / `-protect-self`), and a new lint heuristic that
flags write-scoped policies with no in-band path guard. No breaking changes —
every 0.1.0 policy and audit chain evaluates and verifies identically. The
Enterprise boundary is unchanged: no signing, no PII redaction, no semantic
classification beyond the existing opt-in `llm_classify`.

### `tg hook` — first-class PreToolUse guard for coding agents (`cmd/tg`)

- New `tg hook` verb replaces the hand-rolled `jq` shell adapters in
  `examples/coding-agent-guard/hooks` with a single binary that speaks the
  hook JSON contract Claude Code, OpenAI Codex, and Antigravity share.
- Reads one `{"tool_name":"…","tool_input":{"command":"…","file_path":"…",
  "path":"…"}}` JSON object from stdin, evaluates it against `-policy-dir`
  or `-policy`, and writes
  `{"hookSpecificOutput":{"hookEventName":"PreToolUse",
  "permissionDecision":"deny|ask|allow","permissionDecisionReason":"…"}}`
  to stdout. **Always exits 0** — a PreToolUse hook signals via JSON, never
  via exit code.
- Decision mapping: engine `denied` → `deny`, `escalated` → `ask`,
  everything else → `allow`.
- **Fail-open by default** (`-fail-closed` flips to deny globally;
  `-fail-closed-tools bash,write,edit,notebookedit` denies only for the
  named tools on error — the careful-operator default for coding agents).
  **Unattributable input** (malformed / oversized / unreadable stdin, where
  the tool can't be identified) fails **closed** whenever any fail-closed mode
  is engaged — an unparseable PreToolUse payload can't be proven
  non-destructive; only the pure default (no fail-closed flags) fails open on
  such input. stdin is capped at 1 MiB and read errors are surfaced, not
  silently treated as an empty call.
- The full `tool_input` is forwarded as parameters (not just three
  cherry-picked fields), so a write hidden in an array/nested-edit param is
  still seen by protected-path checks and policies.
- `-protect-paths` / `-protect-self` are wired here as well (see next
  section); they fire before policy evaluation.
- Usage:
  ```
  tg hook (-policy-dir DIR | -policy FILE) [-mode shadow|enforcement]
          [-agent-id NAME] [-fail-closed] [-fail-closed-tools bash,write,edit]
          [-protect-paths P1,P2] [-protect-self]
  ```

### `-protect-paths` / `-protect-self` — self-protection outside the policy (`cmd/tg` + `cmd/tg-proxy`)

An important insight from dogfooding: **any protection written inside a
policy is useless because the agent can just edit the policy**. The only
reliable self-protection is outside the policy, at operator-flag level.

- `engine.ViolatesProtectedPaths(env, prefixes)` is the shared primitive:
  it applies an unconditional pre-policy deny when a write-capable tool
  targets any of the supplied path prefixes. Runs before (and independently
  of) policy evaluation — a policy cannot disable it.
- **Canonicalization (hardened via adversarial review):** both the candidate
  path and every protected prefix are made absolute (relative paths resolve
  against the process CWD) and symlink-resolved on their longest existing
  ancestor, then matched in every combination. This closes the relative-path
  (`file_path: "policy.yaml"`) and symlink-traversal (`/tmp/link/x` where
  `/tmp/link → /protected`) bypasses. Array and one-level-nested edit params
  are extracted, not just flat `file_path`/`path`. (Byte-exact matching —
  case-insensitive filesystems and percent-encoded forms are out of scope.)
- **Write-capable tools** covered: `write`, `edit`, `notebookedit`,
  `multiedit`, `create`, and any unknown tool carrying a `file_path` / `path`
  parameter.  **Read-only tools** (`read`, `glob`, `grep`, `ls`, …) are
  explicitly excluded so protecting the policy directory does not break the
  agent's ability to read it.
- **Shell tools** (`bash`, `shell`, `run_command`, …) receive a
  best-effort heuristic covering redirect targets (`echo x > /protected/f`),
  `rm`, `tee`, `sed -i`, `dd of=`, `cp`, `mv`, and several others.
  **Known limitation:** quoting, variable expansion (`$VAR`), and command
  substitution (`$(…)`) are not resolved. An agent sophisticated enough to
  exploit those forms should have bash scoped out of the write-capable policy
  entirely, or the operator should rely on `-protect-paths` (which fires
  unconditionally regardless of policy content).
- `tg hook` flags:
  - `-protect-paths P1,P2` — comma list of path prefixes to protect.
  - `-protect-self` — automatically protects the `-policy-dir` / the
    directory containing `-policy`, and `$HOME/.claude`.
- `tg-proxy` flags:
  - `-protect-paths P1,P2` — same semantics.
  - `-protect-self` — protects `-policy-dir`, the `-audit-log` path, and the
    running binary's directory.
- When a violation is detected, the proxy returns **HTTP 403** with
  `decision=denied` and records a boundary-deny trace in the hash-chained
  audit log so `tg verify` remains intact.

### `writable-scope-no-self-protection` lint heuristic (`cmd/tg lint`)

- New lint heuristic (severity **warn**) fires when a policy's scope admits
  write-capable tools (`write`, `edit`, `notebookedit`, `bash`, `shell`,
  `run_command`, or an empty scope that matches everything) but no deny- or
  escalate-rule in the policy uses a `path_classify` leaf.
- The in-policy path guard is the best a policy author can do to protect
  sensitive paths; the robust fix is operator-side (`-protect-paths` /
  `-protect-self`) which the agent cannot edit away.  The lint heuristic is
  advisory (not an error) because many shell policies gate by regex
  intentionally.
- Does **not** fire on `policies/refund_cap.yaml` or
  `policies/refund_cap_strict.yaml` — both are scoped to `issue_refund` /
  `process_return`, which are not write-capable tools.
- Suppress it by adding a `path_classify` deny or escalate rule covering the
  policy dir and audit log, or by running the proxy / hook with
  `-protect-paths` / `-protect-self`.

### Velocity tracking — closes amount fragmentation (`tg-proxy`)

- New `-velocity-track` flag makes `tg-proxy` maintain a per-key sliding
  window of monetary actions and inject the trailing 1h/24h sum + count
  into `context.verified.agent_velocity.*` before evaluation. A policy
  then closes the bypass with an ordinary threshold rule
  (`field: context.verified.agent_velocity.monetary_sum_1h, operator: gt`),
  so **no new condition type or engine change** was needed — the schema
  already carried these fields; nothing computed them until now.
- The injected sum **includes the prospective call**, so a `> cap` rule
  denies the call that crosses the line. Only calls that actually proceed
  (allow / flag) are recorded into the window; denied and escalated
  attempts never inflate it.
- The proxy **never overwrites** a caller-supplied `agent_velocity` block
  — a deployment with a real ledger stays authoritative. `-velocity-track`
  is the out-of-the-box default for deployments that have none.
- `-velocity-key-by agent_id|session_id|org_id` (default `agent_id`).
  State is in-memory, bounded (100k keys, 30-min idle eviction) exactly
  like the rate limiter, and does not survive a restart. New
  `tg_proxy_velocity_keys` metric.
- This is the mitigation the 0.1.0 battle-test flagged as missing
  (`docs/battle-test-results.md`: amount fragmentation, "no shipped
  mitigation"). New example policy `policies/refund_velocity_cap.yaml`
  (1h $ cap + 24h count ceiling, lint-clean). End-to-end integration test
  proves 10×$500 refunds allow to exactly $5,000 then deny, with
  independent per-agent windows and caller-supplied ledgers honored.

### New deterministic operators — `pkg/engine`

- `not_in`, `not_contains`, `starts_with`, `ends_with`, `exists`.
- `not_in` / `not_contains` fail **closed** on a missing field (an absent
  value is trivially "not in the allowlist" / "does not contain X"), so a
  deny rule cannot be dodged by omitting the field. Positive operators keep
  the historical no-fire-on-missing behavior. `exists` decides purely by
  presence (`value: true` = must exist, `false` = must be absent).
- Lets policies express a tool-substitution allowlist
  (`tool_name not_in [approved…] → deny`) or a required-justification gate
  (`parameters.reason exists false → deny`) without regex gymnastics.
- Registered across all four coupling points (domain constant, engine
  eval, load-time operand validation, CLI `unknown-operator` allowlist);
  the existing AST-coupling test guarantees none were missed.

### `tg simulate` — batch policy dry-run (CLI)

- `tg simulate (-policy-dir DIR | -policy FILE) -calls CALLS.jsonl` runs a
  whole policy set against a JSONL stream of envelopes and reports the
  decision breakdown, per-rule fire counts, and example envelope_ids per
  non-allow decision. Answers "what would this policy set do to yesterday's
  traffic?" before deploying, using the exact `engine.Evaluate` the proxy
  and `tg evaluate` use — so a simulate verdict cannot diverge from a live
  one.
- `-json` for machine-readable output, `-mode shadow|enforcement`,
  `-examples N`, and `-fail-on-deny` (exit 3 if any call denies — lets CI
  gate a policy change that would start denying real traffic). Malformed
  input lines are counted and skipped, never fatal. Reads stdin with
  `-calls -`.

### Tests

- `pkg/engine/operators_v2_test.go` — every new operator incl. the
  missing-field contract and a composite tool-substitution guard.
- `cmd/tg-proxy/velocity_test.go` — window aggregation, 24h pruning, hard
  per-key cap, keyed bounding/eviction.
- `cmd/tg-proxy/velocity_integration_test.go` — amount-fragmentation
  blocked end-to-end; independent windows; caller-supplied velocity
  honored.
- `cmd/tg/simulate_test.go` — decision/rule counting, exit-code contract,
  policy-dir loading, validation of a bad policy.
- Full suite green under `-race -count=1`, including the integration tag.

## [0.1.0] — 2026-06-09

Initial public release.

### Multimodal content-safety classifier — `pkg/llmguard` (new)

- New `llm_classify` condition type lets policies ask a local
  Ollama-served model (Gemma 4 multimodal by default) whether a
  generative prompt — text only or text+image — falls into a
  policy-configured forbidden category.
- The classifier prompt is deliberately framed as a routing /
  tagging task rather than "content safety" so the model classifies
  rather than refuses; an empty response is interpreted as
  `model_refused` and fires the deny.
- Fail-closed by default: timeout, network error, image-fetch
  failure, parse error, ambiguous response (confidence < 0.6), or
  unknown-label injection all deny.
- New example bundle `examples/content-gen/` covering image, audio,
  and text generators with three lint-clean policies and 16
  deterministic E2E assertions against a real Gemma 4 e4b. Average
  classifier latency ~600 ms.
- The classifier is single-model (one local Gemma). Multi-model
  ensemble voting and voice-print matching do not exist in any
  edition; PII redaction, compliance mappings, and evidence packs
  ship in the separate Tool Guard Enterprise platform, not in this
  repo — see docs/oss-vs-enterprise.md for the boundary.


### `tg-proxy` — runtime HTTP service

- Single binary that loads YAML policies from `-policy-dir`, exposes
  `POST /evaluate`, and writes every decision to a SHA-256
  hash-chained JSONL audit log.
- Operational endpoints: `GET /healthz` (liveness), `GET /readyz`
  (readiness, gated on at least one policy when `-fail-closed=true`),
  `GET /policies` (loaded set), `GET /metrics` (plain-text counters),
  `POST /reload` (also fires on `SIGHUP`).
- Audit log writer holds a mutex around the chain link so concurrent
  evaluations cannot interleave; `fsync` after every append.
- Resumes the chain tail across restarts by scanning the existing log
  on boot.
- Integration tests build the binary in a temp dir, launch it on a
  random free port, and assert the full HTTP contract.

### End-to-end sample app

- `examples/sample-app/` ships a Go refund tool, a hand-coded Go
  agent, and a `run.sh` that brings up the whole stack (`refund-tool`
  ← `tg-proxy` ← `agent`) with a strict policy, prints the live
  allow / deny / escalate flow, and runs `tg verify` on the resulting
  audit chain. `make sample` runs it.

### Real-LLM demo

- `examples/ollama-agent/` ships a Go agent that drives a local
  Ollama model (Gemma 4 e4b by default) through a real tool-use
  conversation. The model emits tool calls, `tg-proxy` evaluates,
  and on a block the model receives the policy note and adapts in
  the next turn — demonstrates the firewall behaviour against a
  genuine LLM, not a hand-coded loop. `make sample-ollama` runs it.

### Integration guide

- `docs/integration.md` covers running `tg-proxy` (with systemd unit
  and Kubernetes manifest), embedding the library in a Go service,
  and wiring the policy decision point into MCP servers, LangChain
  callbacks, AutoGen executors, and the Anthropic / OpenAI native
  tool-use loops.

### Engine — deterministic policy evaluation

- `pkg/engine.Evaluator` evaluates an `ActionEnvelope` against a slice of
  `Policy` and returns an `EvaluationResult` with decision, action taken,
  triggered rules, and primary citation.
- Operators: `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`, `contains`,
  `regex`, plus field-to-field `gt_field` / `lt_field`.
- Condition trees with `and` / `or` / `not` branches.
- Effects: `allow`, `flag`, `escalate`, `deny`. Severity
  hierarchy resolves competing rules deterministically. (There is
  no `redact` effect; scrub free text before it reaches the proxy.)
- Shadow mode preserves the would-be decision as a near-miss while
  letting the call proceed.
- Numeric coercion from string parameters (`"500.00"` → `500.0`) so
  agent SDKs that serialize numbers as strings cannot silently bypass
  amount-threshold rules.
- Zero I/O, zero external dependencies, safe for concurrent use.

### Audit — tamper-evident chain

- `pkg/audit.CanonicalTraceBytes` serializes a `DecisionTrace` to a
  byte-stable representation (locked at `CanonicalTraceVersion = "v1"`).
- SHA-256 hash chain with explicit `previous_trace_hash` linkage.
- `pkg/audit.VerifyChainFromReader` replays a JSONL stream and reports
  the first failure point. No database required.
- Timestamps are normalized to UTC before hashing so chains produced in
  one time zone verify identically in another.

### CLI — `tg`

Four verbs, documented exit codes:

| Verb | Exit |
|---|---|
| `tg evaluate` | 0 allow · 3 deny · 4 escalate · 0 allowed_shadow |
| `tg verify`   | 0 intact · 5 chain-broken |
| `tg lint`     | 0 no error · 6 error-severity findings present |
| `tg benchmark`| 0 always |
| All verbs | 1 internal error · 2 usage error |

Lint heuristics shipped (8):

- `structural-validation` — schema / shape errors (bad operator, malformed condition tree)
- `policy-scope-leak` — empty scope, runs on every call
- `scope-no-tool-group` — narrow scope vulnerable to tool substitution
- `amount-without-semantic-check` — structured-amount-only bypass risk
- `rule-missing-citation` — auditor traceability
- `rule-id-collision` — duplicate rule_id (breaks by-ID lookup)
- `invalid-regex-syntax` — regex that does not compile
- `unknown-operator` — operator the engine cannot evaluate

### Battle-test — real adversarial runs

- `cmd/battle-test/` drives a local LLM (Gemma 4 e4b via Ollama today)
  through three adversarial scenarios against the engine.
- `-temperature` and `-seed` flags for deterministic mode (regression /
  CI runs); defaults keep variety for surfacing new bypass shapes.
- Canonical results published in [`docs/battle-test-results.md`](docs/battle-test-results.md):
  5/5 blocked on direct semantic smuggling; 5/5 bypassed on tool
  substitution (mitigated by `tg lint scope-no-tool-group`) and
  amount fragmentation (no shipped mitigation — keep enforceable
  values in structured fields the policy reads).

### Documentation and hygiene

- `README.md` with quick start, scope boundary, real benchmark
  numbers, and pointers to both demo runners.
- Per-package `doc.go` for godoc / pkg.go.dev.
- `Dockerfile` (multi-stage, distroless-nonroot) at the repo root with
  `-ldflags` version injection.
- `tg version` and `tg-proxy -version` print the build tag via
  `runtime/debug.ReadBuildInfo`.
- `SECURITY.md` private disclosure policy with the HTTP attack surface
  enumerated.
- `CONTRIBUTING.md` contributor guide with the AST-coupling rule for
  new operators and the lint-heuristic naming convention.
- Apache 2.0 LICENSE and NOTICE.
- `.github/workflows/ci.yml` runs `vet + build + race + integration +
  coverage-floor` on Ubuntu and macOS, plus `govulncheck`.

### Example policies — notable changes

- `policies/refund_cap_strict.yaml`: tightened the
  `rule-reason-amount-consistency` regex from `\$?[1-9][0-9]{3,}` to
  `\$[0-9,]{3,}`. The original false-positived on any 4-digit run
  (e.g. order numbers like `ORD-9912`); the tighter version requires a
  `$` sign so it catches the amount-fragmentation pattern without
  collateral damage on order IDs / customer IDs. The
  `examples/ollama-agent/` demo demonstrates the correct behaviour
  against this rule.

### Semantic SQL classifier — `pkg/sqlguard`

- Four-dialect SQL classifier (`postgres`, `mysql`, `sqlite`, `mssql`)
  exposed through the `sql_classify` condition leaf. Pure-Go
  tokenizer-based `lite` implementation is the default; strict variants
  (`pg_query_go`, `tidb/parser`, `rqlite/sql`) are opt-in via the
  `pg_strict` / `mysql_strict` / `sqlite_strict` build tags and override
  the same dialect name through registry last-write-wins.
- `Require` predicates: `top_level_kinds`, `denied_top_level_kinds`,
  `no_dynamic_sql`, `no_program_exec`, `allowed_functions`,
  `no_functions`, `allowed_tables`, `denied_tables`,
  `allowed_function_classes`, `denied_function_classes`.
- Closes the CTE bypass class: `WITH x AS (SELECT 1) DELETE FROM users`
  is correctly classified as `DELETE`, not `SELECT`. Restricted
  Postgres dollar-quote tags to `[A-Za-z_][A-Za-z0-9_]*` per PG
  grammar. Unclosed comments / dollar-quotes at EOF surface as
  `UnclosedConstructError` and the classify call fails closed.
- Table extraction pass walks the tokenizer output, excludes CTE names,
  and feeds the `allowed_tables` / `denied_tables` predicates.
- Function-class registry loadable from a `tools.yaml` file via
  `-tools-yaml` (e.g. group `pg_read`, `pg_write`, `pg_admin` and
  match `allowed_function_classes` / `denied_function_classes`).

### Path / shell classifiers — `pkg/engine`

- `path_classify` predicate (`require:` block) with `clean_first`,
  `absolute_only`, `allowed_canonical_prefixes` /
  `denied_canonical_prefixes`, `deny_shell_metas` (with `include_backslash`
  for Linux-only mode), `resolve_symlinks`, `deny_on_resolve_failure`, and
  `max_path_length`.
- `shell_classify` predicate (`require:` block) with `argv0_allowlist`,
  `denied_argv_paths` for argv path arguments, `argv_deny_patterns`,
  `max_argc`, `resolve_symlinks` for symmetry, and `argv_env_pattern_deny`
  (default catches `env`/`sudo`/`nice`/`ionice`/`chroot`/`doas` envelopes
  used to relaunch a different binary).

### Diagnostic detail in audit chain

- `EvalConditionWithDetail` propagates the classifier's "why" string
  (`"sql_classify: top-level DELETE not in [SELECT]"`) into
  `RuleResult.Details` for the matched rule. AND-branch carries detail
  from the deepest informative sub-condition.

### Hardening — `tg-proxy`

- Per-agent token-bucket rate limiter (`-rate-limit-rps`,
  `-rate-limit-burst`, `-rate-limit-key-by`) with a bounded map
  (100k cap) and a 30-min idle eviction sweep.
- Approval flow with bounded escalation store (10k cap, LRU eviction of
  oldest resolved entries) and constant-time approver-token compare
  (`crypto/subtle.ConstantTimeCompare`).
- `-unknown-tools-deny` flag closes the tool-name-spoofing bypass class
  (`drop_tables`, `DROP_TABLE`, `drop_table_v2`); shadow-mode-aware so
  observed-only policies don't accidentally satisfy the gate.
- `-max-envelope-depth` (default 32) rejects pathologically nested
  JSON envelopes before the decoder runs.
- Audit log rotation via `-audit-rotate-bytes`; three fsync modes
  (`every` / `interval` / `none`) via `-audit-sync-mode`. `tg verify`
  walks the rotation set.

### `tg-proxy` source split

- `cmd/tg-proxy/main.go` split into `handlers.go`, `policy_loader.go`,
  `audit_chain.go`, `helpers.go`, `escalation.go`,
  `escalation_handlers.go`, `ratelimit.go`. main.go drops to ~300 LoC
  of startup/wiring.

### Engine validation

- `engine.ValidatePolicy` rejects nil operands for `eq` / `neq` and
  caps `**` wildcards at 2 per pattern to defeat glob amplification.
- Regex compile cache (`pkg/engine/regex_cache.go`) — patterns are
  compiled once at first use and reused across evaluations. The
  `tg_proxy_regex_cache_size` metric exposes the working set.

### Tests

- `pkg/audit` 87%+ statement coverage.
- `pkg/engine` 87%+ statement coverage.
- `pkg/sqlguard/lite` 66%+ — covers every attack class in the
  battle-test catalogue plus the CTE / dollar-quote / table-extraction
  regression tests.
- `pkg/sqlguard/mssql` 90%+.
- 28-assertion deterministic policy correctness suite
  (`examples/postgres-attack/test-policies.sh`) — every rule in
  both example policies exercised end-to-end against the proxy.
- 45-case and 56-case adversarial bruteforce suites
  (`bruteforce-policies.sh` + `bruteforce-adversarial.sh`) — 0
  bypasses with `-unknown-tools-deny` enabled.
- AST-coupling test guarantees new `domain.Operator` constants are
  registered with the CLI's `unknown-operator` allowlist.
- Golden tests pin lint warning names against the README and the public
  example policy. `TestGolden_LintStrictPolicyClean` pins the README's
  promise that `policies/refund_cap_strict.yaml` lints clean.
- Integration tests shell out the built `tg` binary and assert the exit
  code contract end-to-end.
- All tests pass with `-race -count=1`.

### Known limitations

- Qwen 3.x multilingual adversarial scenarios are not implemented;
  only Gemma 4 e4b is wired today.
- There is no gRPC variant of `tg-proxy`; the proxy exposes only
  the REST endpoints documented above.
- Strict SQL dialect parsers (pg_query_go, tidb/parser, rqlite/sql)
  are opt-in via build tags and add cgo / binary size. The default
  pure-Go `lite` tokenizer covers every attack class in the
  documented battle-test catalogue; the strict variants are for
  operators who already accept those build-time costs.

[Unreleased]: https://github.com/dimaggi-ai/tool-guard-core/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/dimaggi-ai/tool-guard-core/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dimaggi-ai/tool-guard-core/releases/tag/v0.1.0
