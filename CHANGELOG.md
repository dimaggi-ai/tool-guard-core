# Changelog

All notable changes to Tool Guard Core are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Nothing yet.

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

[Unreleased]: https://github.com/dimaggi-ai/tool-guard-core/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dimaggi-ai/tool-guard-core/releases/tag/v0.1.0
