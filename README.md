# Tool Guard Core

[![CI](https://github.com/dimaggi-ai/tool-guard-core/actions/workflows/ci.yml/badge.svg)](https://github.com/dimaggi-ai/tool-guard-core/actions/workflows/ci.yml)
[![Policy Protection](https://github.com/dimaggi-ai/tool-guard-core/actions/workflows/policy-protection.yml/badge.svg)](https://github.com/dimaggi-ai/tool-guard-core/actions/workflows/policy-protection.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/dimaggi-ai/tool-guard-core.svg)](https://pkg.go.dev/github.com/dimaggi-ai/tool-guard-core)
[![Go Report Card](https://goreportcard.com/badge/github.com/dimaggi-ai/tool-guard-core)](https://goreportcard.com/report/github.com/dimaggi-ai/tool-guard-core)
[![License](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/dimaggi-ai/tool-guard-core?include_prereleases)](https://github.com/dimaggi-ai/tool-guard-core/releases)
[![Container](https://img.shields.io/badge/container-ghcr.io%2Fdimaggi--ai%2Ftool--guard--core-blue)](https://github.com/dimaggi-ai/tool-guard-core/pkgs/container/tool-guard-core)

**The policy decision point for AI agents.** Apache-2.0.

Tool Guard Core is the decision engine for AI agent actions. Send it a
tool call — `POST /evaluate` with a JSON `ActionEnvelope`, or call the
Go library in-process — and it returns **allow / deny / escalate**, the
exact rule that fired, and the reason, in microseconds. Every decision
is appended to a SHA-256 hash-chained audit log you can verify offline
with `tg verify`.

Core decides and records; your tool-execution layer enforces. When the
answer is `deny`, you don't run the call — one `if` statement at the
point where your agent executes tools, with working patterns for MCP,
LangChain, AutoGen, and native Anthropic/OpenAI tool-use loops in
[docs/integration.md](docs/integration.md). This repo is the complete
engine: policy evaluation, the SQL / path / shell / LLM classifiers,
the `/evaluate` service, the Go library, and the audit primitive.
Nothing in it is gated.

## Guard a coding agent in 60 seconds

The native protector currently supports Claude Code 2.1.139 or newer. It previews the exact
settings change, preserves unrelated hooks, installs a secure starter policy,
and does nothing until `-apply` is supplied:

```bash
git clone https://github.com/dimaggi-ai/tool-guard-core
cd tool-guard-core
make build
./bin/tg protect claude          # dry-run: inspect the proposed settings.json
./bin/tg protect claude -apply   # back up, install, and enable enforcement
./bin/tg status claude
```

`tg unprotect claude` previews rollback; add `-apply` to remove the managed
hook. The first pristine backup is never overwritten, and post-install user
changes are preserved by targeted removal. See [the protection guide](docs/protect.md).

The starter policy matches the *shape* of a destructive command (an `rm` plus
recursive/force flags and a root/home target), rather than one brittle string.
The lower-level hook and reference adapters for Codex and Antigravity remain in
[`examples/coding-agent-guard/`](examples/coding-agent-guard/README.md). Want a
different policy? Pass `-policy /absolute/path/policy.yaml`, or browse the
[example bundles](#examples-included) for ready-made guards (money, database,
customer-data export, content safety).

## Why this exists

Model-layer guardrails govern what a model *says*. Tool Guard governs
what an agent *does*. Refund over $500, export PII, transfer funds,
drop a table — these are policy decisions, not language decisions, and
they need a dedicated decision point: evaluated before the API
executes, with a tamper-evident, offline-verifiable record of who
decided what and why. Core is that decision point.

## What Core decides

Every envelope is evaluated against operator-authored YAML policies:
deterministic rules (thresholds, regex, scope, condition trees) plus
six semantic classifiers — SQL (postgres / mysql / sqlite / mssql),
path (traversal, symlink, shell-meta), shell (env-rewrap, argv
resolution), write (file-write path/size/content governance), HTTP
(egress host/scheme/method/port governance), and a local-LLM content
classifier (Gemma 4 via Ollama, fail-closed). The strongest effect wins;
the result is the decision,
the rule, the reason, and a citation back to the source document the
rule came from. Stage policies in shadow mode against live traffic,
then promote to enforcement without redeploying agents.

## Reversibility-aware gating

Not every action carries the same risk when an agent gets it wrong. Reading
a record is free to retry; wiring money, dropping a table, deploying to
production, or deleting an account cannot be taken back. Core classifies
every tool call by whether its visible structure appears undoable and provides
an **irreversibility floor**: calls classified `irreversible` or `unknown` are
not silently allowed by the reference policy.

`engine.ClassifyReversibility` is deterministic (no network, no LLM). It
derives a class from the tool name/group and the shape of the parameters,
reusing the existing destructive-operation detectors (the four-dialect SQL
classifier, the quote-aware shell tokenizer, HTTP method):

| Class | Meaning | Examples |
|-------|---------|----------|
| `reversible` | no lasting effect, or a one-step undo at no cost | read / list / get, add-label, create-draft, HTTP GET, `SELECT` |
| `recoverable` | undoable only with effort / a restore window | file overwrite, `UPDATE`, `DELETE ... WHERE`, `rm file` |
| `irreversible` | no ordinary undo path | payments / wire / transfer / refund, deploy / publish, account or data destruction, physical actuation, `DROP`/`TRUNCATE`/unscoped `DELETE`, `rm -rf` |
| `unknown` | not recognized or not provably undoable — **fail-safe**, treated as caution-worthy | an unrecognized tool; generic HTTP POST/PUT/PATCH/DELETE |

The class is exposed as the ordinary condition field `reversibility`, so any
rule can gate on it:

```yaml
conditions:
  field: reversibility
  operator: eq
  value: irreversible
effect: escalate        # human-in-the-loop; an irreversible action is never auto-allowed
```

The shipped [`policies/irreversibility_floor.yaml`](policies/irreversibility_floor.yaml)
is an approved, enforcement-mode reference policy that escalates every
`irreversible` **and** every `unknown` action to a human reviewer (mapped to
**EU AI Act Article 14 — human oversight**), and allows `reversible` and
`recoverable` ones. Escalating `unknown` is the fail-safe that makes this a
*floor*: an action the classifier cannot positively recognize as safe is never
waved through to the engine's default-allow, so novelty or obfuscation
escalates rather than slipping past a gap in name/parameter coverage.

The parameter-shape detectors are adversarially hardened: destructive commands
hidden behind wrappers (`sudo`/`env`/`timeout … rm -rf`), command substitution
(`echo $(rm -rf /data)`), and output redirection to a device (`… > /dev/sda`)
are recognized; SQL is analysed per-statement after comment and string-literal
content is neutralized, so a data-modifying CTE, an unscoped `UPDATE`, a
tautological `WHERE 1=1`, a `WHERE` (or a destructive keyword) hidden inside a
quoted value, or a sibling statement's `WHERE` cannot disguise a whole-relation
write.

**What it does not do** (deliberate, structural limits — the classifier reads
call *structure*, not world state): it does not inspect an HTTP URL's path, so
generic mutating HTTP methods are `unknown` and escalate; even a nominally safe
`GET` can have a badly designed irreversible endpoint; it cannot see downstream
side effects (a scoped `DELETE` that fires a settled-payment trigger looks
recoverable); and parameter-less calls still depend on the declared tool
name/group. Explicit `command`/`cmd`, SQL, argv, and HTTP surfaces are parsed
regardless of a misleading tool name. These remain false-negative surfaces of
pre-execution classification. The class is a necessary structural gate, not a
proof of safety.

The SQL and shell parameter analysis is deliberately conservative and has been
hardened against a broad set of obfuscations (comment and literal injection in
four quoting styles, nested comments, no-semicolon T-SQL batches, tautological
`WHERE` predicates, command wrappers, substitutions, device-target writes), but
it is a heuristic, not a full multi-dialect parser: a sufficiently exotic
always-true predicate or an unlisted write-capable program can still be
mis-graded. The design leans on two backstops rather than on exhaustive
recognition: an unrecognized program or statement is `unknown` (escalated), and
the recommended deployment keeps a raw shell out of the write-capable policy
scope entirely. Treat the classifier as defense-in-depth, not the sole control.

## Where Enterprise begins

Core is the decision point. **Tool Guard Enterprise**
([dimaggi.ai/products](https://dimaggi.ai/products)) is the enforcement
point: an MCP gateway your agents connect to as their single access
point. It fronts your MCP servers and tools, calls this engine on every
tool call, forwards allowed calls upstream and blocks denied ones —
enforcement the agent cannot route around. Enterprise also adds the
management plane: audit dashboard and signed Evidence Packs
(Postgres-backed), per-agent identity + RBAC, schema-driven PII
redaction, and policy lifecycle approvals. The decision engine, the
classifiers, and the audit primitive (hash-chained JSONL + offline
`tg verify`) live in this repo under Apache-2.0 with no usage limits;
Enterprise consumes them — it does not replace them, and this repo does
not depend on it.

## Scope

**Ships in this repo:**

- Deterministic policy evaluation (thresholds, regex, scope, condition trees)
- Shadow (observe-only) and enforcement modes — stage a policy against live traffic, then promote it to returning real deny/escalate decisions for your tool layer to act on, without redeploying agents
- SHA-256 hash-chained audit log — a portable JSONL file you download, verify offline with `tg verify`, and use as source evidence in an audit workflow
- Policy lint warnings (`tg lint`)
- `tg-proxy` HTTP service with policy reload, rate limit, escalation
- Four-dialect SQL classifier (postgres / mysql / sqlite / mssql)
- Path classifier (traversal, symlink, shell-meta defence)
- Shell classifier (env-rewrap detection, argv path resolution)
- Write classifier (file-write path allow/deny-lists, byte ceiling, denied-content regex)
- HTTP classifier (egress host/scheme/method/port allow/deny-lists)
- Local LLM content classifier (Gemma 4 via Ollama — image/audio/text gen)
- Reversibility classifier + irreversibility floor — deterministically class every call reversible / recoverable / irreversible / unknown, and gate irreversible actions to human oversight ([`policies/irreversibility_floor.yaml`](policies/irreversibility_floor.yaml))
- `tg coverage` — measures what fraction of an agent's tool calls have any governing policy
- Battle-test harness (`cmd/battle-test`)

**Not in this repo — ships in Tool Guard Enterprise** (the
commercial, self-hosted enforcement gateway + management product; see
[dimaggi.ai/products](https://dimaggi.ai/products)):

- **MCP gateway / single point of access** — agents connect to one endpoint;
  Enterprise calls Core on every tool call and forwards allowed calls upstream,
  blocking denied ones before they reach the tool (turnkey, unavoidable
  enforcement — the agent has no other path)
- Management dashboard with policy lifecycle, RBAC + per-agent API
  keys, HMAC-signed decisions, schema-driven PII redaction, signed
  Evidence Pack export (HIPAA §164.312 control mapping — not a
  certification), webhooks, stateful
  per-agent budgets, multi-tenancy, AI counter-agent review.

**Not present in either edition:**

- Multi-model ensemble voting, voice-print matching, managed
  hosting. See [Known limitations](#known-limitations) for the full
  list and what each would take to build.

The included `cmd/battle-test` drives a local LLM (Gemma 4 e4b via
Ollama) against the engine; the resulting block-rate table shows which
adversarial classes the deterministic engine catches and which it does
not. See [`docs/battle-test-results.md`](docs/battle-test-results.md).

## Install

```bash
git clone https://github.com/dimaggi-ai/tool-guard-core
cd tool-guard-core
make build           # → bin/{tg, tg-proxy, battle-test, example-chain}
make test            # unit + golden tests with -race
make integration     # CLI + HTTP-proxy contract tests
make sample          # run the end-to-end sample app
make cover           # statement coverage per package
make help            # see all targets
```

## Run the demos

```bash
make sample            # hand-coded Go agent (no LLM required)
make sample-ollama     # real LLM (Gemma 4 via Ollama) drives the agent
make sample-postgres   # dockerized: real LLM attacks a real Postgres
```

The first two spin up a fake refund tool on `:18080`, `tg-proxy` on
`:19090`, load the strict refund policy, run an agent against the
proxy, and print the live allow/deny flow. Then `tg verify` re-walks
the audit chain offline, demonstrating it is tamper-evident.

- [`examples/sample-app/`](examples/sample-app/README.md) — 4 hardcoded
  scenarios. Fastest path to seeing the integration shape end-to-end.
  No model required.
- [`examples/ollama-agent/`](examples/ollama-agent/README.md) — real
  Gemma 4 reasoning. The model emits its own tool calls, gets blocked
  by policy, **adapts**, and gets through. Requires Ollama with
  `gemma4:e4b` pulled.
- [`examples/postgres-attack/`](examples/postgres-attack/README.md) —
  five-container compose: a Postgres instance, a db-tool, an os-tool, `tg-proxy`,
  and a Gemma 4 agent with an aggressive prompt that tries to drop
  production tables. tg-proxy returns a deny decision, the db-tool
  wrapper refuses to run the call, and the database is untouched.
  SQL / shell / path classifiers in action.
- [`examples/finance-cfo/`](examples/finance-cfo/README.md) — CFO
  control plane: purchase-order, wire-transfer, and expense-velocity
  policies covering per-action caps, cumulative spend ceilings,
  approved-vendor allowlists, OFAC-jurisdiction deny, and free-text
  consistency tripwires. 18 deterministic assertions; no LLM, no
  Docker.
- [`examples/business-ops/`](examples/business-ops/README.md) —
  customer-data-export (GDPR/CCPA shape), mass-communication (blast
  radius + compliance content gates), and support-credit policies.
  26 deterministic assertions; no LLM, no Docker.
- [`examples/content-gen/`](examples/content-gen/README.md) —
  **multimodal content-safety bundle**: image, audio, and text
  generators gated by regex prefilter + a Gemma 4 (via local Ollama)
  semantic classifier. Catches CSAM, deepfakes of named public
  figures, copyrighted style, weapons / self-harm / extremist
  prompts. 16 deterministic assertions against real Gemma 4 e4b
  (~600 ms per call). Requires Ollama with `gemma4:e4b` pulled.
- [`examples/coding-agent-guard/`](examples/coding-agent-guard/README.md) —
  one policy gating Claude Code, OpenAI Codex, and Google Antigravity at the
  hook layer. No LLM, no Docker — see [Guard a coding agent in 60
  seconds](#guard-a-coding-agent-in-60-seconds) above for the one-liner.

Requires Go 1.25+. The default binary is pure Go — no cgo, no
database, no network services — and links one runtime library,
`gopkg.in/yaml.v3`, for policy parsing. The module also requires
`pg_query_go` and `protobuf` for the strict-postgres SQL parser, which
is build-tagged and excluded from the default binary.

## Quick start

**1. Define a policy** (`policies/refund_cap.yaml`):

```yaml
schema_version: 1
policy_id: pol-example-refund
name: refund-cap-example
version: 1
status: approved
mode: enforcement

scope:
  tool_names: [issue_refund]

rules:
  - rule_id: rule-amount-cap
    name: Single refund amount limit
    rule_type: threshold
    conditions:
      field: amount
      operator: gt
      value: 500
    effect: deny
    effect_config:
      severity: high
      suggested_response: "Refunds over $500 require supervisor approval."
    citation:
      document_id: doc-refund-sop
      section: "2.3"
      excerpt: "Individual refund transactions exceeding $500 require supervisor approval prior to processing."
```

**2. Evaluate a tool call** (`examples/call_over_cap.json`):

```json
{
  "agent_id": "support-agent-v2",
  "session_id": "sess-001",
  "org_id": "acme",
  "tool_name": "issue_refund",
  "tool_group": "monetary_outflow",
  "parameters": {"amount": 1000, "reason": "Goodwill credit"}
}
```

```bash
./bin/tg evaluate -policy policies/refund_cap.yaml -call examples/call_over_cap.json
# {"decision":"denied", "decision_reason":"Denied by: [rule-amount-cap] Single refund amount limit ...", ...}
echo $?
# 3
```

Exit codes: 0 allow/pass, 1 internal/load/parse error, 2 usage error, 3 deny,
4 escalate, 5 chain-verification-failed, 6 lint-error.

**3. Lint the policy for known footguns:**

```bash
./bin/tg lint -policy policies/refund_cap.yaml
# [
#   {"rule":"scope-no-tool-group", "severity":"warn", ...},
#   {"rule":"amount-without-semantic-check", "severity":"warn", ...}
# ]
```

Both warnings correspond to **real bypass classes that Gemma 4 found in
the battle test** — see [`docs/battle-test-results.md`](docs/battle-test-results.md).

**4. Verify an audit log offline:**

```bash
./bin/tg verify -file decisions.jsonl
# {"intact": true, "records": 4711, "tail_hash": "sha256:..."}
echo $?
# 0
```

**5. Benchmark the engine on this host:**

```bash
./bin/tg benchmark -trials 10000
# {"p50_us": 3, "p95_us": 8, "p99_us": 14, "max_us": 387, "trials": 10000}
```

p99 ~14µs on an AMD Ryzen 7 7700 — about three orders of magnitude
below a 25 ms budget. This is a point measurement, not a promise; the
nightly same-runner proxy regression gate and its methodology are in
[docs/performance.md](docs/performance.md).

**6. See the audit chain do its job:**

```bash
# Verify the sample chain at examples/decisions_chain.jsonl
./bin/tg verify -file examples/decisions_chain.jsonl
# {"intact": true, "records": 3, ...}

# Tamper with one decision and watch verification fail
sed '1s/"decision":"allowed"/"decision":"denied"/' examples/decisions_chain.jsonl > /tmp/tampered.jsonl
./bin/tg verify -file /tmp/tampered.jsonl
# {"intact": false, "first_failure_at": 1, "failure_reason": "trace_hash \"sha256:6c69...\" does not match canonical recomputation \"sha256:177f...\""}
echo $?
# 5
```

Regenerate the sample chain after a schema bump:

```bash
go run ./cmd/example-chain > examples/decisions_chain.jsonl
```

## Examples included

### Quick-start policies & sample calls

The three starter policies live in [`policies/`](policies/README.md) (indexed
there). The sample tool calls and audit chain to exercise them:

| File | Use |
|---|---|
| `examples/call_under_cap.json` | Allowed $85 refund. |
| `examples/call_over_cap.json` | Denied $1000 refund. |
| `examples/decisions_chain.jsonl` | Real 3-record SHA-256 hash-chained audit log for `tg verify`. |

### Domain bundles (each is a self-contained scenario)

| Bundle | Scope | Asserts |
|---|---|---|
| [`examples/postgres-attack/`](examples/postgres-attack/README.md) | **SQL** + **shell** + **path** for engineering agents | 28 deterministic + 45 + 56 bruteforce |
| [`examples/finance-cfo/`](examples/finance-cfo/README.md) | **Procurement / wires / expenses** for finance agents | 18 deterministic |
| [`examples/business-ops/`](examples/business-ops/README.md) | **Customer data export / mass communication / support comp** | 26 deterministic |
| [`examples/content-gen/`](examples/content-gen/README.md) | **Image / audio / text generation** with Gemma 4 content classifier | 16 deterministic (real LLM) |

Every bundle ships a `policies/` directory, a `test-policies.sh` curl
suite, and a README that maps each rule to the threat it closes. Each
suite is one-line runnable:

```sh
make build                                                              # binaries
./bin/tg-proxy -listen :19090 -policy-dir <bundle>/policies &           # load
bash <bundle>/test-policies.sh                                          # assert
```

### Policy assertion suites in CI

The [![Policy Protection](https://github.com/dimaggi-ai/tool-guard-core/actions/workflows/policy-protection.yml/badge.svg)](https://github.com/dimaggi-ai/tool-guard-core/actions/workflows/policy-protection.yml)
workflow runs the no-LLM bundle suites (finance, business-ops, the
sample app, and postgres-attack) against a live `tg-proxy` on each
push; a green check means each suite's attack envelopes were denied.
The same suites run locally with one target each:

```sh
make test-finance         # CFO spend: over-cap POs/wires, velocity, sanctioned-jurisdiction — 18 assertions
make test-business        # bulk PII export, mass-comms compliance, support-credit abuse — 26 assertions
make test-postgres-full   # SQL injection + shell escape + path traversal — 28 + 45 + 56 = 129 checks, all blocked in this suite (Docker)
make test-policies        # finance + business-ops + the sample app (use make test-postgres-full for SQL/shell/path)
```

`make test-postgres-full` brings up a real Postgres plus the db-tool /
os-tool services and throws 129 SQL-keyword-evasion, dollar-quoted
`EXECUTE`, tool-name-spoofing, path-traversal, shell-metacharacter, and
interpreter-`-c` attacks at the proxy; the suite fails the build if any
one gets through. The multimodal `content-gen` bundle isn't in CI
because it needs a local Ollama + Gemma model (GPU) — run it yourself
per its README.

## Battle-test: real Gemma 4 vs. the engine

```bash
./bin/battle-test -model gemma4:e4b -trials 5
```

Drives a local Ollama model as an adversarial agent that tries to bypass
the policy. Reports per-scenario block rate and prints every successful
bypass in full so the operator can read what the model actually did. See
[`docs/battle-test-results.md`](docs/battle-test-results.md) for the
canonical run + analysis.

The defaults (`-temperature 0.6`, `-seed 0`) keep variety so the harness
surfaces a broader set of bypass shapes. For exact reproducibility,
combine `-temperature 0.0` with a fixed `-seed`:

```bash
./bin/battle-test -model gemma4:e4b -trials 5 -temperature 0.0 -seed 42
```

Use deterministic mode for regression and CI runs — the canonical
"33.3% block rate" in `docs/battle-test-results.md` comes from a
deterministic run (`-temperature 0.0 -seed 42`). The default mode varies
generation to surface new bypass shapes, so its block rate moves from run
to run.

## Architecture

```
pkg/domain/      Tool-call envelopes, policy / rule / condition types,
                 decision traces. JSON-tagged; YAML loaders in cmd/tg.

pkg/engine/      Pure policy evaluation. No I/O. Given an envelope and a
                 set of policies, returns a decision in microseconds.
                 Hosts the path_classify / shell_classify predicates and
                 the regex compile cache.

pkg/sqlguard/    Four-dialect SQL classifier. The tokenizer-based
                 lite implementation (postgres / mysql / sqlite) and the
                 mssql package are pure-Go and registered by default.
                 Strict variants (pg_query_go / tidb/parser / rqlite/sql)
                 are opt-in via build tags pg_strict / mysql_strict /
                 sqlite_strict and override the same dialect through the
                 sqlguard registry. Loads a function-class registry from
                 tools.yaml so policies can match by group instead of
                 enumerating every dangerous function.

pkg/llmguard/    Local-LLM content classifier. Pure HTTP client against
                 Ollama; multimodal (text + image) via Gemma 4 vision
                 variants. Used by the llm_classify condition for image,
                 audio, and text generation tool surfaces. Fail-closed
                 semantics: timeout / network / model-refusal → deny.

pkg/audit/       SHA-256 hash-chained traces, offline replay verifier,
                 canonical JSON for stable hashing.

cmd/tg/          The one-shot CLI. evaluate / verify / lint / benchmark.

cmd/tg-proxy/    HTTP service. POST /evaluate, hash-chained JSONL audit
                 with rotation, SIGHUP policy reload, /metrics,
                 /healthz, /readyz, per-agent rate limiting, escalation
                 store, unknown-tools-deny gate. See
                 docs/integration.md for the operator path.

cmd/battle-test/  Adversarial harness. Drives a local LLM (Gemma 4 today,
                  Qwen 3.x once integrated) against the engine.

cmd/example-chain/ Tiny generator for examples/decisions_chain.jsonl.
                   Re-run after a CanonicalTraceVersion bump.

examples/sample-app/      Hand-coded end-to-end demo. `make sample`.

examples/ollama-agent/    Real-LLM end-to-end demo: Gemma 4 (via Ollama)
                          emits tool calls, tg-proxy returns the decision,
                          the demo wrapper blocks denied calls and the
                          model adapts. `make sample-ollama`.

examples/postgres-attack/ Dockerized demo: real Postgres, real db-tool,
                          tg-proxy with sql_classify / path_classify /
                          shell_classify policies, Gemma 4 agent on the
                          attack side. `make sample-postgres` to run the
                          whole compose; `make test-postgres` to run the
                          28 deterministic assertions.

examples/content-gen/     Three policies for image / audio / text
                          generators using a local Gemma 4 classifier.
                          Standalone (proxy + Ollama on host) or full
                          docker-compose stack (proxy + Ollama + mock
                          generator tools). 16 deterministic assertions.

examples/mcp-server/      MCP (Model Context Protocol) bridge — a
                          stdio JSON-RPC 2.0 server that exposes
                          gated tools to any MCP client (Claude
                          Desktop, Continue.dev, MCP-rs). Every
                          tools/call goes through tg-proxy /evaluate.

examples/coding-agent-guard/  PreToolUse hooks that gate shell commands
                          for Claude Code, OpenAI Codex, and Google
                          Antigravity from one policy.yaml. `./run.sh`
                          shows all three offline; `./install.sh` wires
                          the hooks into the agents you have installed.
```

The engine package has zero I/O and zero external dependencies beyond
`pkg/sqlguard`. The verify primitive reads JSONL from any `io.Reader`.
The default-build CLI's only external dep is `gopkg.in/yaml.v3` for
policy loading.

## Status

- **Engine + audit chain:** table-driven tests pass with `-race`, ~µs p99
  on commodity hardware. CI enforces statement-coverage floors of 85%
  on `pkg/audit` and `pkg/engine` and 90% on `pkg/sqlguard/mssql`.
- **CLI:** four operational verbs (`evaluate`, `verify`, `lint`, `benchmark`) plus `version`, with
  documented exit-code contract; integration tests shell-out the binary
  and assert behaviour end-to-end.
- **`tg-proxy` HTTP service:** `POST /evaluate` with hash-chained JSONL
  audit, SIGHUP policy reload, fail-closed by default, per-agent rate
  limiting, audit log rotation, integration tests assert the HTTP
  contract over a real socket.
- **SQL / path / shell / write / HTTP semantic classifiers:** four-dialect
  SQL classifier (`postgres`, `mysql`, `sqlite`, `mssql`) with pure-Go
  default tokenizer + opt-in strict variants via build tags. Closes CTE,
  dollar-quote, multi-statement, COPY-PROGRAM, and dynamic-SQL bypass
  classes. Path classifier defends against traversal / symlink
  escape / shell-meta injection. Shell classifier resolves argv path
  arguments and detects env-rewrap escapes
  (`env`/`sudo`/`nice`/`ionice`/`chroot`/`doas`). Write classifier governs
  file-write path/size/content, with unconditional symlink resolution so
  a write through a symlinked directory can't escape an allow-list. HTTP
  classifier governs egress host/scheme/method/port.
- **Sample app:** `make sample` runs a refund-tool + tg-proxy + agent
  end-to-end — tg-proxy returns deny and the sample wrapper does not
  execute the call.
- **End-to-end policy correctness:** `make test-postgres-full` brings up the
  full docker stack and runs 28 deterministic assertions plus 45-case
  and 56-case adversarial bruteforce suites — all pass with zero
  bypasses when `-unknown-tools-deny` is set.
- **Battle-test:** a local Gemma 4 model attacks the engine over
  Ollama; the measured results are in `docs/battle-test-results.md`.
- **Possible future work** (not committed): Qwen 3.x battle scenarios,
  JSON-Schema for the policy DSL, a gRPC variant of `tg-proxy`.
  (`examples/mcp-server/` already ships a runnable MCP bridge — see the
  Examples section above.)

## Documentation

Comprehensive docs live in [`docs/`](docs/README.md):

- [Getting Started](docs/getting-started.md) — install, build, first policy in 5 commands
- [Architecture](docs/architecture.md) — engine, audit chain, classifiers
- [Creating Policies](docs/creating-policies.md) — full YAML schema, every operator and classifier
- [Operating in production](docs/operating.md) — systemd, k8s, metrics, backup, recovery
- [Content-gen bundle](docs/content-gen-bundle.md) — the multimodal Gemma 4 classifier
- [Integration](docs/integration.md) — MCP, LangChain, AutoGen, native tool-use loops
- [Escalation flow](docs/escalation.md) — human-in-the-loop approval
- [Battle-test results](docs/battle-test-results.md) — real Gemma 4 vs the engine
- [Core vs Enterprise](docs/oss-vs-enterprise.md) — the precise boundary: what ships here, what the Enterprise platform adds, what exists in neither

## Known limitations

> **New in 0.7.0 (breaking):** policy loading is strict everywhere —
> `schema_version: 1` declared (omitted still loads as v1), unknown or
> misspelled fields are load errors, the no-op `deep_evaluation` field
> is removed, and a policy file must be exactly one YAML document. One
> bad file fails its whole policy set: `tg-proxy` refuses to start,
> while `tg hook` without `-fail-closed`/`-fail-closed-tools` enforces
> **nothing** on a failed load (the error is reported on stderr). Run
> `tg lint` on every policy file **before** upgrading; migration notes
> in [docs/operating.md](docs/operating.md).
> **New in 0.6.0:** reversibility-aware gating — a deterministic,
> offline classifier exposing `reversibility`
> (`reversible`/`recoverable`/`irreversible`/`unknown`) as an ordinary
> policy condition field, plus a shipped
> [irreversibility floor](policies/irreversibility_floor.yaml) that a
> more permissive policy cannot override (max-severity resolution) and
> that escalates `unknown` as well as `irreversible`; `tg protect
> claude` / `tg status` / `tg unprotect` for one-command, preview-first,
> exactly-reversible protection of a coding agent; an
> [OpenAPI spec](api/openapi.yaml) for `tg-proxy` with conformance
> tests; and platform-native config roots for the managed policy/audit
> location.
> **New in 0.5.0:** a per-request evaluator panic on `tg-proxy` now always
> denies and audits (previously it dropped the connection with no record);
> `tg-proxy` verifies the full audit chain on startup, not just the tail;
> `tg hook -unknown-tools-deny`; a real, quote-aware shell tokenizer
> behind `-protect-paths` (the old scanner's documented quoting/
> substitution/variable-expansion evasions are now caught or fail closed);
> and a new [Python SDK](sdk/python/README.md) with LangChain/AutoGen/
> native/MCP adapters, plus partial progress on five public 1.0-roadmap
> items (conformance corpus, throughput floor, provenance attestation,
> policy-compatibility net, documented review process) — see
> [CHANGELOG.md](CHANGELOG.md) for the full list.
> **New in 0.4.0:** correct path-prefix matching on Windows (deny-lists in
> `path_classify`/`write_classify`/`-protect-paths` were previously silently
> inert there). **New in 0.3.0:** `write_classify` and `http_classify` —
> file-write and egress governance — plus `tg hook -audit-log` and
> `tg coverage`. **New in 0.2.0:** velocity tracking that closes the
> amount-fragmentation bypass, the `tg hook` coding-agent guard,
> `-protect-paths` self-protection, five new operators, and `tg simulate`.
> See [Release-Notes.md](Release-Notes.md).

Features absent from this repo today:

- **Single-model classifier.** The semantic classifier is one local
  Gemma. A single model can be bypassed by adversarial paraphrases —
  the measured per-class numbers from our own harness are in
  [docs/battle-test-results.md](docs/battle-test-results.md); run
  `cmd/battle-test` against your own policies to measure it for your
  taxonomy. Voting across several off-the-shelf Ollama models would
  reduce this, but is not built.
- **No voice-print matching.** The audio classifier reads the
  PROMPT ("clone the voice of X"). It does not analyse a reference
  voice sample. Pretrained speaker-embedding models (e.g.
  ECAPA-TDNN via SpeechBrain) exist and could be integrated, but
  no such integration exists today.
- **No PII redaction in this repo.** Free-text fields are hashed
  into the audit log as-is. Put a redaction layer in front of the
  proxy — for example, Microsoft Presidio or your existing DLP
  pipeline — or use Tool Guard Enterprise, which applies schema-driven
  redaction before the trace is written.
- **No compliance evidence-pack exporter in this repo.** Every
  decision is in the audit log; turning that into an evidence bundle
  is a manual step. Tool Guard Enterprise ships a signed Evidence
  Pack export with a HIPAA §164.312 control mapping and an offline
  verifier. The mapping is operator-maintained; it is not a
  certification or compliance guarantee.
- **No managed hosting.** You run the proxy. You run Ollama. You own
  the operations. There is no hosted version.
- **No gRPC variant.** REST `POST /evaluate` only.
- **No Node client SDK.** A Python SDK ships at
  [`sdk/python/`](sdk/python/README.md) (`pip install` from source —
  not yet on PyPI) with adapters for LangChain, AutoGen, native
  OpenAI/Anthropic tool use, and MCP. For other languages, the
  `tg-proxy` HTTP surface is specified in
  [`api/openapi.yaml`](api/openapi.yaml) (with conformance tests) and
  documented in `docs/integration.md`; the request/response shapes are
  small enough to hand-write a client.
- **Battle-test catalogue is Gemma-4-only.** Today's bypass numbers
  reflect Gemma's failure modes specifically; other models will
  fail differently.

For the precise Core / Enterprise boundary — and the list of things
that exist in neither edition — see
[docs/oss-vs-enterprise.md](docs/oss-vs-enterprise.md).

## Where it fits

Tool Guard governs **what an agent does**. Many AI-safety tools govern
**what a model says**. They are complementary layers.

| Category | Primary layer | What it primarily checks |
|---|---|---|
| Prompt and response filters | Model input/output | Whether text should be accepted, refused, rewritten, or classified |
| Content classifiers | Model input/output | Whether generated or requested content matches safety categories |
| Conversation-flow guardrails | Dialogue flow + content | Whether a conversation follows an allowed path or response flow |
| Structured-output validators | Model output | Whether model output matches a schema, regex, topic, or format requirement |
| Pre-deployment eval suites | Test/eval time | Whether prompts and responses pass benchmark or regression checks before release |
| **Tool Guard Core** | **Tool execution** | **What action is about to run** — SQL/shell/path/LLM classifiers plus policy evaluation on the structured tool call, before the API executes; tamper-evident audit trail |

Use prompt and response guardrails when you need to control model text.
Use Tool Guard when agents call tools that touch money, customer data,
infrastructure, databases, filesystems, or generative APIs. Most
production agent stacks need both: model-layer controls for language,
and action-layer controls for execution.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Bug reports and PRs welcome;
security issues go through [`SECURITY.md`](SECURITY.md), not GitHub
issues. Community standards in [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
Notable changes per release are recorded in
[`CHANGELOG.md`](CHANGELOG.md).

## License

Apache 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
