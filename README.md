# Tool Guard Core

[![CI](https://github.com/dimaggi-ai/tool-guard-core/actions/workflows/ci.yml/badge.svg)](https://github.com/dimaggi-ai/tool-guard-core/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/dimaggi-ai/tool-guard-core.svg)](https://pkg.go.dev/github.com/dimaggi-ai/tool-guard-core)
[![Go Report Card](https://goreportcard.com/badge/github.com/dimaggi-ai/tool-guard-core)](https://goreportcard.com/report/github.com/dimaggi-ai/tool-guard-core)
[![License](https://img.shields.io/badge/license-Apache_2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/dimaggi-ai/tool-guard-core?include_prereleases)](https://github.com/dimaggi-ai/tool-guard-core/releases)
[![Container](https://img.shields.io/badge/container-ghcr.io%2Fdimaggi--ai%2Ftool--guard--core-blue)](https://github.com/dimaggi-ai/tool-guard-core/pkgs/container/tool-guard-core)

**The runtime policy firewall for AI agents.** Apache-2.0.

Tool Guard sits between your AI agents and the tools they call. Every tool
call is evaluated against your policies *before* it executes, and the
decision is hash-chained into a tamper-evident audit ledger.

This repo is the complete open-source engine: the deterministic
policy engine, the audit chain, a single-binary CLI, and a local-LLM
content classifier (Gemma 4 via Ollama). Nothing in the engine is
gated. A commercial management platform, **Tool Guard Enterprise**,
exists on top of it (dashboard, RBAC, PII redaction, signed evidence
packs — [live demo](https://dimaggi.ai/demo-portal/)); this repo
does not depend on it.

## Why this exists

Model-layer guardrails (LlamaGuard, NeMo, Guardrails AI) govern what a
model *says*. Tool Guard governs what an agent *does*. Refund over $500,
export PII, transfer funds, drop a table — these are policy decisions, not
language decisions. They should be enforced at the tool call, before the
API executes, with an immutable record of who decided what and why.

## What it does, what it doesn't

**Ships in this repo:**

- Deterministic policy evaluation (thresholds, regex, scope, condition trees)
- SHA-256 hash-chained audit log + offline `tg verify`
- Policy lint warnings (`tg lint`)
- `tg-proxy` HTTP service with policy reload, rate limit, escalation
- Four-dialect SQL classifier (postgres / mysql / sqlite / mssql)
- Path classifier (traversal, symlink, shell-meta defence)
- Shell classifier (env-rewrap detection, argv path resolution)
- Local LLM content classifier (Gemma 4 via Ollama — image/audio/text gen)
- Battle-test harness (`cmd/battle-test`)

**Not in this repo — ships in Tool Guard Enterprise** (the
commercial, self-hosted management platform; live demo at
[dimaggi.ai/demo-portal](https://dimaggi.ai/demo-portal/)):

- Management dashboard with policy lifecycle, RBAC + per-agent API
  keys, HMAC-signed decisions, schema-driven PII redaction, signed
  Evidence Pack export (HIPAA §164.312 mapping), webhooks, stateful
  per-agent budgets, multi-tenancy, AI counter-agent review.

**Does NOT exist in either edition:**

- Multi-model ensemble voting, voice-print matching, managed
  hosting, client SDKs. See
  [Honest v0.1 limitations](#honest-v01-limitations) for the full
  list and what each would take to build.

The engine is **honest about its limits**. The included
`cmd/battle-test` drives a real local LLM (Gemma 4 e4b via Ollama) against
the engine; the resulting block-rate table shows exactly which adversarial
classes the deterministic engine catches and which ones it does not.
See [`docs/battle-test-results.md`](docs/battle-test-results.md).

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

## See it firewall in 30 seconds

```bash
make sample            # hand-coded Go agent (no LLM required)
make sample-ollama     # real LLM (Gemma 4 via Ollama) drives the agent
make sample-postgres   # dockerized: real LLM attacks a real Postgres
```

The first two spin up a fake refund tool on `:18080`, `tg-proxy` on
`:19090`, load the strict refund policy, run an agent against the
proxy, and print the live allow/deny flow. Then `tg verify` re-walks
the audit chain offline so you can see it really is tamper-evident.

- [`examples/sample-app/`](examples/sample-app/README.md) — 4 hardcoded
  scenarios. Fastest path to seeing the integration shape end-to-end.
  No model required.
- [`examples/ollama-agent/`](examples/ollama-agent/README.md) — real
  Gemma 4 reasoning. The model emits its own tool calls, gets blocked
  by policy, **adapts**, and gets through. Requires Ollama with
  `gemma4:e4b` pulled.
- [`examples/postgres-attack/`](examples/postgres-attack/README.md) —
  four-container compose: real Postgres, real db-tool, `tg-proxy`,
  and a Gemma 4 agent with an aggressive prompt that tries to drop
  production tables. Proves the proxy denies the destructive call and
  the database is untouched. SQL / shell / path classifiers in action.
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

Requires Go 1.25+. The default build is pure Go with one external
library dependency (`gopkg.in/yaml.v3`, policy file parsing) — no cgo,
no database, no network services. The strict-postgres SQL parser
(`pg_query_go` + `protobuf`) is opt-in behind a build tag and is NOT
in the default binary.

## Quick start

**1. Define a policy** (`policies/refund_cap.yaml`):

```yaml
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

Exit codes: 0 allow/pass, 1 internal error, 2 usage/parse error, 3 deny,
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
the battle test** — see results doc.

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

p99 ~14µs on AMD Ryzen 7 7700 means the OSS engine clears the
"sub-25ms p99" claim with three orders of magnitude headroom.

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

### Quick-start policies (in `policies/`)

| File | Use |
|---|---|
| `policies/refund_cap.yaml` | Intentionally narrow scope; lints with two warnings to demonstrate `scope-no-tool-group` + `amount-without-semantic-check`. |
| `policies/refund_cap_strict.yaml` | Same intent, lints clean. Adds the tool_group scope and a regex tripwire on the reason field. |
| `policies/llm_token_spend_guard.yaml` | Per-agent LLM cost ceilings (escalate $50/h, deny $300/day, flag 10M+ tokens/day). |
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

The deterministic mode is what regression / CI runs should use; the
default mode is what publishes the documented "33.3% block rate, here
are the patterns" results that prove the harness isn't cherry-picking.

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
                          emits tool calls, tg-proxy enforces, the model
                          adapts when blocked. `make sample-ollama`.

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
```

The engine package has zero I/O and zero external dependencies beyond
`pkg/sqlguard`. The verify primitive reads JSONL from any `io.Reader`.
The default-build CLI's only external dep is `gopkg.in/yaml.v3` for
policy loading.

## Status

- **Engine + audit chain:** table-driven tests pass with `-race`, ~µs p99
  on commodity hardware. `pkg/audit` 87.5% statement coverage,
  `pkg/engine` 87.8%, `pkg/sqlguard/mssql` 90.6%.
- **CLI:** four verbs (`evaluate`, `verify`, `lint`, `benchmark`) with
  documented exit-code contract; integration tests shell-out the binary
  and assert behaviour end-to-end.
- **`tg-proxy` HTTP service:** `POST /evaluate` with hash-chained JSONL
  audit, SIGHUP policy reload, fail-closed by default, per-agent rate
  limiting, audit log rotation, integration tests assert the HTTP
  contract over a real socket.
- **SQL / path / shell semantic classifiers:** four-dialect SQL classifier
  (`postgres`, `mysql`, `sqlite`, `mssql`) with pure-Go default
  tokenizer + opt-in strict variants via build tags. Closes CTE,
  dollar-quote, multi-statement, COPY-PROGRAM, and dynamic-SQL bypass
  classes. Path classifier defends against traversal / symlink
  escape / shell-meta injection. Shell classifier resolves argv path
  arguments and detects env-rewrap escapes
  (`env`/`sudo`/`nice`/`ionice`/`chroot`/`doas`).
- **Sample app:** `make sample` runs a refund-tool + tg-proxy + agent
  end-to-end and shows the firewall actually blocking calls.
- **End-to-end policy correctness:** `make test-postgres` brings up the
  full docker stack and runs 28 deterministic assertions plus 45-case
  and 56-case adversarial bruteforce suites — all pass with zero
  bypasses when `-unknown-tools-deny` is set.
- **Battle-test:** real Ollama integration, real Gemma 4 attacks, real
  numbers in `docs/battle-test-results.md`.
- **Ideas under consideration** (no committed timeline — this is a
  small team and none of this is funded work yet): Qwen 3.x battle
  scenarios, JSON-Schema for the policy DSL, a gRPC variant of
  `tg-proxy`. (`examples/mcp-server/` already ships a runnable MCP
  bridge — see the Examples section above.)

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

## Honest v0.1 limitations

Things that are NOT in v0.1 and that we want you to know about
before you choose Tool Guard for your stack:

- **Single-model classifier.** The semantic classifier is one local
  Gemma. A single model can be bypassed by adversarial paraphrases —
  the measured per-class numbers from our own harness are in
  [docs/battle-test-results.md](docs/battle-test-results.md); run
  `cmd/battle-test` against your own policies rather than trusting
  any headline figure. Voting across several off-the-shelf Ollama
  models would reduce this; nobody has built that yet.
- **No voice-print matching.** The audio classifier reads the
  PROMPT ("clone the voice of X"). It does not analyse a reference
  voice sample. Pretrained speaker-embedding models (e.g.
  ECAPA-TDNN via SpeechBrain) exist and could be integrated, but
  no such integration exists today.
- **No PII redaction in this repo.** Free-text fields are hashed
  into the audit log as-is. Put an existing tool (e.g. Microsoft
  Presidio) in front of the proxy, or use Tool Guard Enterprise,
  which applies schema-driven redaction before the trace is written.
- **No compliance evidence-pack exporter in this repo.** Every
  decision is in the audit log; turning that into an evidence bundle
  is a manual step. Tool Guard Enterprise ships a signed Evidence
  Pack export with a HIPAA §164.312 control mapping and an offline
  verifier.
- **No managed hosting.** You run the proxy. You run Ollama. You own
  the operations. There is no hosted version.
- **No gRPC variant.** REST `POST /evaluate` only.
- **No Python / Node client SDK and no OpenAPI spec.** The HTTP API
  is language-agnostic and documented in `docs/integration.md`;
  the request/response shapes are small enough to hand-write a
  client in any language.
- **Battle-test catalogue is Gemma-4-only.** Today's bypass numbers
  reflect Gemma's failure modes specifically; other models will
  fail differently.

For the precise Core / Enterprise boundary — and the list of things
that exist in neither edition — see
[docs/oss-vs-enterprise.md](docs/oss-vs-enterprise.md).

## Where it fits among alternatives

Tool Guard governs **what an agent DOES**. Most popular AI-safety
projects govern **what a model SAYS**. They're complementary, not
competing.

| Project | Primary layer | What it primarily checks |
|---|---|---|
| LlamaGuard, LangKit | Model input/output | Generation-side safety — refusal classification + content categorisation on the model's text |
| NeMo Guardrails | Conversation flow + content | Colang-based dialogue flow control plus content-safety rails; tool calls can be gated through Colang flows, but the policy DSL is conversational, not structured-action |
| Guardrails AI | Model output validation | Pydantic-like schema validation of the model's response: regex / structure / topic checks |
| Lakera Guard | Model input + output | Prompt-injection detection + response classification at the model layer |
| Promptfoo, DeepEval | Pre-deployment eval | Eval suites that score prompts/responses on a benchmark, not at runtime |
| **Tool Guard Core** | **Tool execution** | **What action is about to run** — SQL/shell/path/LLM classifiers + policy engine on the structured tool call, before the API executes; tamper-evident audit trail |

Most of these projects govern what a model SAYS. Tool Guard governs
what an agent DOES. NeMo Guardrails is the closest neighbour because
its Colang flows can also gate tool calls — Tool Guard is the
structured, audit-first complement: a YAML policy DSL, semantic
classifiers per tool surface (SQL/path/shell/LLM), and a SHA-256
hash-chained ledger. If your agent generates text, you want a
model-output guardrail. If your agent CALLS TOOLS that touch money,
customer data, infrastructure, or generative APIs, you want Tool
Guard. Most production agent stacks need both.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Bug reports and PRs welcome;
security issues go through [`SECURITY.md`](SECURITY.md), not GitHub
issues. Community standards in [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
Notable changes per release are recorded in
[`CHANGELOG.md`](CHANGELOG.md).

## License

Apache 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

