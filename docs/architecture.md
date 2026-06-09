# Architecture

Tool Guard Core is a runtime policy firewall for AI agents. It sits
between an agent and the tools the agent calls; every tool call is
evaluated against operator-authored policies before it executes, and
every decision lands in a tamper-evident audit log.

This document describes how the pieces fit together.

## High-level flow

```
   ┌─────────┐  tool_call    ┌──────────┐  decision   ┌─────────┐
   │  agent  │ ────────────▶│ tg-proxy │ ────────────▶│  tool   │
   │ (LLM)   │ ◀────────────│          │  allow only  │ (DB,    │
   └─────────┘   result      └────┬─────┘              │  mail,  │
                                  │                    │  ...)   │
                                  │  every decision    └─────────┘
                                  ▼
                         ┌─────────────────┐
                         │  audit chain    │
                         │  (JSONL +       │
                         │   SHA-256 hash) │
                         └─────────────────┘
```

The agent is anything that emits structured tool calls: an MCP
server, a LangChain executor, an AutoGen runtime, an Anthropic /
OpenAI tool-use loop, or a hand-coded Go program. `tg-proxy` is
transport-agnostic — the only interface is `POST /evaluate` with a
JSON `ActionEnvelope`.

## Packages

```
pkg/domain/      Tool-call envelopes, policy / rule / condition types,
                 decision traces. JSON-tagged; YAML loaders in cmd/tg.

pkg/engine/      Pure policy evaluation. No I/O. Given an envelope and
                 a set of policies, returns a decision in microseconds.
                 Hosts the path_classify / shell_classify predicates and
                 the regex compile cache.

pkg/sqlguard/    Four-dialect SQL classifier (postgres / mysql / sqlite
                 / mssql). The tokenizer-based lite implementation is
                 pure-Go and registered by default. Strict variants
                 (pg_query_go / tidb/parser / rqlite/sql) are opt-in
                 via build tags and override the same dialect through
                 the sqlguard registry.

pkg/llmguard/    Local-LLM content classifier. Pure HTTP client against
                 Ollama; multimodal (text + image) via Gemma 4 vision
                 variants. Used by the llm_classify condition for
                 image / audio / text generation tool surfaces.
                 Fail-closed semantics throughout.

pkg/audit/       SHA-256 hash-chained traces, offline replay verifier,
                 canonical JSON for stable hashing. The canonical
                 encoder covers EVERY trace field (decision, reason,
                 every rule result, amount, identity) so any tamper
                 of the on-disk log is caught.

cmd/tg/          The one-shot CLI: evaluate / verify / lint / benchmark.

cmd/tg-proxy/    HTTP service: POST /evaluate, hash-chained JSONL
                 audit with rotation, SIGHUP policy reload, /metrics,
                 /healthz, /readyz, per-agent rate limiting, escalation
                 store, unknown-tools-deny gate.

cmd/battle-test/ Adversarial harness — drives a local LLM (Gemma 4
                 today, Qwen 3.x once integrated) against the engine.

examples/        Five self-contained policy bundles, each with its own
                 policies, mock tools, test script, and README.
```

## The evaluation pipeline

For every `/evaluate` request the proxy walks this sequence:

1. **Body cap & JSON depth** — the request body is capped at 1 MiB
   (via `http.MaxBytesReader` — silent truncation is not allowed);
   the envelope's JSON nesting is bounded at `-max-envelope-depth`
   (default 32).
2. **Rate limit** — if `-rate-limit-rps` > 0, the envelope's
   configured key field (default `agent_id`) is checked against a
   per-key token bucket. Empty keys collapse to `_unknown` so a
   hostile envelope with no agent_id cannot bypass the limit.
3. **Fail-closed gate** — if no policies are loaded and
   `-fail-closed=true`, the call is denied with a boundary-deny trace
   appended to the audit chain.
4. **Engine evaluation** — every loaded policy whose scope matches
   the envelope contributes its rules to the evaluation. Each rule
   walks its condition tree (`and` / `or` / `not` plus leaf
   comparisons or one of the classifiers: `sql_classify`,
   `path_classify`, `shell_classify`, `llm_classify`).
5. **Effect resolution** — among all rules that fired, the strongest
   effect wins by severity hierarchy (`deny` > `escalate` > `flag` >
   `allow`).
6. **Unknown-tools-deny gate** — if `-unknown-tools-deny` is set and
   the envelope's `tool_name` is not in any enforcement policy's
   `scope.tool_names`, the decision is forced to `denied`.
7. **Escalation** — if the decision is `escalated`, a pending entry
   is registered in the bounded escalation store. The agent gets a
   `poll_url` back and can long-poll for the operator's decision.
8. **Audit append** — the full decision trace is canonical-encoded,
   SHA-256-hashed, linked to the previous trace, and written to the
   JSONL log. `lastHash` advances BEFORE the durability barrier so a
   Sync failure cannot fork the chain.
9. **Response** — JSON `EvaluationResult` with decision, reason,
   matched rules, citations, escalation poll URL (if applicable).

## The condition DSL

Conditions are recursive trees. The four leaf shapes are:

```yaml
# Leaf: simple field comparison
conditions:
  field: amount
  operator: gt
  value: 500

# Classifier leaves
conditions:
  sql_classify: ...
  path_classify: ...
  shell_classify: ...
  llm_classify: ...

# Tree shapes
conditions:
  and: [ {...}, {...} ]
  or:  [ {...}, {...} ]
  not: {...}
```

See [creating-policies.md](creating-policies.md) for every operator
and classifier with examples.

## The audit chain

Every trace's hash covers the canonical JSON of the full trace —
every field of the decision including `decision_reason`, the
matched-rule list, the agent identity, and the amount. Pre-fix the
hash covered only 6 identity fields; tampering decision_reason or
rule_results would not break `tg verify`. The current chain catches
ALL field mutations.

On startup, the proxy reads the audit log tail, recomputes its
canonical hash, and refuses to start if the stored hash doesn't
match (tamper-on-disk detection).

Rotation is opt-in via `-audit-rotate-bytes`. Three fsync modes:
`every` (default, strongest durability), `interval` (per N appends),
`none` (OS-managed). `tg verify` walks the rotation set in order.

## The escalation flow

Rules with `effect: escalate` register a pending entry in the
bounded escalation store. The store is in-memory; a proxy restart
discards pending entries (the agent's poll returns 404, treated as
expired).

The store is hard-capped at 10,000 entries. Eviction prefers the
oldest resolved (approved/denied) entry. When the store is full of
pending entries, new escalations are downgraded to `deny` with an
explicit reason — refusing to silently drop a pending entry an
operator might be polling for.

The approver endpoints (`POST /escalations/<id>/approve` and
`/escalations/<id>/deny`) require a static bearer token configured
via `-approver-token`. The token compare is SHA-256-of-both before
constant-time compare, so token LENGTH is not leaked via timing.
Approve / deny state transitions write a linked audit trace.

## Rate limiting

A token-bucket per agent (or session / org, configurable via
`-rate-limit-key-by`). The bucket map is capped at 100k entries with
30-min idle eviction. Empty keys collapse to a single shared
`_unknown` bucket — refusing to exempt envelopes with missing
identity from rate limiting.

## The LLM classifier (multimodal)

`pkg/llmguard` implements a generic Ollama-served content
classifier. Policies use it via the `llm_classify` condition:

```yaml
conditions:
  llm_classify:
    prompt_field: parameters.prompt
    image_url_field: parameters.source_image_url  # optional
    model: gemma4:e4b
    timeout_seconds: 30
    forbidden:
      - weapons
      - csam
      - real_person_likeness
```

The classifier is framed as a routing task (not a "content safety"
task) so the underlying Gemma's own safety filter doesn't refuse to
engage. Empty model responses are interpreted as `model_refused`
which fires deny (fail-closed). User prompts are wrapped in
unguessable delimiters so a prompt-injected "ignore previous
instructions" pattern cannot reach the classifier's system prompt.

The image-fetch path is SSRF-hardened: dial-time private-CIDR /
loopback / link-local / CGNAT blocking, no redirects ever, scheme
allowlist (http/https only), no userinfo in URLs.

See [content-gen-bundle.md](content-gen-bundle.md) for the
end-to-end demo with three policies (image / audio / text gen) and
16 deterministic E2E assertions against real Gemma 4 e4b.

## Scope boundary

The engine deliberately covers every structured-tool surface
(SQL, shell, path, monetary, customer data, mass comms) AND the
multimodal-gen surface via a single-model local Gemma classifier.
Multi-model ensemble arbitration and voice-print matching do not
exist in any edition; PII redaction and compliance evidence packs
ship in the commercial Tool Guard Enterprise platform, not here —
[oss-vs-enterprise.md](oss-vs-enterprise.md) draws the full
boundary.
