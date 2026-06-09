# Tool Guard Core vs Tool Guard Enterprise

Tool Guard ships in two editions:

- **Tool Guard Core** — Apache 2.0, this repository. The engine:
  policy evaluation, classifiers, hash-chained audit, proxy, CLI.
  No usage limit, no feature gate, deploy at any scale.
- **Tool Guard Enterprise** — a commercial, self-hosted management
  platform built on the same concepts, with a
  [dimaggi.ai/products](https://dimaggi.ai/products) (screenshots; access on request).
  Sold via dimaggi.ai; contact sales@dimaggi.ai.

This page draws the boundary: what's in this repo, what Enterprise
adds, and what exists in neither edition.

## Capability matrix

Enterprise runs the same policy-evaluation concepts as Core; the table
contrasts where each edition's surface differs. A `—` in the Enterprise
column means that capability is delivered by Core (which you self-host
alongside Enterprise), not that Enterprise removes it.

| Capability | Core (OSS) | Enterprise |
|---|---|---|
| Deterministic policy evaluation (thresholds, regex, scope, condition trees) | ✔ | ✔ |
| Shadow mode before enforcement, fail-closed defaults | ✔ | ✔ |
| SHA-256 hash-chained audit trail | ✔ (JSONL + offline `tg verify`) | ✔ (PostgreSQL — downloadable raw traces + offline `verify-chain`) |
| Policy lint (`tg lint`) with 8 heuristics | ✔ | — |
| `tg-proxy` HTTP service: `/evaluate`, `/healthz`, `/readyz`, `/metrics`, `/reload`, SIGHUP | ✔ | — (Enterprise runs its own proxy + management API) |
| Per-agent token-bucket rate limiting | ✔ | ✔ |
| Escalation flow with human approval | ✔ (shared approver token) | ✔ (review queue in the dashboard, RBAC) |
| Four-dialect SQL classifier (postgres / mysql / sqlite / mssql) | ✔ | — |
| Path classifier (traversal / symlink / shell-meta) | ✔ | — |
| Shell classifier (env-rewrap / argv path resolution) | ✔ | — |
| Local LLM content classifier (Gemma via Ollama) | ✔ | ✔ |
| Battle-test harness (`cmd/battle-test`) | ✔ | — |
| Management dashboard with policy lifecycle (draft → review → approved) | ✗ | ✔ |
| JWT auth, role-based access control, per-agent scoped API keys | ✗ | ✔ |
| HMAC-signed decisions with replay-protected nonces | ✗ | ✔ |
| Schema-driven PII redaction before the trace is written | ✗ | ✔ |
| Signed Evidence Pack export + offline verifier | ✗ | ✔ |
| Compliance control mapping templates (HIPAA §164.312 mapping helper; does not certify compliance) | metadata only, unvalidated | ✔ |
| Async webhooks with retry delivery (SIEM / incident routing) | ✗ | ✔ |
| Stateful per-agent budget & velocity tracking | ✗ (runtime supplies aggregates) | ✔ |
| Multi-tenant data model (dedicated instance per customer is the recommended deployment today) | ✗ | ✔ |
| AI counter-agent second-opinion review of risky calls | ✗ | ✔ (optional) |

The example bundles ship 88 deterministic assertions (28
postgres-attack + 18 finance-cfo + 26 business-ops + 16 content-gen)
plus 101 adversarial bruteforce cases (45 + 56 in postgres-attack).
Every one of those documented attack patterns is blocked; they are not
the set of all possible attacks, and a bypass report is welcome (see
SECURITY.md). Each suite is reproducible locally. The `tg verify`
chain integrity is end-to-end tested against on-disk tampering.

## Present in neither edition

These features are not built in either edition today:

- **Multi-model ensemble voting.** Running 2-3 off-the-shelf Ollama
  models with a majority vote is plain engineering on top of the
  existing classifier path — feasible, unbuilt. Patches welcome.
- **Voice-print matching.** Comparing audio-generation requests
  against a reference voice sample is feasible today with pretrained
  speaker-embedding models (ECAPA-TDNN, pyannote) — not integrated
  anywhere. A "registry of public-figure voice-prints" is not
  planned in any edition.
- **Managed hosting / SaaS.** Both editions are self-hosted. No
  hosted service exists, and no latency SLO is quoted for
  infrastructure that isn't running.
- **Client SDKs / OpenAPI spec.** The HTTP APIs are small and
  documented; hand-writing a client takes an afternoon.
- **24/7 SLA.** DIMAGGI is a small team. Enterprise support is a
  contract conversation, not a 24/7 NOC.

## How the line is drawn

The engine is open: new deterministic features (SQL dialects,
classifier types, validators) land in this repo when they're built —
there is no holdback of engine capability. Enterprise's value is the
management plane: the surfaces an organisation builds AROUND the
engine — identity, redaction, evidence, tenancy, integrations — not
a stronger engine. If your organisation wants to evaluate
Enterprise, see [dimaggi.ai/products](https://dimaggi.ai/products)
and contact sales@dimaggi.ai. Core remains Apache 2.0 with no usage
limit either way.
