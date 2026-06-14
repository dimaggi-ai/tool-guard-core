# Tool Guard Core vs Tool Guard Enterprise

Tool Guard ships in two editions:

- **Tool Guard Core** - Apache 2.0, this repository. The Policy Decision Point (PDP) for AI agent tool calls:
  policy evaluation engine, SQL/path/shell/LLM classifiers, the `/evaluate` service, Go library, and the hash-chained
  audit primitive. Core decides and records; your tool-execution layer enforces. No usage limit, no feature gate, deploy at any scale.
- **Tool Guard Enterprise** - a commercial, self-hosted enforcement layer:
  an MCP gateway that intercepts all agent-tool traffic, calls Core on every tool call, forwards allowed calls,
  and blocks denied ones. It adds the management dashboard, RBAC, PII redaction, signed Evidence Packs,
  and policy lifecycle workflows. Sold via dimaggi.ai; contact sales@dimaggi.ai.

This page draws the boundary: what's in this repo, what Enterprise
adds, and what exists in neither edition.

## Capability matrix

Enterprise runs the same policy-evaluation concepts as Core; the table
contrasts where each edition's surface differs. A ` - ` in the Enterprise
column means that capability is delivered by Core (which you self-host
alongside Enterprise), not that Enterprise removes it.

| Capability | Core (OSS, Apache-2.0) | Enterprise |
|---|---|---|
| **Enforcement Point / Gateway** | ✗ (Integrator wires the decision into tool-execution code) | ✔ (Turnkey MCP gateway: single point of access, forwards allowed/blocks denied) |
| **Decision Engine** (policy eval, scope, condition trees) | ✔ (The engine lives here, full stop) | Calls the same engine; never a stronger one |
| **Classifiers** (SQL, path, shell, local-LLM content) | ✔ | Same classifiers |
| **Shadow / Observe-only Mode** | ✔ | ✔ |
| **Audit Primitive** | ✔ (SHA-256 hash-chained JSONL + offline `tg verify` tool) | Consumes it |
| **Audit Management** | ✗ | ✔ (PostgreSQL-backed traces, dashboard search, signed Evidence Packs) |
| **HTTP Service interface** | ✔ (`/evaluate`, `/healthz`, `/readyz`, SIGHUP reload) | Runs its own proxy + management API |
| **Per-agent Rate Limiting** | ✔ | ✔ |
| **Escalations** | ✔ (Shared approver token) | ✔ (Review queue in dashboard, RBAC) |
| **Access Control & Identity** | ✗ | ✔ (JWT auth, role-based access control, per-agent API keys) |
| **Signed Decisions** | ✗ | ✔ (HMAC-signed decisions, replay-protected nonces) |
| **PII Redaction** | ✗ | ✔ (Schema-driven redaction before trace write) |
| **Policy Lifecycle** | YAML in git + `tg lint` | Draft → review → approved in dashboard |
| **Stateful tracking** | ✗ (runtime supplies aggregates) | ✔ (Stateful per-agent budgets & velocity) |

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
  existing classifier path - feasible, unbuilt. Patches welcome.
- **Voice-print matching.** Comparing audio-generation requests
  against a reference voice sample is feasible today with pretrained
  speaker-embedding models (ECAPA-TDNN, pyannote) - not integrated
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
classifier types, validators) land in this repo when they're built - there is no holdback of engine capability. Enterprise's value is
turnkey enforcement plus management: the MCP gateway agents use as
their single access point - forwarding allowed calls, blocking denied
ones - and then the surfaces an organisation builds AROUND the same
open engine: identity, redaction, evidence, tenancy, integrations, and
approvals. Not a stronger engine. If your organisation wants to evaluate
Enterprise, see [dimaggi.ai/products](https://dimaggi.ai/products)
and contact sales@dimaggi.ai. Core remains Apache 2.0 with no usage
limit either way.
