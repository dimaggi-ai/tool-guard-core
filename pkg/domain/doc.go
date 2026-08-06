// Package domain holds the shared types Tool Guard moves across its
// engine, audit, and CLI boundaries.
//
// The central data structures:
//
//   - [ActionEnvelope] — one tool call enriched with agent identity,
//     parameters, session state, and verified context. Built once at the
//     proxy boundary and consumed by the engine and the audit ledger.
//   - [Policy] — a versioned, citation-backed bundle of [Rule]s. Every
//     rule has a [Condition] tree and an [Effect] (allow / flag /
//     escalate / deny).
//   - [DecisionTrace] — the immutable audit record produced by a single
//     evaluation: which envelope, which policies matched, which rules
//     triggered, the chosen action, and the hash-chain links.
//
// All types are JSON-tagged. YAML loading is handled by pkg/policyload via a
// strict generic-map round-trip so the domain stays JSON-only.
//
// Policy conditions opt in to semantic classification via [LLMClassify].
package domain
