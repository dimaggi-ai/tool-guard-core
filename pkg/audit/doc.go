// Package audit produces and verifies the SHA-256 hash-chained audit
// ledger for Tool Guard decisions.
//
// Each [github.com/dimaggi-ai/tool-guard-core/pkg/domain.DecisionTrace] is
// serialised to a canonical byte sequence (see [CanonicalTraceBytes]) and
// hashed with a chain link to the previous trace, yielding a tamper-
// evident sequence: changing any field of any past record changes that
// record's hash, which breaks the chain link held by the next record,
// and so on through to the tail.
//
// The package ships two verification primitives:
//
//   - [VerifyChainFromReader] for offline replay of a JSONL stream — the
//     primitive `tg verify -file decisions.jsonl` runs on. No database
//     required.
//   - [ChainVerifier] for online verification against a [ChainStore]
//     backend (whatever your application uses to persist traces).
//
// New records use canonical version 2 (see [CanonicalTraceVersion]) and carry
// engine, policy-set, and schema provenance inside the integrity commitment.
// Legacy records with no schema_version continue to use the frozen v1 encoder.
// Any future canonical field addition MUST add a new encoder version; existing
// versioned shapes are immutable.
package audit
