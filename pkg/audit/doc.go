// Package audit produces and verifies the SHA-256 hash-chained audit
// ledger for Tool Guard decisions.
//
// Each [github.com/dimaggi-ai/tool-guard-core/pkg/domain.DecisionTrace] is
// serialised to a canonical byte sequence (see [CanonicalTraceBytes]) and
// hashed with a chain link to the previous trace, yielding a tamper-
// evident sequence: changing any field in that record version's canonical
// projection changes its hash, which breaks the chain link held by the next
// record, and so on through to the tail.
//
// The package ships two verification primitives:
//
//   - [VerifyChainFromReader] for offline replay of a JSONL stream — the
//     primitive `tg verify -file decisions.jsonl` runs on. No database
//     required.
//   - [ChainVerifier] for online verification against a [ChainStore]
//     backend (whatever your application uses to persist traces).
//
// Canonicalisation is versioned (see [CanonicalTraceVersion]). Records
// without an on-record version marker use the immutable v1 encoder; current
// writers stamp v2. Any hash-bearing schema change MUST add a new encoder so
// evidence packs produced under every older version remain verifiable.
package audit
