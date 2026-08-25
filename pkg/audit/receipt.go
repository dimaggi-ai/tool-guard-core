package audit

import (
	"fmt"
	"strings"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// ReceiptVersion is the wire-format version of DecisionReceipt. It is
// independent of CanonicalTraceVersion: changing a receipt does not change the
// trace bytes it references.
const ReceiptVersion = "1"

const (
	HashAlgorithmSHA256     = "sha256"
	IntegrityModelHashChain = "hash-chain"
	receiptURNPrefix        = "urn:tool-guard:trace"
)

// DecisionReceipt is a correlation reference to one trace that a proxy
// successfully appended to its audit chain. It is deliberately outside
// pkg/domain because it must never participate in policy evaluation or in the
// canonical trace hash.
//
// This is a tamper-evident hash-chain reference, not a signature or an
// independently authentic statement. Durability is exactly the durability
// provided by the proxy's configured audit sync mode.
type DecisionReceipt struct {
	ReceiptVersion        string             `json:"receipt_version"`
	TraceID               string             `json:"trace_id"`
	TraceHash             string             `json:"trace_hash"`
	HashAlgorithm         string             `json:"hash_algorithm"`
	CanonicalTraceVersion string             `json:"canonical_trace_version"`
	IntegrityModel        string             `json:"integrity_model"`
	Decision              domain.Decision    `json:"decision"`
	ActionTaken           domain.ActionTaken `json:"action_taken"`
	Timestamp             time.Time          `json:"timestamp"`
	Issuer                string             `json:"issuer,omitempty"`
	ReceiptURI            string             `json:"receipt_uri"`
}

// NewDecisionReceipt derives a receipt from an already-appended trace. A nil
// result means the trace lacks a field required for an unambiguous reference.
// Callers must omit the optional receipt in that case; receipt construction is
// never allowed to alter or delay the underlying decision.
func NewDecisionReceipt(trace *domain.DecisionTrace) *DecisionReceipt {
	if trace == nil || strings.TrimSpace(trace.TraceID) == "" ||
		!validReceiptSHA256(trace.TraceHash) || trace.Timestamp.IsZero() ||
		trace.Decision == "" || trace.ActionTaken == "" {
		return nil
	}
	canonicalVersion := trace.SchemaVersion
	if canonicalVersion == "" {
		canonicalVersion = canonicalTraceVersionV1
	}
	if canonicalVersion != canonicalTraceVersionV1 && canonicalVersion != CanonicalTraceVersion {
		return nil
	}
	valid, err := VerifyCanonicalTraceHash(trace)
	if err != nil || !valid {
		return nil
	}
	return &DecisionReceipt{
		ReceiptVersion:        ReceiptVersion,
		TraceID:               trace.TraceID,
		TraceHash:             trace.TraceHash,
		HashAlgorithm:         HashAlgorithmSHA256,
		CanonicalTraceVersion: canonicalVersion,
		IntegrityModel:        IntegrityModelHashChain,
		Decision:              trace.Decision,
		ActionTaken:           trace.ActionTaken,
		Timestamp:             trace.Timestamp,
		Issuer:                trace.SignedBy,
		ReceiptURI:            fmt.Sprintf("%s:%s:%s", receiptURNPrefix, canonicalVersion, trace.TraceHash),
	}
}

func validReceiptSHA256(value string) bool {
	const prefix = HashAlgorithmSHA256 + ":"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	digest := strings.TrimPrefix(value, prefix)
	if len(digest) != 64 {
		return false
	}
	for _, char := range digest {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}
