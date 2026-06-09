package audit

import (
	"testing"
	"time"
)

func TestComputeTraceHash(t *testing.T) {
	ts := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)

	hash1 := ComputeTraceHash("trace-001", "env-001", "allowed", "allowed", ts, "")
	if hash1 == "" {
		t.Error("hash should not be empty")
	}
	if len(hash1) < 70 { // sha256: + 64 hex chars
		t.Errorf("hash too short: %s", hash1)
	}

	// Same inputs produce same hash
	hash2 := ComputeTraceHash("trace-001", "env-001", "allowed", "allowed", ts, "")
	if hash1 != hash2 {
		t.Error("same inputs should produce same hash")
	}

	// Different inputs produce different hash
	hash3 := ComputeTraceHash("trace-002", "env-001", "allowed", "allowed", ts, "")
	if hash1 == hash3 {
		t.Error("different inputs should produce different hash")
	}

	// Chain: second trace references first
	hash4 := ComputeTraceHash("trace-002", "env-002", "denied", "denied", ts, hash1)
	if hash4 == hash1 {
		t.Error("chained hash should differ from previous")
	}
}

func TestVerifyTraceHash(t *testing.T) {
	ts := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)

	hash := ComputeTraceHash("trace-001", "env-001", "allowed", "allowed", ts, "")

	// Correct verification
	if !VerifyTraceHash("trace-001", "env-001", "allowed", "allowed", ts, "", hash) {
		t.Error("valid hash should verify")
	}

	// Tampered data
	if VerifyTraceHash("trace-001", "env-001", "denied", "allowed", ts, "", hash) {
		t.Error("tampered data should not verify")
	}

	// Tampered hash
	if VerifyTraceHash("trace-001", "env-001", "allowed", "allowed", ts, "", "sha256:tampered") {
		t.Error("tampered hash should not verify")
	}
}

func TestHashChainIntegrity(t *testing.T) {
	ts := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)

	// Build a chain of 3 traces
	hash1 := ComputeTraceHash("trace-001", "env-001", "allowed", "allowed", ts, "")
	hash2 := ComputeTraceHash("trace-002", "env-002", "denied", "allowed_shadow", ts.Add(time.Second), hash1)
	hash3 := ComputeTraceHash("trace-003", "env-003", "flagged", "flagged", ts.Add(2*time.Second), hash2)

	// Verify chain
	if !VerifyTraceHash("trace-001", "env-001", "allowed", "allowed", ts, "", hash1) {
		t.Error("trace 1 should verify")
	}
	if !VerifyTraceHash("trace-002", "env-002", "denied", "allowed_shadow", ts.Add(time.Second), hash1, hash2) {
		t.Error("trace 2 should verify with trace 1 as previous")
	}
	if !VerifyTraceHash("trace-003", "env-003", "flagged", "flagged", ts.Add(2*time.Second), hash2, hash3) {
		t.Error("trace 3 should verify with trace 2 as previous")
	}

	// Tamper: change trace 2's previous hash
	if VerifyTraceHash("trace-002", "env-002", "denied", "allowed_shadow", ts.Add(time.Second), "sha256:tampered", hash2) {
		t.Error("broken chain should not verify")
	}
}
