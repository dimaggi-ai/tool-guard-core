package audit

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// StampProvenance marks a trace as a current-schema record before its hash is
// computed. The engine version and policy-set digest are part of canonical v2,
// so changing either after append invalidates verification.
func StampProvenance(t *domain.DecisionTrace, engineVersion, policySetHash string) error {
	if t == nil {
		return fmt.Errorf("stamp provenance: nil trace")
	}
	engineVersion = strings.TrimSpace(engineVersion)
	if engineVersion == "" {
		return fmt.Errorf("stamp provenance: engine version is empty")
	}
	if err := validatePolicySetHash(policySetHash); err != nil {
		return fmt.Errorf("stamp provenance: %w", err)
	}
	t.EngineVersion = engineVersion
	t.PolicySetHash = policySetHash
	t.CanonicalVersion = CanonicalTraceVersion
	t.SchemaVersion = CanonicalTraceVersion
	return nil
}

func validateTraceProvenance(t *domain.DecisionTrace) error {
	if strings.TrimSpace(t.EngineVersion) == "" {
		return fmt.Errorf("canonical %s trace requires engine_version", CanonicalTraceVersion)
	}
	if err := validatePolicySetHash(t.PolicySetHash); err != nil {
		return fmt.Errorf("canonical %s trace: %w", CanonicalTraceVersion, err)
	}
	return nil
}

func validatePolicySetHash(value string) error {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) {
		return fmt.Errorf("policy_set_hash must use sha256:<64 lowercase hex> format")
	}
	hexPart := strings.TrimPrefix(value, prefix)
	if len(hexPart) != 64 || strings.ToLower(hexPart) != hexPart {
		return fmt.Errorf("policy_set_hash must use sha256:<64 lowercase hex> format")
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return fmt.Errorf("policy_set_hash must use sha256:<64 lowercase hex> format")
	}
	return nil
}
