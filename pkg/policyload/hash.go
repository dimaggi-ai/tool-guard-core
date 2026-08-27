package policyload

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// PolicySetHash returns a presentation-independent digest of the loaded
// policy set. Policies are hashed after strict decoding/defaulting, not as raw
// YAML, so comments, whitespace, filenames, and file order do not change the
// digest. Rule and condition order remain significant because they are part of
// the loaded policy objects.
func PolicySetHash(policies []domain.Policy) (string, error) {
	encoded := make([]json.RawMessage, 0, len(policies))
	for i := range policies {
		b, err := json.Marshal(policies[i])
		if err != nil {
			return "", fmt.Errorf("encode policy %d (%q): %w", i, policies[i].PolicyID, err)
		}
		encoded = append(encoded, json.RawMessage(b))
	}

	// Sort by the complete normalized representation. This stays deterministic
	// even for an invalid set containing duplicate policy IDs/versions.
	sort.Slice(encoded, func(i, j int) bool {
		return bytes.Compare(encoded[i], encoded[j]) < 0
	})
	setJSON, err := json.Marshal(encoded)
	if err != nil {
		return "", fmt.Errorf("encode policy set: %w", err)
	}
	sum := sha256.Sum256(setJSON)
	return fmt.Sprintf("sha256:%x", sum), nil
}
