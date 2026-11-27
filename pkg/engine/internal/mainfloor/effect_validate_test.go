package mainfloor_test

import (
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	engine "github.com/dimaggi-ai/tool-guard-core/pkg/engine/internal/mainfloor"
)

// A rule with an unknown effect (e.g. a "denyy" typo) has severity 0 and
// would silently resolve to allowed (fail-open). ValidatePolicy rejects it.
func TestValidatePolicy_RejectsUnknownEffect(t *testing.T) {
	p := &domain.Policy{
		PolicyID: "test",
		Rules: []domain.Rule{{
			RuleID:     "typo",
			Conditions: domain.Condition{Field: "amount", Operator: domain.OpGt, Value: float64(500)},
			Effect:     domain.Effect("denyy"),
		}},
	}
	err := engine.ValidatePolicy(p)
	if err == nil {
		t.Fatalf("expected rejection of unknown effect; got nil")
	}
	if !strings.Contains(err.Error(), "unknown effect") {
		t.Errorf("error doesn't name unknown effect: %v", err)
	}
}
