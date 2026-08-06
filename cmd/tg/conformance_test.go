package main

// TestConformance walks testdata/conformance/*.json and asserts the engine
// produces the exact documented decision for each shipped policy + a real
// envelope. This is the "public conformance corpus green on every release
// and platform" item from the 1.0 roadmap made real: it runs as an
// ordinary `go test` in the existing 3-OS CI matrix (ubuntu/macos/windows),
// so it's already checked on every platform that matrix covers — no
// separate infrastructure needed.
//
// See testdata/conformance/README.md for the case schema and how to add
// one.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
	"github.com/dimaggi-ai/tool-guard-core/pkg/policyload"
)

type conformanceCase struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	PolicyFile  string                 `json:"policy_file"`
	Mode        string                 `json:"mode"`
	Envelope    map[string]interface{} `json:"envelope"`
	Expect      struct {
		Decision    string `json:"decision"`
		ActionTaken string `json:"action_taken"`
	} `json:"expect"`
}

func TestConformance(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "conformance", "*.json"))
	if err != nil {
		t.Fatalf("glob conformance cases: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no conformance cases found — testdata/conformance/*.json is empty or the glob path is wrong")
	}

	for _, file := range files {
		file := file
		t.Run(filepath.Base(file), func(t *testing.T) {
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read case: %v", err)
			}
			var c conformanceCase
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatalf("parse case: %v", err)
			}

			policy, err := policyload.Load(filepath.Join(filepath.Dir(file), c.PolicyFile))
			if err != nil {
				t.Fatalf("load policy %q: %v", c.PolicyFile, err)
			}
			if err := engine.ValidatePolicy(&policy); err != nil {
				t.Fatalf("policy %q fails validation: %v", c.PolicyFile, err)
			}

			envJSON, err := json.Marshal(c.Envelope)
			if err != nil {
				t.Fatalf("re-marshal envelope: %v", err)
			}
			var env domain.ActionEnvelope
			if err := json.Unmarshal(envJSON, &env); err != nil {
				t.Fatalf("parse envelope: %v", err)
			}
			if env.Timestamp.IsZero() {
				env.Timestamp = time.Now()
			}
			if env.EnvelopeID == "" {
				env.EnvelopeID = "conformance-" + c.Name
			}

			var mode domain.PolicyMode
			switch c.Mode {
			case "shadow":
				mode = domain.PolicyModeShadow
			case "enforcement", "":
				mode = domain.PolicyModeEnforcement
			default:
				t.Fatalf("case %q: unknown mode %q", c.Name, c.Mode)
			}

			result := engine.NewEvaluator().Evaluate(&env, []domain.Policy{policy}, mode)

			if string(result.Decision) != c.Expect.Decision {
				t.Errorf("%s: decision = %q, want %q (reason: %s)",
					c.Description, result.Decision, c.Expect.Decision, result.DecisionReason)
			}
			if string(result.ActionTaken) != c.Expect.ActionTaken {
				t.Errorf("%s: action_taken = %q, want %q (reason: %s)",
					c.Description, result.ActionTaken, c.Expect.ActionTaken, result.DecisionReason)
			}
		})
	}
}
