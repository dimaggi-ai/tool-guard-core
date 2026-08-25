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
	"reflect"
	"strings"
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

func TestShadowConformanceFixtureDiffersOnlyByMode(t *testing.T) {
	base, err := policyload.Load(filepath.Join("..", "..", "policies", "refund_cap.yaml"))
	if err != nil {
		t.Fatalf("load shipped refund policy: %v", err)
	}
	shadow, err := policyload.Load(filepath.Join("..", "..", "testdata", "conformance", "fixtures", "refund_cap_shadow.yaml"))
	if err != nil {
		t.Fatalf("load shadow fixture: %v", err)
	}
	if base.Mode != domain.PolicyModeEnforcement || shadow.Mode != domain.PolicyModeShadow {
		t.Fatalf("fixture modes = base:%q shadow:%q, want enforcement/shadow", base.Mode, shadow.Mode)
	}
	shadow.Mode = base.Mode
	if !reflect.DeepEqual(shadow, base) {
		t.Fatal("shadow fixture drifted from policies/refund_cap.yaml in fields other than mode")
	}
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

// TestConformanceCompleteness asserts the corpus can't silently drift from
// the shipped policy set again: every policies/*.yaml must have at least
// one conformance case, case names must be unique, and each case's name
// must match its filename. This is exactly the gap 0.6.0 shipped through —
// irreversibility_floor.yaml landed with zero corpus cases and CI stayed
// green.
func TestConformanceCompleteness(t *testing.T) {
	policyFiles, err := filepath.Glob(filepath.Join("..", "..", "policies", "*.yaml"))
	if err != nil {
		t.Fatalf("glob policies: %v", err)
	}
	if len(policyFiles) == 0 {
		t.Fatal("no shipped policies found under policies/")
	}

	caseFiles, err := filepath.Glob(filepath.Join("..", "..", "testdata", "conformance", "*.json"))
	if err != nil {
		t.Fatalf("glob conformance cases: %v", err)
	}

	covered := map[string]int{}
	seenNames := map[string]string{}
	for _, file := range caseFiles {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read case %s: %v", file, err)
		}
		var c conformanceCase
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatalf("parse case %s: %v", file, err)
		}
		if prev, dup := seenNames[c.Name]; dup {
			t.Errorf("duplicate case name %q in %s (already used by %s)", c.Name, filepath.Base(file), prev)
		}
		seenNames[c.Name] = filepath.Base(file)
		if want := strings.TrimSuffix(filepath.Base(file), ".json"); c.Name != want {
			t.Errorf("case %s: name %q must match its filename (%q)", filepath.Base(file), c.Name, want)
		}
		// Credit coverage only when policy_file resolves to the shipped
		// policies/ directory — a case pointing at a same-named fixture or
		// snapshot elsewhere must not mark the real policy as covered.
		resolved := filepath.Clean(filepath.Join(filepath.Dir(file), c.PolicyFile))
		if filepath.Dir(resolved) == filepath.Clean(filepath.Join("..", "..", "policies")) {
			covered[filepath.Base(resolved)]++
		}
	}

	for _, pf := range policyFiles {
		base := filepath.Base(pf)
		if covered[base] == 0 {
			t.Errorf("shipped policy %s has no conformance case — add at least one to testdata/conformance/ (see its README)", base)
		}
	}
}
