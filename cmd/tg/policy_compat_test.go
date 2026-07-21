package main

// TestPolicyCompat is the "frozen policy schema" leg of the 1.0 roadmap,
// made partial and real rather than promised: it re-runs the conformance
// corpus (testdata/conformance/*.json) against policy YAML snapshots taken
// from each past release tag (testdata/policy-compat/<version>/), instead
// of the live policies/ directory, and asserts the exact same decision.
//
// This does NOT freeze the schema by construction (there's no version
// field or migration machinery) — it's a regression net: if a future
// engine or loader change ever causes an old, unmodified policy file to
// parse differently or evaluate to a different decision, this test breaks
// immediately instead of the break surfacing as a silent behavior change
// in someone's production deployment. See testdata/policy-compat/README.md
// for how to add a new version snapshot after a release.
//
// A case is skipped for a given version if that version's snapshot
// directory doesn't contain a file with the case's policy basename (e.g.
// coding_agent_egress.yaml didn't exist yet at v0.2.0) — that's a missing
// policy, not a compatibility break.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

func TestPolicyCompat(t *testing.T) {
	caseFiles, err := filepath.Glob(filepath.Join("..", "..", "testdata", "conformance", "*.json"))
	if err != nil {
		t.Fatalf("glob conformance cases: %v", err)
	}
	if len(caseFiles) == 0 {
		t.Fatal("no conformance cases found — testdata/conformance/*.json is empty or the glob path is wrong")
	}

	compatRoot := filepath.Join("..", "..", "testdata", "policy-compat")
	versionDirs, err := os.ReadDir(compatRoot)
	if err != nil {
		t.Fatalf("read %s: %v", compatRoot, err)
	}
	if len(versionDirs) == 0 {
		t.Fatal("no version snapshots found under testdata/policy-compat/")
	}

	for _, vd := range versionDirs {
		if !vd.IsDir() {
			continue
		}
		version := vd.Name()

		for _, file := range caseFiles {
			file := file
			raw, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read case %s: %v", file, err)
			}
			var c conformanceCase
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Fatalf("parse case %s: %v", file, err)
			}

			snapshotPath := filepath.Join(compatRoot, version, filepath.Base(c.PolicyFile))
			if _, err := os.Stat(snapshotPath); os.IsNotExist(err) {
				continue // this policy didn't exist yet at this version — not a compat break
			}

			t.Run(version+"/"+c.Name, func(t *testing.T) {
				policy, err := loadPolicyYAML(snapshotPath)
				if err != nil {
					t.Fatalf("load %s policy snapshot %q: %v", version, snapshotPath, err)
				}
				if err := engine.ValidatePolicy(&policy); err != nil {
					t.Fatalf("%s snapshot %q fails validation under the current engine: %v", version, snapshotPath, err)
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
					env.EnvelopeID = "policy-compat-" + version + "-" + c.Name
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
					t.Errorf("%s (%s): decision = %q, want %q (reason: %s) — a %s-vintage policy file now evaluates differently than the corpus expects",
						c.Description, version, result.Decision, c.Expect.Decision, result.DecisionReason, version)
				}
				if string(result.ActionTaken) != c.Expect.ActionTaken {
					t.Errorf("%s (%s): action_taken = %q, want %q (reason: %s) — a %s-vintage policy file now evaluates differently than the corpus expects",
						c.Description, version, result.ActionTaken, c.Expect.ActionTaken, result.DecisionReason, version)
				}
			})
		}
	}
}
