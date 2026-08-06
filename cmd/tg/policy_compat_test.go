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
	"os/exec"
	"path/filepath"
	"strings"
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

// TestPolicyCompatCoverage asserts the snapshot set itself is complete:
// every release tag from v0.2.0 on has a snapshot directory, and every
// snapshot contains every policy its tag shipped. Without this, a
// forgotten snapshot is skipped silently and the regression net thins
// out one release at a time (exactly what happened between v0.4.0 and
// v0.6.0). Needs git tags: CI fetches them (fetch-tags in ci.yml); a
// tag-less local clone skips with an explicit message rather than
// passing vacuously.
func TestPolicyCompatCoverage(t *testing.T) {
	// All git invocations run from the repo root: ls-tree/show pathspecs
	// are resolved relative to the process CWD inside the repo, and this
	// test's CWD is cmd/tg — "policies/" from here would silently match
	// nothing and make the shipped-set checks vacuous.
	gitCmd := func(args ...string) *exec.Cmd {
		cmd := exec.Command("git", args...)
		cmd.Dir = filepath.Join("..", "..")
		return cmd
	}

	out, err := gitCmd("tag", "-l", "v*").Output()
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("git tag unavailable in CI (%v) — the checkout must fetch tags (fetch-depth: 0 + fetch-tags in ci.yml) or this gate silently disappears", err)
		}
		t.Skipf("git tag unavailable (%v) — coverage check needs a git checkout with tags", err)
	}
	tags := strings.Fields(string(out))
	if len(tags) == 0 {
		if os.Getenv("CI") != "" {
			t.Fatal("no release tags in the CI checkout — the checkout must fetch tags (fetch-depth: 0 + fetch-tags in ci.yml) or this gate silently disappears")
		}
		t.Skip("no release tags in this checkout — coverage check needs fetched tags (see fetch-tags in ci.yml)")
	}

	compatRoot := filepath.Join("..", "..", "testdata", "policy-compat")
	for _, tag := range tags {
		if strings.HasPrefix(tag, "v0.1.") {
			continue // pre-net releases: v0.1.x predates the snapshot scheme
		}
		dir := filepath.Join(compatRoot, tag)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("release tag %s has no snapshot directory — run scripts/snapshot-policies.sh %s", tag, tag)
			continue
		}

		lsOut, err := gitCmd("ls-tree", "-r", "--name-only", tag, "--", "policies/").Output()
		if err != nil {
			t.Errorf("git ls-tree %s: %v", tag, err)
			continue
		}
		shipped := map[string]bool{}
		for _, f := range strings.Fields(string(lsOut)) {
			base := filepath.Base(f)
			if base == "README.md" {
				continue
			}
			shipped[base] = true
			got, err := os.ReadFile(filepath.Join(dir, base))
			if os.IsNotExist(err) {
				t.Errorf("snapshot %s is missing %s, which tag %s shipped — re-run scripts/snapshot-policies.sh %s", tag, base, tag, tag)
				continue
			}
			if err != nil {
				t.Errorf("read snapshot %s/%s: %v", tag, base, err)
				continue
			}
			// Byte-equality, not just presence: a hand-edited or "migrated"
			// snapshot that still loads would otherwise satisfy the gate
			// while no longer being what the tag shipped.
			want, err := gitCmd("show", tag+":"+f).Output()
			if err != nil {
				t.Errorf("git show %s:%s: %v", tag, f, err)
				continue
			}
			if string(got) != string(want) {
				t.Errorf("snapshot %s/%s differs from what tag %s shipped — snapshots are frozen copies; re-run scripts/snapshot-policies.sh %s", tag, base, tag, tag)
			}
		}
		// No stale extras: a file in the snapshot the tag never shipped is
		// not a snapshot of that tag.
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Errorf("read snapshot dir %s: %v", tag, err)
			continue
		}
		for _, e := range entries {
			if !shipped[e.Name()] {
				t.Errorf("snapshot %s contains %s, which tag %s never shipped — re-run scripts/snapshot-policies.sh %s", tag, e.Name(), tag, tag)
			}
		}
	}
}
