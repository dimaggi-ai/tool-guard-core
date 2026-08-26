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
// A case is skipped for a given version if that version's snapshot directory
// lacks one of its shipped policy files, if it contains only fixtures, or if
// policy_compat_since says the case relies on policy content introduced later.
// Fixture policies in a multi-policy composition case remain live inputs while
// shipped policies are replaced by their frozen snapshots.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
	"github.com/dimaggi-ai/tool-guard-core/pkg/policyload"
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
	shippedDir := filepath.Clean(filepath.Join("..", "..", "policies"))

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
			c, err := decodeConformanceCase(raw)
			if err != nil {
				t.Fatalf("parse case %s: %v", file, err)
			}
			if c.PolicyCompatSince != "" {
				eligible, err := releaseAtLeast(version, c.PolicyCompatSince)
				if err != nil {
					t.Fatalf("compare snapshot version for case %s: %v", filepath.Base(file), err)
				}
				if !eligible {
					continue
				}
			}

			paths, err := c.policyPaths()
			if err != nil {
				t.Fatalf("policy paths for case %s: %v", filepath.Base(file), err)
			}
			policies := make([]domain.Policy, 0, len(paths))
			hasSnapshotPolicy := false
			missingSnapshotPolicy := false
			for _, path := range paths {
				resolved := filepath.Clean(filepath.Join(filepath.Dir(file), path))
				loadPath := resolved
				if filepath.Dir(resolved) == shippedDir {
					hasSnapshotPolicy = true
					loadPath = filepath.Join(compatRoot, version, filepath.Base(resolved))
					if _, err := os.Stat(loadPath); os.IsNotExist(err) {
						missingSnapshotPolicy = true
						break // this policy did not exist in this release
					} else if err != nil {
						t.Fatalf("stat %s policy snapshot %q: %v", version, loadPath, err)
					}
				}
				policy, err := policyload.Load(loadPath)
				if err != nil {
					t.Fatalf("load %s policy input %q: %v", version, loadPath, err)
				}
				if err := engine.ValidatePolicy(&policy); err != nil {
					t.Fatalf("%s policy input %q fails validation under the current engine: %v", version, loadPath, err)
				}
				policies = append(policies, policy)
			}
			// Fixture-only cases exercise current schema coverage, not frozen
			// policy snapshots. Multi-policy cases remain eligible as long as at
			// least one referenced shipped policy exists in the snapshot.
			if !hasSnapshotPolicy || missingSnapshotPolicy {
				continue
			}

			t.Run(version+"/"+c.Name, func(t *testing.T) {
				result := evaluateConformanceCase(c, policies)

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

func TestReleaseAtLeast(t *testing.T) {
	tests := []struct {
		version string
		minimum string
		want    bool
	}{
		{"v0.5.0", "v0.5.0", true},
		{"v0.5.1", "v0.5.0", true},
		{"v0.6.0", "v0.5.9", true},
		{"v1.0.0", "v0.99.99", true},
		{"v0.4.9", "v0.5.0", false},
	}
	for _, tt := range tests {
		got, err := releaseAtLeast(tt.version, tt.minimum)
		if err != nil {
			t.Fatalf("releaseAtLeast(%q, %q): %v", tt.version, tt.minimum, err)
		}
		if got != tt.want {
			t.Errorf("releaseAtLeast(%q, %q) = %v, want %v", tt.version, tt.minimum, got, tt.want)
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
