package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type workflowContract struct {
	On          map[string]any             `yaml:"on"`
	Permissions map[string]string          `yaml:"permissions"`
	Jobs        map[string]workflowJobSpec `yaml:"jobs"`
}

type workflowJobSpec struct {
	Uses        string             `yaml:"uses"`
	Needs       any                `yaml:"needs"`
	Permissions map[string]string  `yaml:"permissions"`
	Env         map[string]string  `yaml:"env"`
	Steps       []workflowStepSpec `yaml:"steps"`
}

type workflowStepSpec struct {
	Name string         `yaml:"name"`
	Uses string         `yaml:"uses"`
	With map[string]any `yaml:"with"`
	Run  string         `yaml:"run"`
}

func TestReleaseWorkflowReusesFullCI(t *testing.T) {
	ci := loadWorkflow(t, filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if _, callable := ci.On["workflow_call"]; !callable {
		t.Fatal("ci.yml must expose workflow_call so release verification reuses the merge gate")
	}

	release := loadWorkflow(t, filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	verify, ok := release.Jobs["verify"]
	if !ok {
		t.Fatal("release.yml has no full-CI verification job")
	}
	if verify.Uses != "./.github/workflows/ci.yml" {
		t.Fatalf("release verify job uses %q, want local ci.yml", verify.Uses)
	}
	if !workflowDependsOn(release.Jobs, "verify", "preflight", nil) {
		t.Fatal("full CI verification can run before the tag-reachability preflight")
	}
	assertWorkflowPermissions(t, "workflow default", release.Permissions, map[string]string{
		"contents": "read",
	})
	assertWorkflowPermissions(t, "preflight", release.Jobs["preflight"].Permissions, map[string]string{
		"contents": "read",
	})
	assertWorkflowPermissions(t, "verify", verify.Permissions, map[string]string{
		"contents": "read",
	})
	assertWorkflowPermissions(t, "release", release.Jobs["release"].Permissions, map[string]string{
		"contents":     "write",
		"packages":     "write",
		"id-token":     "write",
		"attestations": "write",
	})
	assertStableTagPreflight(t, release.Jobs["preflight"])
	assertReleaseRefusesPublicState(t, release.Jobs["release"])
	assertWorkflowPermissions(t, "publish-python", release.Jobs["publish-python"].Permissions, map[string]string{
		"contents": "read",
		"id-token": "write",
	})
	finalizer, ok := release.Jobs["finalize-release"]
	if !ok {
		t.Fatal("release.yml has no finalizer job")
	}
	assertWorkflowPermissions(t, "finalize-release", finalizer.Permissions, map[string]string{
		"contents": "write",
	})
	if finalizer.Env["GH_REPO"] != "${{ github.repository }}" {
		t.Errorf("finalizer GH_REPO = %q, want explicit github.repository", finalizer.Env["GH_REPO"])
	}
	for _, dependency := range []string{"release", "publish-python"} {
		if !workflowDependsOn(release.Jobs, "finalize-release", dependency, nil) {
			t.Errorf("finalizer can run without successful %s job", dependency)
		}
	}
	assertFinalizerTransaction(t, finalizer)

	for _, jobName := range []string{"python-package", "release", "publish-python"} {
		if !workflowDependsOn(release.Jobs, jobName, "verify", nil) {
			t.Errorf("release job %q can run without successful full CI verification", jobName)
		}
	}

	for jobName, job := range release.Jobs {
		for _, step := range job.Steps {
			run := " " + strings.Join(strings.Fields(strings.ToLower(step.Run)), " ") + " "
			for _, duplicate := range []string{
				" go test ",
				" go vet ",
				" govulncheck ",
				" make test ",
				" make sdk-test ",
				" tg lint ",
			} {
				if strings.Contains(run, duplicate) {
					t.Errorf("release job %q duplicates CI verification command %q", jobName, strings.TrimSpace(duplicate))
				}
			}
		}
	}
}

func assertStableTagPreflight(t *testing.T, preflight workflowJobSpec) {
	t.Helper()
	if len(preflight.Steps) == 0 {
		t.Fatal("release preflight has no steps")
	}
	first := preflight.Steps[0]
	if first.Name != "Reject unsupported tag shapes" || !strings.Contains(first.Run, `^v[0-9]+\.[0-9]+\.[0-9]+$`) {
		t.Errorf("first release preflight step does not reject tags outside stable vN.N.N semver")
	}
}

func assertReleaseRefusesPublicState(t *testing.T, release workflowJobSpec) {
	t.Helper()
	stateCheckIndex, goreleaserIndex := -1, -1
	for index, step := range release.Steps {
		if strings.Contains(step.Run, "refusing to rebuild or push release artifacts") &&
			strings.Contains(step.Run, `jq -r '.draft'`) {
			stateCheckIndex = index
		}
		if strings.HasPrefix(step.Uses, "goreleaser/goreleaser-action@") {
			goreleaserIndex = index
		}
	}
	if stateCheckIndex < 0 {
		t.Error("release job does not reject an already-public GitHub Release")
	}
	if goreleaserIndex < 0 {
		t.Error("release job has no GoReleaser step")
	}
	if stateCheckIndex >= goreleaserIndex {
		t.Errorf("public-release state check step %d must precede GoReleaser step %d", stateCheckIndex, goreleaserIndex)
	}
}

func assertFinalizerTransaction(t *testing.T, finalizer workflowJobSpec) {
	t.Helper()
	const (
		downloadAction = "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
		verifyCommand  = "python3 scripts/verify_pypi_release.py"
		promoteCommand = `gh release edit "${TAG}" --draft=false`
		finalCheck     = `test "$(gh release view "${TAG}" --json isDraft --jq '.isDraft')" = "false"`
	)

	downloadIndex, verifyIndex, promoteIndex, finalCheckIndex := -1, -1, -1, -1
	promoteCount := 0
	for index, step := range finalizer.Steps {
		if step.Uses == downloadAction && step.With["name"] == "python-dist" && step.With["path"] == "dist/python" {
			downloadIndex = index
		}
		if strings.Contains(step.Run, verifyCommand) {
			verifyIndex = index
		}
		if strings.Contains(step.Run, promoteCommand) {
			promoteIndex = index
			promoteCount += strings.Count(step.Run, promoteCommand)
		}
		if strings.Contains(step.Run, finalCheck) {
			finalCheckIndex = index
		}
	}
	if downloadIndex < 0 {
		t.Error("finalizer does not download the exact python-dist artifact")
	}
	if verifyIndex < downloadIndex {
		t.Errorf("PyPI artifact verification step %d must follow download step %d", verifyIndex, downloadIndex)
	}
	if promoteCount != 1 {
		t.Errorf("finalizer has %d active promotion commands, want exactly 1", promoteCount)
	}
	if promoteIndex <= verifyIndex {
		t.Errorf("promotion step %d must follow PyPI verification step %d", promoteIndex, verifyIndex)
	}
	if finalCheckIndex != promoteIndex {
		t.Errorf("final public-state check step %d must be the promotion step %d", finalCheckIndex, promoteIndex)
	}
}

func assertWorkflowPermissions(t *testing.T, name string, got, want map[string]string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s permissions = %v, want %v", name, got, want)
	}
}

func loadWorkflow(t *testing.T, path string) workflowContract {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read workflow %s: %v", path, err)
	}
	var workflow workflowContract
	if err := yaml.Unmarshal(b, &workflow); err != nil {
		t.Fatalf("parse workflow %s: %v", path, err)
	}
	return workflow
}

func workflowDependsOn(jobs map[string]workflowJobSpec, from, target string, seen map[string]bool) bool {
	if from == target {
		return true
	}
	if seen == nil {
		seen = make(map[string]bool)
	}
	if seen[from] {
		return false
	}
	seen[from] = true
	job, ok := jobs[from]
	if !ok {
		return false
	}
	for _, dependency := range workflowNeeds(job.Needs) {
		if workflowDependsOn(jobs, dependency, target, seen) {
			return true
		}
	}
	return false
}

func workflowNeeds(value any) []string {
	switch needs := value.(type) {
	case string:
		return []string{needs}
	case []any:
		out := make([]string, 0, len(needs))
		for _, need := range needs {
			if name, ok := need.(string); ok {
				out = append(out, name)
			}
		}
		return out
	default:
		return nil
	}
}
