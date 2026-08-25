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
	Steps       []workflowStepSpec `yaml:"steps"`
}

type workflowStepSpec struct {
	Run string `yaml:"run"`
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
	assertWorkflowPermissions(t, "publish-python", release.Jobs["publish-python"].Permissions, map[string]string{
		"id-token": "write",
	})

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
