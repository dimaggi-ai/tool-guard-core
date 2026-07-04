package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func wc(w *domain.WriteClassify) domain.Condition { return domain.Condition{WriteClassify: w} }

func TestWriteClassify_AllowedDeniedPrefixes(t *testing.T) {
	dir := t.TempDir()
	allowed := filepath.Join(dir, "workspace")
	protected := filepath.Join(dir, "guard")

	cond := wc(&domain.WriteClassify{Require: domain.WriteRequire{
		AllowedPathPrefixes: []string{allowed},
		DeniedPathPrefixes:  []string{protected},
	}})

	inside := map[string]interface{}{"parameters.file_path": filepath.Join(allowed, "a.txt")}
	if EvalCondition(cond, inside) {
		t.Error("write inside the allowed prefix should not fire")
	}
	outside := map[string]interface{}{"parameters.file_path": filepath.Join(dir, "elsewhere/a.txt")}
	if !EvalCondition(cond, outside) {
		t.Error("write outside all allowed prefixes should fire")
	}
	denied := map[string]interface{}{"parameters.file_path": filepath.Join(protected, "policy.yaml")}
	if !EvalCondition(cond, denied) {
		t.Error("write under a denied prefix should fire")
	}
}

func TestWriteClassify_MaxBytesAndContent(t *testing.T) {
	cond := wc(&domain.WriteClassify{Require: domain.WriteRequire{
		MaxBytes:           10,
		DeniedContentRegex: []string{`(?i)BEGIN RSA PRIVATE KEY`},
	}})
	over := map[string]interface{}{"parameters.file_path": "/tmp/x", "parameters.content": "this is way more than ten bytes"}
	if !EvalCondition(cond, over) {
		t.Error("content over max_bytes should fire")
	}
	under := map[string]interface{}{"parameters.file_path": "/tmp/x", "parameters.content": "short"}
	if EvalCondition(cond, under) {
		t.Error("small content should not fire")
	}
	secret := map[string]interface{}{"parameters.file_path": "/tmp/x", "parameters.content": "-----BEGIN RSA PRIVATE KEY-----"}
	if !EvalCondition(cond, secret) {
		t.Error("content matching a denied pattern should fire")
	}
}

func TestWriteClassify_RelativePathResolvesToCwd(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cond := wc(&domain.WriteClassify{Require: domain.WriteRequire{AllowedPathPrefixes: []string{wd}}})
	// A relative write resolves under the cwd → allowed.
	if EvalCondition(cond, map[string]interface{}{"parameters.file_path": "note.txt"}) {
		t.Error("relative write under the allowed cwd should not fire")
	}
	// An absolute write elsewhere → fires.
	if !EvalCondition(cond, map[string]interface{}{"parameters.file_path": "/etc/hosts"}) {
		t.Error("write outside the allowed prefix should fire")
	}
}

func TestWriteClassify_FailsClosedWhenNoPathButAllowSet(t *testing.T) {
	cond := wc(&domain.WriteClassify{Require: domain.WriteRequire{AllowedPathPrefixes: []string{"/srv"}}})
	// A write tool call with no extractable path, but an allow-list is set.
	if !EvalCondition(cond, map[string]interface{}{"parameters.content": "x"}) {
		t.Error("no write path + allowed_path_prefixes set should fail closed (fire)")
	}
}

func TestWriteClassify_ArrayAndNestedTargets(t *testing.T) {
	dir := t.TempDir()
	protected := filepath.Join(dir, "guard")
	cond := wc(&domain.WriteClassify{Require: domain.WriteRequire{DeniedPathPrefixes: []string{protected}}})

	arr := map[string]interface{}{"parameters.paths": []interface{}{
		filepath.Join(dir, "ok.txt"), filepath.Join(protected, "policy.yaml"),
	}}
	if !EvalCondition(cond, arr) {
		t.Error("an array write touching a denied prefix should fire")
	}
	nested := map[string]interface{}{"parameters.edits": []interface{}{
		map[string]interface{}{"file_path": filepath.Join(protected, "x")},
	}}
	if !EvalCondition(cond, nested) {
		t.Error("a nested edit touching a denied prefix should fire")
	}
}
