package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func protectEnv(tool string, params map[string]any) *domain.ActionEnvelope {
	pj, _ := json.Marshal(params)
	return &domain.ActionEnvelope{ToolName: tool, Parameters: pj}
}

// P1a: a relative write target must be resolved against the CWD so it can't
// dodge an absolute protected prefix.
func TestProtect_RelativePathResolvesToCwd(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	env := protectEnv("write", map[string]any{"file_path": "policy.yaml"})
	if got, _ := ViolatesProtectedPaths(env, []string{wd}); !got {
		t.Fatal("relative file_path should resolve under the protected CWD and violate")
	}
	// A relative path NOT under the protected prefix must not violate.
	other := filepath.Join(filepath.Dir(wd), "definitely-not-here")
	if got, _ := ViolatesProtectedPaths(env, []string{other}); got {
		t.Fatal("relative file_path outside the protected prefix must not violate")
	}
}

// P1b: a write through a symlinked directory into a protected dir is caught,
// even though the write target file does not exist yet.
func TestProtect_SymlinkTraversal(t *testing.T) {
	dir := t.TempDir()
	protected := filepath.Join(dir, "protected")
	if err := os.MkdirAll(protected, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(protected, link); err != nil {
		t.Skipf("symlinks unsupported here: %v", err)
	}
	env := protectEnv("write", map[string]any{"file_path": filepath.Join(link, "policy.yaml")})
	if got, reason := ViolatesProtectedPaths(env, []string{protected}); !got {
		t.Fatalf("write via symlink into protected dir should violate; reason=%q", reason)
	}
	// A symlink into a NON-protected sibling must not violate.
	sibling := filepath.Join(dir, "sibling")
	_ = os.MkdirAll(sibling, 0o755)
	link2 := filepath.Join(dir, "link2")
	if err := os.Symlink(sibling, link2); err == nil {
		env2 := protectEnv("write", map[string]any{"file_path": filepath.Join(link2, "x")})
		if got, _ := ViolatesProtectedPaths(env2, []string{protected}); got {
			t.Fatal("write via symlink into a non-protected dir must not violate")
		}
	}
}

// P3: array-of-paths and nested edit objects are extracted, not just the flat
// file_path/path keys.
func TestProtect_ArrayAndNestedPaths(t *testing.T) {
	dir := t.TempDir()
	protected := filepath.Join(dir, "guard")
	if err := os.MkdirAll(protected, 0o755); err != nil {
		t.Fatal(err)
	}

	arr := protectEnv("multiedit", map[string]any{
		"paths": []any{filepath.Join(dir, "ok.txt"), filepath.Join(protected, "policy.yaml")},
	})
	if got, _ := ViolatesProtectedPaths(arr, []string{protected}); !got {
		t.Error("array-of-paths write into protected dir should violate")
	}

	nested := protectEnv("multiedit", map[string]any{
		"edits": []any{
			map[string]any{"file_path": filepath.Join(dir, "fine.txt")},
			map[string]any{"file_path": filepath.Join(protected, "x")},
		},
	})
	if got, _ := ViolatesProtectedPaths(nested, []string{protected}); !got {
		t.Error("nested edit object into protected dir should violate")
	}

	// All targets clean → no violation.
	clean := protectEnv("multiedit", map[string]any{
		"paths": []any{filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt")},
	})
	if got, _ := ViolatesProtectedPaths(clean, []string{protected}); got {
		t.Error("array of non-protected paths must not violate")
	}
}
