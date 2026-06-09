package sqlguard

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestParseRegistry_HappyPath(t *testing.T) {
	body := []byte(`
functions:
  destructive:
    - cleanup_users
    - PURGE_AUDIT_LOG
    - rotate_secret
  sensitive_read:
    - decrypt_field
`)
	r, err := ParseRegistry(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !r.FunctionInClass("cleanup_users", "destructive") {
		t.Errorf("cleanup_users not in destructive")
	}
	// Class names get lowercased.
	if !r.FunctionInClass("decrypt_field", "SENSITIVE_READ") {
		t.Errorf("class lookup not case-insensitive")
	}
	// Function names get lowercased (PURGE_AUDIT_LOG → purge_audit_log).
	if !r.FunctionInClass("purge_audit_log", "destructive") {
		t.Errorf("function name not lowercased on load")
	}
	// Function not in any class returns false.
	if r.FunctionInClass("does_not_exist", "destructive") {
		t.Errorf("nonexistent function reported as in-class")
	}
	// Class not declared returns false.
	if r.FunctionInClass("cleanup_users", "made-up-class") {
		t.Errorf("nonexistent class reported as matched")
	}
}

func TestParseRegistry_EmptyAndMalformed(t *testing.T) {
	if r, err := ParseRegistry([]byte(``)); err != nil || r == nil {
		t.Errorf("empty input should produce empty registry, got err=%v r=%v", err, r)
	}
	if r, err := ParseRegistry([]byte(`functions: {}`)); err != nil || r == nil {
		t.Errorf("empty functions: should produce empty registry, got err=%v r=%v", err, r)
	}
	if _, err := ParseRegistry([]byte(`not valid yaml: [unclosed`)); err == nil {
		t.Errorf("malformed YAML should error")
	}
}

func TestParseRegistry_SkipsBlankEntries(t *testing.T) {
	body := []byte(`
functions:
  destructive:
    - cleanup_users
    - ""
    - "   "
    - rotate_secret
`)
	r, _ := ParseRegistry(body)
	if !r.FunctionInClass("cleanup_users", "destructive") {
		t.Errorf("cleanup_users missing")
	}
	if !r.FunctionInClass("rotate_secret", "destructive") {
		t.Errorf("rotate_secret missing")
	}
	// Empty entries are dropped.
	bag := r.FunctionClass["destructive"]
	if _, ok := bag[""]; ok {
		t.Errorf("blank entry kept in class")
	}
}

func TestRegistry_ClassesOf(t *testing.T) {
	r, _ := ParseRegistry([]byte(`
functions:
  destructive: [shared_fn]
  sensitive_read: [shared_fn, other_fn]
`))
	got := r.ClassesOf("shared_fn")
	sort.Strings(got)
	want := []string{"destructive", "sensitive_read"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ClassesOf(shared_fn) = %v, want %v", got, want)
	}
	if r.ClassesOf("absent") != nil {
		t.Errorf("ClassesOf(absent) should be nil")
	}
}

func TestRegistry_NilSafe(t *testing.T) {
	var r *Registry
	if r.FunctionInClass("any", "any") {
		t.Errorf("nil receiver should return false")
	}
	if r.ClassesOf("any") != nil {
		t.Errorf("nil receiver ClassesOf should return nil")
	}
}

func TestSetAndCurrentRegistry(t *testing.T) {
	old := CurrentRegistry()
	t.Cleanup(func() { SetRegistry(old) })

	SetRegistry(nil)
	if CurrentRegistry() != nil {
		t.Errorf("CurrentRegistry() != nil after SetRegistry(nil)")
	}

	r, _ := ParseRegistry([]byte(`functions: {destructive: [drop_users]}`))
	SetRegistry(r)
	if CurrentRegistry() != r {
		t.Errorf("CurrentRegistry() did not return the installed registry")
	}
	if !CurrentRegistry().FunctionInClass("drop_users", "destructive") {
		t.Errorf("installed registry doesn't classify correctly")
	}
}

func TestLoadRegistryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tools.yaml")
	if err := os.WriteFile(path, []byte(`
functions:
  destructive: [drop_user_data]
`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	r, err := LoadRegistryFile(path)
	if err != nil {
		t.Fatalf("LoadRegistryFile: %v", err)
	}
	if !r.FunctionInClass("drop_user_data", "destructive") {
		t.Errorf("function not classified after file load")
	}
}

func TestLoadRegistryFile_NotFound(t *testing.T) {
	_, err := LoadRegistryFile("/nonexistent/path.yaml")
	if err == nil {
		t.Errorf("expected error for missing file")
	}
}
