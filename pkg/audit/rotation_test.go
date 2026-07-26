package audit

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeRotationFixture(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("fixture\n"), 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
}

// TestRotationSetOldestFirst_MixedDirectory exercises the real directory
// shape produced by repeated size rotation: numeric siblings are replayed in
// creation order and the active file is always last. Unrelated files,
// non-numeric suffixes, and directories that merely resemble rotations must
// not enter the evidence chain.
func TestRotationSetOldestFirst_MixedDirectory(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "decisions.jsonl")

	for _, path := range []string{
		active,
		active + ".10",
		active + ".2",
		active + ".1",
		active + ".tmp",
		filepath.Join(dir, "other.jsonl.3"),
	} {
		writeRotationFixture(t, path)
	}
	if err := os.Mkdir(active+".3", 0o700); err != nil {
		t.Fatalf("mkdir rotation-shaped directory: %v", err)
	}

	got, err := RotationSetOldestFirst(active)
	if err != nil {
		t.Fatalf("RotationSetOldestFirst: %v", err)
	}
	want := []string{active + ".1", active + ".2", active + ".10", active}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rotation set = %#v, want %#v", got, want)
	}
}

// TestRotationSetOldestFirst_RotationsWithoutActive covers the crash/restart
// state immediately after the active file has been renamed but before a fresh
// active file is created. The rotated evidence remains verifiable.
func TestRotationSetOldestFirst_RotationsWithoutActive(t *testing.T) {
	active := filepath.Join(t.TempDir(), "audit.jsonl")
	writeRotationFixture(t, active+".7")
	writeRotationFixture(t, active+".4")

	got, err := RotationSetOldestFirst(active)
	if err != nil {
		t.Fatalf("RotationSetOldestFirst: %v", err)
	}
	want := []string{active + ".4", active + ".7"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rotation set = %#v, want %#v", got, want)
	}
}

func TestRotationSetOldestFirst_RelativeActivePath(t *testing.T) {
	f, err := os.CreateTemp(".", ".audit-rotation-test-*.jsonl")
	if err != nil {
		t.Fatalf("create relative-path fixture: %v", err)
	}
	active := filepath.Base(f.Name())
	if err := f.Close(); err != nil {
		t.Fatalf("close relative-path fixture: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(active); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove relative-path fixture: %v", err)
		}
	})

	got, err := RotationSetOldestFirst(active)
	if err != nil {
		t.Fatalf("RotationSetOldestFirst: %v", err)
	}
	if want := []string{active}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rotation set = %#v, want %#v", got, want)
	}
}

func TestRotationSetOldestFirst_NoFiles(t *testing.T) {
	active := filepath.Join(t.TempDir(), "missing.jsonl")
	_, err := RotationSetOldestFirst(active)
	if err == nil || !strings.Contains(err.Error(), "no audit log files found") {
		t.Fatalf("error = %v, want no-files error", err)
	}
}

func TestRotationSetOldestFirst_ReadDirectoryError(t *testing.T) {
	notDir := filepath.Join(t.TempDir(), "not-a-directory")
	writeRotationFixture(t, notDir)

	_, err := RotationSetOldestFirst(filepath.Join(notDir, "audit.jsonl"))
	if err == nil {
		t.Fatal("expected error when audit parent is not a directory")
	}
}

func TestRotationSetOldestFirst_ActiveStatError(t *testing.T) {
	dir := t.TempDir()
	active := filepath.Join(dir, "audit.jsonl")
	if err := os.Symlink("audit.jsonl", active); err != nil {
		t.Fatalf("create self-referential active symlink: %v", err)
	}

	_, err := RotationSetOldestFirst(active)
	if err == nil {
		t.Fatal("expected error when active path cannot be statted")
	}
}
