package mainfloor

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestProtectedWindowsNativeShellPaths(t *testing.T) {
	root := t.TempDir()
	protected := filepath.Join(root, "protected directory")
	if err := os.Mkdir(protected, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{
		`echo x > "` + protected + `\new"`,
		`python edit.py "` + protected + `\new"`,
		`cd "` + protected + `" && echo x > new`,
		`rm "` + protected + `\*"`,
	} {
		if !protectHit(t, "shell_command", "", map[string]interface{}{"command": cmd}, []string{protected}) {
			t.Errorf("native protected path allowed: %s", cmd)
		}
	}
	// Backslash remains a POSIX escape too: the native reading must not
	// replace the original reading and turn an existing denial into allow.
	posix := strings.ReplaceAll(filepath.ToSlash(protected), "protected", `pro\tected`)
	posix = strings.ReplaceAll(posix, " ", `\ `)
	if !protectHit(t, "shell_command", "", map[string]interface{}{"command": `echo x > ` + posix + `/new`}, []string{protected}) {
		t.Error("POSIX escaped protected path allowed")
	}
}

func TestProtectedWindowsShortPathAliases(t *testing.T) {
	long := filepath.Join(t.TempDir(), "protected-long-directory")
	if err := os.Mkdir(long, 0o700); err != nil {
		t.Fatal(err)
	}
	p, err := syscall.UTF16PtrFromString(long)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, 32768)
	n, err := syscall.GetShortPathName(p, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		t.Fatalf("GetShortPathName = %d, %v", n, err)
	}
	short := syscall.UTF16ToString(buf[:n])
	if strings.EqualFold(short, long) {
		t.Skip("file system has no short path alias")
	}
	for _, pair := range [][2]string{{short, long}, {long, short}} {
		for _, suffix := range []string{"", `\new\file`} {
			candidate := pair[0] + suffix
			if !protectHit(t, "write", "", map[string]interface{}{"file_path": candidate}, []string{pair[1]}) {
				t.Errorf("write alias %q bypasses %q", candidate, pair[1])
			}
			if !protectHit(t, "shell_command", "", map[string]interface{}{"command": `echo x > "` + candidate + `"`}, []string{pair[1]}) {
				t.Errorf("shell alias %q bypasses %q", candidate, pair[1])
			}
			if !strings.Contains(candidate, " ") && !protectHit(t, "shell_command", "", map[string]interface{}{"command": `echo x > ` + candidate}, []string{pair[1]}) {
				t.Errorf("unquoted shell alias %q bypasses %q", candidate, pair[1])
			}
		}
	}
}

func TestProtectedWindowsNativeHomeRetained(t *testing.T) {
	profile := t.TempDir()
	t.Setenv("USERPROFILE", profile)
	t.Setenv("HOME", t.TempDir())
	prefixes := []string{filepath.Join(profile, "protected")}
	for _, cmd := range []string{"echo x > ~/protected/new", "rm ~/protect*/new", "cd ~ && rm protected/new"} {
		if !protectHit(t, "shell_command", "", map[string]interface{}{"command": cmd}, prefixes) {
			t.Errorf("native home allowed: %s", cmd)
		}
	}
}
