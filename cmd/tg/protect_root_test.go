package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// managedRootFixture points HOME and every platform config-root variable at a
// fresh temp dir and returns the native and legacy roots the code under test
// must choose between. XDG_CONFIG_HOME deliberately points at a NON-default
// subdirectory ("xdg-config", not ".config"), so a passing test proves the
// platform config-directory API is honored rather than a hardcoded ~/.config
// happening to coincide with it. On every supported OS the fixture makes the
// native root differ from the legacy root, or fails loudly.
func managedRootFixture(t *testing.T) (native, legacy string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	cfg, err := os.UserConfigDir()
	if err != nil {
		t.Fatalf("os.UserConfigDir: %v", err)
	}
	native = filepath.Join(cfg, "tool-guard")
	legacy = filepath.Join(home, ".config", "tool-guard")
	if filepath.Clean(native) == filepath.Clean(legacy) {
		t.Fatal("fixture must make the native root differ from the legacy root")
	}
	return native, legacy
}

func TestResolveManagedRootFreshInstallUsesNativeRoot(t *testing.T) {
	native, _ := managedRootFixture(t)
	got, err := resolveManagedRoot()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != filepath.Clean(native) {
		t.Fatalf("fresh install root=%q, want native %q", got, native)
	}
}

func TestResolveManagedRootPrefersExistingLegacyInstall(t *testing.T) {
	_, legacy := managedRootFixture(t)
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := resolveManagedRoot()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != filepath.Clean(legacy) {
		t.Fatalf("with only a legacy install present root=%q, want legacy %q", got, legacy)
	}
}

func TestResolveManagedRootNativeWinsOnceItExists(t *testing.T) {
	native, legacy := managedRootFixture(t)
	for _, dir := range []string{native, legacy} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	got, err := resolveManagedRoot()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != filepath.Clean(native) {
		t.Fatalf("with both roots present root=%q, want native %q", got, native)
	}
}

func TestResolveManagedRootIgnoresLegacyFileImpostor(t *testing.T) {
	native, legacy := managedRootFixture(t)
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveManagedRoot()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != filepath.Clean(native) {
		t.Fatalf("legacy path that is a plain file must be ignored: root=%q, want native %q", got, native)
	}
}

func writeFakeTG(t *testing.T, home string) string {
	t.Helper()
	name := "tg"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(home, "bin", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestResolveProtectPathsDefaultsUnderManagedRoot pins the default policy and
// audit locations to the resolved managed root for both the fresh-install
// (native) and legacy-discovery cases.
func TestResolveProtectPathsDefaultsUnderManagedRoot(t *testing.T) {
	cases := []struct {
		name       string
		makeLegacy bool
		wantLegacy bool
	}{
		{name: "fresh install uses native root", makeLegacy: false, wantLegacy: false},
		{name: "existing legacy install stays discoverable", makeLegacy: true, wantLegacy: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			native, legacy := managedRootFixture(t)
			if tc.makeLegacy {
				if err := os.MkdirAll(filepath.Join(legacy, "policies"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			home := os.Getenv("HOME")
			tgPath := writeFakeTG(t, home)
			p, defaulted, err := resolveProtectPaths("", "", tgPath)
			if err != nil {
				t.Fatal(err)
			}
			if !defaulted {
				t.Fatal("expected the default policy path to be reported as defaulted")
			}
			root := native
			if tc.wantLegacy {
				root = legacy
			}
			wantPolicy := filepath.Join(root, "policies", "coding-agent-baseline.yaml")
			wantAudit := filepath.Join(root, "audit", "claude.jsonl")
			if filepath.Clean(p.policy) != filepath.Clean(wantPolicy) {
				t.Fatalf("default policy=%q, want %q", p.policy, wantPolicy)
			}
			if filepath.Clean(p.audit) != filepath.Clean(wantAudit) {
				t.Fatalf("default audit=%q, want %q", p.audit, wantAudit)
			}
		})
	}
}
