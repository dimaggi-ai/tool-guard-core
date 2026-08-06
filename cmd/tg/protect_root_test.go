package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

func TestResolveManagedRootPrefersEvidencedLegacyInstall(t *testing.T) {
	_, legacy := managedRootFixture(t)
	if err := os.MkdirAll(filepath.Join(legacy, "policies"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := resolveManagedRoot()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != filepath.Clean(legacy) {
		t.Fatalf("with an evidenced legacy install present root=%q, want legacy %q", got, legacy)
	}
}

func TestResolveManagedRootAuditDirIsLegacyEvidence(t *testing.T) {
	_, legacy := managedRootFixture(t)
	if err := os.MkdirAll(filepath.Join(legacy, "audit"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := resolveManagedRoot()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != filepath.Clean(legacy) {
		t.Fatalf("an audit/ dir alone must qualify as legacy evidence: root=%q, want %q", got, legacy)
	}
}

func TestResolveManagedRootIgnoresEmptyLegacyDir(t *testing.T) {
	native, legacy := managedRootFixture(t)
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := resolveManagedRoot()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != filepath.Clean(native) {
		t.Fatalf("an empty legacy dir is not install evidence and must not divert a fresh install: root=%q, want native %q", got, native)
	}
}

func TestResolveManagedRootNativeWinsOnceItExists(t *testing.T) {
	native, legacy := managedRootFixture(t)
	if err := os.MkdirAll(filepath.Join(legacy, "policies"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(native, 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := resolveManagedRoot()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != filepath.Clean(native) {
		t.Fatalf("with both roots present root=%q, want native %q", got, native)
	}
}

func TestResolveManagedRootNoNativeNoEvidenceErrors(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("os.UserConfigDir cannot be forced to fail via env on darwin while HOME is set")
	}
	managedRootFixture(t)
	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", "")
	} else {
		// A relative XDG_CONFIG_HOME makes os.UserConfigDir error on POSIX.
		t.Setenv("XDG_CONFIG_HOME", "relative/xdg")
	}
	if _, err := resolveManagedRoot(); err == nil {
		t.Fatal("an unresolvable platform root with no evidenced legacy install must error, not silently pick a fresh legacy location")
	}
}

func TestResolveManagedRootFallsBackToEvidencedLegacyWhenNativeUnresolvable(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("os.UserConfigDir cannot be forced to fail via env on darwin while HOME is set")
	}
	_, legacy := managedRootFixture(t)
	if err := os.MkdirAll(filepath.Join(legacy, "policies"), 0o700); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		t.Setenv("APPDATA", "")
	} else {
		t.Setenv("XDG_CONFIG_HOME", "relative/xdg")
	}
	got, err := resolveManagedRoot()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(got) != filepath.Clean(legacy) {
		t.Fatalf("unresolvable platform root must fall back to the evidenced legacy install: root=%q, want %q", got, legacy)
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

// TestReprotectPinsRecordedInstall reproduces the root-migration hazard: an
// install whose defaults resolved to the legacy root must keep its recorded
// policy and audit paths on a later default re-protect even after the native
// root comes into existence — otherwise re-protect would abandon a customized
// policy and start a fresh audit chain.
func TestReprotectPinsRecordedInstall(t *testing.T) {
	native, legacy := managedRootFixture(t)
	if err := os.MkdirAll(filepath.Join(legacy, "policies"), 0o700); err != nil {
		t.Fatal(err)
	}
	home := os.Getenv("HOME")
	config := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(config), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tgPath := writeFakeTG(t, home)

	var out, errOut bytes.Buffer
	if code := runProtect([]string{"claude", "-apply", "-config", config, "-tg", tgPath}, &out, &errOut); code != 0 {
		t.Fatalf("first apply code=%d stderr=%s", code, errOut.String())
	}
	first, err := loadProtectState(config + ".tool-guard-state.json")
	if err != nil {
		t.Fatal(err)
	}
	assertUnderRoot(t, legacy, first.PolicyPath)
	assertUnderRoot(t, legacy, first.AuditPath)

	// The native root appearing later must not move the install.
	if err := os.MkdirAll(native, 0o700); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	if code := runProtect([]string{"claude", "-apply", "-config", config, "-tg", tgPath}, &out, &errOut); code != 0 {
		t.Fatalf("re-protect code=%d stderr=%s", code, errOut.String())
	}
	second, err := loadProtectState(config + ".tool-guard-state.json")
	if err != nil {
		t.Fatal(err)
	}
	if second.PolicyPath != first.PolicyPath || second.AuditPath != first.AuditPath {
		t.Fatalf("re-protect moved the install:\nfirst  policy=%q audit=%q\nsecond policy=%q audit=%q",
			first.PolicyPath, first.AuditPath, second.PolicyPath, second.AuditPath)
	}
}

// TestStatusAndUnprotectWorkWithoutHome pins that an explicit -config keeps
// status and unprotect working when HOME/USERPROFILE are unset but the
// platform config root is resolvable — they only need the config-adjacent
// state and its recorded absolute paths.
func TestStatusAndUnprotectWorkWithoutHome(t *testing.T) {
	managedRootFixture(t)
	home := os.Getenv("HOME")
	config := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(config), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tgPath := writeFakeTG(t, home)
	var out, errOut bytes.Buffer
	if code := runProtect([]string{"claude", "-apply", "-config", config, "-tg", tgPath}, &out, &errOut); code != 0 {
		t.Fatalf("apply code=%d stderr=%s", code, errOut.String())
	}

	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("HOMEDRIVE", "")
	t.Setenv("HOMEPATH", "")

	out.Reset()
	errOut.Reset()
	if code := runProtectStatus([]string{"claude", "-config", config}, &out, &errOut); code != 0 {
		t.Fatalf("status without home code=%d stdout=%s stderr=%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), `"protected":true`) {
		t.Fatalf("unexpected status without home: %s", out.String())
	}

	out.Reset()
	errOut.Reset()
	if code := runUnprotect([]string{"claude", "-apply", "-config", config}, &out, &errOut); code != 0 {
		t.Fatalf("unprotect without home code=%d stdout=%s stderr=%s", code, out.String(), errOut.String())
	}
}

func assertUnderRoot(t *testing.T, root, path string) {
	t.Helper()
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		t.Fatalf("path %q is not inside %q (rel=%q err=%v)", path, root, rel, err)
	}
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
