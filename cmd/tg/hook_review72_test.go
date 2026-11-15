package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookReview72NullTypedFields(t *testing.T) {
	policy := writeHookPolicy(t, hookDenyPolicy)
	payloads := []string{
		`{"tool_name":"Bash","tool_input":{"command":null}}`,
		`{"tool_name":"Bash","tool_input":{"CommandLine":null}}`,
		`{"tool_name":"Write","tool_input":{"file_path":null}}`,
		`{"tool_name":"Write","tool_input":{"Content":null}}`,
		`{"tool_name":"Bash","tool_input":{"command":"ls","Cwd":null}}`,
		`{"tool_name":"Bash","tool_input":{"command":"ls","working_directory":null}}`,
		`{"tool_name":"Bash","cwd":null,"tool_input":{"command":"ls"}}`,
		`{"tool_name":"Bash","toolCall":null,"tool_input":{"command":"ls"}}`,
		`{"toolCall":{"name":"run_command","args":{"CommandLine":null}}}`,
		`{"tool_name":null,"tool_input":{}}`,
		`{"toolCall":{"name":null,"args":{}}}`,
	}
	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			out, _ := runHookStr(t, payload, "-policy", policy, "-fail-closed")
			if dec, _ := exampleDecision(t, out); dec != "deny" {
				t.Fatalf("null typed field must deny: %s", out)
			}
			out, _ = runHookStr(t, payload, "-policy", policy)
			if dec, _ := exampleDecision(t, out); dec != "allow" {
				t.Fatalf("default remains fail-open: %s", out)
			}
		})
	}
	for _, payload := range []string{`{"tool_name":"Bash","tool_input":{}}`, `{"tool_name":"Bash","tool_input":{"command":""}}`, `{"tool_name":"Write","tool_input":{"custom":null}}`} {
		out, _ := runHookStr(t, payload, "-policy", policy, "-fail-closed")
		if dec, _ := exampleDecision(t, out); dec != "allow" {
			t.Fatalf("absent, empty or untyped field changed: %s", out)
		}
	}
}

func TestExampleHookReview72StrictOutput(t *testing.T) {
	for harness, wrapper := range exampleWrappers {
		valid := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`
		misplaced := `{"permissionDecision":"allow"}`
		invalid := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"typo"}}`
		wrongEvent := `{"hookSpecificOutput":{"hookEventName":"PostToolUse","permissionDecision":"allow"}}`
		if harness == "antigravity" {
			valid = `{"decision":"allow"}`
			misplaced = `{"nested":{"decision":"allow"}}`
			invalid = `{"decision":"typo"}`
			wrongEvent = `{"decision":null}`
		}
		for name, output := range map[string]string{"prefix": "warning\n" + valid, "misplaced": misplaced, "invalid": invalid, "wrong shape": wrongEvent, "multiple": valid + "\n" + valid, "array": "[" + valid + "]", "invalid utf8": strings.TrimSuffix(valid, "}") + ",\"extra\":\"\xff\"}"} {
			t.Run(harness+"/"+name, func(t *testing.T) {
				stub := filepath.Join(t.TempDir(), "tg")
				// Output is supplied through an environment variable, never shell source.
				if err := os.WriteFile(stub, []byte("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' \"$STUB_OUTPUT\"\n"), 0o755); err != nil {
					t.Fatal(err)
				}
				out := runExampleHook(t, filepath.Join(exampleDir(t), "hooks", wrapper), t.TempDir(), "{}", "TG_BIN="+stub, "STUB_OUTPUT="+output)
				if dec, _ := exampleDecision(t, out); dec != "deny" {
					t.Fatalf("malformed stdout must deny: %s", out)
				}
			})
		}
		for _, number := range []string{"NaN", "Infinity", "-Infinity", "+1", "01", ".1"} {
			t.Run(harness+"/invalid number "+number, func(t *testing.T) {
				stub := filepath.Join(t.TempDir(), "tg")
				if err := os.WriteFile(stub, []byte("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' \"$STUB_OUTPUT\"\n"), 0o755); err != nil {
					t.Fatal(err)
				}
				output := strings.TrimSuffix(valid, "}") + `,"extra":` + number + "}"
				out := runExampleHook(t, filepath.Join(exampleDir(t), "hooks", wrapper), t.TempDir(), "{}", "TG_BIN="+stub, "STUB_OUTPUT="+output)
				if dec, _ := exampleDecision(t, out); dec != "deny" {
					t.Fatalf("invalid JSON number must deny: %s", out)
				}
			})
		}
	}
}

func TestInstallerReview72SafeCommandPaths(t *testing.T) {
	exampleHooksTg(t)
	source, err := os.ReadFile(filepath.Join(exampleDir(t), "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"repo;touch-marker", "repo(paren)", "repo&background", "repo`command`", "repo[glob]", "repo-safe_1.2"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), name)
			script := filepath.Join(root, "examples", "coding-agent-guard", "install.sh")
			if err := os.MkdirAll(filepath.Dir(script), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(root, "bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "bin", "tg"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(script, source, 0o755); err != nil {
				t.Fatal(err)
			}
			home := t.TempDir()
			cmd := exec.Command("bash", script, "claude")
			cmd.Env = installerEnv(t, home)
			output, err := cmd.CombinedOutput()
			safe := name == "repo-safe_1.2"
			if safe {
				if err != nil {
					t.Fatalf("safe path rejected: %v: %s", err, output)
				}
			} else {
				if err == nil {
					t.Errorf("unsafe command path accepted: %s", output)
				}
				if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); !os.IsNotExist(err) {
					t.Errorf("unsafe path wrote a config: %v", err)
				}
				if strings.Contains(string(output), "Done.") {
					t.Error("unsafe path reported success")
				}
			}
		})
	}
}

func TestExampleHookReview72MissingPythonFailsClosed(t *testing.T) {
	exampleHooksTg(t)
	bin := t.TempDir()
	for _, name := range []string{"bash", "dirname", "date", "mkdir", "cat"} {
		path, err := exec.LookPath(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(path, filepath.Join(bin, name)); err != nil {
			t.Fatal(err)
		}
	}
	stub := filepath.Join(bin, "tg")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{\"decision\":\"allow\",\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"allow\"}}'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for harness, wrapper := range exampleWrappers {
		out := runExampleHook(t, filepath.Join(exampleDir(t), "hooks", wrapper), t.TempDir(), "{}", "TG_BIN="+stub, "PATH="+bin)
		if dec, _ := exampleDecision(t, out); dec != "deny" {
			t.Fatalf("%s without python3 must deny: %s", harness, out)
		}
	}
}

func TestExampleHookReview72RawNULFailsClosed(t *testing.T) {
	for harness, wrapper := range exampleWrappers {
		t.Run(harness, func(t *testing.T) {
			stub := filepath.Join(t.TempDir(), "tg")
			if err := os.WriteFile(stub, []byte("#!/bin/sh\ncat >/dev/null\ncat \"$STUB_OUTPUT_FILE\"\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			output := `{"decision":"allow","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"},"extra":"` + "\x00" + `"}`
			fixture := filepath.Join(t.TempDir(), "stdout")
			if err := os.WriteFile(fixture, []byte(output), 0o600); err != nil {
				t.Fatal(err)
			}
			out := runExampleHook(t, filepath.Join(exampleDir(t), "hooks", wrapper), t.TempDir(), "{}", "TG_BIN="+stub, "STUB_OUTPUT_FILE="+fixture)
			if dec, _ := exampleDecision(t, out); dec != "deny" {
				t.Fatalf("raw NUL stdout must deny: %s", out)
			}
		})
	}
}

func TestInstallerReview72CleansPrivateScratch(t *testing.T) {
	exampleHooksTg(t)
	realCat, err := exec.LookPath("cat")
	if err != nil {
		t.Fatal(err)
	}
	realJQ, err := exec.LookPath("jq")
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"copy error", "HUP", "INT", "TERM"} {
		t.Run(failure, func(t *testing.T) {
			home := t.TempDir()
			config, _ := installerConfigFile(home, "claude")
			writeConfig(t, config, `{"private":"scratch-secret"}`)
			scratch := t.TempDir()
			stubs := t.TempDir()
			if failure == "copy error" {
				body := "#!/bin/sh\n\"$REAL_CAT\" \"$@\"\nexit 7\n"
				if err := os.WriteFile(filepath.Join(stubs, "cat"), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			} else {
				body := "#!/bin/sh\nif [ \"$1\" = -e ]; then exec \"$REAL_JQ\" \"$@\"; fi\nkill -\"$TEST_SIGNAL\" \"$PPID\"\nexit 99\n"
				if err := os.WriteFile(filepath.Join(stubs, "jq"), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", filepath.Join(exampleDir(t), "install.sh"), "claude")
			cmd.Env = append(installerEnv(t, home), "PATH="+stubs+":"+os.Getenv("PATH"), "TMPDIR="+scratch, "REAL_CAT="+realCat, "REAL_JQ="+realJQ, "TEST_SIGNAL="+failure)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("installer unexpectedly succeeded: %s", out)
			}
			entries, err := os.ReadDir(scratch)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("private scratch leaked after %s: %v", failure, entries)
			}
			current, err := os.ReadFile(config)
			if err != nil || string(current) != `{"private":"scratch-secret"}` {
				t.Fatalf("failure changed config: %q (%v)", current, err)
			}
		})
	}
}

func TestUninstallReview72CleansPrivateScratch(t *testing.T) {
	exampleHooksTg(t)
	for _, failure := range []string{"write error", "HUP", "INT", "TERM"} {
		t.Run(failure, func(t *testing.T) {
			home := t.TempDir()
			config, _ := installerConfigFile(home, "claude")
			writeConfig(t, config, `{"private":"scratch-secret","toolguard-coding-agent-guard":{}}`)
			scratch := t.TempDir()
			stubs := t.TempDir()
			if failure == "write error" {
				if err := os.WriteFile(filepath.Join(stubs, "cat"), []byte("#!/bin/sh\nexit 7\n"), 0o755); err != nil {
					t.Fatal(err)
				}
			} else {
				body := "#!/bin/sh\nprintf '%s\\n' private-scratch\nkill -\"$TEST_SIGNAL\" \"$PPID\"\nexit 99\n"
				if err := os.WriteFile(filepath.Join(stubs, "jq"), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", filepath.Join(exampleDir(t), "install.sh"), "--uninstall", "claude")
			cmd.Env = append(installerEnv(t, home), "PATH="+stubs+":"+os.Getenv("PATH"), "TMPDIR="+scratch, "TEST_SIGNAL="+failure)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("uninstaller unexpectedly succeeded: %s", out)
			}
			entries, err := os.ReadDir(scratch)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("private uninstall scratch leaked after %s: %v", failure, entries)
			}
		})
	}
}
