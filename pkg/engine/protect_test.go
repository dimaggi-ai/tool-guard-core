package engine

import (
	"encoding/json"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// envWrite builds an ActionEnvelope for a file-write-capable tool
// targeting the given file_path.
func envWrite(tool, filePath string) *domain.ActionEnvelope {
	params, _ := json.Marshal(map[string]string{"file_path": filePath})
	return &domain.ActionEnvelope{
		EnvelopeID: "test-env",
		AgentID:    "test-agent",
		ToolName:   tool,
		Parameters: params,
	}
}

// envCmd builds an ActionEnvelope for a shell tool executing cmd.
func envCmd(tool, cmd string) *domain.ActionEnvelope {
	params, _ := json.Marshal(map[string]string{"command": cmd})
	return &domain.ActionEnvelope{
		EnvelopeID: "test-env",
		AgentID:    "test-agent",
		ToolName:   tool,
		Parameters: params,
	}
}

// prefixes used across all subtests.
var testPrefixes = []string{"/protected"}

// ── A1: write-capable file tools targeting a protected prefix ──────────────

func TestViolatesProtectedPaths_WriteToolsViolate(t *testing.T) {
	writableTools := []string{"write", "edit", "notebookedit", "multiedit", "create"}
	for _, tool := range writableTools {
		t.Run(tool, func(t *testing.T) {
			env := envWrite(tool, "/protected/secret.yaml")
			if hit, reason := ViolatesProtectedPaths(env, testPrefixes); !hit {
				t.Errorf("tool %q targeting /protected/secret.yaml: expected violation, got none (reason=%q)", tool, reason)
			}
		})
	}
}

func TestViolatesProtectedPaths_WriteToolBenignPath(t *testing.T) {
	env := envWrite("write", "/tmp/scratch.txt")
	if hit, _ := ViolatesProtectedPaths(env, testPrefixes); hit {
		t.Error("write to /tmp/scratch.txt should not violate /protected prefix")
	}
}

// ── A2: read-only tools — even on a protected path must NOT violate ─────────

func TestViolatesProtectedPaths_ReadOnlyToolsDoNotViolate(t *testing.T) {
	// Known-safe read-only tool names (see isFileWriteTool exclusion list).
	readTools := []string{"read", "readfile", "read_file", "glob", "grep", "ls",
		"list", "cat", "view", "search", "get", "fetch", "webfetch", "websearch"}
	for _, tool := range readTools {
		t.Run(tool, func(t *testing.T) {
			env := envWrite(tool, "/protected/policy.yaml")
			if hit, _ := ViolatesProtectedPaths(env, testPrefixes); hit {
				t.Errorf("read-only tool %q targeting /protected/policy.yaml must NOT violate — reading the policy dir is legitimate", tool)
			}
		})
	}
}

// ── A3: path canonicalization bypasses that MUST still be caught ───────────
//
// All inputs clean to a path under /protected, so every case must fire.
// filepath.Clean is applied to both the path and the prefix before matching.

func TestViolatesProtectedPaths_CanonicalBypass(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{
			name: "dotdot traversal to same prefix",
			path: "/protected/../protected/secret",
		},
		{
			name: "dot component",
			path: "/protected/./x",
		},
		{
			name: "double slash",
			path: "/protected//x",
		},
		{
			name: "trailing slash on path",
			path: "/protected/x/",
		},
		{
			name: "exact match equals prefix",
			path: "/protected",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := envWrite("write", tc.path)
			if hit, _ := ViolatesProtectedPaths(env, testPrefixes); !hit {
				t.Errorf("path %q must be caught as targeting /protected after Clean — bypass possible", tc.path)
			}
		})
	}
}

// Adjacent path /protectedx must NOT match /protected (component-boundary rule).
func TestViolatesProtectedPaths_NoBoundaryFalsePositive(t *testing.T) {
	env := envWrite("write", "/protectedx/file")
	if hit, _ := ViolatesProtectedPaths(env, testPrefixes); hit {
		t.Error("/protectedx/file must NOT match prefix /protected — requires component boundary")
	}
}

// ── A4: empty prefix list — fast no-op ────────────────────────────────────

func TestViolatesProtectedPaths_EmptyPrefixes(t *testing.T) {
	cases := []struct {
		name     string
		prefixes []string
	}{
		{"nil prefixes", nil},
		{"empty slice", []string{}},
		{"slice of blanks", []string{"", "  "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := envWrite("write", "/protected/anything")
			if hit, _ := ViolatesProtectedPaths(env, tc.prefixes); hit {
				t.Error("empty prefix list must never violate — ViolatesProtectedPaths is a no-op when no paths are configured")
			}
		})
	}
}

// nil envelope guard.
func TestViolatesProtectedPaths_NilEnvelope(t *testing.T) {
	if hit, _ := ViolatesProtectedPaths(nil, testPrefixes); hit {
		t.Error("nil envelope must not panic or violate")
	}
}

// ── A5: shell best-effort heuristics ──────────────────────────────────────
//
// The best-effort shell scanner catches the obvious write-to-protected
// shapes below.  See the "known uncaught" comment for the shapes the
// scanner deliberately does NOT parse (quoting, variable expansion,
// command substitution).

func TestViolatesProtectedPaths_ShellWrite(t *testing.T) {
	// (a) Shell redirection: echo … > /protected/f
	t.Run("echo redirect", func(t *testing.T) {
		env := envCmd("bash", "echo x > /protected/f")
		if hit, _ := ViolatesProtectedPaths(env, testPrefixes); !hit {
			t.Error("echo x > /protected/f must be caught via redirect target")
		}
	})

	// (b) Append redirect: >> is handled the same as >
	t.Run("append redirect", func(t *testing.T) {
		env := envCmd("bash", "printf '%s\n' stuff >> /protected/policy.yaml")
		if hit, _ := ViolatesProtectedPaths(env, testPrefixes); !hit {
			t.Error(">> /protected/policy.yaml must be caught via redirect target")
		}
	})

	// (c) rm /protected/f
	t.Run("rm", func(t *testing.T) {
		env := envCmd("bash", "rm /protected/f")
		if hit, _ := ViolatesProtectedPaths(env, testPrefixes); !hit {
			t.Error("rm /protected/f must be caught (rm is in mutatingProgs)")
		}
	})

	// (d) sed -i — in-place edit
	t.Run("sed -i", func(t *testing.T) {
		env := envCmd("bash", "sed -i s/old/new/ /protected/f")
		if hit, _ := ViolatesProtectedPaths(env, testPrefixes); !hit {
			t.Error("sed -i … /protected/f must be caught")
		}
	})

	// (e) tee to protected path
	t.Run("tee", func(t *testing.T) {
		env := envCmd("bash", "tee /protected/f")
		if hit, _ := ViolatesProtectedPaths(env, testPrefixes); !hit {
			t.Error("tee /protected/f must be caught (tee is in mutatingProgs)")
		}
	})

	// (f) dd of=/protected/f
	t.Run("dd of=", func(t *testing.T) {
		env := envCmd("bash", "dd if=/dev/urandom of=/protected/f bs=512 count=1")
		if hit, _ := ViolatesProtectedPaths(env, testPrefixes); !hit {
			t.Error("dd of=/protected/f must be caught via the of= special-case")
		}
	})

	// (g) tee as second segment of a pipeline — confirms segment splitting.
	t.Run("pipeline tee", func(t *testing.T) {
		env := envCmd("bash", "cat /dev/stdin | tee /protected/policy.yaml")
		if hit, _ := ViolatesProtectedPaths(env, testPrefixes); !hit {
			t.Error("… | tee /protected/policy.yaml must be caught after pipeline split")
		}
	})
}

func TestViolatesProtectedPaths_ShellReadOnly(t *testing.T) {
	// cat touching a protected path must NOT fire — cat is a read.
	// (Not in mutatingProgs; no write redirect.)
	t.Run("cat protected", func(t *testing.T) {
		env := envCmd("bash", "cat /protected/policy.yaml")
		if hit, _ := ViolatesProtectedPaths(env, testPrefixes); hit {
			t.Error("cat /protected/policy.yaml must NOT violate — reading is allowed")
		}
	})

	// A write to an unprotected path must not fire.
	t.Run("rm unprotected", func(t *testing.T) {
		env := envCmd("bash", "rm /tmp/scratch.txt")
		if hit, _ := ViolatesProtectedPaths(env, testPrefixes); hit {
			t.Error("rm /tmp/scratch.txt must NOT violate /protected prefix")
		}
	})

	// echo redirect to an unprotected path.
	t.Run("echo redirect unprotected", func(t *testing.T) {
		env := envCmd("bash", "echo hello > /tmp/out.txt")
		if hit, _ := ViolatesProtectedPaths(env, testPrefixes); hit {
			t.Error("echo … > /tmp/out.txt must NOT violate /protected prefix")
		}
	})
}

// ── A6: expansions the v0.5.0 tokenizer now FAILS CLOSED on ────────────────
//
// This block previously documented these shapes as "known uncaught": the old
// best-effort scanner resolved neither quoting, variable expansion, nor command
// substitution, so a determined agent could evade it, and this test merely
// LOGGED the misses without asserting them. The real shell tokenizer
// (shell_tokenize.go) changes the contract: it cannot evaluate an expansion
// offline, so a redirect target or mutating-command argument built from one is
// marked unresolved and FAILS CLOSED (reported as a hit) instead of silently
// passing; concatenated quoting is resolved outright because adjacent
// quoted/unquoted pieces now form a single word. The three cases the old
// comment admitted to are therefore asserted here as now-caught. (Expectations
// updated per the tokenizer rework — the old code was encoding false negatives.)
func TestViolatesProtectedPaths_FormerlyUncaughtNowFailClosed(t *testing.T) {
	cases := map[string]string{
		// 1. Variable expansion — old scanner left $POLICY_DIR unresolved and
		//    missed it; now the unresolved arg to rm fails closed.
		"variable expansion": "rm $POLICY_DIR/rules.yaml",
		// 2. Command substitution — old scanner did not parse $(...); now the
		//    unresolved `dd of=` target fails closed.
		"command substitution": `dd of=$(echo /protected/f)`,
		// 3. Concatenated quoting — old unquote() stripped only one outer pair
		//    and mangled the path; the tokenizer concatenates the pieces to the
		//    real /protected/f and catches it outright.
		"concatenated quoting": "rm '/prot'ected/f",
	}
	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			env := envCmd("bash", cmd)
			if hit, reason := ViolatesProtectedPaths(env, testPrefixes); !hit {
				t.Errorf("%q must now be caught or fail closed under the tokenizer; got no violation (reason=%q)", cmd, reason)
			}
		})
	}
}

// ── A7: path tool that uses "path" key instead of "file_path" ─────────────

func TestViolatesProtectedPaths_PathKeyAlias(t *testing.T) {
	// Some tools (e.g. "create") use "path" instead of "file_path".
	params, _ := json.Marshal(map[string]string{"path": "/protected/new.txt"})
	env := &domain.ActionEnvelope{
		ToolName:   "create",
		Parameters: params,
	}
	if hit, _ := ViolatesProtectedPaths(env, testPrefixes); !hit {
		t.Error(`"path" key should also be checked alongside "file_path"`)
	}
}
