package main

// TestHookConformance runs raw hook payloads through the REAL hook path:
// stdin parsing, harness dialect decoding, tool grouping, parameter
// canonicalisation, protected-path checks, policy evaluation and decision
// serialisation. It exists because the engine-level conformance corpus feeds
// a pre-resolved envelope and therefore cannot see a defect in any of those
// stages — measured 2026-11-09, four such defects were invisible to it.
//
// Cases live in testdata/hookconformance/. A case whose "capture.captured_from"
// is "real install" was captured from an actual harness run on the host, with
// the harness and version recorded in the case. Synthetic cases say so.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type hookCase struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	Harness        string `json:"harness"`
	HarnessVersion string `json:"harness_version"`
	Capture        struct {
		CapturedFrom string `json:"captured_from"`
		CapturedOn   string `json:"captured_on"`
		Sanitisation string `json:"sanitisation"`
	} `json:"capture"`
	Payload  json.RawMessage `json:"payload"`
	HookArgs []string        `json:"hook_args"`
	// OutputDialect is the contract the harness reads. Empty means the
	// Claude/Codex hookSpecificOutput shape.
	OutputDialect string `json:"output_dialect"`
	Expect        struct {
		Decision string `json:"decision"`
		Cites    string `json:"cites"`
	} `json:"expect"`
}

func loadHookCases(t *testing.T) []hookCase {
	t.Helper()
	dir := filepath.Join("..", "..", "testdata", "hookconformance")
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no hook conformance cases found in %s (err %v)", dir, err)
	}
	var cases []hookCase
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var c hookCase
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatalf("decode %s: %v", f, err)
		}
		if c.Name == "" || len(c.Payload) == 0 || c.Expect.Decision == "" {
			t.Fatalf("%s: name, payload and expect.decision are required", f)
		}
		cases = append(cases, c)
	}
	return cases
}

func TestHookConformance(t *testing.T) {
	for _, c := range loadHookCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			args := make([]string, 0, len(c.HookArgs))
			for _, a := range c.HookArgs {
				if a == "POLICIES" {
					args = append(args, filepath.Join("..", "..", "policies"))
					continue
				}
				args = append(args, a)
			}
			var buf bytes.Buffer
			code := runHook(args, strings.NewReader(string(c.Payload)), &buf)
			out := buf.String()
			if code != 0 {
				t.Fatalf("hook must always exit 0, got %d; output=%s", code, out)
			}
			dec, reason := hookDecisionReason(t, out)
			if c.OutputDialect == "antigravity" {
				var agy struct {
					Decision string `json:"decision"`
					Reason   string `json:"reason"`
				}
				if err := json.Unmarshal([]byte(out), &agy); err != nil {
					t.Fatalf("antigravity dialect must emit a top-level {decision,reason} object: %v; output=%s", err, out)
				}
				dec, reason = agy.Decision, agy.Reason
			}
			if dec != c.Expect.Decision {
				t.Errorf("decision = %q, want %q; harness=%s %s; output=%s",
					dec, c.Expect.Decision, c.Harness, c.HarnessVersion, out)
			}
			if c.Expect.Cites != "" && !strings.Contains(reason, c.Expect.Cites) {
				t.Errorf("expected the decision to cite %q, got reason=%q", c.Expect.Cites, reason)
			}
		})
	}
}

// TestHookConformanceRealCaptureProvenance keeps the support claim honest: a
// case may only assert "real install" provenance if it names a harness and a
// version. A case that cannot say which harness and version it came from is
// synthetic and must say so.
func TestHookConformanceRealCaptureProvenance(t *testing.T) {
	for _, c := range loadHookCases(t) {
		switch c.Capture.CapturedFrom {
		case "real install":
			if c.Harness == "" || c.Harness == "none" || c.HarnessVersion == "" || c.HarnessVersion == "n/a" {
				t.Errorf("%s claims real-install provenance but names harness=%q version=%q", c.Name, c.Harness, c.HarnessVersion)
			}
			if c.Capture.CapturedOn == "" || c.Capture.Sanitisation == "" {
				t.Errorf("%s claims real-install provenance but omits the capture date or the sanitisation note", c.Name)
			}
		case "synthetic", "captured shape":
			// allowed; the support matrix must not count these as verified
		default:
			t.Errorf("%s has capture.captured_from=%q, which must be one of: real install, captured shape, synthetic", c.Name, c.Capture.CapturedFrom)
		}
	}
}
