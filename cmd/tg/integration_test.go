//go:build integration

// Integration tests for the tg CLI. Builds the binary once in TestMain
// and then drives real `./tg <verb>` invocations through os/exec,
// asserting the documented exit-code contract, stdout JSON shape, and
// stderr error prefixes.
//
// Run with: go test -tags=integration ./cmd/tg/...
//
// Skipped by default because the build-then-exec pattern is heavier
// than a unit test; CI runs them via `make integration`.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

var tgBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "tg-integration-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mkdir tmp:", err)
		os.Exit(2)
	}
	defer os.RemoveAll(dir)

	tgBinary = filepath.Join(dir, "tg")
	build := exec.Command("go", "build", "-o", tgBinary, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "build tg:", err)
		os.Exit(2)
	}

	os.Exit(m.Run())
}

// exitCode runs tg with the given arguments and returns its exit code +
// captured stdout/stderr. The test owns the temp dir; this helper does
// not create files.
func exitCode(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(tgBinary, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	stdout = out.String()
	stderr = errb.String()
	if err == nil {
		return 0, stdout, stderr
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), stdout, stderr
	}
	t.Fatalf("tg %v: non-exit error: %v", args, err)
	return -1, stdout, stderr
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// ── tg evaluate ────────────────────────────────────────────────────────────

const policyDenyOver500 = `policy_id: pol-int
name: int-test-refund-cap
version: 1
status: approved
mode: enforcement
scope:
  tool_names: [issue_refund]
  tool_groups: [monetary_outflow]
rules:
  - rule_id: r1
    name: cap
    conditions: {field: amount, operator: gt, value: 500}
    effect: deny
    citation: {document_id: D, excerpt: X}
`

const callUnder = `{"agent_id":"a","session_id":"s","org_id":"o","tool_name":"issue_refund","tool_group":"monetary_outflow","parameters":{"amount":100}}`
const callOver = `{"agent_id":"a","session_id":"s","org_id":"o","tool_name":"issue_refund","tool_group":"monetary_outflow","parameters":{"amount":1000}}`

func TestIntegration_EvaluateExitCodes(t *testing.T) {
	dir := t.TempDir()
	pol := writeFile(t, dir, "policy.yaml", policyDenyOver500)
	under := writeFile(t, dir, "under.json", callUnder)
	over := writeFile(t, dir, "over.json", callOver)

	t.Run("under cap → exit 0 (allow)", func(t *testing.T) {
		code, stdout, _ := exitCode(t, "evaluate", "-policy", pol, "-call", under)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; stdout=%s", code, stdout)
		}
		if !strings.Contains(stdout, `"decision":"allowed"`) {
			t.Errorf("stdout missing allowed decision: %s", stdout)
		}
	})

	t.Run("over cap → exit 3 (deny)", func(t *testing.T) {
		code, stdout, _ := exitCode(t, "evaluate", "-policy", pol, "-call", over)
		if code != 3 {
			t.Fatalf("exit = %d, want 3; stdout=%s", code, stdout)
		}
		if !strings.Contains(stdout, `"decision":"denied"`) {
			t.Errorf("stdout missing denied decision: %s", stdout)
		}
	})

	t.Run("over cap in shadow mode → exit 0 (allowed_shadow) when policy YAML also says shadow", func(t *testing.T) {
		// Engine semantic: the effective mode is the STRICTEST of the
		// call-site mode and every matched policy's mode (engine.Evaluate
		// step 3). So a policy marked enforcement in YAML cannot be
		// dropped to shadow by passing -mode shadow on the CLI — that's
		// intentional (policy authors govern the floor). To observe
		// shadow behaviour the policy itself must opt into it.
		shadowPolicy := strings.Replace(policyDenyOver500, "mode: enforcement", "mode: shadow", 1)
		sp := writeFile(t, dir, "policy_shadow.yaml", shadowPolicy)
		code, stdout, _ := exitCode(t, "evaluate", "-policy", sp, "-call", over, "-mode", "shadow")
		if code != 0 {
			t.Fatalf("shadow must exit 0 even on would-deny; got %d, stdout=%s", code, stdout)
		}
		if !strings.Contains(stdout, `"action_taken":"allowed_shadow"`) {
			t.Errorf("stdout missing allowed_shadow action: %s", stdout)
		}
	})

	t.Run("strictest-mode semantic: policy=enforcement + -mode shadow → still exit 3", func(t *testing.T) {
		// This pins the engine's "strictest mode wins" contract so any
		// future refactor that quietly drops it fails the build.
		code, stdout, _ := exitCode(t, "evaluate", "-policy", pol, "-call", over, "-mode", "shadow")
		if code != 3 {
			t.Fatalf("enforcement-marked policy must still deny under CLI -mode shadow; got %d, stdout=%s", code, stdout)
		}
	})

	t.Run("missing -policy → exit 2 (usage error)", func(t *testing.T) {
		code, _, stderr := exitCode(t, "evaluate", "-call", under)
		if code != 2 {
			t.Errorf("exit = %d, want 2; stderr=%s", code, stderr)
		}
		if !strings.Contains(stderr, "evaluate:") {
			t.Errorf("expected verb-prefixed stderr; got: %s", stderr)
		}
	})

	t.Run("nonexistent policy file → exit 1 (internal error)", func(t *testing.T) {
		code, _, stderr := exitCode(t, "evaluate", "-policy", filepath.Join(dir, "no-such.yaml"), "-call", under)
		if code != 1 {
			t.Errorf("exit = %d, want 1; stderr=%s", code, stderr)
		}
	})
}

// ── tg verify ──────────────────────────────────────────────────────────────

func TestIntegration_VerifyExitCodes(t *testing.T) {
	dir := t.TempDir()

	// Build an intact chain through the OSS audit package and a tampered
	// copy. Using the audit package directly here keeps the integration
	// test self-contained (no separate fixture file to maintain).
	intactPath, tamperedPath := writeIntactAndTamperedChain(t, dir)

	t.Run("intact chain → exit 0", func(t *testing.T) {
		code, stdout, stderr := exitCode(t, "verify", "-file", intactPath)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; stderr=%s", code, stderr)
		}
		if !strings.Contains(stdout, `"intact": true`) {
			t.Errorf("stdout missing intact:true: %s", stdout)
		}
	})

	t.Run("tampered chain → exit 5", func(t *testing.T) {
		code, stdout, _ := exitCode(t, "verify", "-file", tamperedPath)
		if code != 5 {
			t.Fatalf("exit = %d, want 5; stdout=%s", code, stdout)
		}
		if !strings.Contains(stdout, `"intact": false`) {
			t.Errorf("stdout missing intact:false: %s", stdout)
		}
	})

	t.Run("missing file → exit 1", func(t *testing.T) {
		code, _, _ := exitCode(t, "verify", "-file", filepath.Join(dir, "no-such.jsonl"))
		if code != 1 {
			t.Errorf("exit = %d, want 1", code)
		}
	})
}

// writeIntactAndTamperedChain constructs a real 3-trace chain through
// pkg/audit's canonical hasher, writes it as JSONL, and returns paths
// to (intact, tampered). The tampered file flips one byte of one
// TraceHash so streaming verification reports intact=false.
func writeIntactAndTamperedChain(t *testing.T, dir string) (intactPath, tamperedPath string) {
	t.Helper()
	ts := time.Now().UTC().Truncate(time.Microsecond)
	mk := func(traceID, envelopeID, prev string, at time.Time) domain.DecisionTrace {
		tr := domain.DecisionTrace{
			TraceID:           traceID,
			EnvelopeID:        envelopeID,
			Timestamp:         at,
			Decision:          domain.DecisionAllowed,
			ActionTaken:       domain.ActionAllowed,
			PreviousTraceHash: prev,
		}
		h, err := audit.ComputeCanonicalTraceHash(&tr)
		if err != nil {
			t.Fatalf("canonical hash: %v", err)
		}
		tr.TraceHash = h
		return tr
	}
	t1 := mk("t1", "e1", "", ts)
	t2 := mk("t2", "e2", t1.TraceHash, ts.Add(time.Second))
	t3 := mk("t3", "e3", t2.TraceHash, ts.Add(2*time.Second))

	jsonl := func(traces []domain.DecisionTrace) []byte {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		for _, tr := range traces {
			if err := enc.Encode(tr); err != nil {
				t.Fatalf("encode: %v", err)
			}
		}
		return buf.Bytes()
	}

	intactPath = filepath.Join(dir, "intact.jsonl")
	if err := os.WriteFile(intactPath, jsonl([]domain.DecisionTrace{t1, t2, t3}), 0o644); err != nil {
		t.Fatalf("write intact: %v", err)
	}

	// Flip the last character of t2.TraceHash so the canonical
	// recomputation in pkg/audit.VerifyChainFromReader will mismatch.
	tampered := t2
	last := len(tampered.TraceHash) - 1
	if last < 0 {
		t.Fatal("trace hash is empty; cannot tamper")
	}
	switch tampered.TraceHash[last] {
	case 'a':
		tampered.TraceHash = tampered.TraceHash[:last] + "b"
	default:
		tampered.TraceHash = tampered.TraceHash[:last] + "a"
	}
	tamperedPath = filepath.Join(dir, "tampered.jsonl")
	if err := os.WriteFile(tamperedPath, jsonl([]domain.DecisionTrace{t1, tampered, t3}), 0o644); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	return intactPath, tamperedPath
}

// ── tg lint ────────────────────────────────────────────────────────────────

const policyClean = `policy_id: pol-clean
name: clean-policy
version: 1
status: approved
mode: enforcement
scope:
  tool_names: [issue_refund]
  tool_groups: [monetary_outflow]
rules:
  - rule_id: r1
    name: cap
    conditions: {field: context.verified.customer_tier, operator: eq, value: gold}
    effect: flag
    citation: {document_id: D, excerpt: X}
`

const policyError = `policy_id: pol-bad
name: bad
version: 1
status: approved
mode: enforcement
scope: {tool_names: [issue_refund], tool_groups: [monetary_outflow]}
rules:
  - rule_id: dup
    conditions: {field: amount, operator: gt, value: 500}
    effect: deny
    citation: {document_id: D, excerpt: X}
  - rule_id: dup
    conditions: {field: amount, operator: gt, value: 1000}
    effect: deny
    citation: {document_id: D, excerpt: X}
`

func TestIntegration_LintExitCodes(t *testing.T) {
	dir := t.TempDir()

	t.Run("clean policy → exit 0", func(t *testing.T) {
		p := writeFile(t, dir, "clean.yaml", policyClean)
		code, stdout, stderr := exitCode(t, "lint", "-policy", p)
		if code != 0 {
			t.Fatalf("exit = %d, want 0; stderr=%s", code, stderr)
		}
		// Should emit a valid JSON array (possibly with warnings, no errors).
		var findings []map[string]any
		if err := json.Unmarshal([]byte(stdout), &findings); err != nil {
			t.Fatalf("lint output not valid JSON array: %v\n%s", err, stdout)
		}
		for _, f := range findings {
			if f["severity"] == "error" {
				t.Errorf("clean policy returned error finding: %v", f)
			}
		}
	})

	t.Run("policy with error-severity finding → exit 6", func(t *testing.T) {
		p := writeFile(t, dir, "bad.yaml", policyError)
		code, stdout, _ := exitCode(t, "lint", "-policy", p)
		if code != 6 {
			t.Fatalf("exit = %d, want 6; stdout=%s", code, stdout)
		}
		if !strings.Contains(stdout, "rule-id-collision") {
			t.Errorf("expected rule-id-collision finding; got: %s", stdout)
		}
	})
}

// ── tg benchmark ───────────────────────────────────────────────────────────

func TestIntegration_BenchmarkJSONShape(t *testing.T) {
	code, stdout, stderr := exitCode(t, "benchmark", "-trials", "500")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr=%s", code, stderr)
	}
	var bench struct {
		Trials int   `json:"trials"`
		P50us  int64 `json:"p50_us"`
		P95us  int64 `json:"p95_us"`
		P99us  int64 `json:"p99_us"`
		MaxUs  int64 `json:"max_us"`
	}
	if err := json.Unmarshal([]byte(stdout), &bench); err != nil {
		t.Fatalf("benchmark output not valid JSON: %v\n%s", err, stdout)
	}
	if bench.Trials != 500 {
		t.Errorf("Trials = %d, want 500", bench.Trials)
	}
	// Sanity: percentiles should be monotonic.
	if bench.P50us > bench.P95us || bench.P95us > bench.P99us {
		t.Errorf("percentiles non-monotonic: p50=%d p95=%d p99=%d", bench.P50us, bench.P95us, bench.P99us)
	}
}

// ── help text ──────────────────────────────────────────────────────────────

func TestIntegration_Help(t *testing.T) {
	t.Run("no args → usage on stderr, exit 2", func(t *testing.T) {
		code, _, stderr := exitCode(t, /* no args */ )
		if code != 2 {
			t.Errorf("exit = %d, want 2", code)
		}
		if !strings.Contains(stderr, "tg — Tool Guard Core CLI") {
			t.Errorf("stderr missing usage banner: %s", stderr)
		}
	})

	t.Run("help → usage on stdout, exit 0", func(t *testing.T) {
		code, stdout, _ := exitCode(t, "help")
		if code != 0 {
			t.Errorf("exit = %d, want 0", code)
		}
		for _, verb := range []string{"evaluate", "verify", "lint", "benchmark"} {
			if !strings.Contains(stdout, verb) {
				t.Errorf("usage missing verb %q", verb)
			}
		}
	})

	t.Run("unknown verb → exit 2", func(t *testing.T) {
		code, _, stderr := exitCode(t, "frobnicate")
		if code != 2 {
			t.Errorf("exit = %d, want 2", code)
		}
		if !strings.Contains(stderr, "unknown verb") {
			t.Errorf("stderr missing unknown-verb message: %s", stderr)
		}
	})
}
