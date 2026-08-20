package main

// Native Go fuzz tests for the two places tg-proxy parses untrusted bytes:
// the /evaluate request body (JSON) and policy YAML files. Neither had any
// fuzz coverage before — added as part of the stress suite (see
// cmd/stress-test) because a crash/panic on malformed input is exactly the
// kind of instability a load test won't find (load tests send well-formed
// requests fast; fuzzing sends malformed ones, however slow). A panic in
// either path takes down the whole proxy process for every in-flight
// request, not just the one with the bad input — that's the failure mode
// this is checking for, not any particular output value.
//
// Run:
//
//	go test -fuzz=FuzzActionEnvelopeDecode -fuzztime=30s ./cmd/tg-proxy/
//	go test -fuzz=FuzzValidateJSONDepth -fuzztime=30s ./cmd/tg-proxy/
//	go test -fuzz=FuzzPolicyYAML -fuzztime=30s ./cmd/tg-proxy/

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/policyload"
)

func FuzzActionEnvelopeDecode(f *testing.F) {
	f.Add([]byte(`{"tool_name":"issue_refund","tool_group":"monetary_outflow","agent_id":"a1","org_id":"o1","parameters":{"amount":100}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"tool_name":"","parameters":null}`))
	f.Add([]byte(`{"context":{"verified":{"agent_velocity":{"sum_1h":1e308}}}}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic decoding envelope: %v\ninput: %q", r, data)
			}
		}()
		var env domain.ActionEnvelope
		// Only property under test: never panic. A decode error is a
		// completely normal, expected, already-handled outcome (the real
		// handler turns it into a 400) — this is not asserting decode
		// success or any particular field value.
		_ = json.Unmarshal(data, &env)
	})
}

func FuzzValidateJSONDepth(f *testing.F) {
	f.Add([]byte(`{"a":{"b":{"c":1}}}`), 32)
	f.Add([]byte(`[[[[[]]]]]`), 3)
	f.Add([]byte(``), 32)
	f.Add([]byte(`{`), 32)
	f.Add([]byte(`"`), 32)
	f.Fuzz(func(t *testing.T, data []byte, maxDepth int) {
		if maxDepth < 0 || maxDepth > 10000 {
			t.Skip() // out-of-range depth isn't a real config value; not what this checks
		}
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic in validateJSONDepth: %v\ninput: %q maxDepth=%d", r, data, maxDepth)
			}
		}()
		_ = validateJSONDepth(data, maxDepth)
	})
}

func FuzzPolicyYAML(f *testing.F) {
	seeds, _ := filepath.Glob(filepath.Join("..", "..", "policies", "*.yaml"))
	for _, s := range seeds {
		if b, err := os.ReadFile(s); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(`policy_id: p1`))
	f.Add([]byte(``))
	f.Add([]byte(`{`))
	f.Add([]byte("rules:\n  - conditions: *anchor\n"))
	f.Add([]byte("a: &a [*a]")) // self-referential YAML anchor — classic parser bomb shape
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic loading policy YAML: %v\ninput: %q", r, data)
			}
		}()
		dir := t.TempDir()
		path := filepath.Join(dir, "fuzz.yaml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip()
		}
		// Same "never panic" property as the other two — a parse error
		// here is the correct, already-handled outcome (tg-proxy logs it
		// and skips the file at startup); this only checks for a crash.
		_, _ = policyload.Load(path)
	})
}
