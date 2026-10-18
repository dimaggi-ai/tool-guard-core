package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func checkpointFixture(t *testing.T) (PruneCheckpoint, []domain.DecisionTrace) {
	t.Helper()
	ts := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	a := makeTrace("removed", "env", "", ts)
	b := makeTrace("retained-b", "env", a.TraceHash, ts.Add(time.Hour))
	c := makeTrace("retained-c", "env", b.TraceHash, ts.Add(2*time.Hour))
	cp := PruneCheckpoint{RecordType: "prune_checkpoint", Version: 1, RemovedCount: 1, LastRemovedIndex: 1, LastRemovedHash: a.TraceHash, LastRemovedTimestamp: ts, BoundaryCanonicalVersion: "v1", Cutoff: ts.Add(time.Hour), RetainedCount: 2, RetainedTailHash: c.TraceHash}
	cp.CheckpointHash = cp.Hash()
	return cp, []domain.DecisionTrace{a, b, c}
}

func checkpointLine(t *testing.T, cp PruneCheckpoint) []byte {
	t.Helper()
	raw, err := json.Marshal(cp)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func TestCheckpointAdversarial(t *testing.T) {
	cp, traces := checkpointFixture(t)
	prefix := checkpointLine(t, cp)
	suffix := writeJSONL(t, traces[1:])
	valid := append(append([]byte{}, prefix...), suffix...)
	cases := map[string][]byte{
		"valid":                   valid,
		"legacy genesis":          writeJSONL(t, traces),
		"checkpoint in middle":    append(writeJSONL(t, traces[:1]), valid...),
		"two checkpoints":         append(append([]byte{}, prefix...), valid...),
		"removed first retained":  append(append([]byte{}, prefix...), writeJSONL(t, traces[2:])...),
		"removed retained tail":   append(append([]byte{}, prefix...), writeJSONL(t, traces[1:2])...),
		"removed entire suffix":   prefix,
		"reordered":               append(append([]byte{}, prefix...), writeJSONL(t, []domain.DecisionTrace{traces[2], traces[1]})...),
		"truncated json":          valid[:len(valid)-20],
		"forged retained content": bytes.Replace(valid, []byte("retained-b"), []byte("forged"), 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			r, err := VerifyChainFromReader(bytes.NewReader(raw))
			want := name == "valid" || name == "legacy genesis"
			if err != nil || r.Intact != want {
				t.Fatalf("report=%+v error=%v", r, err)
			}
			expectedRecords := len(traces)
			if name == "valid" {
				expectedRecords--
			}
			if want && r.Records != expectedRecords {
				t.Fatalf("wrong record count: %+v", r)
			}
		})
	}
	mutations := map[string]func(*PruneCheckpoint){
		"wrong anchor with recomputed checksum": func(c *PruneCheckpoint) { c.LastRemovedHash = "sha256:" + strings.Repeat("a", 64) },
		"wrong count":                           func(c *PruneCheckpoint) { c.RemovedCount++ },
		"wrong retained count":                  func(c *PruneCheckpoint) { c.RetainedCount++ },
		"wrong retained tail":                   func(c *PruneCheckpoint) { c.RetainedTailHash = "sha256:" + strings.Repeat("b", 64) },
		"negative removed":                      func(c *PruneCheckpoint) { c.RemovedCount = -1; c.LastRemovedIndex = -1 },
		"negative retained":                     func(c *PruneCheckpoint) { c.RetainedCount = -1 },
		"unknown version":                       func(c *PruneCheckpoint) { c.Version++ },
		"wrong type":                            func(c *PruneCheckpoint) { c.RecordType = "other" },
		"bad timestamp boundary":                func(c *PruneCheckpoint) { c.LastRemovedTimestamp = c.Cutoff },
		"missing timestamp":                     func(c *PruneCheckpoint) { c.LastRemovedTimestamp = time.Time{} },
		"unknown canonical version":             func(c *PruneCheckpoint) { c.BoundaryCanonicalVersion = "unknown" },
		"canonical downgrade":                   func(c *PruneCheckpoint) { c.BoundaryCanonicalVersion = CanonicalTraceVersion },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			altered := cp
			mutate(&altered)
			altered.CheckpointHash = altered.Hash()
			raw := append(checkpointLine(t, altered), suffix...)
			r, err := VerifyChainFromReader(bytes.NewReader(raw))
			if err != nil || r.Intact {
				t.Fatalf("accepted alteration: %+v %v", r, err)
			}
		})
	}
	t.Run("metadata checksum", func(t *testing.T) {
		altered := cp
		altered.RemovedCount++
		altered.LastRemovedIndex++
		r, err := VerifyChainFromReader(bytes.NewReader(append(checkpointLine(t, altered), suffix...)))
		if err != nil || r.Intact {
			t.Fatalf("accepted checksum mismatch: %+v %v", r, err)
		}
	})
	t.Run("unknown field", func(t *testing.T) {
		raw := bytes.Replace(valid, []byte(`"record_type":`), []byte(`"extra":true,"record_type":`), 1)
		r, err := VerifyChainFromReader(bytes.NewReader(raw))
		if err != nil || r.Intact {
			t.Fatalf("accepted unknown field: %+v %v", r, err)
		}
	})
}

func TestCheckpointEmptySuffix(t *testing.T) {
	cp, _ := checkpointFixture(t)
	cp.RetainedCount = 0
	cp.RetainedTailHash = cp.LastRemovedHash
	cp.CheckpointHash = cp.Hash()
	r, err := VerifyChainFromReader(bytes.NewReader(checkpointLine(t, cp)))
	if err != nil || !r.Intact || r.Tail != cp.LastRemovedHash || r.Records != 0 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestLegacyTraceRecordTypeExtensions(t *testing.T) {
	_, traces := checkpointFixture(t)
	legacy := writeJSONL(t, traces)
	for _, value := range []string{`null`, `""`, `"extension"`, `123`, `{"kind":"extension"}`} {
		t.Run(value, func(t *testing.T) {
			raw := bytes.ReplaceAll(legacy, []byte(`{"trace_id":`), []byte(`{"record_type":`+value+`,"trace_id":`))
			if bytes.Equal(raw, legacy) {
				t.Fatal("fixture did not inject extension")
			}
			rep, err := VerifyChainFromReader(bytes.NewReader(raw))
			if err != nil || !rep.Intact || rep.Pruned || rep.Records != len(traces) {
				t.Fatalf("legacy extension rejected: %+v %v", rep, err)
			}
		})
	}
}
