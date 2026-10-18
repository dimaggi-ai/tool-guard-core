package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func pruneFixture(t *testing.T, ages ...time.Duration) (string, []byte, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	var raw []byte
	prev := ""
	for i, age := range ages {
		tr := domain.DecisionTrace{TraceID: fmt.Sprintf("trace-%d", i), Timestamp: now.Add(-age), PreviousTraceHash: prev, CanonicalVersion: audit.CanonicalTraceVersion, Decision: domain.DecisionAllowed, ActionTaken: domain.ActionAllowed}
		if err := audit.StampProvenance(&tr, "test", exportPolicySetHash); err != nil {
			t.Fatal(err)
		}
		hash, err := audit.ComputeCanonicalTraceHash(&tr)
		if err != nil {
			t.Fatal(err)
		}
		tr.TraceHash = hash
		prev = hash
		b, err := json.Marshal(tr)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, append(b, '\r', '\n')...)
	}
	path := filepath.Join(t.TempDir(), "closed.jsonl")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path, raw, now
}

func pruneRun(t *testing.T, now time.Time, args ...string) (int, string) {
	t.Helper()
	var out, err bytes.Buffer
	code := runPrune(args, &out, &err, now)
	return code, out.String() + err.String()
}

func readPruned(t *testing.T, path string) (audit.PruneCheckpoint, []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := audit.VerifyChainFromReader(bytes.NewReader(raw))
	if err != nil || !r.Intact {
		t.Fatalf("%+v %v", r, err)
	}
	parts := bytes.SplitN(raw, []byte("\n"), 2)
	cp, err := audit.ParsePruneCheckpoint(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	return *cp, parts[1]
}

func TestPruneDryRunAndWrite(t *testing.T) {
	in, raw, now := pruneFixture(t, 72*time.Hour, 48*time.Hour, 12*time.Hour)
	out := in + ".pruned"
	args := []string{"--older-than", "24h", "-file", in, "-out", out, "-closed"}
	code, msg := pruneRun(t, now, args...)
	if code != 0 || !strings.Contains(msg, "remove 2 records; retain 1") {
		t.Fatalf("%d %s", code, msg)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("dry-run wrote output")
	}
	if runtime.GOOS != "linux" {
		return
	}
	code, msg = pruneRun(t, now, append(args, "--yes")...)
	if code != 0 {
		t.Fatalf("%d %s", code, msg)
	}
	cp, suffix := readPruned(t, out)
	originalSuffix := bytes.SplitAfterN(raw, []byte("\n"), 3)[2]
	if !bytes.Equal(suffix, originalSuffix) || cp.RemovedCount != 2 || cp.LastRemovedIndex != 2 {
		t.Fatalf("suffix or checkpoint changed: %+v", cp)
	}
	original, err := os.ReadFile(in)
	if err != nil || !bytes.Equal(original, raw) {
		t.Fatal("input changed")
	}
	verified, err := openVerifiedAuditFileSet(out)
	if err != nil {
		t.Fatal(err)
	}
	defer verified.close()
	if !verified.report.Intact || !strings.Contains(verified.report.Note, "unsigned") {
		t.Fatalf("CLI verifier: %+v", verified.report)
	}
	st, err := os.Stat(out)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v %v", st, err)
	}
}

func TestPrunePrefixAndRepeatedPrune(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("publication requires Linux")
	}
	// The old third record must survive because the second record stops the prefix.
	in, raw, now := pruneFixture(t, 72*time.Hour, 12*time.Hour, 48*time.Hour)
	out := in + ".pruned"
	code, msg := pruneRun(t, now, "-older-than", "24h", "-file", in, "-out", out, "-closed", "-yes")
	if code != 0 {
		t.Fatalf("%d %s", code, msg)
	}
	cp, suffix := readPruned(t, out)
	if cp.RemovedCount != 1 || cp.RetainedCount != 2 || !bytes.Equal(suffix, bytes.SplitAfterN(raw, []byte("\n"), 2)[1]) {
		t.Fatalf("non-prefix removal: %+v", cp)
	}
	second := out + ".again"
	code, msg = pruneRun(t, now.Add(48*time.Hour), "-older-than", "24h", "-file", out, "-out", second, "-closed", "-yes")
	if code != 0 {
		t.Fatalf("%d %s", code, msg)
	}
	cp, suffix = readPruned(t, second)
	if cp.RemovedCount != 3 || cp.RetainedCount != 0 || len(suffix) != 0 {
		t.Fatalf("repeated prune: %+v", cp)
	}
	code, msg = pruneRun(t, now.Add(72*time.Hour), "-older-than", "24h", "-file", second, "-out", second+".again", "-closed", "-yes")
	if code != 0 || !strings.Contains(msg, "No eligible prefix") {
		t.Fatalf("%d %s", code, msg)
	}
}

func TestPruneRefusals(t *testing.T) {
	for _, name := range []string{"existing output", "bad input", "rotation input", "rotation output", "symlink input", "same path", "missing closed", "zero duration", "negative duration", "invalid duration", "overflow duration", "positional"} {
		t.Run(name, func(t *testing.T) {
			in, _, now := pruneFixture(t, 72*time.Hour, 12*time.Hour)
			out := in + ".pruned"
			age := "24h"
			closed := true
			extra := []string{}
			write := func(path string, data []byte) {
				t.Helper()
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "existing output":
				write(out, []byte("keep me"))
			case "bad input":
				write(in, []byte("{invalid\n"))
			case "rotation input":
				write(in+".1", nil)
			case "rotation output":
				write(out+".1", nil)
			case "symlink input":
				link := in + ".link"
				if err := os.Symlink(in, link); err != nil {
					t.Skip(err)
				}
				in = link
			case "same path":
				out = in
			case "missing closed":
				closed = false
			case "zero duration":
				age = "0s"
			case "negative duration":
				age = "-1h"
			case "invalid duration":
				age = "1d"
			case "overflow duration":
				age = "999999999999999999h"
			case "positional":
				extra = []string{"unexpected"}
			}
			args := []string{"-file", in, "-out", out, "-older-than", age, "-yes"}
			if closed {
				args = append(args, "-closed")
			}
			args = append(args, extra...)
			code, msg := pruneRun(t, now, args...)
			if code == 0 {
				t.Fatalf("accepted: %s", msg)
			}
			if name == "existing output" {
				b, err := os.ReadFile(out)
				if err != nil || string(b) != "keep me" {
					t.Fatal("overwrote output")
				}
			}
		})
	}
}

func TestPruneCutoffAndTimezone(t *testing.T) {
	in, _, now := pruneFixture(t, 24*time.Hour+time.Nanosecond, 24*time.Hour, 25*time.Hour)
	local := now.In(time.FixedZone("test-offset", -7*60*60))
	code, msg := pruneRun(t, local, "-file", in, "-out", in+".pruned", "-older-than", "24h", "-closed")
	if code != 0 || !strings.Contains(msg, "remove 1 records; retain 2") || !strings.Contains(msg, "2026-10-16T12:00:00Z") {
		t.Fatalf("%d %s", code, msg)
	}
}

func TestPruneEmptyAndNoPrefix(t *testing.T) {
	for _, ages := range [][]time.Duration{nil, {time.Hour, 72 * time.Hour}} {
		in, _, now := pruneFixture(t, ages...)
		code, msg := pruneRun(t, now, "-file", in, "-out", in+".pruned", "-older-than", "24h", "-closed", "-yes")
		if code != 0 || !strings.Contains(msg, "No eligible prefix") {
			t.Fatalf("%d %s", code, msg)
		}
		if _, err := os.Stat(in + ".pruned"); !os.IsNotExist(err) {
			t.Fatal("wrote no-op output")
		}
	}
}

func TestPruneDetectsChangedInput(t *testing.T) {
	in, raw, _ := pruneFixture(t, time.Hour)
	f, err := os.Open(in)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	changed := bytes.Replace(raw, []byte("trace-0"), []byte("trace-1"), 1)
	if err := os.WriteFile(in, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(in, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := pruneInputStable(f, in, st, sum[:]); err == nil {
		t.Fatal("accepted same-size mutation")
	}
}

func TestPruneAtomicNoReplace(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("publication requires Linux")
	}
	dir := t.TempDir()
	temp := filepath.Join(dir, "temp")
	out := filepath.Join(dir, "out")
	for _, path := range []string{temp, out} {
		if err := os.WriteFile(path, []byte(path), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := publishPrunedFile(temp, out); err == nil {
		t.Fatal("replaced existing file")
	}
	raw, err := os.ReadFile(out)
	if err != nil || string(raw) != out {
		t.Fatal("destination changed")
	}
}

func TestPruneLegacyEOFAndExport(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("publication requires Linux")
	}
	in, raw, now := pruneFixture(t, 72*time.Hour, 12*time.Hour)
	var legacy []byte
	prev := ""
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var tr domain.DecisionTrace
		if err := json.Unmarshal(line, &tr); err != nil {
			t.Fatal(err)
		}
		tr.CanonicalVersion = ""
		tr.SchemaVersion = ""
		tr.EngineVersion = ""
		tr.PolicySetHash = ""
		tr.PreviousTraceHash = prev
		hash, err := audit.ComputeCanonicalTraceHash(&tr)
		if err != nil {
			t.Fatal(err)
		}
		tr.TraceHash = hash
		prev = hash
		encoded, err := json.Marshal(tr)
		if err != nil {
			t.Fatal(err)
		}
		legacy = append(legacy, append(encoded, '\n')...)
	}
	legacy = bytes.TrimSuffix(legacy, []byte("\n"))
	if err := os.WriteFile(in, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	out := in + ".pruned"
	code, msg := pruneRun(t, now, "-file", in, "-out", out, "-older-than", "24h", "-closed", "-yes")
	if code != 0 {
		t.Fatalf("%d %s", code, msg)
	}
	cp, suffix := readPruned(t, out)
	if cp.BoundaryCanonicalVersion != "v1" || !bytes.Equal(suffix, bytes.SplitN(legacy, []byte("\n"), 2)[1]) {
		t.Fatal("legacy EOF record changed")
	}
	var exported, errs bytes.Buffer
	if code := runExport([]string{"-file", out}, &exported, &errs); code != 0 {
		t.Fatalf("export: %d %s", code, errs.String())
	}
	if !bytes.Equal(exported.Bytes(), append(append([]byte{}, suffix...), '\n')) {
		t.Fatal("export did not return only the retained trace")
	}
}

func TestPruneRepeatedRetainsSuffix(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("publication requires Linux")
	}
	in, raw, now := pruneFixture(t, 72*time.Hour, 36*time.Hour, 12*time.Hour)
	first := in + ".first"
	second := in + ".second"
	for _, step := range []struct{ in, out, age string }{{in, first, "48h"}, {first, second, "24h"}} {
		code, msg := pruneRun(t, now, "-file", step.in, "-out", step.out, "-older-than", step.age, "-closed", "-yes")
		if code != 0 {
			t.Fatalf("%d %s", code, msg)
		}
	}
	cp, suffix := readPruned(t, second)
	if cp.RemovedCount != 2 || cp.RetainedCount != 1 || !bytes.Equal(suffix, bytes.SplitAfterN(raw, []byte("\n"), 3)[2]) {
		t.Fatalf("bad repeated prune: %+v", cp)
	}
}

func TestPrunePublishSymlinkNoReplace(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("publication requires Linux")
	}
	dir := t.TempDir()
	temp := filepath.Join(dir, "temp")
	out := filepath.Join(dir, "out")
	if err := os.WriteFile(temp, []byte("temporary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "missing"), out); err != nil {
		t.Fatal(err)
	}
	if err := publishPrunedFile(temp, out); err == nil {
		t.Fatal("replaced dangling symlink")
	}
	if _, err := os.Readlink(out); err != nil {
		t.Fatal("symlink changed")
	}
}

func TestHookRejectsPrunedChain(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("publication requires Linux")
	}
	in, _, now := pruneFixture(t, 72*time.Hour, 12*time.Hour)
	out := in + ".pruned"
	code, msg := pruneRun(t, now, "-file", in, "-out", out, "-older-than", "24h", "-closed", "-yes")
	if code != 0 {
		t.Fatalf("%d %s", code, msg)
	}
	before, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	env := &domain.ActionEnvelope{EnvelopeID: "test", Timestamp: now}
	if err := appendHookAudit(out, env, nil, "allow", "test"); err == nil || !strings.Contains(err.Error(), "pruned") {
		t.Fatalf("append returned: %v", err)
	}
	after, err := os.ReadFile(out)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("hook changed pruned input")
	}
}
