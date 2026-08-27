package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/audit"
	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

const exportPolicySetHash = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

func makeExportTrace(t *testing.T, id string, timestamp time.Time, action domain.ActionTaken, policyIDs []string, previousHash string) domain.DecisionTrace {
	t.Helper()
	decision := domain.DecisionAllowed
	effect := domain.EffectAllow
	switch action {
	case domain.ActionDenied, domain.ActionAllowedShadow:
		decision = domain.DecisionDenied
		effect = domain.EffectDeny
	case domain.ActionEscalated:
		decision = domain.DecisionEscalated
		effect = domain.EffectEscalate
	case domain.ActionFlagged:
		decision = domain.DecisionFlagged
		effect = domain.EffectFlag
	}
	trace := domain.DecisionTrace{
		TraceID:           id,
		Timestamp:         timestamp,
		EnvelopeID:        "env-" + id,
		AgentID:           "agent-export",
		SessionID:         "session-export",
		OrgID:             "org-export",
		ToolName:          "tool-export",
		ToolGroup:         "group-export",
		Decision:          decision,
		ActionTaken:       action,
		Mode:              domain.PolicyModeEnforcement,
		PreviousTraceHash: previousHash,
	}
	for i, policyID := range policyIDs {
		trace.RuleResults = append(trace.RuleResults, domain.RuleResult{
			RuleID:        id + "-rule-" + string(rune('a'+i)),
			PolicyID:      policyID,
			PolicyVersion: 1,
			Matched:       true,
			Effect:        effect,
		})
	}
	if err := audit.StampProvenance(&trace, "v0.8.0-test", exportPolicySetHash); err != nil {
		t.Fatalf("StampProvenance: %v", err)
	}
	hash, err := audit.ComputeCanonicalTraceHash(&trace)
	if err != nil {
		t.Fatalf("ComputeCanonicalTraceHash: %v", err)
	}
	trace.TraceHash = hash
	return trace
}

func marshalExportTrace(t *testing.T, trace domain.DecisionTrace) string {
	t.Helper()
	raw, err := json.Marshal(trace)
	if err != nil {
		t.Fatalf("marshal trace: %v", err)
	}
	return string(raw)
}

func writeExportFile(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write export fixture: %v", err)
	}
}

func runExportForTest(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runExport(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func exportedTraceIDs(t *testing.T, output string) []string {
	t.Helper()
	var ids []string
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record struct {
			TraceID string `json:"trace_id"`
		}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode exported line: %v", err)
		}
		ids = append(ids, record.TraceID)
	}
	return ids
}

func TestExportUnfilteredPreservesOriginalJSONLines(t *testing.T) {
	base := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	first := makeExportTrace(t, "t1", base, domain.ActionAllowed, []string{"policy-a"}, "")
	second := makeExportTrace(t, "t2", base.Add(time.Minute), domain.ActionDenied, []string{"policy-b"}, first.TraceHash)
	firstLine := "  " + marshalExportTrace(t, first) + " "
	secondLine := "\t" + marshalExportTrace(t, second)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeExportFile(t, path, firstLine, "", secondLine)

	code, stdout, stderr := runExportForTest(t, "-file", path, "-format", "jsonl")
	if code != 0 {
		t.Fatalf("runExport code=%d stderr=%s", code, stderr)
	}
	want := firstLine + "\n" + secondLine + "\n"
	if stdout != want {
		t.Fatalf("export changed JSON lines\nwant: %q\n got: %q", want, stdout)
	}
}

func TestExportAcceptsExactMaximumRecord(t *testing.T) {
	trace := hookAuditTraceOfSize(t, audit.MaxTraceRecordBytes)
	line, err := audit.MarshalTraceRecord(trace)
	if err != nil {
		t.Fatalf("MarshalTraceRecord: %v", err)
	}
	terminators := map[string][]byte{
		"LF":   {'\n'},
		"CRLF": {'\r', '\n'},
		"EOF":  nil,
	}
	for name, terminator := range terminators {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "exact-max.jsonl")
			contents := append(append([]byte(nil), line...), terminator...)
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatalf("write exact-max fixture: %v", err)
			}
			code, stdout, stderr := runExportForTest(t, "-file", path)
			if code != 0 || stderr != "" || stdout != string(line)+"\n" {
				t.Fatalf("exact-max export code=%d stdout-bytes=%d stderr=%q", code, len(stdout), stderr)
			}
		})
	}
}

func TestExportRejectsRecordOverMaximum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "over-max.jsonl")
	raw := bytes.Repeat([]byte{'x'}, audit.MaxTraceRecordBytes+1)
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write over-max fixture: %v", err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = streamAuditExport(
		[]auditFileSnapshot{{path: path, file: f, size: info.Size()}},
		auditExportFilter{},
		&output,
	)
	if err == nil || !strings.Contains(err.Error(), "maximum is 4194304") {
		t.Fatalf("over-max export error=%v, want explicit record-size rejection", err)
	}
	if output.Len() != 0 {
		t.Fatalf("over-max export wrote %d bytes before rejection", output.Len())
	}
}

func TestExportFiltersTimePolicyAndAction(t *testing.T) {
	base := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	t1 := makeExportTrace(t, "t1", base, domain.ActionAllowed, []string{"policy-a"}, "")
	t2 := makeExportTrace(t, "t2", base.Add(time.Hour), domain.ActionDenied, []string{"policy-b"}, t1.TraceHash)
	t3 := makeExportTrace(t, "t3", base.Add(2*time.Hour), domain.ActionDenied, []string{"policy-b", "policy-c"}, t2.TraceHash)
	t4 := makeExportTrace(t, "t4", base.Add(3*time.Hour), domain.ActionFlagged, []string{"policy-c"}, t3.TraceHash)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeExportFile(t, path, marshalExportTrace(t, t1), marshalExportTrace(t, t2), marshalExportTrace(t, t3), marshalExportTrace(t, t4))

	code, stdout, stderr := runExportForTest(t,
		"-file", path,
		"-since", base.Add(time.Hour).Format(time.RFC3339),
		"-until", base.Add(2*time.Hour).Format(time.RFC3339),
		"-policy", "policy-b,policy-c",
		"-action", "denied,flagged",
	)
	if code != 0 {
		t.Fatalf("runExport code=%d stderr=%s", code, stderr)
	}
	ids := exportedTraceIDs(t, stdout)
	if len(ids) != 1 || ids[0] != "t2" {
		t.Fatalf("filtered trace IDs = %v, want [t2] (since inclusive, until exclusive)", ids)
	}
}

func TestExportWalksRotationSetOldestFirst(t *testing.T) {
	base := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	t1 := makeExportTrace(t, "t1", base, domain.ActionAllowed, nil, "")
	t2 := makeExportTrace(t, "t2", base.Add(time.Minute), domain.ActionDenied, nil, t1.TraceHash)
	t3 := makeExportTrace(t, "t3", base.Add(2*time.Minute), domain.ActionAllowedShadow, nil, t2.TraceHash)
	active := filepath.Join(t.TempDir(), "audit.jsonl")
	writeExportFile(t, active+".1", marshalExportTrace(t, t1), marshalExportTrace(t, t2))
	writeExportFile(t, active, marshalExportTrace(t, t3))

	code, stdout, stderr := runExportForTest(t, "-file", active)
	if code != 0 {
		t.Fatalf("runExport code=%d stderr=%s", code, stderr)
	}
	if got := strings.Join(exportedTraceIDs(t, stdout), ","); got != "t1,t2,t3" {
		t.Fatalf("rotation export order = %s, want t1,t2,t3", got)
	}
}

func TestExportRejectsTamperedChainBeforeWriting(t *testing.T) {
	base := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	trace := makeExportTrace(t, "tampered", base, domain.ActionAllowed, nil, "")
	trace.ActionTaken = domain.ActionDenied
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeExportFile(t, path, marshalExportTrace(t, trace))

	code, stdout, stderr := runExportForTest(t, "-file", path)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "not intact") {
		t.Fatalf("tampered export code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestExportSnapshotExcludesLaterAppends(t *testing.T) {
	base := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	first := makeExportTrace(t, "t1", base, domain.ActionAllowed, nil, "")
	second := makeExportTrace(t, "t2", base.Add(time.Minute), domain.ActionDenied, nil, first.TraceHash)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeExportFile(t, path, marshalExportTrace(t, first))

	fileSet, err := openVerifiedAuditFileSet(path)
	if err != nil {
		t.Fatalf("openVerifiedAuditFileSet: %v", err)
	}
	defer fileSet.close()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open append: %v", err)
	}
	if _, err := f.WriteString(marshalExportTrace(t, second) + "\n"); err != nil {
		_ = f.Close()
		t.Fatalf("append trace: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close append: %v", err)
	}

	filter, err := newAuditExportFilter("", "", nil, nil)
	if err != nil {
		t.Fatalf("newAuditExportFilter: %v", err)
	}
	var output bytes.Buffer
	if err := streamAuditExport(fileSet.files, filter, &output); err != nil {
		t.Fatalf("streamAuditExport: %v", err)
	}
	ids := exportedTraceIDs(t, output.String())
	if len(ids) != 1 || ids[0] != "t1" {
		t.Fatalf("snapshot exported IDs = %v, want only pre-snapshot t1", ids)
	}
}

func TestExportSnapshotIgnoresSameSizeSourceRewrite(t *testing.T) {
	base := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	verified := makeExportTrace(t, "t1", base, domain.ActionAllowed, nil, "")
	replacement := makeExportTrace(t, "x1", base, domain.ActionAllowed, nil, "")
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	verifiedRaw := marshalExportTrace(t, verified)
	replacementRaw := marshalExportTrace(t, replacement)
	if len(verifiedRaw) != len(replacementRaw) {
		t.Fatalf("test fixture lengths differ: verified=%d replacement=%d", len(verifiedRaw), len(replacementRaw))
	}
	writeExportFile(t, path, verifiedRaw)

	fileSet, err := openVerifiedAuditFileSet(path)
	if err != nil {
		t.Fatalf("openVerifiedAuditFileSet: %v", err)
	}
	defer fileSet.close()
	writeExportFile(t, path, replacementRaw)

	var output bytes.Buffer
	if err := streamAuditExport(fileSet.files, auditExportFilter{}, &output); err != nil {
		t.Fatalf("streamAuditExport: %v", err)
	}
	ids := exportedTraceIDs(t, output.String())
	if len(ids) != 1 || ids[0] != "t1" {
		t.Fatalf("snapshot exported IDs = %v, want immutable verified record t1", ids)
	}
}

func TestExportNoMatchesIsSuccessfulEmptyStream(t *testing.T) {
	trace := makeExportTrace(t, "t1", time.Now().UTC(), domain.ActionAllowed, []string{"policy-a"}, "")
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeExportFile(t, path, marshalExportTrace(t, trace))
	code, stdout, stderr := runExportForTest(t, "-file", path, "-policy", "missing-policy")
	if code != 0 || stdout != "" {
		t.Fatalf("empty export code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestExportRejectsInvalidArguments(t *testing.T) {
	base := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	trace := makeExportTrace(t, "t1", base, domain.ActionAllowed, nil, "")
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	writeExportFile(t, path, marshalExportTrace(t, trace))

	tests := []struct {
		name string
		args []string
		code int
	}{
		{name: "missing file", args: nil, code: 2},
		{name: "missing path", args: []string{"-file", filepath.Join(t.TempDir(), "missing.jsonl")}, code: 1},
		{name: "unsupported format", args: []string{"-file", path, "-format", "csv"}, code: 2},
		{name: "bad since", args: []string{"-file", path, "-since", "yesterday"}, code: 2},
		{name: "bad until", args: []string{"-file", path, "-until", "tomorrow"}, code: 2},
		{name: "reversed range", args: []string{"-file", path, "-since", base.Add(time.Hour).Format(time.RFC3339), "-until", base.Format(time.RFC3339)}, code: 2},
		{name: "equal range", args: []string{"-file", path, "-since", base.Format(time.RFC3339), "-until", base.Format(time.RFC3339)}, code: 2},
		{name: "unknown action", args: []string{"-file", path, "-action", "blocked"}, code: 2},
		{name: "empty selector", args: []string{"-file", path, "-policy", ","}, code: 2},
		{name: "positional argument", args: []string{"-file", path, "extra"}, code: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, stdout, _ := runExportForTest(t, tt.args...)
			if code != tt.code || stdout != "" {
				t.Fatalf("runExport code=%d stdout=%q, want code=%d empty stdout", code, stdout, tt.code)
			}
		})
	}
}
