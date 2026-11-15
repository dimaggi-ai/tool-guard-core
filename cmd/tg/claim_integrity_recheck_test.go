package main

// These tests close claim holes that a re-check of the tree found on
// 2026-11-10. Each test names the edit that passed the suite before it
// existed.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestHarnessManifestStagesAreConsistent recomputes the two derived fields of
// every stage from its outcome counts, with the rule that
// examples/coding-agent-guard/verify_harnesses.py uses. Before this test, a
// stage whose "outcome" was edited from "blocked" to "ran" passed the suite.
func TestHarnessManifestStagesAreConsistent(t *testing.T) {
	m := loadHarnessManifest(t)
	for _, h := range m.Harnesses {
		for _, s := range h.Stages {
			where := fmt.Sprintf("%s [%s] %s", h.ID, h.Configuration, s.ID)
			wantOutcome := "mixed"
			if len(s.Outcomes) == 1 {
				for word := range s.Outcomes {
					wantOutcome = word
				}
			}
			if s.Outcome != wantOutcome {
				t.Errorf("%s: outcome is %q, the counts %v give %q", where, s.Outcome, s.Outcomes, wantOutcome)
			}
			wantResult := "MEASURED"
			if s.Expect != "measure" {
				opposite := 0
				for word, n := range s.Outcomes {
					if word != s.Expect && word != "not_measured" {
						opposite += n
					}
				}
				wantResult = "FAIL"
				if opposite == 0 && s.Outcomes[s.Expect]*2 > s.Runs {
					wantResult = "PASS"
				}
			}
			if s.Result != wantResult {
				t.Errorf("%s: result is %q, expect %q with counts %v gives %q", where, s.Result, s.Expect, s.Outcomes, wantResult)
			}
		}
	}
}

// hookCaseToolName returns the tool name a captured payload carries, in
// either envelope shape.
func hookCaseToolName(c hookCase) string {
	var p struct {
		ToolName string `json:"tool_name"`
		ToolCall struct {
			Name string `json:"name"`
		} `json:"toolCall"`
	}
	if json.Unmarshal(c.Payload, &p) != nil {
		return ""
	}
	if p.ToolName != "" {
		return p.ToolName
	}
	return p.ToolCall.Name
}

// capturedToolsByVersion returns, for one matrix row, the tool names of the
// real-install captures at each harness version.
func capturedToolsByVersion(t *testing.T, row string) map[string][]string {
	t.Helper()
	sets := map[string]map[string]bool{}
	for _, c := range loadHookCases(t) {
		if c.Capture.CapturedFrom != "real install" || !aliasIsVerified(map[string]string{row: "verified"}, c.Harness) {
			continue
		}
		if sets[c.HarnessVersion] == nil {
			sets[c.HarnessVersion] = map[string]bool{}
		}
		if name := hookCaseToolName(c); name != "" {
			sets[c.HarnessVersion][name] = true
		}
	}
	out := map[string][]string{}
	for v, set := range sets {
		for name := range set {
			out[v] = append(out[v], name)
		}
		sort.Strings(out[v])
	}
	return out
}

// TestMatrixCapturedToolsMatchCorpus requires the "What was captured" cell of
// every verified row to list, for each version, exactly the tools that have a
// real-install capture at that version. Before this test the Claude Code row
// said "Read, Write, Bash at both versions" while the corpus held no Read
// capture at 2.1.321, and deleting the Write capture at that version passed.
func TestMatrixCapturedToolsMatchCorpus(t *testing.T) {
	for name, status := range loadSupportMatrix(t) {
		if status != "verified" {
			continue
		}
		line := loadMatrixLine(t, name)
		byVersion := capturedToolsByVersion(t, name)
		for _, v := range matrixVersions(line) {
			tools := byVersion[v]
			if len(tools) == 0 {
				t.Errorf("matrix row %q names version %s, and the corpus holds no real-install capture with a tool name at that version", name, v)
				continue
			}
			want := v + ": `" + strings.Join(tools, "`, `") + "`"
			// The list must end right after the last tool, so that a longer
			// list in the row does not satisfy a shorter list in the corpus.
			if !strings.Contains(line, want+".") && !strings.Contains(line, want+" |") {
				t.Errorf("matrix row %q must contain %q followed by a full stop or the end of the cell: the tools captured from a real install at that version", name, want)
			}
		}
	}
}

// TestRealInstallCasesCarryAHarnessEnvelope fails when a case labelled "real
// install" lacks the fields every real hook call of that harness carried, or
// says in its own note that its values are synthetic. Before this test,
// relabelling a hand-written payload as "real install" passed the suite. The
// check does not prove a payload came from a harness: a hand-written payload
// with the full envelope still passes.
func TestRealInstallCasesCarryAHarnessEnvelope(t *testing.T) {
	need := map[string][]string{
		"claude-code":     {"session_id", "hook_event_name", "tool_name", "tool_input"},
		"codex-cli":       {"session_id", "hook_event_name", "tool_name", "tool_input"},
		"antigravity-cli": {"conversationId", "toolCall"},
	}
	dir := filepath.Join("..", "..", "testdata", "hookconformance")
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no cases in %s (err %v)", dir, err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var c struct {
			Harness string `json:"harness"`
			Capture struct {
				CapturedFrom string `json:"captured_from"`
				Note         string `json:"note"`
			} `json:"capture"`
			Payload map[string]json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatalf("decode %s: %v", f, err)
		}
		if c.Capture.CapturedFrom != "real install" {
			continue
		}
		keys, known := need[c.Harness]
		if !known {
			t.Errorf("%s: labelled real install for harness %q, which this test has no envelope for", filepath.Base(f), c.Harness)
		}
		for _, k := range keys {
			if _, ok := c.Payload[k]; !ok {
				t.Errorf("%s: labelled real install, but the payload has no %q field; a real %s hook call carries it", filepath.Base(f), k, c.Harness)
			}
		}
		if strings.Contains(strings.ToLower(c.Capture.Note), "synthetic") {
			t.Errorf("%s: labelled real install, and its own note says the values are synthetic", filepath.Base(f))
		}
	}
}

var supportVerbRe = regexp.MustCompile(`(?i)\btool guard\s+(?:now\s+|also\s+)?(?:supports?|works\s+with|is\s+compatible\s+with|integrates\s+with)\s+([^.\n]{0,100})`)

var productShapeRe = regexp.MustCompile(`\b(?:CLI|IDE|Copilot)\b|[0-9]+\.[0-9]+\.[0-9]+`)

// TestSupportSentencesNameOnlyVerifiedHarnesses covers a harness name that
// harnessAliases does not list. A sentence of the form "Tool Guard supports
// <name>", where <name> has the word CLI, IDE or Copilot or a three-part
// version, must name a verified harness. Before this test, "Tool Guard
// supports NovaPilot CLI 9.9.9." passed. Other sentence forms about a harness
// that the tests do not list still pass.
func TestSupportSentencesNameOnlyVerifiedHarnesses(t *testing.T) {
	rows := loadSupportMatrix(t)
	for _, f := range claimDocFiles(t) {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, m := range supportVerbRe.FindAllStringSubmatch(string(raw), -1) {
			object := m[1]
			if !productShapeRe.MatchString(object) {
				continue
			}
			lower := strings.ToLower(object)
			verified := false
			for _, alias := range harnessAliases {
				if strings.Contains(lower, alias) && aliasIsVerified(rows, alias) {
					verified = true
				}
			}
			if !verified {
				t.Errorf("%s says %q, and that names no harness that docs/support-matrix.md marks verified", f, strings.TrimSpace(m[0]))
			}
		}
	}
}

var (
	approvalWordRe = regexp.MustCompile(`(?i)\b(wait(s|ed|ing)?|approv\w+|prompt(s|ed|ing)?|confirm\w*)\b`)
	stopWordRe     = regexp.MustCompile(`(?i)\b(block(s|ed|ing)?|stop(s|ped|ping)?|held|hold(s|ing)?|refus\w+|paus\w+)\b`)
	harnessWordRe  = regexp.MustCompile(`(?i)\b(claude code|codex|antigravity|agy)\b`)
)

// TestOperatorDocsDoNotStateEscalationOutcomes keeps statements about what a
// harness does with a request for approval in docs/support-matrix.md, where a
// test renders them from the manifest. In the three operator documents, two
// neighbouring lines that name a harness, a word for stopping a call and a
// word for approval must also point to the matrix. Before this test, "Codex
// CLI blocks the call and waits until you approve it" passed.
func TestOperatorDocsDoNotStateEscalationOutcomes(t *testing.T) {
	for _, parts := range [][]string{
		{"README.md"},
		{"docs", "getting-started.md"},
		{"examples", "coding-agent-guard", "README.md"},
	} {
		lines := strings.Split(readRepoFile(t, parts...), "\n")
		for i := range lines {
			unit := lines[i]
			if i+1 < len(lines) {
				unit += " " + lines[i+1]
			}
			if harnessWordRe.MatchString(unit) && approvalWordRe.MatchString(unit) && stopWordRe.MatchString(unit) && !strings.Contains(unit, "support-matrix") {
				t.Errorf("%s:%d says what a harness does with an approval request without pointing to docs/support-matrix.md: %s",
					strings.Join(parts, "/"), i+1, strings.TrimSpace(lines[i]))
			}
		}
	}
}

// TestHookEscalatesAboveTheVariantLimit pins the limit that CHANGELOG.md
// states: the hook evaluates at most maxHookParamVariants extra values, and a
// call with more is escalated, or denied with -escalate-as deny.
func TestHookEscalatesAboveTheVariantLimit(t *testing.T) {
	// Path alias spellings that differ only in case and separators all
	// normalise to the alias "path", so each one is one extra value.
	spellings := []string{"Path", "PATH", "pAth", "paTh", "patH", "PAth", "pATh", "paTH", "PaTh", "pAtH",
		"p_ath", "pa_th", "pat_h", "p-ath", "pa-th", "pat-h", "p.ath", "pa.th", "pat.h", "P_ATH"}
	build := func(n int) string {
		args := map[string]string{"file_path": "plain-0.txt", "content": "package main"}
		for i := 0; i < n; i++ {
			args[spellings[i]] = fmt.Sprintf("plain-%d.txt", i+1)
		}
		b, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": args})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return string(b)
	}
	policies := filepath.Join("..", "..", "policies")
	if _, over := hookParamVariants(json.RawMessage(`{"file_path":"a","Path":"b"}`)); over {
		t.Fatalf("two values must not exceed the limit")
	}
	atLimit, _ := runHookStr(t, build(maxHookParamVariants), "-policy-dir", policies, "-mode", "enforcement", "-dialect", "claude")
	if !strings.Contains(atLimit, `"permissionDecision":"allow"`) {
		t.Errorf("%d extra values of an unprotected path must be allowed, got: %s", maxHookParamVariants, atLimit)
	}
	over, _ := runHookStr(t, build(maxHookParamVariants+1), "-policy-dir", policies, "-mode", "enforcement", "-dialect", "claude")
	if !strings.Contains(over, `"permissionDecision":"ask"`) {
		t.Errorf("%d extra values must be escalated, got: %s", maxHookParamVariants+1, over)
	}
	denied, _ := runHookStr(t, build(maxHookParamVariants+1), "-policy-dir", policies, "-mode", "enforcement", "-dialect", "claude", "-escalate-as", "deny")
	if !strings.Contains(denied, `"permissionDecision":"deny"`) {
		t.Errorf("%d extra values with -escalate-as deny must be denied, got: %s", maxHookParamVariants+1, denied)
	}
}

// TestGuardHookFailClosedListsAreComplete reads the two lists the shipped
// wrapper passes to tg hook. Before this test, removing "write" from the first
// list changed only the wiring hash, and a new release run would have accepted
// the weaker wrapper.
func TestGuardHookFailClosedListsAreComplete(t *testing.T) {
	text := readRepoFile(t, "examples", "coding-agent-guard", "hooks", "guard-hook.sh")
	for flag, want := range map[string][]string{
		"-fail-closed-tools":  {"bash", "powershell", "write", "edit", "notebookedit"},
		"-fail-closed-groups": {"shell", "filesystem_writes", "network_egress"},
	} {
		m := regexp.MustCompile(`(?m)^args\+=\(` + flag + ` ([a-z_,]+)\)$`).FindStringSubmatch(text)
		if m == nil {
			t.Errorf("guard-hook.sh has no line args+=(%s <list>)", flag)
			continue
		}
		have := strings.Split(m[1], ",")
		for _, name := range want {
			found := false
			for _, h := range have {
				found = found || h == name
			}
			if !found {
				t.Errorf("guard-hook.sh passes %s %s, which lacks %q", flag, m[1], name)
			}
		}
	}
}

// TestCodexTemplateCommentIsDocumented covers a hand copy of the Codex
// template. Codex CLI 0.166.0 rejects a hooks.json with an unknown top-level
// key and then loads no hook. While the template carries "_comment", the
// example README must tell the reader to delete it, and the installer must
// not write it.
func TestCodexTemplateCommentIsDocumented(t *testing.T) {
	var template map[string]json.RawMessage
	raw := readRepoFile(t, "examples", "coding-agent-guard", "config", "codex.hooks.json")
	if err := json.Unmarshal([]byte(raw), &template); err != nil {
		t.Fatalf("codex.hooks.json: %v", err)
	}
	if strings.Contains(readRepoFile(t, "examples", "coding-agent-guard", "install.sh"), "_comment") {
		t.Error("install.sh mentions _comment; it must not write that key into a harness config")
	}
	if _, has := template["_comment"]; !has {
		return
	}
	readme := readRepoFile(t, "examples", "coding-agent-guard", "README.md")
	if !strings.Contains(readme, "delete its `_comment` key") {
		t.Error("codex.hooks.json carries _comment and the example README does not tell the reader to delete it")
	}
}
