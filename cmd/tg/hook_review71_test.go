package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestHookReview71FlagErrorDialect(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"antigravity before error", []string{"-dialect", "antigravity", "-nope"}, "antigravity"},
		{"antigravity after error", []string{"-nope", "-dialect", "antigravity"}, "antigravity"},
		{"antigravity equals after error", []string{"-nope", "--dialect=antigravity"}, "antigravity"},
		{"claude after error", []string{"-nope", "--dialect", "claude"}, "claude"},
		{"auto", []string{"-nope", "-dialect", "auto"}, "both"},
		{"unspecified", []string{"-nope"}, "both"},
		{"invalid", []string{"-nope", "-dialect=typo"}, "both"},
		{"missing value", []string{"-fail-closed", "-dialect"}, "both"},
		{"last explicit dialect", []string{"-dialect", "claude", "-nope", "-dialect=antigravity"}, "antigravity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"-fail-closed-groups", "shell"}, tc.args...)
			out, code := runHookStr(t, `{"toolCall":{"name":"run_command","args":{}}}`, args...)
			if code != 0 {
				t.Fatalf("exit %d", code)
			}
			dec, dialect := exampleDecision(t, out)
			if dec != "deny" || dialect != tc.want {
				t.Fatalf("got %s/%s, want deny/%s: %s", dec, dialect, tc.want, out)
			}
			if dialect == "both" && hookDecision(t, out) != "deny" {
				t.Fatalf("Claude field must also deny: %s", out)
			}
		})
	}
}

func TestHookReview71UnknownInputDialect(t *testing.T) {
	for _, payload := range []string{"{", strings.Repeat("x", (1<<20)+1)} {
		out, _ := runHookStr(t, payload, "-fail-closed")
		dec, dialect := exampleDecision(t, out)
		if dec != "deny" || dialect != "both" || hookDecision(t, out) != "deny" {
			t.Fatalf("unidentified input got %s/%s: %s", dec, dialect, out)
		}
	}
}

func TestHookReview71AbsentArgsFailClosed(t *testing.T) {
	pol := writeHookPolicy(t, hookDenyPolicy)
	for _, tc := range []struct {
		payload string
		want    string
	}{
		{`{"toolCall":{"name":"write_file"}}`, "deny"},
		{`{"toolCall":{"name":"write_file","args":null}}`, "deny"},
		{`{"tool_name":"Write"}`, "deny"},
		{`{"tool_name":"Write","tool_input":null}`, "deny"},
		{`{"toolCall":{"name":"read_file"}}`, "allow"},
		{`{"toolCall":{"name":"write_file","args":{}}}`, "allow"},
	} {
		out, _ := runHookStr(t, tc.payload, "-policy", pol, "-fail-closed-groups", "shell,filesystem_writes")
		dec, _ := exampleDecision(t, out)
		if dec != tc.want {
			t.Errorf("%s: got %s, want %s", tc.payload, dec, tc.want)
		}
	}
	out, _ := runHookStr(t, `{"toolCall":{"name":"write_file"}}`, "-policy", pol)
	if dec, _ := exampleDecision(t, out); dec != "allow" {
		t.Fatalf("default must remain fail-open: %s", out)
	}
}

func review71AliasParams(distinct bool) map[string]string {
	params := map[string]string{"file_path": "base"}
	for i := 0; i < 33; i++ {
		key := []byte("filename")
		for bit := range key {
			if i&(1<<bit) != 0 {
				key[bit] -= 'a' - 'A'
			}
		}
		value := "same"
		if distinct {
			value = fmt.Sprintf("file-%02d", i)
		}
		params[string(key)] = value
	}
	return params
}

func TestHookReview71AliasLimitCountsDistinctValues(t *testing.T) {
	raw, _ := json.Marshal(review71AliasParams(false))
	variants, truncated := hookParamVariants(raw)
	if truncated || len(variants) != 1 {
		t.Fatalf("33 equal aliases: got %d variants, truncated=%v; want 1, false", len(variants), truncated)
	}
}

func TestHookReview71AliasLimitReason(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"tool_name": "Write", "tool_input": review71AliasParams(true)})
	out, _ := runHookStr(t, string(raw), "-policy", writeHookPolicy(t, hookDenyPolicy))
	_, reason := hookDecisionReason(t, out)
	if !strings.Contains(reason, "parameter-spelling limit: more than 16 distinct alias values") {
		t.Fatalf("reason must state a lower bound, not sampled envelope count: %s", reason)
	}
}
