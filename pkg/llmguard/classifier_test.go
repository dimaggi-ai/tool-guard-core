package llmguard

import (
	"strings"
	"testing"
)

func TestParseClassifyJSON_BarePayload(t *testing.T) {
	out, err := parseClassifyJSON(`{"category":"safe","confidence":1.0,"reasoning":"ok"}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.Category != "safe" || out.Confidence != 1.0 {
		t.Errorf("decoded wrong: %+v", out)
	}
}

func TestParseClassifyJSON_StripsCodeFence(t *testing.T) {
	// Some models wrap JSON in ```json ... ``` despite the format
	// directive. The parser must tolerate this.
	out, err := parseClassifyJSON("```json\n{\"category\":\"weapons\",\"confidence\":0.9,\"reasoning\":\"x\"}\n```")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.Category != "weapons" {
		t.Errorf("got %s, want weapons", out.Category)
	}
}

func TestParseClassifyJSON_EmptyString_Errors(t *testing.T) {
	if _, err := parseClassifyJSON(""); err == nil {
		t.Errorf("empty input should error (downstream maps it to model_refused)")
	}
}

func TestParseClassifyJSON_MissingCategory_Errors(t *testing.T) {
	if _, err := parseClassifyJSON(`{"confidence":1.0}`); err == nil {
		t.Errorf("missing category should error")
	}
}

// Trailing JSON after the first object must be REJECTED. Pre-fix, a
// prompt-injected model could emit
// {"category":"safe",...}{"category":"weapons",...}
// and the verifier would accept the safe verdict, masking the unsafe
// one. dec.More() now catches this.
func TestParseClassifyJSON_TrailingJSON_Rejected(t *testing.T) {
	_, err := parseClassifyJSON(`{"category":"safe","confidence":1.0,"reasoning":"ok"}{"category":"weapons","confidence":1.0}`)
	if err == nil {
		t.Errorf("trailing JSON should be rejected")
	}
}

// Symmetric confidence threshold: low-confidence SAFE must also be
// treated as ambiguous (deny). Pre-fix, the threshold only applied to
// non-safe verdicts, letting an attacker get away with
// {"category":"safe","confidence":0.01}.
func TestCapReasoning_StripsControlAndAngleBrackets(t *testing.T) {
	in := "<script>alert(1)</script>\n\x00\x07embedded"
	out := capReasoning(in)
	for _, r := range "<>\x00\x07" {
		if strings.ContainsRune(out, r) {
			t.Errorf("capReasoning failed to strip %q: out=%q", r, out)
		}
	}
}

func TestCapReasoning_CapsLength(t *testing.T) {
	in := strings.Repeat("A", 1024)
	out := capReasoning(in)
	if len(out) > maxReasoningLen {
		t.Errorf("capReasoning output %d > maxReasoningLen %d", len(out), maxReasoningLen)
	}
}

func TestEncodeImageBase64_Roundtrip(t *testing.T) {
	in := []byte{0x89, 0x50, 0x4e, 0x47, 0x00, 0xff} // PNG magic + bytes
	out := EncodeImageBase64(in)
	if out == "" {
		t.Errorf("encoded to empty")
	}
	// Sanity: base64 of 6 bytes is 8 chars.
	if len(out) != 8 {
		t.Errorf("expected 8 chars for 6 bytes, got %d (%q)", len(out), out)
	}
}
