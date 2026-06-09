package domain

import (
	"encoding/json"
	"testing"
)

func TestAmount_ValidFloat(t *testing.T) {
	env := &ActionEnvelope{
		Parameters: json.RawMessage(`{"amount": 250.50}`),
	}
	amt, err := env.Amount()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if amt != 250.50 {
		t.Errorf("expected 250.50, got %f", amt)
	}
}

func TestAmount_ValidInteger(t *testing.T) {
	env := &ActionEnvelope{
		Parameters: json.RawMessage(`{"amount": 1000}`),
	}
	amt, err := env.Amount()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if amt != 1000 {
		t.Errorf("expected 1000, got %f", amt)
	}
}

func TestAmount_Zero(t *testing.T) {
	env := &ActionEnvelope{
		Parameters: json.RawMessage(`{"amount": 0}`),
	}
	amt, err := env.Amount()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if amt != 0 {
		t.Errorf("expected 0, got %f", amt)
	}
}

func TestAmount_MissingField(t *testing.T) {
	env := &ActionEnvelope{
		Parameters: json.RawMessage(`{"tool_name": "issue_refund"}`),
	}
	amt, err := env.Amount()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if amt != 0 {
		t.Errorf("expected 0 for missing amount, got %f", amt)
	}
}

func TestAmount_NilParameters(t *testing.T) {
	env := &ActionEnvelope{}
	amt, err := env.Amount()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if amt != 0 {
		t.Errorf("expected 0 for nil params, got %f", amt)
	}
}

// --- BYPASS TESTS: These verify that previously exploitable inputs are now rejected ---

// String amounts that parse as numbers are coerced — the previous
// behaviour (reject all strings) created a worse bypass because the
// hardened semantic from the CHANGELOG was a lie: a hostile envelope
// using "amount":"99999" tripped the reject path AND the proxy
// discarded the error, leaving amount=0 in fields. Now string-numeric
// is coerced and unparseable garbage / objects / bools still error.
func TestAmount_StringNumericIsParsed(t *testing.T) {
	cases := map[string]float64{
		`{"amount": "99999"}`:    99999,
		`{"amount": "10000.00"}`: 10000,
		`{"amount": "  1234 "}`:  1234, // whitespace tolerated
		`{"amount": ""}`:         0,    // empty string → no monetary action
	}
	for body, want := range cases {
		env := &ActionEnvelope{Parameters: json.RawMessage(body)}
		amt, err := env.Amount()
		if err != nil {
			t.Errorf("%s: unexpected error: %v", body, err)
			continue
		}
		if amt != want {
			t.Errorf("%s: got amount=%f want %f", body, amt, want)
		}
	}
}

func TestAmount_UnparseableStringRejected(t *testing.T) {
	for _, body := range []string{
		`{"amount": "abc"}`,
		`{"amount": "10k"}`,
		`{"amount": "$100"}`,
	} {
		env := &ActionEnvelope{Parameters: json.RawMessage(body)}
		_, err := env.Amount()
		if err == nil {
			t.Errorf("%s: expected AmountError, got nil", body)
		}
	}
}

func TestAmount_NegativeBypass_Rejected(t *testing.T) {
	// Negative amounts could inflate budget by reducing usedToday
	env := &ActionEnvelope{
		Parameters: json.RawMessage(`{"amount": -5000}`),
	}
	amt, err := env.Amount()
	if err == nil {
		t.Fatalf("negative amount should be rejected, got amount=%f", amt)
	}
}

func TestAmount_ObjectBypass_Rejected(t *testing.T) {
	// Nested object previously returned 0 silently
	env := &ActionEnvelope{
		Parameters: json.RawMessage(`{"amount": {"value": 99999}}`),
	}
	_, err := env.Amount()
	if err == nil {
		t.Fatal("object amount should be rejected")
	}
}

func TestAmount_BoolBypass_Rejected(t *testing.T) {
	env := &ActionEnvelope{
		Parameters: json.RawMessage(`{"amount": true}`),
	}
	_, err := env.Amount()
	if err == nil {
		t.Fatal("boolean amount should be rejected")
	}
}

func TestAmount_NullValue(t *testing.T) {
	env := &ActionEnvelope{
		Parameters: json.RawMessage(`{"amount": null}`),
	}
	_, err := env.Amount()
	if err == nil {
		t.Fatal("null amount should be rejected")
	}
}

func TestAmount_ArrayBypass_Rejected(t *testing.T) {
	env := &ActionEnvelope{
		Parameters: json.RawMessage(`{"amount": [100, 200]}`),
	}
	_, err := env.Amount()
	if err == nil {
		t.Fatal("array amount should be rejected")
	}
}
