package engine

import (
	"encoding/json"
	"testing"
)

// TestToFloat64_AllTypes pins toFloat64 against every supported and
// unsupported input type. Without this the function was 46% covered;
// these cases push it to 100% and lock the contract.
func TestToFloat64_AllTypes(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want *float64 // nil = expect nil
	}{
		{"float64", float64(3.14), f64(3.14)},
		{"float32", float32(2.5), f64(2.5)},
		{"int", int(42), f64(42)},
		{"int32", int32(7), f64(7)},
		{"int64", int64(99), f64(99)},
		{"json.Number ok", json.Number("12.5"), f64(12.5)},
		{"json.Number invalid → nil", json.Number("not-a-number"), nil},
		{"string ok", "100.00", f64(100)},
		{"string invalid → nil", "not-a-number", nil},
		{"bool → nil (unsupported)", true, nil},
		{"nil → nil", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := toFloat64(tc.in)
			switch {
			case got == nil && tc.want == nil:
				// ok
			case got == nil || tc.want == nil:
				t.Errorf("toFloat64(%v) nil mismatch: got=%v want=%v", tc.in, got, tc.want)
			case *got != *tc.want:
				t.Errorf("toFloat64(%v) = %v, want %v", tc.in, *got, *tc.want)
			}
		})
	}
}

func f64(v float64) *float64 { return &v }

// TestCompareIn_AllListShapes exercises compareIn's three legitimate
// list encodings ([]interface{}, []string, JSON-string-of-array) plus
// the unsupported-default branch.
func TestCompareIn_AllListShapes(t *testing.T) {
	if !compareIn("a", []interface{}{"a", "b"}) {
		t.Error("compareIn []interface{} hit case failed")
	}
	if compareIn("z", []interface{}{"a", "b"}) {
		t.Error("compareIn []interface{} miss case failed")
	}

	if !compareIn("a", []string{"a", "b"}) {
		t.Error("compareIn []string hit case failed")
	}
	if compareIn("z", []string{"a", "b"}) {
		t.Error("compareIn []string miss case failed")
	}

	// JSON-string-of-array shape — the policy DSL allows authors to
	// write "['a','b']" as a value when YAML quoting gets in the way.
	if !compareIn("a", `["a","b"]`) {
		t.Error("compareIn JSON-string hit case failed")
	}
	if compareIn("a", `not json`) {
		t.Error("compareIn bad JSON should not match")
	}

	// Unsupported list type → returns false (the default branch).
	if compareIn("a", 42) {
		t.Error("compareIn int list should return false")
	}
}

// TestCompareRegex covers the error path (invalid regex returns false).
func TestCompareRegex_InvalidPattern(t *testing.T) {
	if compareRegex("anything", "[unclosed") {
		t.Error("compareRegex with invalid regex should return false, not panic")
	}
	if !compareRegex("hello world", `^hello`) {
		t.Error("compareRegex with valid pattern should match")
	}
}
