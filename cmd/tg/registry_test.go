package main

import (
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
)

// The tg CLI must register the default SQL dialects (via the blank imports
// in main.go) so sql_classify policies classify for real. Without them,
// sqlguard.Classify returns "no parser registered" and the fail-closed
// classifier fires, so `tg evaluate` would DENY benign SQL that tg-proxy
// allows. This test pins the registration so the CLI and proxy can't drift.
func TestCLIRegistersSQLDialects(t *testing.T) {
	registered := map[string]bool{}
	for _, d := range sqlguard.Dialects() {
		registered[d] = true
	}
	for _, want := range []string{"postgres", "mysql", "sqlite", "mssql"} {
		if !registered[want] {
			t.Errorf("SQL dialect %q is not registered in the tg CLI — sql_classify policies would fail-closed; check the blank imports in cmd/tg/main.go", want)
		}
	}
	// A benign SELECT must classify without a "no parser registered" error.
	if _, err := sqlguard.Classify("postgres", "SELECT 1"); err != nil {
		t.Errorf("postgres Classify returned an error (parser not linked?): %v", err)
	}
}
