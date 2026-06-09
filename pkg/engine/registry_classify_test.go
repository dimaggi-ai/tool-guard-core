package engine_test

import (
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/engine"
	"github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard"
	_ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/lite"
)

// The "DBA created cleanup_users() that internally drops" scenario.
// Without the registry, the function call slips through any
// AllowedFunctions check because cleanup_users isn't a known pg_*
// function. With a registry, the operator declares it belongs to
// `destructive` and the policy denies based on class.
func TestSQLClassify_FunctionRegistry_ClosesCustomUDFGap(t *testing.T) {
	// Install a registry naming cleanup_users as destructive.
	reg, err := sqlguard.ParseRegistry([]byte(`
functions:
  destructive:
    - cleanup_users
    - purge_audit_log
    - rotate_secret
  sensitive_read:
    - decrypt_field
    - get_user_pii
`))
	if err != nil {
		t.Fatalf("parse registry: %v", err)
	}
	sqlguard.SetRegistry(reg)
	t.Cleanup(func() { sqlguard.SetRegistry(nil) })

	cond := domain.Condition{
		SQLClassify: &domain.SQLClassify{
			Field:   "parameters.sql",
			Dialect: "postgres",
			Require: domain.SQLRequire{
				TopLevelKinds: []string{"SELECT"},
				DeniedFunctionClasses: []string{"destructive", "sensitive_read"},
			},
		},
	}

	// Cases the registry catches (would slip past without it).
	deny := []string{
		"SELECT cleanup_users()",
		"SELECT * FROM purge_audit_log()",
		"SELECT rotate_secret('token')",
		"SELECT decrypt_field(encrypted_blob) FROM secrets",
		"SELECT get_user_pii(42)",
	}
	for _, sql := range deny {
		t.Run("deny/"+sql, func(t *testing.T) {
			fields := map[string]interface{}{
				"tool_name":      "query",
				"parameters.sql": sql,
			}
			if !engine.EvalCondition(cond, fields) {
				t.Errorf("registry-class denied function not blocked: %q", sql)
			}
		})
	}

	// Sanity: clean SELECTs unaffected.
	clean := []string{
		"SELECT id FROM users",
		"SELECT count(*) FROM payments",
	}
	for _, sql := range clean {
		t.Run("allow/"+sql, func(t *testing.T) {
			fields := map[string]interface{}{
				"tool_name":      "query",
				"parameters.sql": sql,
			}
			if engine.EvalCondition(cond, fields) {
				t.Errorf("clean SELECT denied: %q", sql)
			}
		})
	}
}

// AllowedFunctionClasses is the inverse model: only registered
// safe-class functions pass. Anything outside the safe classes is
// denied — including unregistered functions.
func TestSQLClassify_FunctionRegistry_AllowedClassesOnly(t *testing.T) {
	reg, err := sqlguard.ParseRegistry([]byte(`
functions:
  safe_aggregate:
    - count
    - sum
    - avg
    - min
    - max
    - lower
    - upper
`))
	if err != nil {
		t.Fatalf("parse registry: %v", err)
	}
	sqlguard.SetRegistry(reg)
	t.Cleanup(func() { sqlguard.SetRegistry(nil) })

	cond := domain.Condition{
		SQLClassify: &domain.SQLClassify{
			Field:   "parameters.sql",
			Dialect: "postgres",
			Require: domain.SQLRequire{
				TopLevelKinds:          []string{"SELECT"},
				AllowedFunctionClasses: []string{"safe_aggregate"},
			},
		},
	}

	deny := []string{
		"SELECT pg_read_file('/etc/passwd')", // outside the safe class
		"SELECT now()",                       // not in safe_aggregate
		"SELECT cleanup_users()",             // unregistered = also outside
	}
	for _, sql := range deny {
		t.Run("deny/"+sql, func(t *testing.T) {
			fields := map[string]interface{}{
				"tool_name":      "query",
				"parameters.sql": sql,
			}
			if !engine.EvalCondition(cond, fields) {
				t.Errorf("outside-class function not denied: %q", sql)
			}
		})
	}

	allow := []string{
		"SELECT count(*) FROM users",
		"SELECT sum(amount), avg(amount), max(amount) FROM payments",
		"SELECT lower(email), upper(name) FROM users",
	}
	for _, sql := range allow {
		t.Run("allow/"+sql, func(t *testing.T) {
			fields := map[string]interface{}{
				"tool_name":      "query",
				"parameters.sql": sql,
			}
			if engine.EvalCondition(cond, fields) {
				t.Errorf("safe-class SELECT denied: %q", sql)
			}
		})
	}
}

// Missing registry + class-based predicate = fail-closed deny.
func TestSQLClassify_FunctionRegistry_FailsClosedWhenMissing(t *testing.T) {
	sqlguard.SetRegistry(nil)
	cond := domain.Condition{
		SQLClassify: &domain.SQLClassify{
			Field:   "parameters.sql",
			Dialect: "postgres",
			Require: domain.SQLRequire{
				TopLevelKinds:         []string{"SELECT"},
				DeniedFunctionClasses: []string{"destructive"},
			},
		},
	}
	fields := map[string]interface{}{
		"tool_name":      "query",
		"parameters.sql": "SELECT 1",
	}
	if !engine.EvalCondition(cond, fields) {
		t.Errorf("did not fail-closed when registry is nil but class predicate is set")
	}
}
