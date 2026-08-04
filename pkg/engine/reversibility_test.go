package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	_ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/lite" // register SQL dialects
	"gopkg.in/yaml.v3"
)

// envFor builds a minimal envelope for a tool call with the given parameters.
func envFor(tool, group string, params map[string]any) domain.ActionEnvelope {
	var raw json.RawMessage
	if params != nil {
		b, _ := json.Marshal(params)
		raw = b
	}
	return domain.ActionEnvelope{
		EnvelopeID: "env-rev",
		Timestamp:  time.Now().UTC(),
		ToolName:   tool,
		ToolGroup:  group,
		Parameters: raw,
	}
}

func TestClassifyReversibility(t *testing.T) {
	cases := []struct {
		name   string
		tool   string
		group  string
		params map[string]any
		want   ReversibilityClass
	}{
		// ── Reversible: reads and trivially-undoable actions ──
		{"read tool", "read_file", "filesystem", nil, Reversible},
		{"list tool", "list_orders", "orders", nil, Reversible},
		{"get tool", "get_ticker", "market_data", nil, Reversible},
		{"add-label", "add_label", "gmail", nil, Reversible},
		{"create-draft", "create_draft", "gmail", nil, Reversible},
		{"camelCase get wins over object noun", "getRefundStatus", "", nil, Reversible},

		// ── Recoverable: undoable with effort ──
		{"update verb", "update_record", "crm", nil, Recoverable},
		{"edit verb", "edit_document", "docs", nil, Recoverable},
		{"filesystem_writes group", "write_file", "filesystem_writes", nil, Recoverable},

		// ── Irreversible: tool-group / tool-name signals ──
		{"payments group", "charge_card", "payments", nil, Irreversible},
		{"monetary_outflow group (refund demo)", "issue_refund", "monetary_outflow", nil, Irreversible},
		{"wire transfer name", "wire_transfer", "", nil, Irreversible},
		{"transfer verb", "transfer_funds", "", nil, Irreversible},
		{"payout noun anywhere", "process_payout", "", nil, Irreversible},
		{"deploy verb", "deploy_service", "", nil, Irreversible},
		{"publish verb", "publish_release", "", nil, Irreversible},
		{"physical actuation verb", "actuate_valve", "", nil, Irreversible},
		{"physical actuation group", "open", "physical_actuation", nil, Irreversible},
		{"send (irrevocable comms)", "send_email", "gmail", nil, Irreversible},
		{"delete-account exact name", "delete_account", "", nil, Irreversible},
		{"drop-database exact name", "dropDatabase", "", nil, Irreversible},

		// ── Irreversible: destructive SQL ──
		{"SQL DROP", "run_sql", "", map[string]any{"sql": "DROP TABLE users"}, Irreversible},
		{"SQL TRUNCATE", "run_sql", "", map[string]any{"sql": "TRUNCATE TABLE audit"}, Irreversible},
		{"SQL DELETE without WHERE", "run_sql", "", map[string]any{"sql": "DELETE FROM users"}, Irreversible},
		{"SQL DELETE with WHERE is Recoverable", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE id = 1"}, Recoverable},
		{"SQL UPDATE is Recoverable", "run_sql", "", map[string]any{"sql": "UPDATE users SET name = 'x' WHERE id = 1"}, Recoverable},
		{"SQL SELECT is Reversible", "run_sql", "", map[string]any{"sql": "SELECT * FROM users"}, Reversible},

		// ── Destructive shell ──
		{"shell rm -rf", "bash", "", map[string]any{"command": "rm -rf /data"}, Irreversible},
		{"shell rm single file is Recoverable", "bash", "", map[string]any{"command": "rm /tmp/file.txt"}, Recoverable},
		{"shell shred", "bash", "", map[string]any{"command": "shred -u secret.key"}, Irreversible},
		{"shell mkfs", "bash", "", map[string]any{"command": "mkfs.ext4 /dev/sdb"}, Irreversible},
		{"shell read-only ls", "bash", "", map[string]any{"command": "ls -la /tmp"}, Reversible},
		{"shell worst-of-segments", "bash", "", map[string]any{"command": "ls /etc && rm -rf /data"}, Irreversible},
		{"argv rm -rf", "shell", "", map[string]any{"argv": []any{"rm", "-rf", "/data"}}, Irreversible},

		// ── HTTP method ──
		{"HTTP GET", "http_request", "", map[string]any{"url": "https://api.example.com/x", "method": "GET"}, Reversible},
		{"HTTP DELETE is Recoverable", "http_request", "", map[string]any{"url": "https://api.example.com/x/1", "method": "DELETE"}, Recoverable},
		{"HTTP POST is Recoverable", "http_request", "", map[string]any{"url": "https://api.example.com/x", "method": "POST"}, Recoverable},

		// ── Unknown default (fail-safe) ──
		{"unrecognized tool", "frobnicate_widget", "misc", nil, Unknown},
		{"empty envelope", "", "", nil, Unknown},
		{"unknown shell prog stays Unknown", "bash", "", map[string]any{"command": "customtool --go"}, Unknown},

		// ── Hardening: destructive verbs hidden behind wrappers/substitution ──
		{"env-wrapped rm -rf", "bash", "", map[string]any{"command": "env rm -rf /data"}, Irreversible},
		{"sudo-wrapped rm -rf", "bash", "", map[string]any{"command": "sudo rm -rf /data"}, Irreversible},
		{"env with assignment then rm -rf", "bash", "", map[string]any{"command": "env FOO=bar rm -rf /data"}, Irreversible},
		{"timeout-wrapped rm -rf", "bash", "", map[string]any{"command": "timeout 5 rm -rf /data"}, Irreversible},
		{"command-substitution hides rm -rf", "bash", "", map[string]any{"command": "echo $(rm -rf /data)"}, Irreversible},
		{"backtick substitution hides shred", "bash", "", map[string]any{"command": "echo `shred -u k`"}, Irreversible},
		{"redirect overwrites a raw device", "bash", "", map[string]any{"command": "cat img > /dev/sda"}, Irreversible},
		{"redirect truncates a file is Recoverable", "bash", "", map[string]any{"command": "echo hi > /etc/motd"}, Recoverable},
		{"redirect to /dev/null is Reversible", "bash", "", map[string]any{"command": "echo hi > /dev/null"}, Reversible},

		// ── Hardening: SQL CTE / tautology / multi-statement / comments ──
		{"data-modifying CTE (DELETE) is Irreversible", "run_sql", "", map[string]any{"sql": "WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x"}, Irreversible},
		{"DELETE WHERE 1=1 is Irreversible (tautology)", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE 1=1"}, Irreversible},
		{"DELETE WHERE true is Irreversible (tautology)", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE true"}, Irreversible},
		{"unscoped DELETE + sibling SELECT WHERE is Irreversible", "run_sql", "", map[string]any{"sql": "DELETE FROM users; SELECT * FROM logs WHERE id = 1"}, Irreversible},
		{"WHERE hidden in a comment does not scope a DELETE", "run_sql", "", map[string]any{"sql": "DELETE FROM users -- WHERE id = 1"}, Irreversible},
		{"unscoped UPDATE is Irreversible", "run_sql", "", map[string]any{"sql": "UPDATE users SET banned = true"}, Irreversible},
		{"multi-statement with a DROP is Irreversible", "run_sql", "", map[string]any{"sql": "SELECT 1; DROP TABLE users"}, Irreversible},

		// ── Hardening: name tables ──
		{"deploy token in non-leading position", "trigger_deploy", "", nil, Irreversible},
		{"release token in non-leading position", "run_release", "", nil, Irreversible},
		{"delete_database exact name", "delete_database", "", nil, Irreversible},
		{"delete_production_data exact name", "delete_production_data", "", nil, Irreversible},
		{"get_deployment_status stays a read", "get_deployment_status", "", nil, Reversible},
		{"git force-push via +refspec", "shell", "", map[string]any{"argv": []any{"git", "push", "origin", "+main"}}, Irreversible},

		// ── Fail-safe: unknown tool name yields to a benign parsed command ──
		{"unknown tool name + benign ls is Reversible", "run", "", map[string]any{"command": "ls"}, Reversible},

		// ── Regression: keywords/WHERE inside string literals must be ignored ──
		{"DROP inside a string literal is a read", "run_sql", "", map[string]any{"sql": "SELECT * FROM articles WHERE title = 'How to DROP a table in SQL'"}, Reversible},
		{"TRUNCATE inside a string is a plain INSERT", "run_sql", "", map[string]any{"sql": "INSERT INTO audit(msg) VALUES ('nightly TRUNCATE done')"}, Recoverable},
		{"scoped DELETE whose value contains DROP stays Recoverable", "run_sql", "", map[string]any{"sql": "DELETE FROM t WHERE name = 'DROP'"}, Recoverable},
		{"dollar-quoted body with ; and DROP is one INSERT", "run_sql", "", map[string]any{"sql": "INSERT INTO events VALUES ($$a; DROP TABLE x$$)"}, Recoverable},
		{"backtick identifier with apostrophe cannot hide a DROP", "run_sql", "", map[string]any{"sql": "SELECT id FROM `a'b`; DROP TABLE users; SELECT `c'd`"}, Irreversible},
		{"backtick identifier named like a keyword is not a verb", "run_sql", "", map[string]any{"sql": "SELECT * FROM `drop`"}, Reversible},
		{"data-modifying INSERT-CTE with a dollar body is Irreversible", "run_sql", "", map[string]any{"sql": "WITH w AS (INSERT INTO audit VALUES ($$logged$$) RETURNING id) SELECT id FROM w"}, Irreversible},
		{"backtick table in an unscoped DELETE is Irreversible", "run_sql", "", map[string]any{"sql": "DELETE FROM `a'b`"}, Irreversible},
		{"WHERE inside a bracket identifier does not scope a DELETE", "run_sql", "", map[string]any{"sql": "DELETE FROM [t WHERE id=5]"}, Irreversible},
		{"WHERE inside a bracket identifier does not scope an UPDATE", "run_sql", "", map[string]any{"sql": "UPDATE [t WHERE x=1] SET c=2"}, Irreversible},
		{"real WHERE after a bracket table stays scoped", "run_sql", "", map[string]any{"sql": "DELETE FROM [my table] WHERE id=5"}, Recoverable},
		{"WHERE hidden in a MySQL # comment does not scope a DELETE", "run_sql", "", map[string]any{"sql": "DELETE FROM t #WHERE id=5"}, Irreversible},
		{"T-SQL no-semicolon: leading SELECT WHERE cannot scope a trailing DELETE", "run_sql", "", map[string]any{"sql": "SELECT * FROM logs WHERE severity='high' DELETE FROM users"}, Irreversible},
		{"T-SQL no-semicolon: scoped UPDATE then unscoped DELETE is Irreversible", "run_sql", "", map[string]any{"sql": "UPDATE settings SET v=1 WHERE k='a' DELETE FROM users"}, Irreversible},
		{"subquery WHERE in SET clause does not scope an unscoped UPDATE", "run_sql", "", map[string]any{"sql": "UPDATE t SET c=(SELECT x FROM u WHERE y=1)"}, Irreversible},
		{"UPDATE scoped by a real WHERE after a subquery SET stays Recoverable", "run_sql", "", map[string]any{"sql": "UPDATE t SET c=(SELECT x FROM u WHERE y=1) WHERE id=2"}, Recoverable},
		{"DELETE scoped by its own subquery WHERE stays Recoverable", "run_sql", "", map[string]any{"sql": "DELETE FROM t WHERE id IN (SELECT id FROM u WHERE x=1)"}, Recoverable},

		// ── Regression: find as a command executor / mass deleter ──
		{"find -delete is Irreversible", "bash", "", map[string]any{"command": "find /important/data -delete"}, Irreversible},
		{"find -exec rm -rf is Irreversible", "bash", "", map[string]any{"command": "find / -name '*.db' -exec rm -rf {} +"}, Irreversible},
		{"plain find (search) stays Reversible", "bash", "", map[string]any{"command": "find . -name '*.go'"}, Reversible},
		{"sort -o writes a file (Recoverable)", "bash", "", map[string]any{"command": "sort -o /etc/hosts /etc/hosts"}, Recoverable},
		{"plain sort stays Reversible", "bash", "", map[string]any{"command": "sort names.txt"}, Reversible},
		{"wrapped find -delete is Irreversible", "bash", "", map[string]any{"command": "sudo find /data -delete"}, Irreversible},

		// ── Regression: kernel/hardware control-surface redirects ──
		{"redirect to /proc/sysrq-trigger is Irreversible", "bash", "", map[string]any{"command": "echo b > /proc/sysrq-trigger"}, Irreversible},
		{"redirect under /sys is Irreversible", "bash", "", map[string]any{"command": "echo 1 > /sys/kernel/x"}, Irreversible},

		// ── Round-6: write-capable command targeting a raw device via an operand ──
		{"uniq output operand to a device is Irreversible", "bash", "", map[string]any{"command": "uniq /etc/passwd /dev/sda"}, Irreversible},
		{"uniq with two file operands is Recoverable", "bash", "", map[string]any{"command": "uniq in.txt out.txt"}, Recoverable},
		{"plain uniq stays Reversible", "bash", "", map[string]any{"command": "uniq names.txt"}, Reversible},
		{"cp to a raw device is Irreversible", "bash", "", map[string]any{"command": "cp /dev/zero /dev/sda"}, Irreversible},
		{"tee to a control surface is Irreversible", "bash", "", map[string]any{"command": "tee /proc/sysrq-trigger"}, Irreversible},
		{"sort -o to a device is Irreversible", "bash", "", map[string]any{"command": "sort -o /dev/sda in"}, Irreversible},
		{"wrapped cp to a device is Irreversible", "bash", "", map[string]any{"command": "sudo cp x /dev/nvme0n1"}, Irreversible},
		{"cp between regular files stays Recoverable", "bash", "", map[string]any{"command": "cp a.txt b.txt"}, Recoverable},

		// ── Round-6: nested block comment cannot fake-scope a write ──
		{"nested block comment does not scope an UPDATE", "run_sql", "", map[string]any{"sql": "UPDATE accounts SET balance=0 /* x /* y */ WHERE id=1 */"}, Irreversible},
		{"nested block comment does not scope a DELETE", "run_sql", "", map[string]any{"sql": "DELETE FROM users /* a /* b */ WHERE id=1 */"}, Irreversible},

		// ── Round-7: comparison-operator tautologies ──
		{"WHERE 1<2 is a tautology (unscoped DELETE)", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE 1<2"}, Irreversible},
		{"WHERE 2>1 is a tautology", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE 2>1"}, Irreversible},
		{"WHERE 1<>2 is a tautology", "run_sql", "", map[string]any{"sql": "UPDATE accounts SET balance=0 WHERE 1<>2"}, Irreversible},
		{"WHERE 1>2 (constant-only, no column) escalates", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE 1>2"}, Irreversible}, // always-false no-op; constant-only predicate over-approximates to whole-relation (safe)
		{"genuinely scoped WHERE col<18 stays Recoverable", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE age<18"}, Recoverable},

		// ── Round-8: constant-only predicates (whole family) via column-reference rule ──
		{"WHERE 1=1 OR true is a tautology", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE 1=1 OR true"}, Irreversible},
		{"WHERE NOT 1=2 is a tautology", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE NOT 1=2"}, Irreversible},
		{"WHERE 2 BETWEEN 1 AND 3 is a tautology", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE 2 BETWEEN 1 AND 3"}, Irreversible},
		{"WHERE 1 IN (1) is a tautology", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE 1 IN (1)"}, Irreversible},
		{"WHERE huge<>1 (overflow) is a tautology", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE 99999999999999999999 <> 1"}, Irreversible},
		{"real scope WHERE status IN (subquery) stays Recoverable", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE status IN (SELECT s FROM flags)"}, Recoverable},
		{"real scope WHERE col IS NULL stays Recoverable", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE deleted_at IS NULL"}, Recoverable},
		{"tautology disjunct in OR: col=5 OR 1=1", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE id=5 OR 1=1"}, Irreversible},
		{"tautology disjunct: col=col OR x=1", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE name=name OR x=1"}, Irreversible},
		{"genuine OR of scoped predicates stays Recoverable", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE region='EU' OR region='US'"}, Recoverable},
		{"col=5 OR (always-false) stays scoped Recoverable", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE id=5 OR 1>2"}, Recoverable},
		{"AND of tautologies: col=col AND 1=1", "run_sql", "", map[string]any{"sql": "DELETE FROM users WHERE name=name AND 1=1"}, Irreversible},
		{"parenthesized tautology conjunct in OR", "run_sql", "", map[string]any{"sql": "UPDATE t SET x=1 WHERE (name=name AND 1=1) OR z=3"}, Irreversible},
		{"double-parens tautology", "run_sql", "", map[string]any{"sql": "DELETE FROM t WHERE ((1=1))"}, Irreversible},
		{"scoped AND with a tautology conjunct stays Recoverable", "run_sql", "", map[string]any{"sql": "DELETE FROM t WHERE col=5 AND 1=1"}, Recoverable},
		{"OR of two parenthesized scoped predicates stays Recoverable", "run_sql", "", map[string]any{"sql": "DELETE FROM t WHERE (status='x') OR (status='y')"}, Recoverable},

		// ── Round-8: find file-writing predicates ──
		{"find -fprint to a device is Irreversible", "bash", "", map[string]any{"command": "find / -fprint /dev/sda"}, Irreversible},
		{"find -fprintf to a regular file is Recoverable", "bash", "", map[string]any{"command": "find . -fprintf /etc/passwd '%p'"}, Recoverable},

		// ── Round-7: device path glued to a short option ──
		{"sort -o glued to a device is Irreversible", "bash", "", map[string]any{"command": "sort -o/dev/sda /etc/hosts"}, Irreversible},

		// ── Round-7: plural destructive datastore names ──
		{"delete_backups (plural) is Irreversible", "delete_backups", "", nil, Irreversible},
		{"drop_tables (plural) is Irreversible", "drop_tables", "", nil, Irreversible},
		{"delete_snapshots is Irreversible", "delete_snapshots", "", nil, Irreversible},
		{"delete_user_session (record-level) stays Recoverable", "delete_user_session", "", nil, Recoverable},

		// ── Regression: wrapper option that takes a value must not be the peel target ──
		{"env -u VALUE then rm -rf", "bash", "", map[string]any{"command": "env -u ls rm -rf /"}, Irreversible},
		{"sudo -u USER then rm -rf", "bash", "", map[string]any{"command": "sudo -u root rm -rf /data"}, Irreversible},
		{"xargs -I REPL then rm -rf", "shell", "", map[string]any{"argv": []any{"xargs", "-I", "ls", "rm", "-rf", "/"}}, Irreversible},
		{"benign wrapped read (sudo cat) stays Reversible", "bash", "", map[string]any{"command": "sudo cat /etc/hosts"}, Reversible},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyReversibility(envFor(tc.tool, tc.group, tc.params))
			if got != tc.want {
				t.Errorf("ClassifyReversibility(tool=%q, group=%q, params=%v) = %q, want %q",
					tc.tool, tc.group, tc.params, got, tc.want)
			}
		})
	}
}

// TestReversibilityHelpers white-box-tests the lower-level helpers so each
// operator/branch is pinned directly (not only via ClassifyReversibility).
func TestReversibilityHelpers(t *testing.T) {
	// constPredicateTrue: always-true evaluation for OR-disjuncts.
	constTrue := map[string]bool{
		"true": true, "1": true, "false": false, "0": false,
		"1=1": true, "1=2": false, "1<>2": true, "1!=1": false,
		"1<2": true, "2<1": false, "3>2": true, "2>3": false,
		"1<=1": true, "2<=1": false, "5>=5": true, "4>=9": false,
		"x=x": true, "x<x": false, "x<=x": true,
		"2 BETWEEN 1 AND 3": true, // un-evaluable const -> over-approx true
	}
	for in, want := range constTrue {
		if got := constPredicateTrue(in); got != want {
			t.Errorf("constPredicateTrue(%q)=%v want %v", in, got, want)
		}
	}
	// stripOptionPrefix
	sop := map[string]string{
		"--output=/dev/sda": "/dev/sda", "-o/dev/sda": "/dev/sda",
		"/dev/sda": "/dev/sda", "-o": "-o", "--verbose": "--verbose",
		"plain.txt": "plain.txt", "my/dev/x": "my/dev/x",
	}
	for in, want := range sop {
		if got := stripOptionPrefix(in); got != want {
			t.Errorf("stripOptionPrefix(%q)=%q want %q", in, got, want)
		}
	}
	// httpMethodReversibility (all method families)
	hm := map[string]ReversibilityClass{
		"GET": Reversible, "HEAD": Reversible, "OPTIONS": Reversible, "TRACE": Reversible,
		"POST": Recoverable, "PUT": Recoverable, "PATCH": Recoverable, "DELETE": Recoverable,
		"PROPFIND": Unknown, "": Unknown,
	}
	for in, want := range hm {
		if got := httpMethodReversibility(in); got != want {
			t.Errorf("httpMethodReversibility(%q)=%s want %s", in, got, want)
		}
	}
	// isDurationOrNumber
	dur := map[string]bool{"5": true, "5s": true, "1m": true, "2h": true, "0.5": true, "": false, "abc": false, "5x5": false}
	for in, want := range dur {
		if got := isDurationOrNumber(in); got != want {
			t.Errorf("isDurationOrNumber(%q)=%v want %v", in, got, want)
		}
	}
	// redirectReversibility
	rr := []struct {
		tgt        string
		unresolved bool
		want       ReversibilityClass
	}{
		{"/dev/null", false, Reversible}, {"/dev/sda", false, Irreversible},
		{"/proc/sysrq-trigger", false, Irreversible}, {"/sys/x", false, Irreversible},
		{"/tmp/out.txt", false, Recoverable}, {"anything", true, Unknown},
	}
	for _, c := range rr {
		if got := redirectReversibility(redirTarget{value: c.tgt, unresolved: c.unresolved}); got != c.want {
			t.Errorf("redirectReversibility(%q,unres=%v)=%s want %s", c.tgt, c.unresolved, got, c.want)
		}
	}
	// isGitForcePush
	if !isGitForcePush([]string{"push", "origin", "+main"}) {
		t.Error("git push +main should be force")
	}
	if !isGitForcePush([]string{"push", "-f"}) || isGitForcePush([]string{"push", "origin", "main"}) {
		t.Error("git force-push detection wrong")
	}
}

// TestSQLSkeletonEdgeCases pins the length-preserving literal/comment blanking
// against quoting edge cases, so a later change cannot silently reopen the
// string-literal keyword-injection holes.
func TestSQLSkeletonEdgeCases(t *testing.T) {
	cases := []struct {
		sql  string
		want ReversibilityClass
	}{
		{"SELECT $1, $2 FROM t WHERE id = $1", Reversible},                  // bind params, not dollar-quotes
		{"SELECT '' AS empty FROM t", Reversible},                           // empty string literal
		{"SELECT 'a''b DROP' FROM t", Reversible},                           // doubled-quote escape, DROP in string
		{`SELECT "weird DROP col" FROM t`, Reversible},                      // DROP in a quoted identifier
		{"SELECT 1 /* DROP TABLE x */ FROM t", Reversible},                  // DROP in a block comment
		{"SELECT 1 FROM t -- ; DELETE FROM u\n", Reversible},                // ; and DELETE in a line comment
		{"UPDATE t SET note = 'has ; and WHERE' WHERE id = 5", Recoverable}, // scoped; string has ; and WHERE
		{"SELECT 'unterminated DROP", Reversible},                           // unterminated string runs to end, safe
	}
	for _, tc := range cases {
		t.Run(tc.sql, func(t *testing.T) {
			got := sqlReversibility(tc.sql)
			if got != tc.want {
				t.Errorf("sqlReversibility(%q) = %q, want %q", tc.sql, got, tc.want)
			}
		})
	}
}

// TestSQLSkeletonInvariants asserts the two safety invariants of sqlSkeleton
// (byte-length preservation, so downstream offsets never go out of range; and
// no panic on adversarial/malformed input) and that sqlReversibility itself
// never panics on the same inputs.
func TestSQLSkeletonInvariants(t *testing.T) {
	inputs := []string{
		"", "'", "\"", "$", "$$", "$tag$", "--", "/*", "/*/", "*/",
		"'unterminated", "\"unterminated", "$$unterminated",
		"$tag$ body no close",
		"SELECT '' '' '' FROM t",
		"SELECT 'a''b''c' FROM t",
		"SELECT \"a\"\"b\" FROM t",
		"SELECT $1, $2, $3 FROM t WHERE id = $1",
		"WITH x AS (DELETE FROM t) SELECT * FROM x",
		"DROP TABLE x; -- '\nSELECT 1",
		"SELECT '/*' FROM t /* '); DROP TABLE x -- */",
		"$$ ; ; ; DROP TABLE x $$",
		"$a$ nested $b$ still-a $b$ close-a $a$",
		"'\\'; DROP TABLE users; --",
		"SELECT 1\r\nFROM t\r\nWHERE 1=1",
		"''''''''",
		"\\\\\\'",
		"select 'DROP' as x, \"TRUNCATE\" from \"tbl\"",
		"`", "``", "`a'b`", "`unterminated", "`a``b`;DROP TABLE x",
		"SELECT `a'b`; DROP TABLE users; SELECT `c'd`",
		"$1 $2 $1$ WHERE",
		"[", "[unterminated", "[a]]b]", "DELETE FROM [t WHERE x]",
		"#", "# c", "SELECT 1 # ;DROP", "DELETE FROM t #WHERE x",
	}
	for _, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("panic on input %q: %v", in, r)
				}
			}()
			sk := sqlSkeleton(in)
			if len(sk) != len(in) {
				t.Errorf("sqlSkeleton(%q): length %d != input length %d", in, len(sk), len(in))
			}
			_ = sqlReversibility(in) // must not panic
		}()
	}
}

// FuzzSQLSkeleton hammers the literal/comment blanker with random input to
// prove it never panics and always preserves byte length (the invariants the
// downstream offset math depends on).
func FuzzSQLSkeleton(f *testing.F) {
	for _, s := range []string{
		"SELECT 1", "'a''b'", "$$x$$", "-- c", "DELETE FROM t WHERE 1=1",
		"$tag$ ; $tag$", "'\\'; DROP", "\"id\"", "/* */",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		sk := sqlSkeleton(s)
		if len(sk) != len(s) {
			t.Fatalf("length not preserved: %d vs %d for %q", len(sk), len(s), s)
		}
		_ = sqlReversibility(s) // must not panic
	})
}

// FuzzSQLForParser proves the parser-sanitizer never panics on arbitrary input
// (a bad output only makes the parser fail and fall back to the safe skeleton
// keyword path, but a panic would take down the caller).
func FuzzSQLForParser(f *testing.F) {
	for _, s := range []string{
		"SELECT 1", "`a'b`", "$$x$$", "$tag$y$tag$", "'\\'", "``", "$", "`",
		"WITH w AS (INSERT INTO a VALUES ($$q$$)) SELECT 1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = sqlForParser(s)     // must not panic
		_ = sqlReversibility(s) // exercises the whole SQL path
	})
}

// FuzzShellReversibility hammers the shell path (tokenizer, wrapper unwrap,
// danger scan, command-substitution recursion, redirect handling) to prove it
// never panics on arbitrary command strings.
func FuzzShellReversibility(f *testing.F) {
	for _, s := range []string{
		"rm -rf /", "env -u ls rm -rf /", "echo $(rm -rf /)", "sudo -u root rm x",
		"a > /dev/sda", "ls && rm -rf .", "timeout 5 shred k", "`x`", "$(", "|| |",
		"xargs -I", "sudo", "env",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = shellStringReversibility(s) // must not panic
	})
}

// TestSQLKeywordFallback pins the dialect-free path directly, so the
// destructive-SQL mapping is covered even in a deployment where no sqlguard
// parser is linked into the binary.
func TestSQLKeywordFallback(t *testing.T) {
	cases := []struct {
		sql  string
		want ReversibilityClass
	}{
		{"DROP TABLE users", Irreversible},
		{"truncate table audit", Irreversible},
		{"DELETE FROM users", Irreversible},
		{"DELETE FROM users WHERE id = 1", Recoverable},
		{"UPDATE users SET x = 1", Irreversible}, // no WHERE: overwrites every row
		{"UPDATE users SET x = 1 WHERE id = 2", Recoverable},
		{"INSERT INTO users VALUES (1)", Recoverable},
		{"SELECT * FROM users", Reversible},
		{"EXPLAIN ANALYZE foo", Unknown},
		{"", Unknown},
	}
	for _, tc := range cases {
		t.Run(tc.sql, func(t *testing.T) {
			if got := sqlKeywordFallback(tc.sql); got != tc.want {
				t.Errorf("sqlKeywordFallback(%q) = %q, want %q", tc.sql, got, tc.want)
			}
		})
	}
}

// TestHasSQLWord confirms whole-word matching (no substring false positives).
func TestHasSQLWord(t *testing.T) {
	if hasSQLWord("SELECT elsewhere FROM t", "WHERE") {
		t.Error("hasSQLWord matched WHERE inside the column name 'elsewhere'")
	}
	if !hasSQLWord("delete from t where id=1", "WHERE") {
		t.Error("hasSQLWord failed to match a real WHERE clause")
	}
}

func TestHasRecursiveFlag(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"-rf", "/x"}, true},
		{[]string{"-fr", "/x"}, true},
		{[]string{"-R", "/x"}, true},
		{[]string{"--recursive", "/x"}, true},
		{[]string{"-f", "/x"}, false},
		{[]string{"/x"}, false},
		{[]string{"--force", "/x"}, false},
	}
	for _, tc := range cases {
		if got := hasRecursiveFlag(tc.args); got != tc.want {
			t.Errorf("hasRecursiveFlag(%v) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

// TestReversibilityFieldExposed proves the class is available to rule
// conditions as the flattened "reversibility" field.
func TestReversibilityFieldExposed(t *testing.T) {
	env := envFor("wire_transfer", "payments", nil)
	fields := FlattenEnvelope(&env)
	if got := fields["reversibility"]; got != "irreversible" {
		t.Fatalf("fields[\"reversibility\"] = %v, want \"irreversible\"", got)
	}
	// And it must be matchable with a normal leaf condition.
	cond := domain.Condition{Field: "reversibility", Operator: domain.OpEq, Value: "irreversible"}
	if !EvalCondition(cond, fields) {
		t.Error("expected {field: reversibility, eq, irreversible} to match")
	}
}

// TestFloorDoesNotNullifyCoLoadedShadowPolicy proves the always-matching
// enforcement floor does not silently enforce a co-loaded SHADOW policy's own
// (higher-severity) decision, nor suppress its near-miss telemetry.
func TestFloorDoesNotNullifyCoLoadedShadowPolicy(t *testing.T) {
	floor := domain.Policy{
		PolicyID: "floor", Version: 1, Mode: domain.PolicyModeEnforcement, Status: domain.PolicyStatusApproved,
		Rules: []domain.Rule{{RuleID: "f1", Effect: domain.EffectEscalate, EffectConfig: domain.EffectConfig{Severity: "high"},
			Conditions: domain.Condition{Field: "reversibility", Operator: domain.OpEq, Value: "irreversible"}}},
	}
	shadowDeny := domain.Policy{
		PolicyID: "refundcap", Version: 1, Mode: domain.PolicyModeShadow, Status: domain.PolicyStatusApproved,
		Scope: domain.PolicyScope{ToolNames: []string{"issue_refund"}},
		Rules: []domain.Rule{{RuleID: "r1", Effect: domain.EffectDeny, EffectConfig: domain.EffectConfig{Severity: "critical"},
			Conditions: domain.Condition{Field: "amount", Operator: domain.OpGt, Value: float64(1000)}}},
	}
	env := makeEnvelope(5000, "issue_refund", "a", "o")
	res := NewEvaluator().Evaluate(env, []domain.Policy{floor, shadowDeny}, domain.PolicyModeShadow)
	if res.Decision != domain.DecisionDenied {
		t.Fatalf("decision=%v want denied", res.Decision)
	}
	if res.ActionTaken == domain.ActionDenied {
		t.Errorf("co-loaded shadow policy was ENFORCED (action=%v); the floor nullified shadow mode", res.ActionTaken)
	}
	if !res.IsNearMiss {
		t.Error("shadow deny should be recorded as a near-miss")
	}
	// And the floor still enforces an irreversible action it OWNS, even in a shadow deployment.
	env2 := envFor("wire_transfer", "payments", nil)
	res2 := NewEvaluator().Evaluate(&env2, []domain.Policy{floor}, domain.PolicyModeShadow)
	if res2.ActionTaken != domain.ActionEscalated {
		t.Errorf("floor should enforce its own irreversible escalation even in shadow deployment, got %v", res2.ActionTaken)
	}
}

// loadYAMLPolicy loads a shipped YAML policy the same way the proxy loader
// does (YAML → JSON → domain.Policy), so the engine test exercises the real
// on-disk policy file.
func loadYAMLPolicy(t *testing.T, path string) domain.Policy {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read policy %s: %v", path, err)
	}
	var raw any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		t.Fatalf("parse YAML %s: %v", path, err)
	}
	js, err := json.Marshal(normalizeYAMLTest(raw))
	if err != nil {
		t.Fatalf("yaml→json %s: %v", path, err)
	}
	var pol domain.Policy
	if err := json.Unmarshal(js, &pol); err != nil {
		t.Fatalf("decode policy %s: %v", path, err)
	}
	return pol
}

// normalizeYAMLTest rewrites any map[any]any nodes into map[string]any so
// encoding/json can marshal the parsed YAML (mirrors the proxy loader).
func normalizeYAMLTest(v any) any {
	switch m := v.(type) {
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[fmt.Sprint(k)] = normalizeYAMLTest(val)
		}
		return out
	case map[string]any:
		for k, val := range m {
			m[k] = normalizeYAMLTest(val)
		}
		return m
	case []any:
		for i, x := range m {
			m[i] = normalizeYAMLTest(x)
		}
		return m
	default:
		return v
	}
}

// TestIrreversibilityFloorPolicy is the evaluator-level integration test: it
// loads the shipped policies/irreversibility_floor.yaml and proves an
// irreversible action escalates while a reversible one is allowed.
func TestIrreversibilityFloorPolicy(t *testing.T) {
	policy := loadYAMLPolicy(t, filepath.Join("..", "..", "policies", "irreversibility_floor.yaml"))
	if err := ValidatePolicy(&policy); err != nil {
		t.Fatalf("shipped policy failed validation: %v", err)
	}
	if policy.Status != domain.PolicyStatusApproved {
		t.Fatalf("policy status = %q, want approved (so it is actually enforced)", policy.Status)
	}

	cases := []struct {
		name   string
		tool   string
		group  string
		params map[string]any
		want   domain.Decision
	}{
		{"wire transfer escalates", "wire_transfer", "payments", nil, domain.DecisionEscalated},
		{"refund escalates", "issue_refund", "monetary_outflow", map[string]any{"amount": 20}, domain.DecisionEscalated},
		{"DROP TABLE escalates", "run_sql", "", map[string]any{"sql": "DROP TABLE users"}, domain.DecisionEscalated},
		{"rm -rf escalates", "bash", "", map[string]any{"command": "rm -rf /data"}, domain.DecisionEscalated},
		// Fail-safe: an action the classifier cannot recognize (Unknown) must
		// escalate, NOT fall through to the engine's default-allow.
		{"unrecognized tool escalates (fail-safe)", "frobnicate_widget", "misc", nil, domain.DecisionEscalated},
		{"unknown shell prog escalates (fail-safe)", "bash", "", map[string]any{"command": "customtool --wipe"}, domain.DecisionEscalated},
		{"wrapper-hidden rm -rf escalates", "bash", "", map[string]any{"command": "sudo rm -rf /data"}, domain.DecisionEscalated},
		{"read is allowed", "get_ticker", "market_data", nil, domain.DecisionAllowed},
		{"add-label is allowed", "add_label", "gmail", nil, domain.DecisionAllowed},
		// Recoverable (scoped write) is permitted — it is undoable with effort.
		{"scoped UPDATE is allowed", "run_sql", "", map[string]any{"sql": "UPDATE users SET x = 1 WHERE id = 2"}, domain.DecisionAllowed},
	}

	eval := NewEvaluator()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := envFor(tc.tool, tc.group, tc.params)
			result := eval.Evaluate(&env, []domain.Policy{policy}, domain.PolicyModeEnforcement)
			if result.Decision != tc.want {
				t.Fatalf("decision = %q, want %q (reason: %s)", result.Decision, tc.want, result.DecisionReason)
			}
			if tc.want == domain.DecisionEscalated && result.ActionTaken != domain.ActionEscalated {
				t.Errorf("action_taken = %q, want escalated", result.ActionTaken)
			}
		})
	}
}
