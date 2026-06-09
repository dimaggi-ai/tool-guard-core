// Package lite provides tokenizer-based SQL classifiers for all four
// supported dialects (postgres, mysql, sqlite, mssql) using a single
// shared codebase. This is the OSS default — pure Go, no cgo, ~5 MB
// binary contribution.
//
// The strict variants in pkg/sqlguard/{postgres,mysql,sqlite} use
// real parsers (pg_query_go via cgo, pingcap/tidb/pkg/parser, rqlite/sql)
// and are accessible via build tags:
//
//	go build -tags pg_strict,mysql_strict,sqlite_strict ./cmd/tg-proxy
//
// Lite vs strict trade-off:
//
//   - lite is a tokenizer-driven first-keyword classifier with a state
//     machine for modifying-CTE detection. Covers every attack class
//     enumerated in the bruteforce suites (DROP/DELETE/UPDATE/INSERT,
//     COPY FROM PROGRAM, DO/EXECUTE, modifying CTE, dangerous PG
//     functions). Misses edge cases around exotic syntax (recursive
//     CTEs with deeply nested CASE expressions, etc).
//   - strict is the literal Postgres grammar (via pg_query_go) and
//     equivalent for MySQL / SQLite. Highest accuracy, biggest binary.
//
// Both report identical Classification shapes, so the engine and
// policy YAML are unchanged.
package lite
