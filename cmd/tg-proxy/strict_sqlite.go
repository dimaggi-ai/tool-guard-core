//go:build sqlite_strict

package main

// When built with -tags sqlite_strict the strict SQLite classifier
// (rqlite/sql, pure Go) is linked in.
import _ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/sqlite"
