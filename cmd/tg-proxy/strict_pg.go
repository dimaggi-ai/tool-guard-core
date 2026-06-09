//go:build pg_strict

package main

// When built with -tags pg_strict the strict Postgres classifier
// (pg_query_go via cgo) is linked in. Its init() runs after lite's
// and replaces the "postgres" dialect entry via the registry's
// last-write-wins semantic.
import _ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/postgres"
