// Package sqlguard parses SQL strings into a small, dialect-neutral
// Classification that policies can match against.
//
// The point is to make the proxy understand SQL semantically, so policy
// rules can demand "top-level statement must be SELECT" or "function calls
// must be in the allowlist" rather than fighting the open-ended family of
// regex evasions (DO blocks, COPY FROM PROGRAM, CALL of arbitrary
// procedures, runtime string-concat of destructive verbs, etc.).
//
// Each dialect (postgres, mysql, sqlite, mssql) lives in its own
// subpackage and registers a Classifier at init time. The engine looks
// up classifiers by dialect name and falls closed (deny) when an
// unknown dialect is requested.
package sqlguard
