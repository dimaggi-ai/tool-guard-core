//go:build mysql_strict

package main

// When built with -tags mysql_strict the strict MySQL classifier
// (pingcap/tidb/pkg/parser, pure Go but heavy) is linked in.
import _ "github.com/dimaggi-ai/tool-guard-core/pkg/sqlguard/mysql"
