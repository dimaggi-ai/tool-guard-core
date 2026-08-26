//go:build !windows

package main

import (
	"path/filepath"
	"testing"
)

func TestSyncAuditDirectory_RejectsMissingDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	if err := syncAuditDirectory(missing); err == nil {
		t.Fatal("syncAuditDirectory(missing) = nil, want platform open/sync error")
	}
}
