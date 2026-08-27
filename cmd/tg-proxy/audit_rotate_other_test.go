//go:build !windows

package main

import (
	"path/filepath"
	"testing"
)

func TestSyncAuditDirectory_RejectsMissingDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	ops := platformAuditRotationOps()
	if err := ops.syncDirectory(missing); err == nil {
		t.Fatal("platform rotation directory sync(missing) = nil, want open/sync error")
	}
}
