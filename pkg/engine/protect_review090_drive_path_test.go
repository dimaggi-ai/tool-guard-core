package engine

import (
	"path/filepath"
	"testing"
)

// TestPhysicalPathCachedDriveShape prints what the Windows branch of
// physicalPathCached can see on this host. The shape of the path is the
// variable.
func TestPhysicalPathCachedDriveShape(t *testing.T) {
	// The variable is the shape of the drive path: the volume form, the
	// separator form, and a plain POSIX path as the control.
	for _, p := range []string{`C:\dir\..\x`, `C:dir\..\x`, `C:/dir/../x`, `c:/a/b/../x`, `/x/../y`, `rel/../y`} {
		slash := filepath.ToSlash(p)
		t.Logf("WIN [%s] volOf=[%s] phys=[%s]", p, volumeNameOf(slash), physicalPathCached(slash, map[string]string{}))
	}
}
