package engine

import (
	"os"
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
		os.Stderr.WriteString("WIN [" + p + "] volOf=[" + volumeNameOf(slash) + "] phys=[" + physicalPathCached(slash, map[string]string{}) + "]\n")
	}
}
