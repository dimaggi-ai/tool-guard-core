package engine

import (
	"testing"
)

// TestPhysicalPathCachedDriveShape checks what volumeNameOf and the drive
// branch of physicalPathCached return. The variable is the shape of the
// path: the drive with backslashes, the drive with slashes, a lower-case
// drive, and plain POSIX paths as controls. The check reads drive paths with
// slashes (the command text is decoded first), so a path with backslashes
// only has no ".." part to resolve and gets "" from physicalPathCached.
func TestPhysicalPathCachedDriveShape(t *testing.T) {
	cases := []struct {
		in   string
		vol  string
		phys string
	}{
		{`C:\dir\..\x`, "C:", ""},
		{`C:/dir/../x`, "C:", "C:/x"},
		{`c:/a/b/../x`, "c:", "c:/a/x"},
		{`C:/x`, "C:", ""},
		{`/x/../y`, "", "/y"},
		{`/x/y`, "", ""},
	}
	for _, c := range cases {
		if got := volumeNameOf(c.in); got != c.vol {
			t.Errorf("volumeNameOf(%q) = %q, want %q", c.in, got, c.vol)
		}
		if got := physicalPathCached(c.in, map[string]string{}); got != c.phys {
			t.Errorf("physicalPathCached(%q) = %q, want %q", c.in, got, c.phys)
		}
	}
}
