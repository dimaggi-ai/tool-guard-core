//go:build !darwin && !windows

package engine

import "os"

// remoteMountPoints returns the mount points of the FUSE and network file
// systems. A system without /proc/self/mountinfo gives none.
func remoteMountPoints() []string {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	return mountinfoRemote(string(data))
}
