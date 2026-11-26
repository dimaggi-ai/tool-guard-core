//go:build darwin

package engine

import "syscall"

// mntNoWait is MNT_NOWAIT of <sys/mount.h>: getfsstat returns the cached
// statistics and does not ask a file system that may not answer.
const mntNoWait = 2

// remoteMountPoints returns the mount points of the FUSE and network file
// systems.
func remoteMountPoints() []string {
	n, err := syscall.Getfsstat(nil, mntNoWait)
	if err != nil || n <= 0 {
		return nil
	}
	buf := make([]syscall.Statfs_t, n+8)
	n, err = syscall.Getfsstat(buf, mntNoWait)
	if err != nil {
		return nil
	}
	var out []string
	for _, fs := range buf[:n] {
		if netRemoteType(cString(fs.Fstypename[:])) {
			out = append(out, cString(fs.Mntonname[:]))
		}
	}
	return out
}

func cString(b []int8) string {
	s := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		s = append(s, byte(c))
	}
	return string(s)
}
