package engine

import (
	"path/filepath"
	"runtime"
	"strings"
)

// Paths in the net (protect_net.go) are POSIX paths that start with "/".
// On Windows a path with a drive, C:\Users\x or C:/Users/x, is held as
// /C:/Users/x: the root "/" holds the drives as directories, and a path
// under it names the same file as the drive path. A UNC path,
// \\server\share\x, is held as /UNC/server/share/x; the check does not
// look into it (remote).

// netWindows is true when the net reads the paths of Windows.
var netWindows = runtime.GOOS == "windows"

func upperDrive(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 'a' + 'A'
	}
	return c
}

// netInternal returns the net form of a path of the system. On a system
// other than Windows it returns the path unchanged.
func netInternal(p string) string {
	if !netWindows {
		return p
	}
	p = strings.ReplaceAll(p, `\`, "/")
	if strings.HasPrefix(p, "//?/") || strings.HasPrefix(p, "//./") {
		p = p[len("//?/"):]
		if len(p) >= 4 && strings.EqualFold(p[:4], "UNC/") {
			return "/UNC/" + p[4:]
		}
	} else if strings.HasPrefix(p, "//") {
		return "/UNC/" + strings.TrimLeft(p, "/")
	}
	if len(p) >= 2 && isDriveLetter(p[0]) && p[1] == ':' && (len(p) == 2 || p[2] == '/') {
		return "/" + string(upperDrive(p[0])) + ":" + p[2:]
	}
	return p
}

// netOSPath returns the path of the system for a path of the net. ok is
// false for a path that names no file of the system: on Windows the root
// "/" and a path under it that does not start with a drive.
func netOSPath(p string) (string, bool) {
	if !netWindows {
		return p, true
	}
	if len(p) >= 3 && p[0] == '/' && isDriveLetter(p[1]) && p[2] == ':' && (len(p) == 3 || p[3] == '/') {
		if len(p) == 3 {
			return p[1:] + "/", true
		}
		return filepath.FromSlash(p[1:]), true
	}
	if strings.HasPrefix(p, "/UNC/") {
		return filepath.FromSlash("//" + p[len("/UNC/"):]), true
	}
	return "", false
}

// netDriveStarts returns, for each drive letter the pattern can read from
// the states set, the net directory of the drive root and the states after
// the letter and its colon: C: at the start of a reading names /C:.
func (p *netPattern) netDriveStarts(set []int32) (dirs []string, sets [][]int32) {
	if !netWindows {
		return nil, nil
	}
	for c := byte('A'); c <= 'Z'; c++ {
		var after []int32
		for _, l := range []byte{c, c - 'A' + 'a'} {
			s := p.step(set, l, false)
			if len(s) == 0 {
				continue
			}
			if s = p.step(s, ':', false); len(s) > 0 {
				after = append(after, s...)
			}
		}
		if len(after) > 0 {
			dirs = append(dirs, "/"+string(c)+":")
			sets = append(sets, p.closureOf(after))
		}
	}
	return dirs, sets
}
