package engine

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
)

// The file lookups of the protect checks go through this file. A path at
// or under a FUSE or network mount (netRemoteMounts) is not looked into: a
// call there can wait on another process or host without end. Before a
// lookup, fsChain follows the path one part at a time, with the links in
// it, and stops with errRemoteMount at the first part that is on such a
// mount. So a link that points into a mount is not followed either.
//
// The sys* functions are the only places that call the system. Tests set
// fsTrace to see every path that is looked up.

// errRemoteMount is the error of a lookup that would reach a FUSE or
// network mount.
var errRemoteMount = errors.New("on a network or FUSE file system")

// fsTrace, when set, is called with each path before the system is asked
// about it. Only tests set it.
var fsTrace func(op, p string)

func sysLstat(p string) (os.FileInfo, error) {
	if fsTrace != nil {
		fsTrace("lstat", p)
	}
	return os.Lstat(p)
}

func sysStat(p string) (os.FileInfo, error) {
	if fsTrace != nil {
		fsTrace("stat", p)
	}
	return os.Stat(p)
}

func sysReadlink(p string) (string, error) {
	if fsTrace != nil {
		fsTrace("readlink", p)
	}
	return os.Readlink(p)
}

func sysReadDir(p string) ([]os.DirEntry, error) {
	if fsTrace != nil {
		fsTrace("readdir", p)
	}
	return os.ReadDir(p)
}

func sysOpen(p string) (*os.File, error) {
	if fsTrace != nil {
		fsTrace("open", p)
	}
	return os.Open(p)
}

func sysEvalSymlinks(p string) (string, error) {
	if fsTrace != nil {
		fsTrace("evalsymlinks", p)
	}
	return filepath.EvalSymlinks(p)
}

// fsGuarded reports whether lookups must follow paths part by part: there
// is a remote mount, or the system is Windows, where every UNC path is
// remote and a link can point to one.
func fsGuarded() bool {
	netRemoteOnce.Do(loadRemoteMounts)
	return netWindows || len(netRemoteMounts) > 0
}

// fsRemote reports whether a path of the system is at or under a remote
// mount.
func fsRemote(p string) bool {
	return remote(strings.TrimRight(netInternal(filepath.ToSlash(p)), "/"))
}

// fsMaxLinks is the number of links fsChain follows before it gives up, as
// the kernel does.
const fsMaxLinks = 255

var errTooManyLinks = errors.New("too many links")

// fsChain follows the absolute form of p one part at a time, with the
// links in it, and returns the physical path. It returns errRemoteMount
// when a part is on a remote mount, before the system is asked about that
// part. When follow is false, a link in the last part is not followed.
func fsChain(p string, follow bool) (string, error) {
	abs := p
	if !filepath.IsAbs(abs) {
		wd, err := fsGetwd()
		if err != nil {
			return "", err
		}
		abs = filepath.Join(wd, p)
	}
	sep := string(filepath.Separator)
	vol := filepath.VolumeName(abs)
	if fsRemote(vol + sep) {
		return "", errRemoteMount
	}
	rest := abs[len(vol):]
	dest := vol + sep
	links := 0
	for rest != "" {
		var part string
		i := strings.IndexAny(rest, `/`+sep)
		if i < 0 {
			part, rest = rest, ""
		} else {
			part, rest = rest[:i], rest[i+1:]
		}
		switch part {
		case "", ".":
			continue
		case "..":
			dest = filepath.Dir(dest)
			continue
		}
		next := filepath.Join(dest, part)
		if fsRemote(next) {
			return "", errRemoteMount
		}
		if !follow && strings.Trim(rest, `/`+sep) == "" {
			return next, nil
		}
		fi, err := sysLstat(next)
		if err != nil {
			return "", err
		}
		target := ""
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			if target, err = sysReadlink(next); err != nil {
				return "", err
			}
		case netWindows && fi.Mode()&os.ModeIrregular != 0:
			// A junction or a mount point: a reparse point that names
			// a place.
			target, _ = sysReadlink(next)
		}
		if target == "" {
			dest = next
			continue
		}
		if links++; links > fsMaxLinks {
			return "", errTooManyLinks
		}
		if v := filepath.VolumeName(target); v != "" || strings.HasPrefix(target, sep) || strings.HasPrefix(target, "/") {
			if v == "" {
				v = vol
			} else {
				vol = v
			}
			if fsRemote(v + sep) {
				return "", errRemoteMount
			}
			dest = v + sep
			target = target[len(filepath.VolumeName(target)):]
		}
		rest = target + sep + rest
	}
	return dest, nil
}

// fsGetwd is os.Getwd that does not reach a remote mount. os.Getwd looks
// up "." and $PWD; when the working directory is on a remote mount, it asks
// the system only for the name.
func fsGetwd() (string, error) {
	if !fsGuarded() || runtime.GOOS == "windows" {
		return os.Getwd()
	}
	wd, err := syscall.Getwd()
	if err != nil || fsRemote(wd) {
		return wd, err
	}
	pwd := os.Getenv("PWD")
	if filepath.IsAbs(pwd) {
		if _, err := fsChain(pwd, true); err != nil {
			return wd, nil
		}
	}
	// os.Getwd looks up "." and $PWD, both now known to be off the
	// remote mounts.
	if fsTrace != nil {
		fsTrace("stat", wd)
		if filepath.IsAbs(pwd) {
			fsTrace("stat", pwd)
		}
	}
	return os.Getwd()
}

// fsEvalSymlinks is filepath.EvalSymlinks that does not reach a remote
// mount.
func fsEvalSymlinks(p string) (string, error) {
	if !fsGuarded() {
		return sysEvalSymlinks(p)
	}
	r, err := fsChain(p, true)
	if err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" && filepath.IsAbs(p) {
		return r, nil
	}
	// Every part is now known to be off the remote mounts. On Windows the
	// system call also gives the long names and the case of the parts.
	return sysEvalSymlinks(p)
}

// fsParentsOK follows the parent directory of p and reports whether p
// can be looked up without reaching a remote mount.
func fsParentsOK(p string) error {
	if !fsGuarded() {
		return nil
	}
	_, err := fsChain(p, false)
	return err
}

// fsLstat is os.Lstat that does not reach a remote mount.
func fsLstat(p string) (os.FileInfo, error) {
	if err := fsParentsOK(p); err != nil {
		return nil, err
	}
	return sysLstat(p)
}

// fsReadlink is os.Readlink that does not reach a remote mount.
func fsReadlink(p string) (string, error) {
	if err := fsParentsOK(p); err != nil {
		return "", err
	}
	return sysReadlink(p)
}

// fsStat is os.Stat that does not reach a remote mount.
func fsStat(p string) (os.FileInfo, error) {
	if fsGuarded() {
		if _, err := fsChain(p, true); err != nil {
			return nil, err
		}
	}
	return sysStat(p)
}

// fsReadDir is os.ReadDir that does not reach a remote mount.
func fsReadDir(p string) ([]os.DirEntry, error) {
	if fsGuarded() {
		if _, err := fsChain(p, true); err != nil {
			return nil, err
		}
	}
	return sysReadDir(p)
}

// fsGlob is filepath.Glob that does not reach a remote mount. It is the
// code of filepath.Glob with its lookups replaced; a directory on a remote
// mount is read as one that cannot be opened.
func fsGlob(pattern string) ([]string, error) {
	return fsGlobDepth(pattern, 0)
}

func fsGlobDepth(pattern string, depth int) (matches []string, err error) {
	if depth == 10000 {
		return nil, filepath.ErrBadPattern
	}
	if _, err := filepath.Match(pattern, ""); err != nil {
		return nil, err
	}
	if !fsHasMeta(pattern) {
		if _, err = fsLstat(pattern); err != nil {
			return nil, nil
		}
		return []string{pattern}, nil
	}
	dir, file := filepath.Split(pattern)
	volumeLen := 0
	if runtime.GOOS == "windows" {
		volumeLen, dir = fsCleanGlobPathWindows(dir)
	} else {
		dir = fsCleanGlobPath(dir)
	}
	if !fsHasMeta(dir[volumeLen:]) {
		return fsGlobDir(dir, file, nil)
	}
	if dir == pattern {
		return nil, filepath.ErrBadPattern
	}
	m, err := fsGlobDepth(dir, depth+1)
	if err != nil {
		return nil, err
	}
	for _, d := range m {
		if matches, err = fsGlobDir(d, file, matches); err != nil {
			return matches, err
		}
	}
	return matches, nil
}

func fsCleanGlobPath(path string) string {
	switch path {
	case "":
		return "."
	case string(filepath.Separator):
		return path
	default:
		return path[:len(path)-1]
	}
}

func fsCleanGlobPathWindows(path string) (int, string) {
	vollen := len(filepath.VolumeName(path))
	switch {
	case path == "":
		return 0, "."
	case vollen+1 == len(path) && os.IsPathSeparator(path[len(path)-1]):
		return vollen + 1, path
	case vollen == len(path) && len(path) == 2:
		return vollen, path + "."
	default:
		if vollen >= len(path) {
			vollen = len(path) - 1
		}
		return vollen, path[:len(path)-1]
	}
}

func fsGlobDir(dir, pattern string, matches []string) ([]string, error) {
	fi, err := fsStat(dir)
	if err != nil || !fi.IsDir() {
		return matches, nil
	}
	list, err := sysReadDir(dir)
	if err != nil && len(list) == 0 {
		return matches, nil
	}
	names := make([]string, 0, len(list))
	for _, e := range list {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	for _, n := range names {
		ok, err := filepath.Match(pattern, n)
		if err != nil {
			return matches, err
		}
		if ok {
			matches = append(matches, filepath.Join(dir, n))
		}
	}
	return matches, nil
}

func fsHasMeta(path string) bool {
	magic := `*?[`
	if runtime.GOOS != "windows" {
		magic = `*?[\`
	}
	return strings.ContainsAny(path, magic)
}
