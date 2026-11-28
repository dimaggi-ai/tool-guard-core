//go:build windows

package engine

import (
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	netKernel32         = syscall.NewLazyDLL("kernel32.dll")
	netGetLogicalDrives = netKernel32.NewProc("GetLogicalDrives")
	netGetDriveType     = netKernel32.NewProc("GetDriveTypeW")
)

// driveRemote is the GetDriveType value of a network drive.
const driveRemote = 4

// netDriveLetters returns the letters of the drives of the system.
func netDriveLetters() []byte {
	mask, _, _ := netGetLogicalDrives.Call()
	var out []byte
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) != 0 {
			out = append(out, byte('A'+i))
		}
	}
	return out
}

// netDriveNames returns the names of the drives, C: and the others, as
// the root of the net lists them.
func netDriveNames() []string {
	var out []string
	for _, l := range netDriveLetters() {
		out = append(out, string(l)+":")
	}
	return out
}

// remoteMountPoints returns the network drives and the root of the UNC
// paths: a call into one can wait on another host.
func remoteMountPoints() []string {
	out := []string{`\\`}
	for _, l := range netDriveLetters() {
		root, err := syscall.UTF16PtrFromString(string(l) + `:\`)
		if err != nil {
			continue
		}
		if t, _, _ := netGetDriveType.Call(uintptr(unsafe.Pointer(root))); t == driveRemote {
			out = append(out, string(l)+":/")
		}
	}
	return out
}

// netShortNames returns the short 8.3 names of the entries of the
// directory dir, each with the name of its entry. An entry whose name is
// already short has none.
func netShortNames(dir string) map[string]string {
	if fsTrace != nil {
		fsTrace("findfirst", dir)
	}
	pat, err := syscall.UTF16PtrFromString(filepath.Join(dir, "*"))
	if err != nil {
		return nil
	}
	var data syscall.Win32finddata
	h, err := syscall.FindFirstFile(pat, &data)
	if err != nil {
		return nil
	}
	defer syscall.FindClose(h)
	var out map[string]string
	for {
		if short := syscall.UTF16ToString(data.AlternateFileName[:]); short != "" {
			if out == nil {
				out = map[string]string{}
			}
			out[short] = syscall.UTF16ToString(data.FileName[:])
		}
		if syscall.FindNextFile(h, &data) != nil {
			return out
		}
	}
}

// netLongName returns the long name of the last part of the path, which can
// be a short 8.3 name, or "".
func netLongName(p string) string {
	u, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		return ""
	}
	buf := make([]uint16, syscall.MAX_LONG_PATH)
	n, err := syscall.GetLongPathName(u, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		return ""
	}
	return filepath.Base(syscall.UTF16ToString(buf[:n]))
}
