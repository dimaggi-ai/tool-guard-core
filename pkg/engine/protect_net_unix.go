//go:build !windows

package engine

// netDriveNames returns the drives the root of the net lists: none outside
// Windows.
func netDriveNames() []string { return nil }

// netLongName returns the long name of a short 8.3 name: none outside
// Windows.
func netLongName(string) string { return "" }

// netShortNames returns the short 8.3 names of the entries of a directory:
// none outside Windows.
func netShortNames(string) map[string]string { return nil }
