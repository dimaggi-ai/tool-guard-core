//go:build !windows

package engine

// netDriveNames returns the drives the root of the net lists: none outside
// Windows.
func netDriveNames() []string { return nil }

// netLongName returns the long name of a short 8.3 name: none outside
// Windows.
func netLongName(string) string { return "" }
