//go:build !linux

package main

import "fmt"

func publishPrunedFile(temp, out string) error {
	return fmt.Errorf("prune publication requires Linux renameat2 with RENAME_NOREPLACE; dry-run is available")
}
