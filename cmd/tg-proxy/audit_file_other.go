//go:build !windows

package main

func (f *diskAuditLog) Truncate(size int64) error {
	return f.File.Truncate(size)
}
