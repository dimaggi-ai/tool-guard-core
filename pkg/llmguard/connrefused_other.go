//go:build !windows

package llmguard

import (
	"errors"
	"syscall"
)

func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
