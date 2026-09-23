//go:build windows

package llmguard

import (
	"errors"
	"syscall"
)

// wsaeconnrefused is WSAECONNREFUSED. Windows reports a refused connect
// with it rather than ECONNREFUSED, and package syscall does not name it.
const wsaeconnrefused syscall.Errno = 10061

func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, wsaeconnrefused)
}
