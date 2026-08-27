//go:build js || wasip1

package main

import "os"

// Browser and WASI targets do not expose process signals. These builds are
// compile-supported for embedders; lifecycle control belongs to the host.
func notifyReloadSignal(chan<- os.Signal) {}

func notifyShutdownSignals(chan<- os.Signal) {}
