//go:build !js && !wasip1

package main

import (
	"os"
	"os/signal"
	"syscall"
)

func notifyReloadSignal(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGHUP)
}

func notifyShutdownSignals(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
}
