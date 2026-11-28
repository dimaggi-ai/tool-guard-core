//go:build !race

package main

// raceEnabled is false in a build without the race detector; see
// race_on_test.go.
const raceEnabled = false
