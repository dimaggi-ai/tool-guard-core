//go:build race

package main

// raceEnabled is true in a build with the race detector. Such a build on a
// shared CI runner is several times slower than on a developer machine, so
// the time tests of the 0.9.0 review do not assert a wall-clock time in it.
const raceEnabled = true
