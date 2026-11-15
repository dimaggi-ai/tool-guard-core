//go:build race

package engine

// The race detector slows regex-heavy code by about 15 times, so timing
// bounds in tests scale by this factor.
const raceSlowdown = 15
