//go:build performance

package engine_test

import (
	"testing"
	"time"
)

// TestPerformance_SQLClassifyPathologicalInput is deliberately excluded from
// ordinary `go test` runs. Absolute wall-clock assertions are meaningful only
// on the nightly reference runner documented in docs/performance.md; running
// this under the race detector or on every shared PR runner creates noise.
func TestPerformance_SQLClassifyPathologicalInput(t *testing.T) {
	const perCaseBudget = 2 * time.Second
	cond := pathologicalSQLCondition()

	for _, tc := range pathologicalSQLCases() {
		t.Run(tc.name, func(t *testing.T) {
			result := make(chan struct {
				fired    bool
				panicked any
			}, 1)
			go func() {
				fired, panicked := evaluatePathologicalSQL(cond, tc.sql)
				result <- struct {
					fired    bool
					panicked any
				}{fired: fired, panicked: panicked}
			}()

			timer := time.NewTimer(perCaseBudget)
			defer timer.Stop()
			select {
			case got := <-result:
				assertPathologicalSQLCorrectness(t, tc, got.fired, got.panicked)
			case <-timer.C:
				t.Fatalf("EvalCondition exceeded nightly %s ceiling on %q (len=%d)",
					perCaseBudget, tc.name, len(tc.sql))
			}
		})
	}
}
