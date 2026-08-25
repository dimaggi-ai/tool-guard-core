package main

import (
	"math"
	"net/http"
	"testing"
	"time"
)

func TestAppendSuccessfulLatencyCountsEvery2xxResponse(t *testing.T) {
	var latencies []time.Duration
	for _, outcome := range []reqOutcome{
		{statusCode: http.StatusOK, latency: time.Millisecond},
		{statusCode: http.StatusAccepted, latency: 2 * time.Millisecond},
		{statusCode: http.StatusNoContent, latency: 3 * time.Millisecond},
		{statusCode: http.StatusFound, latency: 4 * time.Millisecond},
		{statusCode: http.StatusInternalServerError, latency: 5 * time.Millisecond},
	} {
		latencies = appendSuccessfulLatency(latencies, outcome)
	}

	if got, want := len(latencies), 3; got != want {
		t.Fatalf("successful latency count = %d, want %d (200, 202, and 204 only)", got, want)
	}
}

func TestSuccessfulRPSUsesSuccessfulResponsesAndGuardsZeroDuration(t *testing.T) {
	result := levelResult{latencies: []time.Duration{
		time.Millisecond, 2 * time.Millisecond, 3 * time.Millisecond,
	}}
	if got, want := successfulRPS(result, 1500*time.Millisecond), 2.0; got != want {
		t.Fatalf("successfulRPS() = %.1f, want %.1f", got, want)
	}
	if got := successfulRPS(result, 0); got != 0 {
		t.Fatalf("successfulRPS() with zero duration = %.1f, want 0", got)
	}
}

func TestValidateComparisonConfig(t *testing.T) {
	tests := []struct {
		name             string
		baselineTarget   string
		concurrency      int
		duration         time.Duration
		maxRegressionPct float64
		wantError        bool
	}{
		{name: "disabled", duration: 15 * time.Second, maxRegressionPct: 10},
		{name: "valid", baselineTarget: "http://127.0.0.1:9091", concurrency: 50, duration: 15 * time.Second, maxRegressionPct: 10},
		{name: "missing baseline", concurrency: 50, duration: 15 * time.Second, maxRegressionPct: 10, wantError: true},
		{name: "missing concurrency", baselineTarget: "http://127.0.0.1:9091", duration: 15 * time.Second, maxRegressionPct: 10, wantError: true},
		{name: "zero duration", baselineTarget: "http://127.0.0.1:9091", concurrency: 50, maxRegressionPct: 10, wantError: true},
		{name: "zero threshold", baselineTarget: "http://127.0.0.1:9091", concurrency: 50, duration: 15 * time.Second, wantError: true},
		{name: "hundred percent threshold", baselineTarget: "http://127.0.0.1:9091", concurrency: 50, duration: 15 * time.Second, maxRegressionPct: 100, wantError: true},
		{name: "nan threshold", baselineTarget: "http://127.0.0.1:9091", concurrency: 50, duration: 15 * time.Second, maxRegressionPct: math.NaN(), wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateComparisonConfig(tt.baselineTarget, tt.concurrency, tt.duration, tt.maxRegressionPct)
			if (err != nil) != tt.wantError {
				t.Fatalf("validateComparisonConfig() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestRelativeThroughputGate(t *testing.T) {
	tests := []struct {
		name      string
		candidate float64
		baseline  float64
		limit     float64
		wantPct   float64
		wantPass  bool
		wantValid bool
	}{
		{name: "equal passes", candidate: 100, baseline: 100, limit: 10, wantPct: 0, wantPass: true, wantValid: true},
		{name: "faster passes", candidate: 110, baseline: 100, limit: 10, wantPct: -10, wantPass: true, wantValid: true},
		{name: "below threshold passes", candidate: 90.01, baseline: 100, limit: 10, wantPct: 9.99, wantPass: true, wantValid: true},
		{name: "exact threshold fails", candidate: 90, baseline: 100, limit: 10, wantPct: 10, wantValid: true},
		{name: "above threshold fails", candidate: 89, baseline: 100, limit: 10, wantPct: 11, wantValid: true},
		{name: "zero baseline invalid", candidate: 100, baseline: 0, limit: 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPct, gotPass, gotValid := relativeThroughputGate(tt.candidate, tt.baseline, tt.limit)
			if math.Abs(gotPct-tt.wantPct) > 0.0001 {
				t.Fatalf("relativeThroughputGate() percentage = %.4f, want %.4f", gotPct, tt.wantPct)
			}
			if gotPass != tt.wantPass || gotValid != tt.wantValid {
				t.Fatalf("relativeThroughputGate() pass/valid = %v/%v, want %v/%v", gotPass, gotValid, tt.wantPass, tt.wantValid)
			}
		})
	}
}
