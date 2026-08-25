package main

import (
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
