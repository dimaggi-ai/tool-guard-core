package main

import (
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAppendSuccessfulLatencyCountsOnlyContractValidResponses(t *testing.T) {
	var latencies []time.Duration
	for _, outcome := range []reqOutcome{
		{statusCode: http.StatusOK, latency: time.Millisecond, contractValid: true},
		{statusCode: http.StatusAccepted, latency: 2 * time.Millisecond, contractValid: true},
		{statusCode: http.StatusNoContent, latency: 3 * time.Millisecond},
		{statusCode: http.StatusOK, latency: 4 * time.Millisecond},
		{statusCode: http.StatusFound, latency: 4 * time.Millisecond},
		{statusCode: http.StatusInternalServerError, latency: 5 * time.Millisecond},
	} {
		latencies = appendSuccessfulLatency(latencies, outcome)
	}

	if got, want := len(latencies), 2; got != want {
		t.Fatalf("successful latency count = %d, want %d (valid 200 and 202 only)", got, want)
	}
}

func TestFireRejectsEmpty204AndMalformedDecisionBodies(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		wantValid  bool
		wantAction string
	}{
		{name: "empty 204", status: http.StatusNoContent},
		{name: "empty 200", status: http.StatusOK},
		{name: "valid deny", status: http.StatusOK, body: `{"decision":"denied","action_taken":"denied"}`, wantValid: true, wantAction: "denied"},
		{name: "valid escalation", status: http.StatusAccepted, body: `{"decision":"escalated","action_taken":"escalated","escalation_id":"esc-1","poll_url":"/escalations/esc-1"}`, wantValid: true, wantAction: "escalated"},
		{name: "valid mixed-mode escalation", status: http.StatusAccepted, body: `{"decision":"denied","action_taken":"escalated","escalation_id":"esc-1","poll_url":"/escalations/esc-1"}`, wantValid: true, wantAction: "escalated"},
		{name: "202 missing poll metadata", status: http.StatusAccepted, body: `{"decision":"escalated","action_taken":"escalated"}`, wantAction: "escalated"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			out := fire(server.Client(), server.URL, envelope{}, true, time.Second)
			if out.contractValid != tt.wantValid || out.actionTaken != tt.wantAction {
				t.Fatalf("fire() valid/action = %v/%q, want %v/%q", out.contractValid, out.actionTaken, tt.wantValid, tt.wantAction)
			}
			if got := len(appendSuccessfulLatency(nil, out)); got != boolInt(tt.wantValid) {
				t.Fatalf("successful latency count = %d, want %d", got, boolInt(tt.wantValid))
			}
		})
	}
}

func TestValidEvaluationResponseDecisionActionMatrix(t *testing.T) {
	decisions := []string{"allowed", "flagged", "escalated", "denied"}
	actions := []string{"allowed", "flagged", "escalated", "denied", "allowed_shadow"}
	valid := map[string]bool{
		"allowed/allowed":          true,
		"flagged/flagged":          true,
		"escalated/flagged":        true,
		"escalated/escalated":      true,
		"escalated/allowed_shadow": true,
		"denied/flagged":           true,
		"denied/escalated":         true,
		"denied/denied":            true,
		"denied/allowed_shadow":    true,
	}

	for _, decision := range decisions {
		for _, action := range actions {
			name := decision + "/" + action
			status := http.StatusOK
			result := evalResult{Decision: decision, ActionTaken: action}
			if action == "escalated" {
				status = http.StatusAccepted
				result.EscalationID = "esc-1"
				result.PollURL = "/escalations/esc-1"
			}
			if got := validEvaluationResponse(status, result); got != valid[name] {
				t.Errorf("validEvaluationResponse(%d, %s) = %v, want %v", status, name, got, valid[name])
			}
		}
	}
}

func TestValidEvaluationResponseRejectsWrongStatusAndMissingEscalationMetadata(t *testing.T) {
	tests := []struct {
		name   string
		status int
		result evalResult
	}{
		{name: "ordinary action with 202", status: http.StatusAccepted, result: evalResult{Decision: "denied", ActionTaken: "denied"}},
		{name: "escalation with 200", status: http.StatusOK, result: evalResult{Decision: "escalated", ActionTaken: "escalated", EscalationID: "esc-1", PollURL: "/escalations/esc-1"}},
		{name: "escalation missing id", status: http.StatusAccepted, result: evalResult{Decision: "escalated", ActionTaken: "escalated", PollURL: "/escalations/esc-1"}},
		{name: "escalation missing poll URL", status: http.StatusAccepted, result: evalResult{Decision: "denied", ActionTaken: "escalated", EscalationID: "esc-1"}},
		{name: "unsupported status", status: http.StatusNoContent, result: evalResult{Decision: "allowed", ActionTaken: "allowed"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if validEvaluationResponse(tt.status, tt.result) {
				t.Fatal("validEvaluationResponse() = true, want false")
			}
		})
	}
}

func TestResponseIsWrongDistinguishesFailClosedFromMalformedSuccess(t *testing.T) {
	tests := []struct {
		name    string
		outcome reqOutcome
		want    bool
	}{
		{name: "503 is fail closed", outcome: reqOutcome{statusCode: http.StatusServiceUnavailable, mustNotAllow: true}},
		{name: "429 is fail closed", outcome: reqOutcome{statusCode: http.StatusTooManyRequests, mustNotAllow: true}},
		{name: "204 is malformed success", outcome: reqOutcome{statusCode: http.StatusNoContent, mustNotAllow: true}, want: true},
		{name: "empty 200 is malformed success", outcome: reqOutcome{statusCode: http.StatusOK, mustNotAllow: true}, want: true},
		{name: "valid deny is safe", outcome: reqOutcome{statusCode: http.StatusOK, contractValid: true, actionTaken: "denied", mustNotAllow: true}},
		{name: "valid escalation is safe", outcome: reqOutcome{statusCode: http.StatusAccepted, contractValid: true, actionTaken: "escalated", mustNotAllow: true}},
		{name: "valid allow is unsafe", outcome: reqOutcome{statusCode: http.StatusOK, contractValid: true, actionTaken: "allowed", mustNotAllow: true}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := responseIsWrong(tt.outcome); got != tt.want {
				t.Fatalf("responseIsWrong() = %v, want %v", got, tt.want)
			}
		})
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

func TestComparisonResultHealthyRejectsCorrectnessAndAvailabilityFailures(t *testing.T) {
	tests := []struct {
		name   string
		result levelResult
		want   bool
	}{
		{name: "healthy", result: levelResult{total: 2, byStatus: map[int]int64{200: 1, 202: 1}, latencies: []time.Duration{time.Millisecond, time.Millisecond}}, want: true},
		{name: "empty", result: levelResult{byStatus: map[int]int64{}}},
		{name: "server errors", result: levelResult{total: 2, byStatus: map[int]int64{200: 1, 500: 1}, latencies: []time.Duration{time.Millisecond}}},
		{name: "client errors", result: levelResult{total: 2, byStatus: map[int]int64{200: 1, 429: 1}, latencies: []time.Duration{time.Millisecond}}},
		{name: "unsupported 2xx", result: levelResult{total: 1, byStatus: map[int]int64{204: 1}}},
		{name: "connection errors", result: levelResult{total: 2, byStatus: map[int]int64{200: 1}, connErrors: 1, latencies: []time.Duration{time.Millisecond}}},
		{name: "timeouts", result: levelResult{total: 2, byStatus: map[int]int64{200: 1}, timeouts: 1, latencies: []time.Duration{time.Millisecond}}},
		{name: "wrong decisions", result: levelResult{total: 1, byStatus: map[int]int64{200: 1}, wrongDec: 1, latencies: []time.Duration{time.Millisecond}}},
		{name: "incomplete accounting", result: levelResult{total: 2, byStatus: map[int]int64{200: 2}, latencies: []time.Duration{time.Millisecond}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := comparisonResultHealthy(tt.result)
			if got != tt.want {
				t.Fatalf("comparisonResultHealthy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateAuditReportRequiresIntactExpectedRecords(t *testing.T) {
	tests := []struct {
		name     string
		report   string
		expected int64
		wantErr  bool
	}{
		{name: "valid", report: `{"intact":true,"records":3}`, expected: 3},
		{name: "allows preexisting records", report: `{"intact":true,"records":5}`, expected: 3},
		{name: "empty expected", report: `{"intact":true,"records":0}`, wantErr: true},
		{name: "empty report", report: `{"intact":true,"records":0}`, expected: 1, wantErr: true},
		{name: "too few records", report: `{"intact":true,"records":2}`, expected: 3, wantErr: true},
		{name: "not intact", report: `{"intact":false,"records":3}`, expected: 3, wantErr: true},
		{name: "malformed", report: `{`, expected: 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAuditReport([]byte(tt.report), tt.expected)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateAuditReport() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
