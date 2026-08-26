// cmd/stress-test load-tests a running tg-proxy instance and checks that
// concurrency doesn't compromise correctness — not just how fast it goes.
//
// This is a different concern from `tg benchmark` (single-goroutine latency
// probe against the in-process engine, no HTTP, no audit chain) and from
// `battle-test` (adversarial LLM bypass-attempt harness — policy-catches-
// creativity, not engine-holds-up-under-load).
//
// What it measures
//   - Throughput and p50/p95/p99/max latency at each concurrency level in
//     -concurrency, firing a realistic mix of under- and over-cap refunds
//     against the shipped policy set so every engine path (allow, escalate,
//     deny, and the escalate→deny saturation downgrade) runs under load, not
//     just the cheap one.
//   - A brief overload phase at -overload concurrency: does tg-proxy fail
//     CLOSED (reject cleanly — connection refused, timeout, or 5xx) or fail
//     OPEN (silently return 200 with a wrong decision, hang forever, or
//     corrupt a response) when genuinely overwhelmed? This project's whole
//     design point is fail-closed; this phase is the one place that gets
//     checked under actual concurrent load instead of in a unit test.
//   - Audit chain integrity after every phase completes: shells out to
//     `tg verify -file <audit-log>` and reports whether the hash chain
//     written by hundreds of goroutines racing through the audit mutex is
//     still intact. This is the single most product-specific correctness
//     property a generic load-test tool would never think to check.
//
// Usage
//
//	go build -o bin/tg-proxy ./cmd/tg-proxy
//	go build -o bin/tg ./cmd/tg
//	go build -o bin/stress-test ./cmd/stress-test
//	./bin/tg-proxy -listen :9090 -policy-dir ./policies -audit-log /tmp/stress.jsonl &
//	./bin/stress-test -target http://localhost:9090 -tg-bin ./bin/tg -audit-log /tmp/stress.jsonl
//
// Output
//   - One results line per concurrency level (contract-valid req/s, latency
//     percentiles, error breakdown by cause).
//   - One line for the overload phase, classified as PASS (failed closed:
//     rejected, errored, or denied — never auto-allowed an over-cap refund) or
//     FAIL (let an over-cap refund back through with a 200 that wasn't a deny,
//     or hung past -overload-timeout).
//   - A final PASS/FAIL verdict from `tg verify` on the resulting audit log.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// envelope mirrors the subset of pkg/domain.ActionEnvelope this tool needs
// to build requests. Kept local (not imported from pkg/domain) so this
// binary has zero dependency on internal engine packages — it only ever
// talks to tg-proxy over HTTP, exactly like a real integration would.
type envelope struct {
	EnvelopeID string          `json:"envelope_id"`
	Timestamp  string          `json:"timestamp"`
	AgentID    string          `json:"agent_id"`
	SessionID  string          `json:"session_id"`
	OrgID      string          `json:"org_id"`
	ToolName   string          `json:"tool_name"`
	ToolGroup  string          `json:"tool_group"`
	Parameters json.RawMessage `json:"parameters"`
}

type evalResult struct {
	Decision     string `json:"decision"`
	ActionTaken  string `json:"action_taken"`
	EscalationID string `json:"escalation_id"`
	PollURL      string `json:"poll_url"`
}

type reqOutcome struct {
	latency       time.Duration
	statusCode    int
	err           error
	actionTaken   string
	contractValid bool
	mustNotAllow  bool
}

func main() {
	var (
		target             = flag.String("target", "http://localhost:9090", "tg-proxy base URL")
		concurrencyList    = flag.String("concurrency", "1,10,50,200", "comma-separated concurrency levels to run in sequence")
		duration           = flag.Duration("duration", 5*time.Second, "how long to sustain each concurrency level")
		overload           = flag.Int("overload", 2000, "concurrency for the brief fail-closed/fail-open overload phase (0 disables it)")
		overloadFor        = flag.Duration("overload-for", 3*time.Second, "how long to sustain the overload phase")
		overloadTimeout    = flag.Duration("overload-timeout", 10*time.Second, "a request outstanding this long during the overload phase counts as a hang, not a slow success")
		tgBin              = flag.String("tg-bin", "tg", "path to the tg binary, used to verify the audit chain afterward")
		auditLog           = flag.String("audit-log", "", "path tg-proxy was started with -audit-log; if set, verified with `tg verify` after all phases")
		floorConcurrency   = flag.Int("floor-concurrency", 0, "if set, must also appear in -concurrency: assert an absolute floor at this level (0 disables floor checking)")
		floorMinRPS        = flag.Float64("floor-min-rps", 0, "minimum acceptable req/s at -floor-concurrency")
		floorMaxP99        = flag.Duration("floor-max-p99", 0, "maximum acceptable p99 latency at -floor-concurrency")
		baselineTarget     = flag.String("baseline-target", "", "optional baseline tg-proxy URL for a same-runner relative throughput comparison")
		compareConcurrency = flag.Int("compare-concurrency", 0, "concurrency per target for the relative comparison (requires -baseline-target)")
		compareDuration    = flag.Duration("compare-duration", 15*time.Second, "duration of the simultaneous candidate/baseline comparison")
		maxRegressionPct   = flag.Float64("max-regression-pct", 10, "fail when candidate throughput is this percentage or more below baseline")
	)
	flag.Parse()

	levels, err := parseConcurrency(*concurrencyList)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stress-test:", err)
		os.Exit(2)
	}
	if err := validateComparisonConfig(*baselineTarget, *compareConcurrency, *compareDuration, *maxRegressionPct); err != nil {
		fmt.Fprintln(os.Stderr, "stress-test:", err)
		os.Exit(2)
	}

	client := newClient(0)
	if err := waitHealthy(client, *target, 10*time.Second); err != nil {
		fmt.Fprintln(os.Stderr, "stress-test: target not healthy:", err)
		os.Exit(1)
	}
	if *baselineTarget != "" {
		if err := waitHealthy(client, *baselineTarget, 10*time.Second); err != nil {
			fmt.Fprintln(os.Stderr, "stress-test: baseline target not healthy:", err)
			os.Exit(1)
		}
	}

	fmt.Printf("target=%s levels=%v duration=%s\n\n", *target, levels, *duration)

	overallFailClosed := true
	floorMet := true
	comparisonMet := true
	var expectedAuditRecords int64
	for _, phase := range measurementPlan(levels, *baselineTarget != "") {
		if phase.comparison {
			fmt.Printf("\n--- relative regression phase: concurrency=%d per target for %s ---\n", *compareConcurrency, *compareDuration)
			candidate, baseline := runTargetComparison(*target, *baselineTarget, *compareConcurrency, *compareDuration)
			expectedAuditRecords += int64(len(candidate.latencies))
			fmt.Println("candidate:")
			printLevel(*compareConcurrency, *compareDuration, candidate)
			fmt.Println("baseline:")
			printLevel(*compareConcurrency, *compareDuration, baseline)

			candidateRPS := successfulRPS(candidate, *compareDuration)
			baselineRPS := successfulRPS(baseline, *compareDuration)
			candidateHealthy, candidateReason := comparisonResultHealthy(candidate)
			baselineHealthy, baselineReason := comparisonResultHealthy(baseline)
			regressionPct, throughputPassed, valid := relativeThroughputGate(candidateRPS, baselineRPS, *maxRegressionPct)
			if !candidateHealthy {
				fmt.Printf("  ⚠ REGRESSION CHECK INVALID: candidate result is unhealthy: %s\n", candidateReason)
				comparisonMet = false
			} else if !baselineHealthy {
				fmt.Printf("  ⚠ REGRESSION CHECK INVALID: baseline result is unhealthy: %s\n", baselineReason)
				comparisonMet = false
			} else if !valid {
				fmt.Println("  ⚠ REGRESSION CHECK INVALID: baseline completed zero successful responses")
				comparisonMet = false
			} else if !throughputPassed {
				fmt.Printf("  ⚠ REGRESSION: candidate %.1f req/s is %.2f%% below baseline %.1f req/s (limit: < %.2f%%)\n",
					candidateRPS, regressionPct, baselineRPS, *maxRegressionPct)
				comparisonMet = false
			} else {
				fmt.Printf("  ✓ relative gate passed: candidate %.1f req/s, baseline %.1f req/s, regression %.2f%% (< %.2f%%)\n",
					candidateRPS, baselineRPS, regressionPct, *maxRegressionPct)
			}
			continue
		}

		c := phase.concurrency
		res := runLevel(*target, c, *duration, 0)
		expectedAuditRecords += int64(len(res.latencies))
		printLevel(c, *duration, res)

		if *floorConcurrency != 0 && c == *floorConcurrency {
			sort.Slice(res.latencies, func(i, j int) bool { return res.latencies[i] < res.latencies[j] })
			gotRPS := successfulRPS(res, *duration)
			gotP99 := percentile(res.latencies, 0.99)
			if *floorMinRPS > 0 && gotRPS < *floorMinRPS {
				fmt.Printf("  ⚠ FLOOR MISS: req/s %.1f < absolute floor %.1f at concurrency=%d\n", gotRPS, *floorMinRPS, c)
				floorMet = false
			}
			if *floorMaxP99 > 0 && gotP99 > *floorMaxP99 {
				fmt.Printf("  ⚠ FLOOR MISS: p99 %s > absolute floor %s at concurrency=%d\n", gotP99, *floorMaxP99, c)
				floorMet = false
			}
			if floorMet && (*floorMinRPS > 0 || *floorMaxP99 > 0) {
				fmt.Printf("  ✓ floor held at concurrency=%d (req/s=%.1f p99=%s)\n", c, gotRPS, gotP99)
			}
		}
	}
	if *floorConcurrency != 0 && (*floorMinRPS > 0 || *floorMaxP99 > 0) {
		found := false
		for _, c := range levels {
			if c == *floorConcurrency {
				found = true
			}
		}
		if !found {
			fmt.Printf("stress-test: -floor-concurrency=%d was never tested — add it to -concurrency\n", *floorConcurrency)
			floorMet = false
		}
	}

	if *overload > 0 {
		fmt.Printf("\n--- overload phase: concurrency=%d for %s (timeout=%s) ---\n", *overload, *overloadFor, *overloadTimeout)
		res := runLevel(*target, *overload, *overloadFor, *overloadTimeout)
		expectedAuditRecords += int64(len(res.latencies))
		printLevel(*overload, *overloadFor, res)
		ok, reason := judgeOverload(res)
		overallFailClosed = ok
		if ok {
			fmt.Println("overload verdict: PASS (failed closed —", reason, ")")
		} else {
			fmt.Println("overload verdict: FAIL (", reason, ")")
		}
	}

	chainOK := true
	if *auditLog != "" {
		chainOK = verifyAuditChain(*tgBin, *auditLog, expectedAuditRecords)
	} else {
		fmt.Println("\n(no -audit-log given — skipping chain-integrity check)")
	}

	fmt.Println()
	if overallFailClosed && chainOK && floorMet && comparisonMet {
		fmt.Println("STRESS SUITE: PASS")
		return
	}
	fmt.Println("STRESS SUITE: FAIL")
	os.Exit(1)
}

// ---------------------------------------------------------------------------
// Load generation
// ---------------------------------------------------------------------------

type levelResult struct {
	total      int64
	byStatus   map[int]int64
	timeouts   int64
	connErrors int64
	wrongDec   int64           // malformed/unsupported 2xx or unsafe over-cap action
	latencies  []time.Duration // contract-valid 200/202 responses only
	worstHang  time.Duration
}

type measurementPhase struct {
	comparison  bool
	concurrency int
}

// measurementPlan keeps both proxies in equivalent initial state for the
// relative gate. Candidate-only levels mutate bounded runtime state (notably
// the pending-escalation store), so the simultaneous comparison must always be
// the first state-mutating phase when a baseline is configured.
func measurementPlan(levels []int, includeComparison bool) []measurementPhase {
	plan := make([]measurementPhase, 0, len(levels)+1)
	if includeComparison {
		plan = append(plan, measurementPhase{comparison: true})
	}
	for _, concurrency := range levels {
		plan = append(plan, measurementPhase{concurrency: concurrency})
	}
	return plan
}

func validateComparisonConfig(baselineTarget string, concurrency int, duration time.Duration, maxRegressionPct float64) error {
	enabled := baselineTarget != "" || concurrency != 0
	if !enabled {
		return nil
	}
	if baselineTarget == "" || concurrency <= 0 {
		return fmt.Errorf("-baseline-target and a positive -compare-concurrency must be set together")
	}
	if duration <= 0 {
		return fmt.Errorf("-compare-duration must be positive")
	}
	if !(maxRegressionPct > 0 && maxRegressionPct < 100) {
		return fmt.Errorf("-max-regression-pct must be greater than 0 and less than 100")
	}
	return nil
}

func runLevel(target string, concurrency int, duration time.Duration, perReqTimeout time.Duration) levelResult {
	client := newClient(concurrency)
	var mu sync.Mutex
	agg := levelResult{byStatus: map[int]int64{}}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	time.AfterFunc(duration, func() { close(stop) })

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(workerID) + time.Now().UnixNano()))
			local := make([]time.Duration, 0, 256)
			var localStatus = map[int]int64{}
			var localTimeouts, localConnErr, localWrong, localTotal int64
			var localWorstHang time.Duration

			for {
				select {
				case <-stop:
					mu.Lock()
					agg.total += localTotal
					agg.timeouts += localTimeouts
					agg.connErrors += localConnErr
					agg.wrongDec += localWrong
					agg.latencies = append(agg.latencies, local...)
					for k, v := range localStatus {
						agg.byStatus[k] += v
					}
					if localWorstHang > agg.worstHang {
						agg.worstHang = localWorstHang
					}
					mu.Unlock()
					return
				default:
				}

				env, mustNotAllow := buildEnvelope(rng)
				out := fire(client, target, env, mustNotAllow, perReqTimeout)
				localTotal++
				if out.err != nil {
					if isTimeout(out.err) {
						localTimeouts++
						if out.latency > localWorstHang {
							localWorstHang = out.latency
						}
					} else {
						localConnErr++
					}
					continue
				}
				localStatus[out.statusCode]++
				local = appendSuccessfulLatency(local, out)
				if responseIsWrong(out) {
					localWrong++
				}
			}
		}(w)
	}
	wg.Wait()
	return agg
}

func responseIsWrong(out reqOutcome) bool {
	if out.statusCode >= 200 && out.statusCode < 300 && !out.contractValid {
		return true
	}
	if !out.contractValid {
		// Non-2xx responses are explicit rejection/failure and therefore
		// fail closed. They still invalidate a relative throughput sample,
		// but are not a corrupt or unsafe evaluation response.
		return false
	}
	// Over-cap refunds may be denied directly or remain pending escalation,
	// but they must never proceed. The action, not the raw decision, is
	// authoritative in shadow mode and after the proxy's escalate→deny
	// overload downgrade.
	return out.mustNotAllow && out.actionTaken != "denied" && out.actionTaken != "escalated"
}

func runTargetComparison(candidateTarget, baselineTarget string, concurrency int, duration time.Duration) (levelResult, levelResult) {
	start := make(chan struct{})
	var candidate, baseline levelResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		candidate = runLevel(candidateTarget, concurrency, duration, 0)
	}()
	go func() {
		defer wg.Done()
		<-start
		baseline = runLevel(baselineTarget, concurrency, duration, 0)
	}()
	close(start)
	wg.Wait()
	return candidate, baseline
}

// appendSuccessfulLatency records only contract-valid evaluation responses.
// tg-proxy uses 200 for terminal outcomes and 202 for a pending escalation;
// another 2xx status or a malformed body is a correctness failure, not useful
// throughput.
func appendSuccessfulLatency(dst []time.Duration, out reqOutcome) []time.Duration {
	if out.contractValid && (out.statusCode == http.StatusOK || out.statusCode == http.StatusAccepted) {
		return append(dst, out.latency)
	}
	return dst
}

func successfulRPS(result levelResult, duration time.Duration) float64 {
	if duration <= 0 {
		return 0
	}
	return float64(len(result.latencies)) / duration.Seconds()
}

func throughputRegressionPercent(candidateRPS, baselineRPS float64) (float64, bool) {
	if baselineRPS <= 0 {
		return 0, false
	}
	return ((baselineRPS - candidateRPS) / baselineRPS) * 100, true
}

func relativeThroughputGate(candidateRPS, baselineRPS, maxRegressionPct float64) (float64, bool, bool) {
	regressionPct, valid := throughputRegressionPercent(candidateRPS, baselineRPS)
	if !valid {
		return 0, false, false
	}
	return regressionPct, regressionPct < maxRegressionPct, true
}

// comparisonResultHealthy rejects throughput samples that do not represent a
// functioning proxy. Comparing only successful RPS can otherwise make a
// candidate look faster than a baseline that spent most of the phase returning
// errors. The relative gate is intentionally strict: either side producing a
// transport error, timeout, non-contract status/body, or wrong decision
// invalidates the sample instead of turning correctness failures into a
// performance number.
func comparisonResultHealthy(result levelResult) (bool, string) {
	if result.total <= 0 {
		return false, "no requests completed"
	}
	if result.connErrors > 0 || result.timeouts > 0 {
		return false, fmt.Sprintf("transport failures: conn_err=%d timeouts=%d", result.connErrors, result.timeouts)
	}
	if result.wrongDec > 0 {
		return false, fmt.Sprintf("wrong decisions=%d", result.wrongDec)
	}
	for status, count := range result.byStatus {
		if count > 0 && status != http.StatusOK && status != http.StatusAccepted {
			return false, fmt.Sprintf("HTTP %d responses=%d", status, count)
		}
	}
	successes := int64(len(result.latencies))
	if successes != result.total {
		return false, fmt.Sprintf("successful response ratio %.2f%% (%d/%d), want 100%%", 100*float64(successes)/float64(result.total), successes, result.total)
	}
	return true, ""
}

func buildEnvelope(rng *rand.Rand) (envelope, bool) {
	// issue_refund is money movement, so the shipped ./policies set guards it
	// in depth: refund_cap.yaml denies any single amount over $500, while the
	// irreversibility floor escalates under-cap money movement — and when the
	// pending-escalation store saturates under sustained load, the proxy
	// fail-CLOSES by downgrading that escalate to a deny. The one decision that
	// is load-independent and always safety-critical is the per-call cap: an
	// over-cap refund must never come back auto-allowed. We still fire a mix of
	// amounts (a near-boundary 499-501 slice, clearly-under, clearly-over) so
	// every engine path runs under load; we just assert the invariant that
	// holds regardless of which policies happen to be loaded. See the worker
	// loop and judgeOverload.
	var amount int
	switch rng.Intn(4) {
	case 0:
		amount = 499 + rng.Intn(3) // 499, 500, 501 — straddles the cap
	case 1:
		amount = 10 + rng.Intn(400) // under the cap
	default:
		amount = 600 + rng.Intn(5000) // over the cap — must never be allowed
	}
	mustNotAllow := amount > 500 // over the per-call cap: deny or escalate, never allow

	params, _ := json.Marshal(map[string]any{"amount": amount, "account_id": "acct-stress-test"})
	return envelope{
		EnvelopeID: randID(rng),
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		AgentID:    "stress-test-agent",
		SessionID:  randID(rng),
		OrgID:      "org-stress-test",
		ToolName:   "issue_refund",
		ToolGroup:  "monetary_outflow",
		Parameters: params,
	}, mustNotAllow
}

func fire(client *http.Client, target string, env envelope, mustNotAllow bool, timeout time.Duration) reqOutcome {
	body, _ := json.Marshal(env)
	ctx := context.Background()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(target, "/")+"/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return reqOutcome{latency: elapsed, err: err, mustNotAllow: mustNotAllow}
	}
	defer resp.Body.Close()

	out := reqOutcome{latency: elapsed, statusCode: resp.StatusCode, mustNotAllow: mustNotAllow}
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusAccepted {
		var r evalResult
		if err := json.NewDecoder(resp.Body).Decode(&r); err == nil {
			out.actionTaken = r.ActionTaken
			out.contractValid = validEvaluationResponse(resp.StatusCode, r)
		}
	}
	return out
}

func validEvaluationResponse(status int, result evalResult) bool {
	validPair := false
	switch result.Decision {
	case "allowed":
		validPair = result.ActionTaken == "allowed"
	case "flagged":
		validPair = result.ActionTaken == "flagged"
	case "escalated":
		// A shadow escalation can proceed, while a lower-severity enforced
		// flag can own the action even though the aggregate decision remains
		// escalated.
		validPair = result.ActionTaken == "allowed_shadow" ||
			result.ActionTaken == "flagged" ||
			result.ActionTaken == "escalated"
	case "denied":
		// A shadow deny can coexist with a lower-severity enforcement action.
		validPair = result.ActionTaken == "allowed_shadow" ||
			result.ActionTaken == "flagged" ||
			result.ActionTaken == "escalated" ||
			result.ActionTaken == "denied"
	}
	if !validPair {
		return false
	}
	switch status {
	case http.StatusOK:
		return result.ActionTaken != "escalated"
	case http.StatusAccepted:
		return result.ActionTaken == "escalated" && result.EscalationID != "" && result.PollURL != ""
	default:
		return false
	}
}

func isTimeout(err error) bool {
	if e, ok := err.(interface{ Timeout() bool }); ok {
		return e.Timeout()
	}
	return strings.Contains(err.Error(), "context deadline exceeded")
}

func newClient(concurrency int) *http.Client {
	maxConns := concurrency
	if maxConns < 100 {
		maxConns = 100 // headroom so the client's own pool is never the bottleneck we're measuring
	}
	return &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        maxConns * 2,
			MaxIdleConnsPerHost: maxConns * 2,
			MaxConnsPerHost:     0, // unlimited — we want to see the SERVER's real limit, not an artificial client one
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: 30 * time.Second,
	}
}

func waitHealthy(client *http.Client, target string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(strings.TrimRight(target, "/") + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("still not ready after %s (last error: %v)", timeout, lastErr)
}

func randID(rng *rand.Rand) string {
	const chars = "abcdef0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = chars[rng.Intn(len(chars))]
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func printLevel(concurrency int, duration time.Duration, r levelResult) {
	sort.Slice(r.latencies, func(i, j int) bool { return r.latencies[i] < r.latencies[j] })
	successful := int64(len(r.latencies))
	rps := successfulRPS(r, duration)

	statusStr := make([]string, 0, len(r.byStatus))
	for code, n := range r.byStatus {
		statusStr = append(statusStr, fmt.Sprintf("%d=%d", code, n))
	}
	sort.Strings(statusStr)

	fmt.Printf(
		"concurrency=%-5d total=%-8d success_contract=%-8d req/s=%-8.1f p50=%-8s p95=%-8s p99=%-8s max=%-8s conn_err=%-5d timeouts=%-5d wrong_decision=%-4d status=[%s]\n",
		concurrency, r.total, successful, rps,
		percentile(r.latencies, 0.50), percentile(r.latencies, 0.95), percentile(r.latencies, 0.99),
		percentile(r.latencies, 1.0),
		r.connErrors, r.timeouts, r.wrongDec,
		strings.Join(statusStr, ","),
	)
	if r.wrongDec > 0 {
		fmt.Printf("  ⚠ %d responses violated the evaluation contract or let an over-cap refund proceed\n", r.wrongDec)
	}
}

// judgeOverload decides whether the overload phase demonstrates fail-closed
// behavior. Any of these count as "failed closed": connection refused,
// context-deadline timeouts, non-2xx status codes, and — importantly — a
// deny (including the escalate→deny downgrade the proxy performs when the
// pending-escalation store saturates under load). What must NEVER happen: an
// over-cap refund coming back 200 without a deny (auto-allowed or a corrupt
// decision — silent fail-open), or a request that outlives -overload-timeout
// (a hang, which in production would exhaust a caller's own timeout budget and
// likely get treated as fail-open by whatever's calling tg-proxy).
func judgeOverload(r levelResult) (bool, string) {
	if r.wrongDec > 0 {
		return false, fmt.Sprintf("%d responses violated the evaluation contract or let an over-cap refund proceed under overload", r.wrongDec)
	}
	if r.worstHang > 0 {
		return false, fmt.Sprintf("at least one request hung past the overload timeout (worst observed: %s) instead of erroring", r.worstHang)
	}
	rejected := r.connErrors + r.timeouts
	for code, n := range r.byStatus {
		if code >= 500 {
			rejected += n
		}
	}
	if rejected == 0 && r.total > 0 {
		// Every single request succeeded even under overload — not a
		// failure, just means -overload wasn't high enough to find the
		// server's actual limit. Still a pass (nothing failed OPEN), but
		// worth a note for whoever's tuning -overload.
		return true, "server absorbed the full overload without shedding any load — try a higher -overload to find its actual ceiling"
	}
	return true, fmt.Sprintf("%d/%d requests were cleanly rejected (connection error, timeout, or 5xx) instead of corrupting a decision", rejected, r.total)
}

type auditVerifyReport struct {
	Intact  bool `json:"intact"`
	Records int  `json:"records"`
}

func verifyAuditChain(tgBin, auditLog string, expectedRecords int64) bool {
	cmd := exec.Command(tgBin, "verify", "-file", auditLog)
	out, err := cmd.CombinedOutput()
	fmt.Printf("\n--- tg verify -file %s ---\n%s\n", auditLog, strings.TrimSpace(string(out)))
	if err != nil {
		fmt.Println("audit chain verdict: FAIL (tg verify exited non-zero:", err, ")")
		return false
	}
	if err := validateAuditReport(out, expectedRecords); err != nil {
		fmt.Println("audit chain verdict: FAIL (", err, ")")
		return false
	}
	fmt.Println("audit chain verdict: PASS")
	return true
}

func validateAuditReport(out []byte, expectedRecords int64) error {
	if expectedRecords <= 0 {
		return fmt.Errorf("no contract-valid candidate responses were recorded")
	}
	var report auditVerifyReport
	if err := json.Unmarshal(out, &report); err != nil {
		return fmt.Errorf("decode tg verify report: %w", err)
	}
	if !report.Intact {
		return fmt.Errorf("report marks the audit chain non-intact")
	}
	if int64(report.Records) < expectedRecords {
		return fmt.Errorf("report contains %d records, want at least %d candidate responses", report.Records, expectedRecords)
	}
	return nil
}

func parseConcurrency(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("invalid concurrency value %q", p)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no concurrency levels given")
	}
	return out, nil
}
