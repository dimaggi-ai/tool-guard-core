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
//   - One results line per concurrency level (req/s, latency percentiles,
//     error breakdown by cause).
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
	Decision string `json:"decision"`
}

type reqOutcome struct {
	latency      time.Duration
	statusCode   int
	err          error
	decision     string
	mustNotAllow bool
}

func main() {
	var (
		target           = flag.String("target", "http://localhost:9090", "tg-proxy base URL")
		concurrencyList  = flag.String("concurrency", "1,10,50,200", "comma-separated concurrency levels to run in sequence")
		duration         = flag.Duration("duration", 5*time.Second, "how long to sustain each concurrency level")
		overload         = flag.Int("overload", 2000, "concurrency for the brief fail-closed/fail-open overload phase (0 disables it)")
		overloadFor      = flag.Duration("overload-for", 3*time.Second, "how long to sustain the overload phase")
		overloadTimeout  = flag.Duration("overload-timeout", 10*time.Second, "a request outstanding this long during the overload phase counts as a hang, not a slow success")
		tgBin            = flag.String("tg-bin", "tg", "path to the tg binary, used to verify the audit chain afterward")
		auditLog         = flag.String("audit-log", "", "path tg-proxy was started with -audit-log; if set, verified with `tg verify` after all phases")
		floorConcurrency = flag.Int("floor-concurrency", 0, "if set, must also appear in -concurrency: assert the published floor at this level (0 disables floor checking)")
		floorMinRPS      = flag.Float64("floor-min-rps", 0, "minimum acceptable req/s at -floor-concurrency")
		floorMaxP99      = flag.Duration("floor-max-p99", 0, "maximum acceptable p99 latency at -floor-concurrency")
	)
	flag.Parse()

	levels, err := parseConcurrency(*concurrencyList)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stress-test:", err)
		os.Exit(2)
	}

	client := newClient(0)
	if err := waitHealthy(client, *target, 10*time.Second); err != nil {
		fmt.Fprintln(os.Stderr, "stress-test: target not healthy:", err)
		os.Exit(1)
	}

	fmt.Printf("target=%s levels=%v duration=%s\n\n", *target, levels, *duration)

	overallFailClosed := true
	floorMet := true
	for _, c := range levels {
		res := runLevel(*target, c, *duration, 0)
		printLevel(c, *duration, res)

		if *floorConcurrency != 0 && c == *floorConcurrency {
			sort.Slice(res.latencies, func(i, j int) bool { return res.latencies[i] < res.latencies[j] })
			gotRPS := float64(len(res.latencies)) / duration.Seconds()
			gotP99 := percentile(res.latencies, 0.99)
			if *floorMinRPS > 0 && gotRPS < *floorMinRPS {
				fmt.Printf("  ⚠ FLOOR MISS: req/s %.1f < published floor %.1f at concurrency=%d\n", gotRPS, *floorMinRPS, c)
				floorMet = false
			}
			if *floorMaxP99 > 0 && gotP99 > *floorMaxP99 {
				fmt.Printf("  ⚠ FLOOR MISS: p99 %s > published floor %s at concurrency=%d\n", gotP99, *floorMaxP99, c)
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
		chainOK = verifyAuditChain(*tgBin, *auditLog)
	} else {
		fmt.Println("\n(no -audit-log given — skipping chain-integrity check)")
	}

	fmt.Println()
	if overallFailClosed && chainOK && floorMet {
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
	wrongDec   int64 // 200 OK but decision didn't match what the amount should have produced
	latencies  []time.Duration
	worstHang  time.Duration
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
				if out.statusCode == http.StatusOK {
					local = append(local, out.latency)
					// Fail-open = an over-cap refund that came back 200 without
					// being denied (auto-allowed, or a corrupt/empty decision).
					// A denial is fail-CLOSED and safe — including the
					// escalate→deny downgrade the proxy performs when the
					// pending-escalation store saturates under overload. Under-cap
					// outcomes vary with the loaded policy set (allow vs escalate),
					// so they are deliberately not asserted here.
					if out.mustNotAllow && out.decision != "denied" {
						localWrong++
					}
				}
			}
		}(w)
	}
	wg.Wait()
	return agg
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
	if resp.StatusCode == http.StatusOK {
		var r evalResult
		if err := json.NewDecoder(resp.Body).Decode(&r); err == nil {
			out.decision = r.Decision
		}
	}
	return out
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
		resp, err := client.Get(strings.TrimRight(target, "/") + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		lastErr = err
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("still unhealthy after %s (last error: %v)", timeout, lastErr)
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
	ok := int64(len(r.latencies))
	rps := float64(ok) / duration.Seconds()

	statusStr := make([]string, 0, len(r.byStatus))
	for code, n := range r.byStatus {
		statusStr = append(statusStr, fmt.Sprintf("%d=%d", code, n))
	}
	sort.Strings(statusStr)

	fmt.Printf(
		"concurrency=%-5d total=%-8d ok=%-8d req/s=%-8.1f p50=%-8s p95=%-8s p99=%-8s max=%-8s conn_err=%-5d timeouts=%-5d wrong_decision=%-4d status=[%s]\n",
		concurrency, r.total, ok, rps,
		percentile(r.latencies, 0.50), percentile(r.latencies, 0.95), percentile(r.latencies, 0.99),
		percentile(r.latencies, 1.0),
		r.connErrors, r.timeouts, r.wrongDec,
		strings.Join(statusStr, ","),
	)
	if r.wrongDec > 0 {
		fmt.Printf("  ⚠ %d over-cap refunds returned 200 OK without being denied — a genuine fail-open, not a load issue\n", r.wrongDec)
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
		return false, fmt.Sprintf("%d over-cap refunds returned 200 without a deny under overload — silent fail-open", r.wrongDec)
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

func verifyAuditChain(tgBin, auditLog string) bool {
	cmd := exec.Command(tgBin, "verify", "-file", auditLog)
	out, err := cmd.CombinedOutput()
	fmt.Printf("\n--- tg verify -file %s ---\n%s\n", auditLog, strings.TrimSpace(string(out)))
	if err != nil {
		fmt.Println("audit chain verdict: FAIL (tg verify exited non-zero:", err, ")")
		return false
	}
	// tg verify prints a JSON report; treat any "ok": false or "valid":
	// false as a failure even though the exit code was 0, in case the
	// command's exit-code contract ever changes underneath us.
	if bytes.Contains(out, []byte(`"valid": false`)) || bytes.Contains(out, []byte(`"ok": false`)) {
		fmt.Println("audit chain verdict: FAIL (report reports invalid, despite exit 0)")
		return false
	}
	fmt.Println("audit chain verdict: PASS")
	return true
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
