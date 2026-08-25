# Performance: what is measured, where, and what is promised

Performance is checked at three layers. The engine microbenchmark is an
informational point measurement; the proxy load floor and pathological-input
ceiling are nightly assertions with their environments stated below.

## 1. Engine microbenchmark (informational, not a promise)

`tg benchmark` runs the deterministic evaluation path in-process —
no HTTP, no audit write — and reports percentiles:

```bash
tg benchmark -trials 10000
# {"p50_us": 3, "p95_us": 8, "p99_us": 14, "max_us": 387, "trials": 10000}
```

The p99 ≈ 14µs figure quoted in the README and
[docs/integration.md](integration.md) was measured on an AMD Ryzen 7
7700 (16 threads). It is a point measurement on one machine, not a
floor: run `tg benchmark` on your own hardware and use that number.
The proxy adds one HTTP hop plus JSON marshal/unmarshal on top —
expect sub-millisecond round trips over loopback TCP on the same host
(`tg-proxy` listens on a TCP `host:port`) and 1–3 ms across a
Kubernetes pod.

## 2. Qualified `tg-proxy` regression floor (asserted nightly)

The qualified nightly floor is **1,900 successful 2xx responses/second with
p99 ≤ 200 ms at concurrency 50**, measured over a 15-second window by
[`.github/workflows/nightly-stress.yml`](../.github/workflows/nightly-stress.yml)
against a real `tg-proxy` process.

Methodology, exactly as the workflow runs it:

- **Harness:** `cmd/stress-test` fires a realistic allow/deny mix of
  `/evaluate` envelopes at a `tg-proxy` loaded with the shipped
  `policies/` directory, stepping concurrency through 1, 10, 50, 200,
  then an overload phase (2,000 in-flight) that must fail *closed*
  (clean rejections — never a 200 with the wrong decision, never a
  hang).
- **Throughput denominator:** every completed HTTP 2xx response counts,
  including HTTP 202 for a valid escalation. Earlier harness versions counted
  only HTTP 200, so the reported rate changed with the random allow/deny/
  escalate mix even when the proxy handled the same number of requests.
- **Correctness under load:** after the load and overload phases
  complete, the harness shells out to `tg verify` and asserts the audit
  hash chain written by the concurrent goroutines is still intact.
- **Hardware:** GitHub-hosted `ubuntu-latest` x64, Go 1.25.13, without the race
  detector. The workflow prints `uname -a`, `lscpu`, and `go version` so each
  run records its actual shared-runner environment.
- **Baseline evidence:** the five healthy scheduled runs from 2026-08-21
  through 2026-08-25, after the stress correctness fix, handled 1,956.6,
  2,593.8, 2,409.4, 1,949.6, and 2,067.4 successful responses/second at
  concurrency 50 when recomputed from their logged 2xx totals. The 1,900 floor
  is below the minimum and the longer 15-second window smooths short scheduler
  contention.
- **Regression sensitivity:** a 10% drop from the previous 2,000 req/s
  baseline is 1,800 req/s and therefore fails the 1,900 gate. This number is a
  qualified CI regression floor for the workload and runner above, not a
  capacity promise for arbitrary deployments.
- **Why nightly, not per-PR:** gating every PR on shared-tenant
  throughput noise produces flaky failures unrelated to the change
  under review. PRs still run the 30s-per-target fuzz gate; the floor
  runs on a fixed schedule and on manual dispatch.

Reproduce locally:

```bash
make stress          # build, start a real tg-proxy, load/overload/verify, then fuzz
# or directly, against your own deployment:
go run ./cmd/stress-test -target http://127.0.0.1:9090 \
  -concurrency 1,10,50,200 -duration 15s -overload 2000 \
  -tg-bin ./bin/tg -audit-log /path/to/decisions.jsonl \
  -floor-concurrency 50 -floor-min-rps 1900 -floor-max-p99 200ms
```

A floor for *your* hardware is the same command with your numbers: run
it in your environment, pick conservative values the same way, and wire
it into your own scheduler.

## 3. Pathological SQL classifier ceiling (asserted nightly)

The SQL classifier must process each bounded adversarial fixture in less than
**2 seconds**. The set includes 200,000-column SELECT input, 20,000 nested
parentheses, a 100,000-item IN list, comment and string floods, null bytes,
unterminated strings, a 50,000-statement flood ending in DROP, and a modifying
CTE buried behind 5,000 UNION branches.

Measurement conditions:

- **Runner:** GitHub-hosted `ubuntu-latest` x64, without the race detector.
- **Toolchain:** Go 1.25.13.
- **Evidence:** the nightly workflow prints `uname -a`, `lscpu`, and
  `go version` before the assertion so each result records the actual shared
  runner CPU and image environment.
- **Frequency:** nightly and manual dispatch only. Shared macOS/Windows/Linux
  PR runners do not enforce an absolute duration.

Every PR still runs the same inputs as a correctness test: no panic, a bounded
boolean result, and fail-closed decisions for the malicious cases. The ordinary
test relies on the Go test/CI job timeout for a true hang, not a two-second
machine-speed threshold.

Reproduce the nightly ceiling:

```bash
go test -tags=performance \
  -run '^TestPerformance_SQLClassifyPathologicalInput$' \
  -count=1 -timeout=3m ./pkg/engine/
```
