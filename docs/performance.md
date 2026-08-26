# Performance: what is measured, where, and what is promised

Performance is checked at three layers. The engine microbenchmark is an
informational point measurement; the proxy relative-regression gate and
pathological-input ceiling are nightly assertions with their environments
stated below.

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

## 2. `tg-proxy` relative-regression gate (asserted nightly)

[`.github/workflows/nightly-stress.yml`](../.github/workflows/nightly-stress.yml)
builds the candidate commit and the latest reachable release tag, starts both
real `tg-proxy` binaries on the same GitHub runner, and drives them
simultaneously at concurrency 50 for 15 seconds each. The gate fails when the
candidate's contract-valid 200/202 throughput is **at least 10% lower than the
release baseline**. An exact 10% regression fails.

Methodology, exactly as the workflow runs it:

- **Harness:** `cmd/stress-test` first measures the fresh candidate and baseline
  concurrently, before candidate-only load can mutate the bounded escalation
  store. It then fires a realistic allow/deny mix of `/evaluate` envelopes at
  the candidate loaded with the shipped `policies/` directory, stepping
  concurrency through 1, 10, 50, 200, before an overload phase (2,000
  in-flight) that must fail *closed* (clean rejections — never a 200 with the
  wrong decision, never a hang).
- **Throughput denominator:** every contract-valid HTTP 200/202 evaluation
  response counts, including HTTP 202 for a valid escalation. Earlier harness versions counted
  only HTTP 200, so the reported rate changed with the random allow/deny/
  escalate mix even when the proxy handled the same number of requests.
- **Correctness under load:** after the load and overload phases
  complete, the harness shells out to `tg verify` and asserts the audit
  hash chain written by the concurrent goroutines is still intact.
- **Control selection:** `git describe --tags --abbrev=0` selects the latest
  release reachable from the candidate. The workflow fetches complete history
  and tags, builds that checkout in a detached worktree, and logs both refs.
- **Hardware:** GitHub-hosted `ubuntu-latest` x64, Go 1.25.13, without the race
  detector. The workflow prints `uname -a`, `lscpu`, and `go version` so each
  run records its actual shared-runner environment. Running both proxies
  together means host-wide throttling affects both sides of the comparison.
- **Why relative, not absolute:** unchanged code on this shared runner produced
  roughly 1,950-2,594 successful responses/second in five August 2026 runs,
  then only 274.5 responses/second in a fresh run on 2026-08-25 while every
  correctness, audit, overload, fuzz, and pathological-input check passed.
  Runner allocation is therefore not stable enough for a defensible absolute
  throughput or p99 assertion.
- **Interpretation:** this detects a candidate that regresses against the
  latest release under the same immediate host conditions. It is not a
  capacity promise for arbitrary deployments.
- **Why nightly, not per-PR:** gating every PR on shared-tenant
  throughput noise produces flaky failures unrelated to the change
  under review. PRs still run the 30s-per-target fuzz gate; the relative gate
  runs on a fixed schedule and on manual dispatch.

Reproduce locally:

```bash
make stress          # build, start a real tg-proxy, load/overload/verify, then fuzz
# Or start candidate and baseline proxies on ports 9090 and 9091, then:
go run ./cmd/stress-test -target http://127.0.0.1:9090 \
  -concurrency 1,10,50,200 -overload 2000 \
  -tg-bin ./bin/tg -audit-log /path/to/decisions.jsonl \
  -baseline-target http://127.0.0.1:9091 \
  -compare-concurrency 50 -compare-duration 15s -max-regression-pct 10
```

For a capacity floor on dedicated hardware, first record the CPU model,
available cores, memory, operating system, Go version, proxy configuration,
policy set, and repeated baseline results. Then use the harness's separate
absolute-floor flags with thresholds qualified for that environment:

```bash
go run ./cmd/stress-test -target http://127.0.0.1:9090 \
  -concurrency 1,10,50,200 -duration 30s -overload 2000 \
  -tg-bin ./bin/tg -audit-log /path/to/decisions.jsonl \
  -floor-concurrency 50 -floor-min-rps "${MIN_RPS}" \
  -floor-max-p99 "${MAX_P99}"
```

Do not reuse another machine's values: qualify conservative thresholds from
repeated runs on the hardware and deployment shape the gate protects.

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
