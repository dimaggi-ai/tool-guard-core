# Performance: what is measured, where, and what is promised

Two different numbers get quoted around this project. They measure
different things and only one of them is a published floor.

## 1. Engine microbenchmark (informational, not a promise)

`tg benchmark` runs the deterministic evaluation path in-process —
no HTTP, no audit write — and reports percentiles:

```bash
tg benchmark -trials 10000
# {"p50_us": 3, "p95_us": 8, "p99_us": 14, "max_us": 387, "trials": 10000}
```

The p99 ≈ 14µs figure in the README and
[docs/integration.md](integration.md) comes from an AMD Ryzen 7 7700
(16 threads). It is a single point measurement, not a floor. Run
`tg benchmark` on your hardware and use that result. The proxy adds
one HTTP hop plus JSON marshal/unmarshal: expect sub-millisecond
round trips over loopback TCP on the same host (`tg-proxy` listens on
a TCP `host:port`) and 1–3 ms across a Kubernetes pod.

## 2. Published `tg-proxy` floor (asserted nightly)

The published floor is **2,000 req/s with p99 ≤ 200 ms at
concurrency 50**, asserted every night by
[`.github/workflows/nightly-stress.yml`](../.github/workflows/nightly-stress.yml)
against a real `tg-proxy` process.

Methodology, exactly as the workflow runs it:

- **Harness:** `cmd/stress-test` fires a realistic allow/deny mix of
  `/evaluate` envelopes at a `tg-proxy` loaded with the shipped
  `policies/` directory, stepping concurrency through 1, 10, 50, 200,
  then an overload phase (2,000 in-flight) that must fail *closed*
  (clean rejections — never a 200 with the wrong decision, never a
  hang).
- **Correctness under load:** after the load and overload phases
  complete, the harness shells out to `tg verify` and asserts the audit
  hash chain written by the concurrent goroutines is still intact.
- **Hardware:** GitHub-hosted `ubuntu-latest` runners — shared-tenant
  machines with real variance. Identical code has measured anywhere
  from ~10k to ~26k req/s at concurrency 50 depending on runner load.
- **Why the floor is conservative:** 2,000 req/s is far below the
  ~10–26k req/s actually measured, by design — wide enough margin that
  a slow shared runner doesn't false-fail, tight enough that a genuine
  collapse (audit-mutex contention going pathological, an accidental
  serialization) still fails within a day.
- **Why nightly, not per-PR:** gating every PR on shared-tenant
  throughput noise produces flaky failures unrelated to the change
  under review. PRs still run the 30s-per-target fuzz gate; the floor
  runs on a fixed schedule and on manual dispatch.

Reproduce locally:

```bash
make stress          # build, start a real tg-proxy, load/overload/verify, then fuzz
# or directly, against your own deployment:
go run ./cmd/stress-test -target http://127.0.0.1:9090 \
  -concurrency 1,10,50,200 -overload 2000 \
  -tg-bin ./bin/tg -audit-log /path/to/decisions.jsonl \
  -floor-concurrency 50 -floor-min-rps 2000 -floor-max-p99 200ms
```

A floor for *your* hardware is the same command with your numbers: run
it in your environment, pick conservative values the same way, and wire
it into your own scheduler.
