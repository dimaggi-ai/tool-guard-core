#!/usr/bin/env bash
# Orchestrates the full stress suite: builds the binaries, starts a real
# tg-proxy against the shipped example policies, runs cmd/stress-test
# against it (throughput/latency at increasing concurrency, an overload
# phase checking fail-closed behavior, and an audit-chain integrity check),
# then runs the fuzz targets in cmd/tg-proxy/fuzz_test.go for a bounded
# time each. Exits non-zero if anything fails.
#
# Usage:
#   ./scripts/run-stress.sh                  # defaults (~90s total)
#   FUZZTIME=60s ./scripts/run-stress.sh      # longer fuzz runs
#   CONCURRENCY=1,10,50,200,1000 ./scripts/run-stress.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FUZZTIME="${FUZZTIME:-15s}"
CONCURRENCY="${CONCURRENCY:-1,10,50,200}"
OVERLOAD="${OVERLOAD:-2000}"

WORKDIR="$(mktemp -d)"
AUDIT_LOG="$WORKDIR/decisions.jsonl"
PROXY_PORT=19090
PROXY_PID=""

cleanup() {
  if [[ -n "$PROXY_PID" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

echo "==> Building binaries"
mkdir -p bin
go build -o bin/tg ./cmd/tg
go build -o bin/tg-proxy ./cmd/tg-proxy
go build -o bin/stress-test ./cmd/stress-test

echo "==> Starting tg-proxy on :$PROXY_PORT (audit-log=$AUDIT_LOG)"
./bin/tg-proxy \
  -listen ":$PROXY_PORT" \
  -policy-dir ./policies \
  -audit-log "$AUDIT_LOG" \
  -default-mode enforcement \
  > "$WORKDIR/tg-proxy.log" 2>&1 &
PROXY_PID=$!

echo "==> Load + overload phase"
LOAD_OK=1
./bin/stress-test \
  -target "http://127.0.0.1:$PROXY_PORT" \
  -concurrency "$CONCURRENCY" \
  -overload "$OVERLOAD" \
  -tg-bin ./bin/tg \
  -audit-log "$AUDIT_LOG" \
  || LOAD_OK=0

if [[ "$LOAD_OK" -ne 1 ]]; then
  echo "==> tg-proxy log (last 40 lines, for context on the failure above):"
  tail -40 "$WORKDIR/tg-proxy.log" || true
fi

echo "==> Fuzzing (fuzztime=$FUZZTIME per target)"
FUZZ_OK=1
for target in FuzzActionEnvelopeDecode FuzzValidateJSONDepth FuzzPolicyYAML; do
  echo "--- $target ---"
  go test -run '^$' -fuzz="$target" -fuzztime="$FUZZTIME" ./cmd/tg-proxy/ || FUZZ_OK=0
done

echo ""
if [[ "$LOAD_OK" -eq 1 && "$FUZZ_OK" -eq 1 ]]; then
  echo "STRESS SUITE (full): PASS"
  exit 0
fi
echo "STRESS SUITE (full): FAIL (load=$LOAD_OK fuzz=$FUZZ_OK)"
exit 1
