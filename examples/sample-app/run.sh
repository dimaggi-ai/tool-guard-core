#!/usr/bin/env bash
#
# End-to-end demo: refund-tool ← agent ← tg-proxy ← policies/
#
# Brings up the proxy and the fake refund API in the background, runs
# the sample agent against them, then verifies the audit chain that
# tg-proxy produced. All three programs are Go; no Python deps.
#
# Re-run any time. State (port reuse, audit log) is cleaned at the top.

set -euo pipefail

cd "$(dirname "$0")"

ROOT_DIR=$(cd ../.. && pwd)
BIN_DIR=$ROOT_DIR/bin

TOOL_LISTEN=:18080
PROXY_LISTEN=:19090
AUDIT_LOG="$PWD/decisions.jsonl"

echo "=== build everything (no-op if already built) ==="
(cd "$ROOT_DIR" && make build > /dev/null)
go build -o "$BIN_DIR/sample-tool" ./tool
go build -o "$BIN_DIR/sample-agent" ./agent

# Fresh chain so the demo is reproducible.
rm -f "$AUDIT_LOG"

cleanup() {
  echo
  echo "=== shutdown ==="
  [[ -n "${TOOL_PID:-}" ]] && kill "$TOOL_PID" 2>/dev/null || true
  [[ -n "${PROXY_PID:-}" ]] && kill "$PROXY_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

echo
echo "=== start refund-tool on $TOOL_LISTEN ==="
"$BIN_DIR/sample-tool" -listen "$TOOL_LISTEN" > tool.log 2>&1 &
TOOL_PID=$!

echo "=== start tg-proxy on $PROXY_LISTEN ==="
"$BIN_DIR/tg-proxy" \
  -listen "$PROXY_LISTEN" \
  -policy-dir ./policies \
  -audit-log "$AUDIT_LOG" \
  > proxy.log 2>&1 &
PROXY_PID=$!

# Wait (bounded) for both processes to come up instead of a fixed sleep.
wait_ready() {
  local url="$1" name="$2"
  for _ in $(seq 1 50); do
    curl -sf "$url" > /dev/null 2>&1 && return 0
    sleep 0.2
  done
  echo "$name not ready after 10s — is the port already in use?"
  exit 1
}
wait_ready http://localhost:18080/healthz refund-tool
wait_ready http://localhost:19090/readyz tg-proxy

echo
echo "=== run the agent ==="
"$BIN_DIR/sample-agent" \
  -proxy "http://localhost:19090" \
  -tool  "http://localhost:18080"

echo
echo "=== tg verify on the proxy's audit log ==="
"$BIN_DIR/tg" verify -file "$AUDIT_LOG"

echo
echo "=== proxy metrics (counter view) ==="
curl -s http://localhost:19090/metrics

echo
echo "Audit log: $AUDIT_LOG"
echo "Tool log:  $PWD/tool.log"
echo "Proxy log: $PWD/proxy.log"
