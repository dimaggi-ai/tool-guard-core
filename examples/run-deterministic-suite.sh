#!/usr/bin/env bash
#
# run-deterministic-suite.sh — start tg-proxy against ONE example
# bundle's policies, run that bundle's curl assertion suite, verify the
# resulting audit chain, and tear the proxy down. Exits non-zero if any
# assertion fails or the chain is broken.
#
# This is the exact path CI runs (.github/workflows/policy-protection.yml)
# and the exact path you can run locally:
#
#   ./examples/run-deterministic-suite.sh finance-cfo
#   ./examples/run-deterministic-suite.sh business-ops
#
# No Docker, no LLM — pure deterministic policy enforcement over HTTP.
set -euo pipefail

BUNDLE="${1:?usage: run-deterministic-suite.sh <bundle-dir under examples/>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROXY_BIN="$ROOT/bin/tg-proxy"
TG_BIN="$ROOT/bin/tg"
POLICY_DIR="$ROOT/examples/$BUNDLE/policies"
SUITE="$ROOT/examples/$BUNDLE/test-policies.sh"
AUDIT_LOG="$(mktemp -t "tg-${BUNDLE}-XXXXXX.jsonl")"
LISTEN="127.0.0.1:19090"

[ -x "$PROXY_BIN" ] || { echo "missing $PROXY_BIN — run 'make build' first"; exit 2; }
[ -d "$POLICY_DIR" ] || { echo "no policy dir: $POLICY_DIR"; exit 2; }
[ -f "$SUITE" ]      || { echo "no test suite: $SUITE"; exit 2; }

echo "→ starting tg-proxy for '$BUNDLE' on $LISTEN"
"$PROXY_BIN" -listen "$LISTEN" -policy-dir "$POLICY_DIR" -audit-log "$AUDIT_LOG" \
  > "/tmp/tg-proxy-$BUNDLE.log" 2>&1 &
PROXY_PID=$!
cleanup() { kill "$PROXY_PID" 2>/dev/null || true; rm -f "$AUDIT_LOG"; }
trap cleanup EXIT

echo "→ waiting for /readyz"
ready=0
for _ in $(seq 1 50); do
  if curl -fs "http://$LISTEN/readyz" >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.2
done
if [ "$ready" != 1 ]; then
  echo "tg-proxy never became ready; log:"; cat "/tmp/tg-proxy-$BUNDLE.log"; exit 1
fi

echo "→ running $BUNDLE assertion suite"
PROXY="http://$LISTEN/evaluate" bash "$SUITE"

echo "→ verifying the audit chain the suite just produced"
"$TG_BIN" verify -file "$AUDIT_LOG"

echo "✓ $BUNDLE: assertions passed and audit chain intact"
