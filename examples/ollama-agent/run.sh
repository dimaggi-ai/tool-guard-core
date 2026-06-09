#!/usr/bin/env bash
#
# Real-LLM demo: gemma4 (via Ollama) calls a tool through tg-proxy.
#
# Brings up refund-tool + tg-proxy in the background, then runs the
# Ollama-driven agent against them. Prints the live transcript so an
# operator can see the model reason about the policy and adapt.
#
# Requires Ollama running locally with gemma4:e4b pulled. Override
# with -model on the agent command line if you have a different model.

set -euo pipefail

cd "$(dirname "$0")"

ROOT_DIR=$(cd ../.. && pwd)
BIN_DIR=$ROOT_DIR/bin
SAMPLE=$ROOT_DIR/examples/sample-app

TOOL_LISTEN=:18080
PROXY_LISTEN=:19090
AUDIT_LOG="$PWD/decisions.jsonl"
OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
MODEL="${MODEL:-gemma4:e4b}"
USER_MSG="${USER_MSG:-Customer CUST-001 had a damaged item from order ORD-9912. Please process a full refund of \$1000.}"

echo "=== preflight ==="
echo "ollama: $OLLAMA_URL"
echo "model:  $MODEL"

if ! curl -sf "$OLLAMA_URL/api/tags" > /dev/null; then
  echo "Ollama is not reachable at $OLLAMA_URL"
  echo "Start Ollama (e.g. \`ollama serve\`) and pull the model (\`ollama pull $MODEL\`), then re-run."
  exit 1
fi

if ! curl -sf "$OLLAMA_URL/api/tags" | grep -q "\"name\":\"$MODEL\""; then
  echo "Model $MODEL is not pulled. Run: ollama pull $MODEL"
  exit 1
fi

echo
echo "=== build (no-op if already built) ==="
(cd "$ROOT_DIR" && make build > /dev/null)
go build -o "$BIN_DIR/sample-tool" "$SAMPLE/tool"
go build -o "$BIN_DIR/ollama-agent" ./

# Fresh chain so the demo is reproducible.
rm -f "$AUDIT_LOG"

cleanup() {
  echo
  echo "=== shutdown ==="
  [[ -n "${TOOL_PID:-}" ]]  && kill "$TOOL_PID"  2>/dev/null || true
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
  -policy-dir "$SAMPLE/policies" \
  -audit-log "$AUDIT_LOG" \
  > proxy.log 2>&1 &
PROXY_PID=$!

sleep 1
curl -sf http://localhost:18080/healthz > /dev/null || { echo "refund-tool not reachable"; exit 1; }
curl -sf http://localhost:19090/readyz   > /dev/null || { echo "tg-proxy not ready"; exit 1; }

echo
echo "=== conversation ==="
"$BIN_DIR/ollama-agent" \
  -ollama "$OLLAMA_URL" \
  -model "$MODEL" \
  -proxy "http://localhost:19090" \
  -tool  "http://localhost:18080" \
  -user "$USER_MSG"

echo
echo "=== tg verify on the audit chain ==="
"$BIN_DIR/tg" verify -file "$AUDIT_LOG"

echo
echo "=== proxy metrics ==="
curl -s http://localhost:19090/metrics

echo
echo "Audit log: $AUDIT_LOG"
echo "Tool log:  $PWD/tool.log"
echo "Proxy log: $PWD/proxy.log"
