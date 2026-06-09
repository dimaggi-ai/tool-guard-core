#!/usr/bin/env bash
#
# run-all-suites.sh — bring up the postgres-attack Docker stack (real
# Postgres + tg-proxy + db-tool + os-tool) and run ALL THREE protection
# suites against it:
#
#   1. test-policies.sh          — 28 deterministic SQL/shell/path assertions
#   2. bruteforce-policies.sh    — 45 evasion attempts (case games, comments,
#                                  dollar-quoting, tool-name spoofing, traversal)
#   3. bruteforce-adversarial.sh — 56 deeper attacks (modifying CTEs, server-side
#                                  file functions, shell-meta paths, interpreter -c)
#
# Each suite exits non-zero on any failed assertion or any BYPASS, so this
# script fails loudly if the firewall ever lets an attack through.
#
# No LLM required — these are deterministic. Needs Docker + curl + jq.
set -euo pipefail

cd "$(dirname "$0")"
trap 'docker compose down -v >/dev/null 2>&1 || true' EXIT

echo "→ building + starting postgres / tg-proxy / db-tool / os-tool"
docker compose up -d --build postgres tg-proxy db-tool os-tool >/dev/null

echo "→ waiting for tg-proxy /healthz"
ready=0
for _ in $(seq 1 60); do
  if curl -fs http://127.0.0.1:19090/healthz >/dev/null 2>&1; then ready=1; break; fi
  sleep 1
done
if [ "$ready" != 1 ]; then
  echo "tg-proxy never became healthy; logs:"; docker compose logs tg-proxy | tail -20
  exit 1
fi
echo "  proxy healthy"

echo
echo "════════ 1/3  test-policies.sh (28 deterministic assertions) ════════"
bash test-policies.sh

echo
echo "════════ 2/3  bruteforce-policies.sh (45 evasion attempts) ════════"
bash bruteforce-policies.sh

echo
echo "════════ 3/3  bruteforce-adversarial.sh (56 adversarial attacks) ════════"
bash bruteforce-adversarial.sh

echo
echo "✓ postgres-attack: 28 + 45 + 56 = 129 checks, zero bypasses"
