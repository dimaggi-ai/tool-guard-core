#!/usr/bin/env bash
# Upgrade shim. install.sh up to 0.8.x wrote this file's absolute path into
# harness config files. For such a config it uses the one policy file of that
# version (TG_POLICY, default policy.yaml) and returns an escalation as
# force_ask. The 0.8.x adapter returned ask.
# Re-run install.sh to move to the current wiring.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TG_BIN="${TG_BIN:-$here/../../../bin/tg}"
export TG_POLICY_FILE="${TG_POLICY:-$here/../policy.yaml}"
export TG_PROTECT_BASELINE="${TG_PROTECT_BASELINE:-0}"
if [ "${TG_FAIL:-closed}" = open ] && { [ ! -x "$TG_BIN" ] || [ ! -f "$TG_POLICY_FILE" ]; }; then
  cat >/dev/null
  exit 0
fi
exec "$here/guard-hook.sh" antigravity
