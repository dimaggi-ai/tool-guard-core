#!/usr/bin/env bash
# Upgrade shim. install.sh up to 0.8.x wrote this file's absolute path into
# harness config files. It keeps those installs working with the policy and the
# blocking behaviour they had: one policy file (TG_POLICY, default policy.yaml)
# and an escalation that blocks the call.
# Re-run install.sh to move to the current wiring.
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TG_BIN="${TG_BIN:-$here/../../../bin/tg}"
export TG_POLICY_FILE="${TG_POLICY:-$here/../policy.yaml}"
export TG_PROTECT_BASELINE="${TG_PROTECT_BASELINE:-0}"
if [ "${TG_FAIL:-closed}" = open ] && { [ ! -x "$TG_BIN" ] || [ ! -f "$TG_POLICY_FILE" ]; }; then
  cat >/dev/null
  exit 0
fi
export TG_ESCALATE_AS=deny
exec "$here/guard-hook.sh" claude
