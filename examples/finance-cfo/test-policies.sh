#!/usr/bin/env bash
# Deterministic policy correctness suite for examples/finance-cfo/.
# Curated envelopes hit every rule in every policy. No LLM, no
# external services — just curl + jq against a local tg-proxy.
#
# Usage:
#   ../../bin/tg-proxy -listen :19090 \
#     -policy-dir ./policies \
#     -audit-log /tmp/finance-decisions.jsonl &
#   bash test-policies.sh
#
# Each test asserts (decision, rule_id_substring). Exits non-zero on
# any miss.
set -e
PROXY=${PROXY:-http://127.0.0.1:19090/evaluate}
PASS=0
FAIL=0

check() {
  local name="$1" body="$2" want="$3" want_rule="${4:-}"
  local resp got rule
  resp=$(curl -s -X POST -H 'Content-Type: application/json' -d "$body" "$PROXY")
  got=$(echo "$resp" | jq -r '.action_taken' 2>/dev/null || echo PARSE_ERR)
  rule=$(echo "$resp" | jq -r '.decision_reason' 2>/dev/null)
  if [ "$got" = "$want" ]; then
    # Match the rule_id as a bracketed token `[rule-id]` exactly as
    # the proxy formats it in decision_reason. Bare substring grep
    # would let `rule-po-amount-cap` falsely satisfy a future
    # `rule-po-amount-cap-strict` assertion (or vice versa); the
    # bracket anchors prevent that footgun.
    if [ -n "$want_rule" ] && ! echo "$rule" | grep -qF "[$want_rule]"; then
      printf "  FAIL %-58s got=%s rule=%s\n" "$name" "$got" "$rule"
      FAIL=$((FAIL+1))
    else
      printf "  PASS %-58s -> %s\n" "$name" "$got"
      PASS=$((PASS+1))
    fi
  else
    printf "  FAIL %-58s got=%s want=%s\n" "$name" "$got" "$want"
    FAIL=$((FAIL+1))
  fi
}

# build_env params_json [velocity_1h] [velocity_24h]
# Builds an envelope with parameters (must include "amount" inside),
# tool_name, tool_group, and a verified context that carries the
# agent_velocity buckets the policies key on.
build_env() {
  local tool="$1" group="$2" params="$3" v1h="${4:-0}" v24h="${5:-0}"
  cat <<EOF
{
  "envelope_id": "env-$(date +%s%N)",
  "agent_id": "finance-bot",
  "session_id": "sess-fin-test",
  "org_id": "acme",
  "tool_name": "$tool",
  "tool_group": "$group",
  "parameters": $params,
  "context": {
    "verified": {
      "agent_velocity": {
        "monetary_count_1h": 0,
        "monetary_sum_1h": $v1h,
        "monetary_count_24h": 0,
        "monetary_sum_24h": $v24h,
        "token_count_1h": 0,
        "token_count_24h": 0,
        "llm_cost_usd_1h": 0,
        "llm_cost_usd_24h": 0
      }
    }
  }
}
EOF
}

echo "── A. Purchase order (5 rules) ──"
check "PO under cap, approved vendor"          "$(build_env place_purchase_order procurement '{"amount":5000,"vendor_id":"V-1234","justification":"Quarterly office supplies","outside_business_hours":false}')"               allowed
check "PO over $10k cap"                       "$(build_env place_purchase_order procurement '{"amount":15000,"vendor_id":"V-1234","justification":"Quarterly office supplies","outside_business_hours":false}')"              denied    rule-po-amount-cap
check "PO under cap, unapproved vendor"        "$(build_env place_purchase_order procurement '{"amount":5000,"vendor_id":"ACME-WIDGETS","justification":"Quarterly office supplies","outside_business_hours":false}')"          escalated rule-po-vendor-allowlist
check "PO under cap, NEW- vendor prefix"       "$(build_env place_purchase_order procurement '{"amount":5000,"vendor_id":"NEW-7","justification":"Quarterly office supplies","outside_business_hours":false}')"                 escalated rule-po-vendor-allowlist
check "PO under cap, justification fragments"  "$(build_env place_purchase_order procurement '{"amount":100,"vendor_id":"V-1234","justification":"Buying $200,000 of widgets","outside_business_hours":false}')"                escalated rule-po-justification-amount-tripwire
check "PO daily cumulative blown ($60k)"       "$(build_env place_purchase_order procurement '{"amount":5000,"vendor_id":"V-1234","justification":"Quarterly office supplies","outside_business_hours":false}' 0 60000)"          denied    rule-po-daily-spend
check "PO off-hours"                           "$(build_env place_purchase_order procurement '{"amount":5000,"vendor_id":"V-1234","justification":"Quarterly office supplies","outside_business_hours":true}')"                 escalated rule-po-off-hours

echo
echo "── B. Wire transfer (5 rules) ──"
check "Wire small — always escalates"          "$(build_env send_wire high_risk_payment '{"amount":1000,"beneficiary_id":"B-1234","beneficiary_country":"US"}')"                                                                escalated rule-wire-always-escalate
check "Wire over hard cap ($300k)"             "$(build_env send_wire high_risk_payment '{"amount":300000,"beneficiary_id":"B-1234","beneficiary_country":"US"}')"                                                              denied    rule-wire-amount-hard-cap
check "Wire to NEW- beneficiary"               "$(build_env send_wire high_risk_payment '{"amount":1000,"beneficiary_id":"NEW-9","beneficiary_country":"US"}')"                                                                 denied    rule-wire-deny-new-beneficiary
check "Wire to sanctioned country (IR)"        "$(build_env send_wire high_risk_payment '{"amount":1000,"beneficiary_id":"B-1234","beneficiary_country":"IR"}')"                                                                denied    rule-wire-sanctioned-country
check "Wire to sanctioned country (ru lower)"  "$(build_env send_wire high_risk_payment '{"amount":1000,"beneficiary_id":"B-1234","beneficiary_country":"ru"}')"                                                                denied    rule-wire-sanctioned-country
check "Wire to non-B-NNNN beneficiary"         "$(build_env send_wire high_risk_payment '{"amount":1000,"beneficiary_id":"ACME-CORP","beneficiary_country":"US"}')"                                                              denied    rule-wire-deny-new-beneficiary
check "Wire daily cumulative blown ($600k)"    "$(build_env send_wire high_risk_payment '{"amount":1000,"beneficiary_id":"B-1234","beneficiary_country":"US"}' 0 600000)"                                                       denied    rule-wire-daily-cumulative

echo
echo "── C. Expense velocity (3 rules) ──"
check "Expense under burn"                     "$(build_env submit_expense expense '{"amount":100,"line_item_count":3}')"                                                                                                       allowed
check "Expense hourly burn escalates ($6k/h)"  "$(build_env submit_expense expense '{"amount":100,"line_item_count":3}' 6000 6000)"                                                                                             escalated rule-expense-hourly-escalate
check "Expense daily burn denies ($25k/24h)"   "$(build_env submit_expense expense '{"amount":100,"line_item_count":3}' 0 25000)"                                                                                               denied    rule-expense-daily-deny
check "Expense report 120 line items flagged"  "$(build_env submit_expense expense '{"amount":100,"line_item_count":120}')"                                                                                                     flagged   rule-expense-line-item-count

echo
echo "── RESULT: $PASS passed, $FAIL failed ──"
[ "$FAIL" -eq 0 ]
