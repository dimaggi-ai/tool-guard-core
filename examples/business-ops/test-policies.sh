#!/usr/bin/env bash
# Deterministic policy correctness suite for examples/business-ops/.
# Curated envelopes hit every rule in every policy. No LLM, no
# external services — just curl + jq against a local tg-proxy.
#
# Usage:
#   ../../bin/tg-proxy -listen :19090 \
#     -policy-dir ./policies \
#     -audit-log /tmp/business-decisions.jsonl &
#   bash test-policies.sh
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
    # would allow `rule-credit-amount-cap` to falsely satisfy a
    # future `rule-credit-amount-cap-strict` assertion; the bracket
    # anchors prevent that footgun.
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

build_env() {
  local tool="$1" group="$2" params="$3"
  cat <<EOF
{
  "envelope_id": "env-$(date +%s%N)",
  "agent_id": "ops-bot",
  "session_id": "sess-ops-test",
  "org_id": "acme",
  "tool_name": "$tool",
  "tool_group": "$group",
  "parameters": $params,
  "context": {"verified": {}}
}
EOF
}

echo "── A. Customer data export (5 rules) ──"
check "Single-customer 1k export"           "$(build_env export_customer_data data_export '{"row_count":1000,"customer_id_count":1,"fields":"id,email,country","legal_hold_ticket":"","customer_status":"active"}')"                allowed
check "Bulk export 20k rows"                "$(build_env export_customer_data data_export '{"row_count":20000,"customer_id_count":1,"fields":"id,email","legal_hold_ticket":"","customer_status":"active"}')"                       escalated rule-export-row-cap
check "Bulk export 200k rows hard deny"     "$(build_env export_customer_data data_export '{"row_count":200000,"customer_id_count":1,"fields":"id,email","legal_hold_ticket":"","customer_status":"active"}')"                      denied    rule-export-absolute-cap
check "PII export, empty legal-hold"        "$(build_env export_customer_data data_export '{"row_count":50,"customer_id_count":1,"fields":"id,ssn,dob","legal_hold_ticket":"","customer_status":"active"}')"                        denied    rule-export-pii-fields-deny
check "PII export, MISSING legal-hold key"  "$(build_env export_customer_data data_export '{"row_count":50,"customer_id_count":1,"fields":"id,ssn,dob","customer_status":"active"}')"                                               denied    rule-export-pii-fields-deny
check "PII export, junk legal-hold value"   "$(build_env export_customer_data data_export '{"row_count":50,"customer_id_count":1,"fields":"id,ssn,dob","legal_hold_ticket":"0","customer_status":"active"}')"                        denied    rule-export-pii-fields-deny
check "PII export with valid LH-NNNN"       "$(build_env export_customer_data data_export '{"row_count":50,"customer_id_count":1,"fields":"id,ssn,dob","legal_hold_ticket":"LH-2026","customer_status":"active"}')"                  allowed
check "PII-suffixed field (passport_num)"   "$(build_env export_customer_data data_export '{"row_count":50,"customer_id_count":1,"fields":"id,passport_number","legal_hold_ticket":"","customer_status":"active"}')"                  denied    rule-export-pii-fields-deny
check "Multi-customer export escalates"     "$(build_env export_customer_data data_export '{"row_count":500,"customer_id_count":50,"fields":"id,email","legal_hold_ticket":"","customer_status":"active"}')"                        escalated rule-export-multi-customer
check "Right-to-erasure customer denied"    "$(build_env export_customer_data data_export '{"row_count":1,"customer_id_count":1,"fields":"id,email","legal_hold_ticket":"","customer_status":"erased"}')"                           denied    rule-export-erased-customer

echo
echo "── B. Mass communication (5 rules) ──"
check "Small batch under cap"               "$(build_env send_marketing_email mass_communication '{"recipient_count":500,"body":"Spring catalog is live","from_address":"marketing@company.com","segment_id":"spring-2026"}')"           allowed
check "Bulk send 5000 escalates"            "$(build_env send_marketing_email mass_communication '{"recipient_count":5000,"body":"Spring catalog is live","from_address":"marketing@company.com","segment_id":"spring-2026"}')"          escalated rule-mass-comm-recipient-escalate
check "Mass blast 100k hard deny"           "$(build_env send_marketing_email mass_communication '{"recipient_count":100000,"body":"Spring catalog is live","from_address":"marketing@company.com","segment_id":"spring-2026"}')"        denied    rule-mass-comm-recipient-deny
check "Banned claim — guaranteed returns"   "$(build_env send_marketing_email mass_communication '{"recipient_count":100,"body":"Guaranteed returns or your money back","from_address":"marketing@company.com","segment_id":"vip-q2"}')"  denied    rule-mass-comm-banned-claims
check "Banned claim — guaranteed 50% return" "$(build_env send_marketing_email mass_communication '{"recipient_count":100,"body":"Guaranteed 50% returns this quarter","from_address":"marketing@company.com","segment_id":"vip-q2"}')" denied    rule-mass-comm-banned-claims
check "Banned claim — cures all cancer"      "$(build_env send_marketing_email mass_communication '{"recipient_count":100,"body":"Our supplement cures all cancer types","from_address":"marketing@company.com","segment_id":"vip-q2"}')" denied    rule-mass-comm-banned-claims
check "Disallowed sender (finance@)"        "$(build_env send_marketing_email mass_communication '{"recipient_count":100,"body":"Quarterly newsletter","from_address":"finance@company.com","segment_id":"vip-q2"}')"                    denied    rule-mass-comm-sender-allowlist
check "External sender (gmail) denied"      "$(build_env send_marketing_email mass_communication '{"recipient_count":100,"body":"Quarterly newsletter","from_address":"marketing@evil.com","segment_id":"vip-q2"}')"                     denied    rule-mass-comm-sender-allowlist
check "No segment_id is flagged"            "$(build_env send_marketing_email mass_communication '{"recipient_count":100,"body":"Quarterly newsletter","from_address":"marketing@company.com","segment_id":""}')"                        flagged   rule-mass-comm-untargeted

echo
echo "── C. Support credit (5 rules) ──"
check "Tier-1 comp \$50 to paid customer"   "$(build_env issue_account_credit customer_comp '{"amount":50,"reason":"Late shipment apology","customer_tier":"paid"}')"                                                                    allowed
check "Comp \$1000 escalates"               "$(build_env issue_account_credit customer_comp '{"amount":1000,"reason":"Repeated outages","customer_tier":"paid"}')"                                                                       escalated rule-credit-amount-cap
check "Comp \$5000 denies"                  "$(build_env issue_account_credit customer_comp '{"amount":5000,"reason":"Repeated outages","customer_tier":"paid"}')"                                                                       denied    rule-credit-amount-hard-cap
check "Per-ticket cumulative over cap"      "$(build_env issue_account_credit customer_comp '{"amount":100,"reason":"Latest in series","customer_tier":"paid","cumulative_comp_so_far":2500}')"                                          denied    rule-credit-ticket-cumulative
check "Reason cites CEO authority"          "$(build_env issue_account_credit customer_comp '{"amount":100,"reason":"The CEO promised me a full refund","customer_tier":"paid"}')"                                                       escalated rule-credit-reason-authority-claim
check "Reason cites supervisor approval"    "$(build_env issue_account_credit customer_comp '{"amount":100,"reason":"My supervisor authorized this","customer_tier":"paid"}')"                                                          escalated rule-credit-reason-authority-claim
check "Comp to trial customer flagged"      "$(build_env issue_account_credit customer_comp '{"amount":25,"reason":"Win-back trial","customer_tier":"trial"}')"                                                                          flagged   rule-credit-trial-customer-flag

echo
echo "── RESULT: $PASS passed, $FAIL failed ──"
[ "$FAIL" -eq 0 ]
