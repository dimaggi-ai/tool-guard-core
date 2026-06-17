# Policies

The quick-start policies that ship in this directory:

| File | What it does |
|------|--------------|
| [`refund_cap.yaml`](refund_cap.yaml) | Refund over the cap → deny. Narrow scope on purpose — `tg lint` flags the tool-substitution gap. |
| [`refund_cap_strict.yaml`](refund_cap_strict.yaml) | Same cap, lint-clean (adds tool-group scope + a reason-field tripwire). |
| [`llm_token_spend_guard.yaml`](llm_token_spend_guard.yaml) | Per-agent LLM cost ceilings (escalate $50/h, deny $300/day). Reads `agent_velocity.*` from the call context — **you supply the running totals**; Core is stateless and does not track spend over time. |

Run or check one — from the repo root, after `make build`:

```bash
./bin/tg evaluate -policy policies/refund_cap.yaml -call examples/call_over_cap.json -mode enforcement
./bin/tg lint     -policy policies/refund_cap.yaml      # scope + rule hygiene
```

Larger real-world policy sets — finance (POs / wires / expenses), customer-data
export (GDPR/CCPA), database & shell guards, multimodal content safety — ship
with their scenarios under [`../examples/`](../examples) and are indexed in the
main [README → Examples included](../README.md#examples-included).

**Contribute a policy:** open a PR with a `tg lint`-clean `.yaml` and a one-line
description. No account, no hub — just a file.
