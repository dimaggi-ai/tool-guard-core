# Policies

The quick-start policies that ship in this directory:

| File | What it does |
|------|--------------|
| [`refund_cap.yaml`](refund_cap.yaml) | Refund over the cap → deny. Narrow scope on purpose — `tg lint` flags the tool-substitution gap. |
| [`refund_cap_strict.yaml`](refund_cap_strict.yaml) | Same cap, lint-clean (adds tool-group scope + a reason-field tripwire). |
| [`refund_velocity_cap.yaml`](refund_velocity_cap.yaml) | Rolling **1h refund total** cap + 24h count ceiling — closes the amount-fragmentation bypass (many small refunds under a per-call cap). Run `tg-proxy -velocity-track` to have the proxy compute the windows, or supply your own `agent_velocity.*` totals. |
| [`irreversibility_floor.yaml`](irreversibility_floor.yaml) | An action the reversibility classifier marks irreversible (money movement, data destruction, production deploy, `rm -rf`, SQL `DROP`) or cannot classify → escalate to a human. Reversible actions are allowed. |
| [`coding_agent_writes.yaml`](coding_agent_writes.yaml) | Coding-agent file writes: deny system paths, writes over 5 MiB, and private-key material. |
| [`coding_agent_context_files.yaml`](coding_agent_context_files.yaml) | A write to an agent instruction or config file (AGENTS.md, CLAUDE.md, `.mcp.json`, `.claude/settings.json` and others) → escalate. A file write with a known key format in its content → deny, whatever the file. Shell redirects are not covered: use `tg hook -protect-path`. |
| [`coding_agent_egress.yaml`](coding_agent_egress.yaml) | Coding-agent outbound HTTP: deny the cloud metadata endpoints and any scheme other than https. |
| [`coding_agent_secret_egress.yaml`](coding_agent_secret_egress.yaml) | Deny a call that carries a known key format to a host outside its list, and a client command line that names a dotenv file. A narrow pattern check: read the five limits in the file. |
| [`coding_agent_secret_commands.yaml`](coding_agent_secret_commands.yaml) | Record a secret typed into a shell command, an agent config file or a note. Ships in shadow mode: it blocks nothing until you switch it to enforcement. |
| [`llm_token_spend_guard.yaml`](llm_token_spend_guard.yaml) | Per-agent LLM cost ceilings (escalate $50/h, deny $300/day). Reads `agent_velocity.*` from the call context. Core does not track *token/cost* spend over time — **you supply those running totals**; only the monetary window is proxy-computable (via `-velocity-track`). |

`-policy-dir policies` loads every `.yaml` policy in this directory, the coding-agent
policies included.

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
