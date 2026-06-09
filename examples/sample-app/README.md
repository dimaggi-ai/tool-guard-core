# Sample App — End-to-End Tool Guard Demo

A minimal, runnable end-to-end demo: a hand-coded agent's tool calls are gated by `tg-proxy`. It shows how the OSS module
firewalls AI agent tool calls. Three programs cooperate:

```
┌──────────┐      ?    ┌────────────┐   evaluate    ┌───────────┐
│  agent   │ ─────────▶│  tg-proxy  │ ─────────────▶│  engine   │
│ (Go)     │           │            │   policy hit  │  + audit  │
│          │ ◀──── ✅ ──│ /evaluate  │ ◀─ decision ──│  ledger   │
│          │   or 🛑   └────────────┘               └───────────┘
│          │
│          │ allow only ┌────────────┐
│          │ ──────────▶│ refund-tool│
└──────────┘            │ (Go)       │
                        │ /refund    │
                        └────────────┘
```

- `tool/` — fake "refund API". Returns a tx_id when called. Stands in
  for your real refunds service / SQL backend / payment processor.
- `agent/` — sample agent that wants to issue four refunds. Before each
  one, it asks `tg-proxy` whether the call is allowed and only invokes
  the refund tool on `allowed`.
- `policies/` — the single policy `refund_cap_strict.yaml` (from the
  parent `policies/` directory) that enforces:
  - amount > $500 → DENY
  - reason field mentions $1000+ regardless of structured amount → ESCALATE

## Run it

```bash
./run.sh
```

The script:
1. Builds `tg-proxy`, `sample-tool`, and `sample-agent` into the repo
   root's `bin/`.
2. Starts the refund tool (`:18080`) and `tg-proxy` (`:19090`) in the
   background.
3. Runs the agent against both.
4. Calls `tg verify` on the audit chain `tg-proxy` produced.
5. Prints the proxy's metrics counters.
6. Cleans up.

## What you should see

```text
──────── scenario 1/4 ────────
  → small refund ($85) for a damaged item — should pass
  tg-proxy: decision=allowed action=allowed reason=No rules triggered; ...
  refund-tool: tx_id=tx-... amount=$85.00

──────── scenario 2/4 ────────
  → large refund ($1000) without supervisor approval — should be denied
  tg-proxy: decision=denied action=denied reason=Denied by: [rule-amount-cap] ...
  refund-tool: NOT CALLED (proxy denied)

──────── scenario 3/4 ────────
  → modest refund but reason mentions $1500 — strict policy should escalate
  tg-proxy: decision=escalated action=escalated reason=Escalated by: [rule-reason-amount-consistency] ...
  refund-tool: NOT CALLED (proxy escalated for human review)

──────── scenario 4/4 ────────
  → another small refund ($120) for a clean reason — should pass
  tg-proxy: decision=allowed action=allowed reason=No rules triggered; ...
  refund-tool: tx_id=tx-... amount=$120.00
```

Then `tg verify` reports `intact: true` with 4 records, and the metrics
endpoint shows the counts.

## What the demo shows

1. **The proxy runs the engine over HTTP.** It accepts the agent's
   evaluation request, evaluates policies, and returns a decision the
   agent obeys.
2. **A denied decision blocks the action.** When the proxy returns
   `denied`, the agent does not call the refund tool — `tool.log` shows
   the "processing $X for CUST-Y" line only for the allowed scenarios.
3. **The audit log is tamper-evident.** `tg verify` re-derives every
   trace's hash from the canonical bytes and walks the chain links;
   editing one byte of one record reports the exact failure line.
4. **The agent's contract is portable.** The agent talks to `tg-proxy`
   over plain HTTP and JSON — no Tool Guard SDK required. Any agent
   framework (MCP, LangChain, AutoGen, the Anthropic / OpenAI tool-use
   loop) can wire the same callback pattern in a few lines. See
   [`../../docs/integration.md`](../../docs/integration.md).

## Files

| Path | Purpose |
|---|---|
| `tool/main.go` | The fake refund API server |
| `agent/main.go` | The sample agent loop |
| `policies/refund_cap_strict.yaml` | The policy enforced by the proxy |
| `run.sh` | Orchestrate the full demo |
| `decisions.jsonl` | (produced) hash-chained audit log |
| `tool.log`, `proxy.log` | (produced) stderr from the background services |

## Reset / re-run

The script wipes `decisions.jsonl` at the start of every run so the
demo is fully reproducible.

## Next

- Replace `tool/main.go` with your real tool (or call the real API
  directly from the agent — `tg-proxy` doesn't care, it only sees the
  envelope you send it).
- Replace the policy with your own (`tg lint` will warn if the new one
  has a known footgun).
- Embed the library directly in your agent instead of going through the
  HTTP proxy — see [`../../docs/integration.md`](../../docs/integration.md)
  for the two patterns.
