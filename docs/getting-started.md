# Getting Started

Tool Guard Core is a single Go binary plus a YAML policy file. From a
clean checkout, the path to a working policy firewall is five
commands.

## Prerequisites

- Go 1.25 or later (`go version`)
- `make`, `curl`, and `jq` (used by the build and the example assertion suites)
- (optional) Docker + Docker Compose for the postgres-attack and content-gen bundles
- (optional, for the content-gen / ollama-agent bundles) Ollama with `gemma4:e4b` pulled

## 1. Build the binaries

```sh
git clone https://github.com/dimaggi-ai/tool-guard-core
cd tool-guard-core
make build
```

Output:

```
bin/tg            # one-shot CLI: evaluate / verify / lint / benchmark
bin/tg-proxy      # HTTP service: POST /evaluate, hash-chained audit log
bin/battle-test   # adversarial harness driving a local Ollama model
bin/example-chain # generator for the sample audit chain
```

The default build is pure Go, statically linked, ~10 MB. No cgo.

## 2. Lint a policy

```sh
./bin/tg lint -policy policies/refund_cap.yaml
```

You will see two warnings — `scope-no-tool-group` and
`amount-without-semantic-check`. Both are intentional in this
quick-start file; they showcase how `tg lint` catches real bypass
classes before policies reach production. The `policies/refund_cap_strict.yaml`
sibling fixes both warnings.

Exit codes for `tg lint`:

| Exit | Meaning |
|---|---|
| 0 | No error-severity findings (warnings OK) |
| 6 | At least one error-severity finding |

## 3. Evaluate a tool call

```sh
./bin/tg evaluate \
  -policy policies/refund_cap.yaml \
  -call examples/call_over_cap.json
```

Output: a JSON `EvaluationResult` whose `decision` field is `denied`,
because the call's `parameters.amount = 1000` violates the policy's
`amount > 500` threshold. Exit code 3.

For a $85 refund (`call_under_cap.json`), the same command exits 0
with `decision: allowed`.

## 4. Run the HTTP proxy

```sh
./bin/tg-proxy \
  -listen 127.0.0.1:9090 \
  -policy-dir ./policies \
  -audit-log /tmp/decisions.jsonl &
```

POST a tool call to `/evaluate`:

```sh
curl -s -X POST -H 'Content-Type: application/json' -d '{
  "envelope_id":"env-001",
  "agent_id":"support-bot",
  "session_id":"sess-1",
  "org_id":"acme",
  "tool_name":"issue_refund",
  "tool_group":"monetary_outflow",
  "parameters":{"amount":1000,"reason":"Goodwill"}
}' http://127.0.0.1:9090/evaluate
```

The proxy's response is the same `EvaluationResult` as `tg evaluate`,
and every decision is appended to the SHA-256 hash-chained audit log
at `-audit-log`.

## 5. Verify the audit chain offline

```sh
./bin/tg verify -file /tmp/decisions.jsonl
```

Output:

```json
{
  "intact": true,
  "records": 1,
  "first_trace_id": "trc-...",
  "tail_hash": "sha256:..."
}
```

Flip one byte in the file and re-verify — `tg verify` reports the
exact line where the chain broke and exits 5.

## Next steps

- Read [creating-policies.md](creating-policies.md) for the full YAML
  schema.
- Read [architecture.md](architecture.md) for how the engine, the
  audit chain, and the classifiers fit together.
- Explore the four example bundles: `examples/finance-cfo/`,
  `examples/business-ops/`, `examples/postgres-attack/`,
  `examples/content-gen/`. Each ships its own policies, test
  script, and README.
- For the multimodal Gemma classifier walk-through, see
  [content-gen-bundle.md](content-gen-bundle.md).
- For the Core / Enterprise boundary, see [oss-vs-enterprise.md](oss-vs-enterprise.md).
