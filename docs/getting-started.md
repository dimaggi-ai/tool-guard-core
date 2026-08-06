# Getting Started

Tool Guard Core is a single Go binary plus a YAML policy file. From a
clean checkout, the path to a working policy decision endpoint is five
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

You will see two warnings - `scope-no-tool-group` and
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

Flip one byte in the file and re-verify - `tg verify` reports the
exact line where the chain broke and exits 5.

## 5. Dry-run a policy set over a batch of calls

Before deploying a policy change, see what it would do to real traffic.
`tg simulate` runs the whole policy set against a JSONL file of envelopes
(one per line) and prints the decision breakdown plus per-rule fire counts:

```sh
./bin/tg simulate -policy-dir policies -calls yesterdays-calls.jsonl
```

```
Tool Guard simulate — 3 policies, 1000 calls
────────────────────────────────────────────────
  allowed        942   94.2%
  flagged          6    0.6%
  escalated       21    2.1%
  denied          31    3.1%
             e.g. env-8831, env-9002, env-9114
────────────────────────────────────────────────
  rule fires (by rule_id):
    rule-amount-cap               22  [deny]
    rule-refund-1h-sum             9  [deny]
    ...
```

It uses the exact same engine as `tg evaluate` and the proxy, so a
simulate verdict can't diverge from a live one. Add `-fail-on-deny` to
exit 3 when any call denies (gate a policy change in CI), `-json` for
machine-readable output, or `-calls -` to read from stdin.

## 5b. Measure coverage — what fraction of calls is governed at all

`tg simulate` shows the *decisions*; `tg coverage` shows the *blind spots* —
how many of your agent's tool calls have any governing policy versus pass only
because nothing governs them. It reads envelopes **or** decision traces, so you
can point it straight at an audit log:

```sh
./bin/tg coverage -policy-dir policies -calls audit-log.jsonl
```

```
Tool Guard coverage — 3 policies, 3705 tool calls
────────────────────────────────────────────────────────
  GOVERNED     3701   99.9%
  ungoverned      4    0.1%
  …
  coverage gaps (ungoverned tools, most frequent first):
    monitor    4 calls with no governing policy
```

`-min-coverage 90` exits 3 when coverage drops below the threshold (a CI gate
against a growing agent outrunning its policy); `-json` for machines.

## 6. Guard Claude Code with `tg protect`

The native workflow is preview-first and reversible:

```sh
./bin/tg protect claude
./bin/tg protect claude -apply
./bin/tg status claude
```

It merges one managed `PreToolUse` entry into `~/.claude/settings.json`,
preserves unrelated settings and hooks, installs a starter policy, enables
self-protection and consequential-tool fail-closed behavior, and records a
hash-chained audit log. Preview shows the complete proposed configuration and
writes nothing.

To remove it, preview and then apply rollback:

```sh
./bin/tg unprotect claude
./bin/tg unprotect claude -apply
```

See [protect.md](protect.md) for paths, overrides, backup behavior, and current
target support.

## 6b. Wire another agent with `tg hook`

`tg hook` is the batteries-included alternative to the hand-rolled shell
adapters in `examples/coding-agent-guard/`. It reads one PreToolUse JSON
object from stdin, evaluates it, and writes the hook response to stdout.
**Always exits 0** — the hook signals via JSON, never via exit code.

Add it to your Claude Code `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "bin/tg hook -policy-dir /path/to/policies -protect-self -fail-closed-tools bash,write,edit,notebookedit"
          }
        ]
      }
    ]
  }
}
```

Key flags:

| Flag | Purpose |
|---|---|
| `-policy-dir DIR` | Load all `*.yaml` policies from this directory |
| `-policy FILE` | Load a single policy file (mutually exclusive with `-policy-dir`) |
| `-protect-self` | Unconditionally protect the policy dir and `$HOME/.claude` from writes — the agent cannot edit this away |
| `-protect-path PATH` | Protect one exact prefix; repeat for multiple paths (preserves commas in names) |
| `-protect-paths P1,P2` | Additional prefixes to protect (comma-separated) |
| `-fail-closed` | Deny on any internal error (tooling glitch, bad policy load) |
| `-fail-closed-tools bash,write,edit,notebookedit` | Deny only these tools on error; others fail open |
| `-unknown-tools-deny` | Deny any tool_name not declared in `scope.tool_names` of a loaded enforcement policy — closes the gap where a new tool the agent starts calling matches no policy and is silently ungoverned |
| `-mode shadow\|enforcement` | Shadow mode records decisions without blocking (default: enforcement) |

`-protect-self` is the key insight: any deny rule you write inside the
policy can be edited away by the agent. `-protect-self` runs unconditionally
at the flag level and cannot be removed by an agent.

> **Recommended default for enforcing deployments: set `-fail-closed-tools`
> (or `-fail-closed`).** Without either flag, `tg hook` fails OPEN on any
> internal error (unparseable stdin, a policy that fails to load, an
> evaluator panic) — an unattributable tooling glitch never wedges the
> agent, but it also means an error waves the call through with no deny
> decision at all (as of 0.7.0 the load error is at least reported on
> stderr — visible, not prevented). That default exists so a transient hiccup on a dev
> machine doesn't block work; a deployment that's actually meant to enforce
> policy should not run without one of these flags. The example above
> already sets `-fail-closed-tools` for exactly this reason — treat it as
> the baseline for any real deployment, not an optional extra.

See `examples/coding-agent-guard/README.md` for the full wiring guide
covering Claude Code, OpenAI Codex, and Google Antigravity.

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
