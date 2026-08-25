# Integration Guide

Tool Guard Core ships in two shapes: a **runtime HTTP service**
(`tg-proxy`) and a **Go library** (`pkg/engine`, `pkg/audit`,
`pkg/domain`). Pick the shape that matches how your agent is built; the
underlying engine is identical and produces the same audit traces.

- **Runtime service** - your agent talks to `tg-proxy` over HTTP.
  Easiest to drop in, language-agnostic, lets you scale Tool Guard
  independently of your agent. This is what
  [`examples/sample-app/`](../examples/sample-app/) demonstrates.
- **Embedded library** - your Go agent calls `engine.Evaluator.Evaluate`
  directly. Zero network hop, you own the lifecycle. Best when the
  agent is already a Go service.

This guide covers both, plus how to wire the proxy into MCP servers,
LangChain, AutoGen, and the Anthropic / OpenAI tool-use loops.

---

## 1. Run `tg-proxy` next to your agent

The proxy is a single binary with zero external dependencies. It loads
YAML policies from a directory, exposes `POST /evaluate`, and appends
every decision to a JSONL audit log.

### 1.1 Minimal local run

```bash
make build       # produces ./bin/tg-proxy
./bin/tg-proxy \
  -listen :9090 \
  -policy-dir ./policies \
  -audit-log ./decisions.jsonl
```

Available flags:

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `:9090` | host:port to bind |
| `-policy-dir` | `./policies` | directory of `*.yaml` to load on startup and on SIGHUP |
| `-audit-log` | `./decisions.jsonl` | path to append the SHA-256 hash-chained JSONL |
| `-default-mode` | `enforcement` | `shadow` for observe-only |
| `-fail-closed` | `true` | return 503 from `/readyz` and from `/evaluate` when zero policies are loaded |

Endpoints:

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/evaluate` | body: `ActionEnvelope` JSON; returns `EvaluationResult` JSON |
| `GET` | `/healthz` | liveness; 200 OK if process is alive |
| `GET` | `/readyz` | readiness; 200 OK if at least one policy is loaded |
| `GET` | `/policies` | list the policies currently loaded (debugging) |
| `GET` | `/metrics` | plain-text counters; scrape-friendly |
| `POST` | `/reload` | trigger a policy reload without restarting (also fires on `SIGHUP`) |

### 1.2 Make a request from any language

```bash
curl -X POST http://localhost:9090/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "support-agent-v2",
    "session_id": "sess-001",
    "org_id": "acme",
    "tool_name": "issue_refund",
    "tool_group": "monetary_outflow",
    "parameters": {"amount": 1000, "reason": "Goodwill credit"}
  }'
```

Response (`HTTP 200`):

```json
{
  "decision": "denied",
  "action_taken": "denied",
  "decision_reason": "Denied by: [rule-amount-cap] ...",
  "effective_mode": "enforcement",
  "policies_matched": 2,
  "rules_evaluated": 3,
  "rules_triggered": 2,
  "rule_results": [{ "...": "..." }],
  "primary_citation": { "...": "..." }
}
```

In your agent code: call the tool when `action_taken` is `allowed`
(enforcement), `allowed_shadow` (shadow), or `flagged`. A `flag` effect
is a recorded near-miss - the call still proceeds, but the decision is
logged for review. `denied` means do not call the tool; `escalated`
means wait for human approval (see [escalation.md](escalation.md))
before calling it.

### 1.3 Systemd unit (Linux)

```ini
# /etc/systemd/system/tg-proxy.service
[Unit]
Description=Tool Guard Core HTTP proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=tgproxy
Group=tgproxy
ExecStart=/usr/local/bin/tg-proxy \
  -listen 127.0.0.1:9090 \
  -policy-dir /etc/tg-proxy/policies \
  -audit-log /var/lib/tg-proxy/decisions.jsonl \
  -default-mode enforcement \
  -fail-closed=true
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2s
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/tg-proxy

[Install]
WantedBy=multi-user.target
```

Reload a new policy set without dropping requests:

```bash
sudo systemctl reload tg-proxy
```

### 1.4 Kubernetes (minimal)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tg-proxy
spec:
  replicas: 2
  selector:
    matchLabels:
      app: tg-proxy
  template:
    metadata:
      labels:
        app: tg-proxy
    spec:
      containers:
        - name: tg-proxy
          image: ghcr.io/dimaggi-ai/tool-guard-core:v0.2.0
          args:
            - -listen=:9090
            - -policy-dir=/etc/tg/policies
            - -audit-log=/var/lib/tg/decisions.jsonl
            - -fail-closed=true
          ports:
            - containerPort: 9090
          livenessProbe:
            httpGet: { path: /healthz, port: 9090 }
          readinessProbe:
            httpGet: { path: /readyz, port: 9090 }
          volumeMounts:
            - { name: policies, mountPath: /etc/tg/policies, readOnly: true }
            - { name: audit, mountPath: /var/lib/tg }
      volumes:
        - name: policies
          configMap: { name: tg-policies }
        - name: audit
          persistentVolumeClaim: { claimName: tg-audit }
---
apiVersion: v1
kind: Service
metadata:
  name: tg-proxy
spec:
  selector: { app: tg-proxy }
  ports:
    - port: 9090
      targetPort: 9090
```

The audit log is the source of truth for `tg verify`. Use a `PVC` for
durability across pod restarts, and rotate the log on a schedule that
matches your evidence-pack windows (per-day or per-week is typical).

> **Image note:** tagged releases publish multi-arch images to
> `ghcr.io/dimaggi-ai/tool-guard-core` via the GoReleaser pipeline in
> this repo, so the manifest above works as-is once a release is
> tagged. To run from source before a tagged release exists, build and
> push your own image with the [minimal Dockerfile](#minimal-dockerfile)
> below and override `image:`.

---

## 2. Embed the library in a Go service

If your agent is itself a Go service, skip the HTTP hop:

```go
package main

import (
    "context"
    "encoding/json"
    "os"

    "github.com/dimaggi-ai/tool-guard-core/pkg/audit"
    "github.com/dimaggi-ai/tool-guard-core/pkg/domain"
    "github.com/dimaggi-ai/tool-guard-core/pkg/engine"
)

// Guard wraps the engine and an append-only audit log writer.
// Construct it once at startup and reuse across requests; it is safe
// for concurrent use.
type Guard struct {
    eval     *engine.Evaluator
    policies []domain.Policy
    auditFile *os.File
    auditEnc  *json.Encoder
    lastHash string
}

func NewGuard(policies []domain.Policy, logPath string) (*Guard, error) {
    f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
    if err != nil {
        return nil, err
    }
    return &Guard{
        eval: engine.NewEvaluator(),
        policies: policies,
        auditFile: f,
        auditEnc: json.NewEncoder(f),
    }, nil
}

func (g *Guard) Check(ctx context.Context, env *domain.ActionEnvelope) (bool, *domain.EvaluationResult) {
    result := g.eval.Evaluate(env, g.policies, domain.PolicyModeEnforcement)
    // Append to the audit chain. Use the CANONICAL hash
    // (ComputeCanonicalTraceHash) - it covers the decision and the
    // fields that produce it (the exact set is canonicalTraceV1 in
    // pkg/audit/canonical.go) and is what `tg verify` recomputes. The
    // legacy ComputeTraceHash covers only six identity fields and will
    // not verify.
    trace := domain.DecisionTrace{
        TraceID:           "trc-" + env.EnvelopeID,
        EnvelopeID:        env.EnvelopeID,
        Timestamp:         env.Timestamp,
        OrgID:             env.OrgID,
        AgentID:           env.AgentID,
        SessionID:         env.SessionID,
        ToolName:          env.ToolName,
        ToolGroup:         env.ToolGroup,
        Decision:          result.Decision,
        ActionTaken:       result.ActionTaken,
        DecisionReason:    result.DecisionReason,
        Mode:              result.EffectiveMode,
        PreviousTraceHash: g.lastHash,
    }
    hash, err := audit.ComputeCanonicalTraceHash(&trace)
    if err != nil {
        return false, nil // fail closed on audit errors
    }
    trace.TraceHash = hash
    _ = g.auditEnc.Encode(trace)
    g.lastHash = trace.TraceHash

    // A `flag` effect is a recorded near-miss - the call still proceeds.
    return result.ActionTaken == domain.ActionAllowed ||
           result.ActionTaken == domain.ActionAllowedShadow ||
           result.ActionTaken == domain.ActionFlagged, result
}
```

Then in your tool-call path:

```go
ok, result := guard.Check(ctx, envelope)
if !ok {
    // Don't execute the tool. Return result.SuggestedResponse to the
    // model so it knows what to say to the user.
    return result.SuggestedResponse, nil
}
// Allowed - call the real tool.
return realTool.Execute(ctx, envelope)
```

Same engine, same audit chain, no HTTP hop. Best for high-throughput
agents where every millisecond matters.

---

## 3. Wire it into your agent framework

The integration pattern is always: **before executing a tool call,
call the policy decision point. Only execute on `allowed`.**

### 3.1 MCP (Model Context Protocol)

If your MCP server wraps other tools, intercept every `CallTool` request:

```go
// Pseudo-Go inside an MCP CallTool handler.
func (s *Server) CallTool(ctx context.Context, req CallToolRequest) (CallToolResult, error) {
    env := &domain.ActionEnvelope{
        AgentID:    s.agentID,
        SessionID:  req.SessionID,
        OrgID:      s.orgID,
        ToolName:   req.Name,
        ToolGroup:  s.toolGroups[req.Name],
        Parameters: req.Arguments,
        Timestamp:  time.Now().UTC(),
        EnvelopeID: uuid.NewString(),
    }
    ok, result := guard.Check(ctx, env)
    if !ok {
        return CallToolResult{
            IsError: true,
            Content: []TextContent{{Type: "text", Text: result.SuggestedResponse}},
        }, nil
    }
    return s.upstreamTools[req.Name].Call(ctx, req)
}
```

### 3.2 LangChain (Python)

Install the SDK (not yet published to PyPI — install from a clone of this repo):

```bash
pip install "./tool-guard-core/sdk/python[langchain]"
```

Use the drop-in `ToolGuardCallbackHandler` — no boilerplate required:

```python
from toolguard import ToolGuard
from toolguard.adapters.langchain import ToolGuardCallbackHandler

guard = ToolGuard(
    mode="proxy",
    proxy_url="http://localhost:9090",
    agent_id="lc-agent",
    org_id="acme",
)
handler = ToolGuardCallbackHandler(guard, tool_groups={"issue_refund": "monetary_outflow"})

# Add the handler to any chain or agent executor.
chain = my_chain.with_config({"callbacks": [handler]})
```

The handler intercepts `on_tool_start` and raises `ToolDenied` /
`ToolEscalated` on a block, which stops the chain.  Allowed and flagged
calls proceed normally.  See `sdk/python/README.md` for full examples.

### 3.3 Microsoft AutoGen

Install the SDK:

```bash
pip install "./tool-guard-core/sdk/python[autogen]"
```

Use the `guarded` decorator:

```python
from toolguard import ToolGuard
from toolguard.adapters.autogen import guarded

guard = ToolGuard(
    mode="proxy",
    proxy_url="http://localhost:9090",
    agent_id="autogen-agent",
    org_id="acme",
)

@guarded(guard, tool_name="issue_refund", tool_group="monetary_outflow")
def issue_refund(order_id: str, amount: float) -> dict:
    ...  # real implementation

# Register with AutoGen as normal:
assistant.register_for_execution(name="issue_refund")(issue_refund)
```

On a deny or escalate, the wrapper returns `{"error": "denied", "reason": "...",
"suggested_response": "..."}` so AutoGen's conversation loop can surface the
refusal to the LLM.

### 3.4 Anthropic / OpenAI native tool use

Install the SDK:

```bash
pip install "./tool-guard-core/sdk/python[anthropic]"   # or [openai]
```

```python
from toolguard import ToolGuard
from toolguard.adapters.native import guard_tool_calls

guard = ToolGuard(
    mode="proxy",
    proxy_url="http://localhost:9090",
    agent_id="my-agent",
    org_id="acme",
)

# response.content is the list of tool_use blocks from the model.
allowed, denied = guard_tool_calls(
    response.content,
    guard,
    provider="anthropic",   # or "openai"
    tool_groups={"issue_refund": "monetary_outflow"},
)

# Execute only the allowed calls, then return results + error stubs to the model.
tool_results = []
for item in allowed:
    call = item["call"]
    output = TOOLS[call["name"]](**call["input"])
    tool_results.append({"type": "tool_result", "tool_use_id": call["id"], "content": output})

for item in denied:
    tool_results.append(item["tool_result"])  # pre-built is_error=True result
```

See `sdk/python/README.md` for the full OpenAI shape example.

---

## 4. Audit storage choices

`tg-proxy` writes JSONL to disk by default. Treat that file as
append-only and back it up like any other ledger. Common patterns:

- **Local file + nightly upload to object storage.** Simplest. Rotate
  daily; the rotated file is a self-contained chain you hand to your
  auditor.
- **Sidecar log shipper (fluent-bit / vector).** Tail
  `decisions.jsonl` to your existing logging pipeline. Verify chains
  on the receiving end with `tg verify`.
- **Database (Postgres / DynamoDB / etc.).** Skip the proxy's file
  output; embed the library directly (Section 2) and write each trace
  to your DB in `Guard.Check`. The hash-chain link still holds because
  it's just a string field on each row.

Whichever you pick, the rule is: do not let `tg verify` fail. If
hand-edited rows break the chain, your evidence pack stops being
tamper-evident.

---

## 5. Operational notes

- **Mode policy.** Call-site `enforcement` applies the aggregate decision.
  In call-site `shadow`, matched effects from enforcement policies still apply,
  while shadow-policy effects remain telemetry only. The engine resolves those
  sets separately, so a higher-severity shadow effect cannot cancel a
  lower-severity enforcement gate, and an allow-only enforcement policy does not
  promote an unrelated shadow deny. A policy marked `mode: enforcement` in YAML
  cannot be downgraded by either flag.
- **Latency.** Deterministic evaluation is in-process and p99 ≈ 14µs
  on commodity hardware (see `tg benchmark`). The proxy adds one
  HTTP hop plus JSON marshal/unmarshal; expect sub-millisecond round
  trips over loopback TCP on the same host and 1–3 ms across a
  Kubernetes pod.
  Measurement conditions and the nightly same-runner regression gate
  are documented in [performance.md](performance.md).
- **Failure mode.** Run with `-fail-closed=true` (the default). On
  policy load failure the proxy refuses new requests; an upstream
  Envoy / NGINX can then route to a "blocked by policy" handler.
- **Hot reload.** `SIGHUP` (or `POST /reload`) re-reads `-policy-dir`
  atomically. In-flight requests finish under the old policies; the
  next request sees the new ones.
- **Concurrency.** All endpoints are safe under concurrent load. The
  audit-log writer is serialised by a mutex so hash-chain links cannot
  interleave; expect ~tens of thousands of evaluations per second per
  CPU before that serialisation becomes the bottleneck.

---

## 6. Verification

After every deploy:

```bash
# Was the policy directory loaded?
curl -sf http://localhost:9090/readyz

# Are decisions being recorded?
tail -f /var/lib/tg-proxy/decisions.jsonl

# Is the chain intact?
./bin/tg verify -file /var/lib/tg-proxy/decisions.jsonl

# Score a known-bad envelope to confirm the proxy denies it.
# (examples/call_over_cap.json ships in the repo: a $1000 refund
#  against the $500 cap policy.)
curl -X POST http://localhost:9090/evaluate \
  -H "Content-Type: application/json" \
  -d @examples/call_over_cap.json | jq .decision
# expected: "denied"
```

---

## Minimal Dockerfile

```dockerfile
# syntax=docker/dockerfile:1.6
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/tg-proxy ./cmd/tg-proxy
RUN CGO_ENABLED=0 go build -trimpath -o /out/tg ./cmd/tg

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/tg-proxy /usr/local/bin/tg-proxy
COPY --from=build /out/tg /usr/local/bin/tg
USER nonroot:nonroot
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/tg-proxy"]
CMD ["-listen=:9090"]
```

Build with `docker build -t tg-proxy:dev .` and run with `docker run -p 9090:9090 -v $PWD/policies:/policies tg-proxy:dev -policy-dir=/policies`.
