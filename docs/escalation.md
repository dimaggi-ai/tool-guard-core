# Escalation flow — human-in-the-loop approvals

Tool Guard supports policy-driven escalation: a rule's `effect:
escalate` registers the call as a pending decision and returns
`action_taken=escalated` + an `escalation_id` to the agent. An
operator approves or denies via the proxy's REST endpoints; the audit
chain captures every transition.

## Endpoints

```
POST /evaluate
  → if a rule fires with effect=escalate:
      response = 202 Accepted
      body includes:
        {
          "action_taken": "escalated",
          "decision":     "escalated",
          "escalation_id": "<envelope_id>",
          "poll_url":     "/escalations/<envelope_id>",
          ...
        }
      a pending entry is registered in the proxy
      the audit chain logs the create event

GET  /escalations
  → snapshot of every escalation (pending + resolved)

GET  /escalations/<id>
  → fetch one entry: state, approver, reason, timestamps

POST /escalations/<id>/approve
  Authorization: Bearer <approver-token>
  Body (optional): {"approver": "alice", "reason": "verified runbook"}
  → state transitions pending → approved
  → audit chain logs the approve event

POST /escalations/<id>/deny
  Authorization: Bearer <approver-token>
  Body (optional): {"approver": "alice", "reason": "policy violation"}
  → state transitions pending → denied
  → audit chain logs the deny event
```

## Token configuration

```
tg-proxy -approver-token=<strong-random-string>
        -escalation-default-timeout-min=30
```

When `-approver-token` is empty (default), the mutating endpoints
return 401 — escalation lives in the audit log but cannot be
resolved. Set the flag to enable the flow.

The token is a single shared bearer string. For per-operator identity,
put a reverse proxy in front that maps user identity to the token; the
mutating endpoints accept an optional `approver` field in the body so
the identity lands in the audit chain.

## Lifecycle states

```
pending  ──── approve ───▶  approved
   │
   ├──────── deny ──────▶  denied
   │
   └──── timeout (default 15 min, configurable) ────▶  expired
```

The reaper sweeps every 30 seconds; any pending entry past its
`expires_at` becomes `expired`. The agent's poll loop should treat
`expired` the same as `denied`.

## Example policy

```yaml
policy_id: pol-sql-write-needs-approval
scope:
  tool_names: [query]
  tool_groups: [database_ops]
rules:
  - rule_id: rule-sql-write-needs-approval
    rule_type: sql_classify
    conditions:
      and:
        - field: tool_name
          operator: eq
          value: query
        - sql_classify:
            field: parameters.sql
            dialect: postgres
            require:
              denied_top_level_kinds: [INSERT, UPDATE, DELETE]
    effect: escalate
    effect_config:
      severity: high
      escalate_to: dba-on-call
      timeout_minutes: 30
```

`denied_top_level_kinds` fires the rule when the SQL IS one of the
listed kinds (the inverse of `top_level_kinds`). For escalation
policies this is the natural shape: "escalate writes" rather than
"only allow reads."

## Agent-side resume

A real agent loop integrates escalation with a poll-or-give-up
pattern:

```python
import time, requests

def call_with_approval(envelope):
    r = requests.post(PROXY + "/evaluate", json=envelope)
    body = r.json()
    if body["action_taken"] != "escalated":
        return body  # allow or deny — done

    poll_url = PROXY + body["poll_url"]
    deadline = time.time() + 30 * 60  # 30 min
    while time.time() < deadline:
        time.sleep(15)
        e = requests.get(poll_url).json()
        if e["state"] == "approved":
            return requests.post(PROXY + "/evaluate", json=envelope).json()
        if e["state"] in ("denied", "expired"):
            return e
    return {"state": "client_timeout"}
```

## Combining with deny policies

If a stricter policy (`effect: deny`) and the escalation policy
(`effect: escalate`) both match the same envelope, the proxy returns
the strictest result — deny wins. The escalation rule only takes
effect when no deny rule fires for the same call.

The recommended pattern is to **scope escalation policies to a
specific tool, agent_id, or session_id** so they don't collide with
the org-wide deny policies. For example: only escalate writes that
come from agent_id="ops-bot", since that agent has the appropriate
audit context.

## Audit chain

Every transition (`create`, `approve`, `deny`, `expire`) emits a new
hash-chained entry. `tg verify` walks the full chain — including
rotated files — and surfaces the lifecycle as a sequence of linked
records.

## Storage

The pending-escalation store is in-memory for v0.1.0, bounded
(`defaultEscalationMaxEntries = 10_000`) with LRU eviction of the
oldest **resolved** entries — pending requests are never silently
dropped, only ones already approved or denied. A proxy restart
discards all pending entries (the agent's poll returns 404, which the
client treats as expired). File-backed persistence so restarts
preserve outstanding approvals is a known gap; until it exists,
drain pending escalations before restarting the proxy.

## Metrics

```
tg_proxy_evaluations_escalated_total
```

is bumped on every escalation create. Combine with the `/escalations`
endpoint's snapshot for a dashboard showing pending count and oldest
pending age.
