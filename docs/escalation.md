# Escalation flow - human-in-the-loop approvals

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
  → audit chain logs the approve event
  → only then state transitions pending → approved

POST /escalations/<id>/deny
  Authorization: Bearer <approver-token>
  Body (optional): {"approver": "alice", "reason": "policy violation"}
  → audit chain logs the deny event
  → only then state transitions pending → denied
```

Approval and denial are transactional with their audit record. If the record
cannot be written and synced durably, the proxy rolls it back and the endpoint
returns HTTP 503 with a structured `audit_append_failed` response. A successful
rollback leaves the escalation `pending`; repair the writer and retry that
escalation. Approval and denial force this durability barrier even when general
evaluation logging uses `audit-sync-mode=interval` or `none`.

If the rollback itself cannot be proven durable, the audit tail is ambiguous,
`/readyz` returns 503, and the escalation becomes `indeterminate`. Stop approval
processing, preserve and repair the audit log, run `tg verify`, restart the
proxy, and have the originating action resubmitted with a fresh envelope ID.
The escalation registry is in memory, so the old ID cannot be retried after a
restart. A 200 approval therefore never authorizes execution without a durably
linked audit entry.

## Token configuration

```
tg-proxy -approver-token=<strong-random-string>
        -escalation-default-timeout-min=30
```

When `-approver-token` is empty (default), the mutating endpoints
return 401 - escalation lives in the audit log but cannot be
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
   ├──── timeout (default 15 min, configurable) ────▶  expired
   │
   └──── uncertain audit durability ───────────────▶  indeterminate
```

The reaper sweeps every 30 seconds; any pending entry past its
`expires_at` becomes `expired`. The agent's poll loop should treat
`expired` the same as `denied`.

Expiry is also audit-before-publish. A proven pre-write audit failure leaves
the overdue entry visibly `pending` so the reaper can retry, but the original
deadline remains authoritative: approval and denial return HTTP 409
`escalation_past_due` and cannot emit an authorization trace. Repair the audit
writer if necessary and let the reaper complete the `expired` transition. If a
terminal expiry record may have been written but cannot be proven durable, the
entry becomes `indeterminate`; follow the audit-reconciliation procedure above
and never authorize the original action.

## Example policy

```yaml
schema_version: 1
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
        return body  # allow or deny - done

    poll_url = PROXY + body["poll_url"]
    deadline = time.time() + 30 * 60  # 30 min
    while time.time() < deadline:
        time.sleep(15)
        e = requests.get(poll_url).json()
        if e["state"] == "approved":
            # Approval IS the authorization - call the tool now.
            # Do NOT re-POST the same envelope to /evaluate: the proxy
            # rejects a re-used envelope_id (collision guard, below).
            return {"action_taken": "allowed", "via": "human-approval"}
        if e["state"] in ("denied", "expired"):
            return e
    return {"state": "client_timeout"}
```

## Re-submitting an approved envelope

The `envelope_id` is the escalation's identity. Once an escalation for
an `envelope_id` exists, a second `/evaluate` carrying the same
`envelope_id` is **rejected** rather than re-evaluated - this guards
against an authorization-confusion bypass where a caller reuses a
known-approved `envelope_id` with a fresh payload. So a poll that
returns `approved` IS the authorization to proceed: call the tool,
don't re-evaluate. Use a fresh `envelope_id` for every new tool call.

## Combining with deny policies

Among enforcement policies, the strictest matching effect controls the action:
an enforcement deny beats an enforcement escalation. Shadow policies remain
telemetry. A shadow deny can therefore make the raw `decision` be `denied`
while an enforcement escalation makes `action_taken` be `escalated`; the
pending request and its timeout come only from the enforcement escalation.

Scope escalation policies to a specific tool name, agent_id, or
tool_group (the fields `scope` supports) so they don't collide with
the org-wide deny policies. For example: only escalate writes that
come from agent_id="ops-bot", since that agent has the appropriate
audit context.

## Audit chain

Every transition (`create`, `approve`, `deny`, `expire`) emits a new
hash-chained entry. `tg verify` walks the full chain - including
rotated files - and surfaces the lifecycle as a sequence of linked
records.

## Storage

The pending-escalation store is in-memory (bounded)
(`defaultEscalationMaxEntries = 10_000`) with LRU eviction of the
oldest **resolved** entries - pending requests are never silently
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
