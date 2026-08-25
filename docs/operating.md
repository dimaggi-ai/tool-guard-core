# Operating tg-proxy in production

A reference for setting up, monitoring, and maintaining a Tool Guard
proxy under production load.

## Deployment shapes

### Single-binary on a VM

The simplest deployment: copy `bin/tg-proxy` to the host, write a
systemd unit, and load the policies from a directory mounted
read-only.

```ini
# /etc/systemd/system/tg-proxy.service
[Unit]
Description=Tool Guard Core policy decision service
After=network-online.target

[Service]
Type=simple
User=tgproxy
Group=tgproxy
WorkingDirectory=/var/lib/tg-proxy
ExecStart=/usr/local/bin/tg-proxy \
  -listen 127.0.0.1:9090 \
  -policy-dir /etc/tg-proxy/policies \
  -audit-log /var/lib/tg-proxy/audit/decisions.jsonl \
  -default-mode enforcement \
  -fail-closed=true \
  -unknown-tools-deny=true \
  -rate-limit-rps 20 \
  -rate-limit-burst 100 \
  -velocity-track \
  -audit-sync-mode interval \
  -audit-sync-every 10 \
  -audit-rotate-bytes 104857600 \
  -approver-token-file /etc/tg-proxy/approver.token \
  -max-envelope-depth 32
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2
LimitNOFILE=65536
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

After `systemctl daemon-reload && systemctl enable --now tg-proxy`,
the proxy reads `/etc/tg-proxy/policies/*.yaml`, fail-closes if any
policy file is malformed, and writes the audit log to
`/var/lib/tg-proxy/audit/`.

### Velocity tracking (amount fragmentation)

`-velocity-track` makes the proxy maintain a per-key sliding window of
monetary actions and inject the trailing 1h/24h sum and count into
`context.verified.agent_velocity.*` before evaluation. A policy then
closes the amount-fragmentation bypass with an ordinary threshold rule
(see [`policies/refund_velocity_cap.yaml`](../policies/refund_velocity_cap.yaml)):

```yaml
conditions:
  field: context.verified.agent_velocity.monetary_sum_1h
  operator: gt
  value: 5000        # deny once the 1h refund total would cross $5k
```

Notes:

- The injected sum **includes the prospective call**, so a `> cap` rule
  denies the call that crosses the line. Only calls that actually proceed
  (allow / flag) are recorded into the window — denied attempts never
  inflate it.
- The proxy **never overwrites** a caller-supplied `agent_velocity`
  block. If you already compute rolling totals from a ledger, keep
  sending them and leave `-velocity-track` off; the two are mutually
  exclusive per request.
- State is in-memory, keyed by `-velocity-key-by` (agent_id by default),
  bounded (100k keys, 30-min idle eviction) exactly like the rate
  limiter. It does **not** survive a restart — for durable cross-restart
  aggregates, supply the totals yourself. `tg_proxy_velocity_keys` in
  `/metrics` reports the live key count.

### Docker / Kubernetes

The shipped `Dockerfile` produces a distroless-nonroot image with
`tg-proxy` as the default entrypoint. Multi-stage; final image is
~10 MB statically linked.

```sh
docker build -t ghcr.io/dimaggi-ai/tool-guard-core:0.2.0 .
docker run --rm \
  -p 9090:9090 \
  -v "$(pwd)/policies:/policies:ro" \
  -v "$(pwd)/audit:/var/lib/tg" \
  ghcr.io/dimaggi-ai/tool-guard-core:0.2.0 \
  -policy-dir /policies \
  -audit-log /var/lib/tg/decisions.jsonl \
  -listen :9090
```

For Kubernetes, mount the policy directory as a ConfigMap (or a
git-sync sidecar for live edits) and the audit-log directory as a
PersistentVolumeClaim. Run with `readinessProbe` against `/readyz`
(returns 200 once at least one policy is loaded) and
`livenessProbe` against `/healthz`.

### Behind an API gateway

If a tool runs inside a managed agent runtime (LangChain on
Cloud Run, MCP servers on Fly.io, etc.), point the runtime's
tool-call interceptor at `tg-proxy`'s `/evaluate`. The proxy
returns `200 OK` with `decision: allowed` to pass-through, `200`
with `denied`, or `202 Accepted` with a `poll_url` for escalations.

The proxy is stateless beyond its in-memory escalation store and
the on-disk audit chain. It scales horizontally - N proxies
sharing the same policy directory and writing to N independent
audit logs. Each log is its own hash chain: run `tg verify` against
each file separately. There is no tooling to merge or cross-link
independent chains.

### Network exposure and authentication

`tg-proxy` has **no built-in authentication or TLS**. `/evaluate`,
`/reload`, `/policies`, `/metrics`, and the read-only escalation
listing are all unauthenticated; `/evaluate` and the audit log carry
tool-call payloads (potentially sensitive). Bind to `127.0.0.1` or a
private network and put authentication, TLS, and rate limiting at an
API gateway or service mesh in front of it. The only built-in secret
is the optional `-approver-token`, which gates the escalation
approve/deny endpoints.

## Flag reference

The full flag list, copied from `tg-proxy -help`:

```
-listen string
    host:port to bind (default ":9090")
-policy-dir string
    directory of YAML policy files to load (default "./policies")
-audit-log string
    path to append the JSONL audit chain (default "./decisions.jsonl")
-default-mode string
    shadow | enforcement (default "enforcement")
-fail-closed
    deny calls when no policies are loaded (default true)
-unknown-tools-deny
    deny any tool_name not in scope.tool_names of some loaded
    enforcement policy (closes the tool-name-spoofing class)
-max-envelope-depth int
    reject /evaluate envelopes whose JSON nests deeper than this
    (DoS defense) (default 32)
-audit-sync-mode string
    audit fsync mode: every | interval | none (default "every")
-audit-sync-every int
    when audit-sync-mode=interval, fsync once every N appends (default 100)
-audit-rotate-bytes int
    rotate audit log when active file exceeds this many bytes
    (0 = never rotate)
-rate-limit-rps float
    per-agent steady-state limit (req/s); 0 disables
-rate-limit-burst float
    per-agent burst capacity used when rate-limit-rps > 0 (default 50)
-rate-limit-key-by string
    envelope field to key the limiter on: agent_id | session_id | org_id
    (default "agent_id")
-velocity-track
    compute a sliding-window monetary velocity (1h/24h sum + count) per key
    and inject it into context.verified.agent_velocity before evaluation —
    closes the amount-fragmentation bypass. Never overwrites a caller-supplied
    agent_velocity block (a real ledger stays authoritative).
-velocity-key-by string
    envelope field to key velocity windows on: agent_id | session_id | org_id
    (default "agent_id")
-tools-yaml string
    path to a tools.yaml function classification registry
-approver-token string
    static bearer token required on POST /escalations/<id>/approve|deny
-approver-token-file string
    read the approver token from this file instead of the command line
    (keeps it out of /proc cmdline); mutually exclusive with -approver-token
-escalation-default-timeout-min int
    default timeout (minutes) for an escalation that doesn't
    specify one (default 15)
-protect-paths string
    comma-separated list of path prefixes; a write-capable tool
    call targeting any of them is denied BEFORE policy evaluation,
    unconditionally — the agent cannot disable this by editing a policy
-protect-self
    automatically protect -policy-dir, the -audit-log path, and the
    running binary's directory; prepended to -protect-paths
-version
    print build version and exit
```

### Self-protection (`-protect-paths` / `-protect-self`)

Any deny rule written inside a policy can be edited away by an agent that
has write access to the policy directory. `-protect-paths` and `-protect-self`
close this gap at the operator-flag level, outside the policy:

```
tg-proxy \
  -policy-dir /etc/tg-proxy/policies \
  -audit-log   /var/lib/tg-proxy/audit/decisions.jsonl \
  -protect-self
```

With `-protect-self`, the proxy automatically protects:

- The `-policy-dir` itself (the agent cannot overwrite its own rules).
- The `-audit-log` path (the agent cannot truncate the audit record).
- The directory containing the running binary (prevents binary replacement).

`-protect-paths P1,P2` accepts additional prefixes (comma-separated).

**Matching semantics**: the same `matchPathPrefix` used by `path_classify`
is applied after `filepath.Clean`, so `..`, `.`, and `//` in a file path
are resolved before matching. The guard fires on writes (tools carrying
`file_path` or `path` parameters, plus shell redirection, `rm`, `tee`,
`sed -i`, `dd of=`, and similar mutating commands). Read-only tools
(`read`, `glob`, `grep`, `ls`, …) are explicitly excluded.

**Shell limitation**: quoting, variable expansion, and command substitution
in `bash` / `run_command` commands are not resolved. Use `-protect-paths`
for the policy and audit paths; keep `bash` out of the write-capable policy
scope if you need stronger shell containment.

When the guard fires, the proxy returns **HTTP 403** and records a
boundary-deny trace in the audit chain so `tg verify` remains intact.

## Observability

### Health endpoints

| Endpoint | Returns |
|---|---|
| `GET /healthz` | 200 OK if the process is alive |
| `GET /readyz` | 200 OK if at least one policy is loaded |
| `GET /policies` | JSON snapshot of loaded policy IDs (debugging) |
| `GET /escalations` | JSON snapshot of pending+resolved escalations |

### Metrics

`GET /metrics` returns Prometheus-format counters and gauges:

```
tg_proxy_uptime_seconds            65
tg_proxy_policies_loaded           4
tg_proxy_policy_reloads_total      2
tg_proxy_evaluations_total         12451
tg_proxy_evaluations_allowed_total 9120
tg_proxy_evaluations_denied_total  2401
tg_proxy_evaluations_escalated_total 612
tg_proxy_evaluations_flagged_total 318
tg_proxy_evaluations_fail_closed_total 0
tg_proxy_audit_append_failures_total 0
tg_proxy_audit_current_bytes       16384231
tg_proxy_audit_appends_total       12453
tg_proxy_regex_cache_size          7
tg_proxy_rate_limit_keys           312
```

The audit counters are read under the audit mutex so
`/metrics` does not race with append.

### Logs

Every `/evaluate` writes an access-log line:

```
2026/06/08 14:03:08 POST /evaluate → 200 in 145us
```

Errors (audit append failures, classifier timeouts, ollama
unreachable) log to stderr and increment the corresponding
`*_failures_total` counter.

## Policy lifecycle

### Authoring

1. Write the policy YAML.
2. `tg lint -policy <file>` - fix any error-severity findings.
3. `tg evaluate -policy <file> -call <envelope.json>` - sanity
   check against representative tool calls.
4. Stage in shadow mode (`mode: shadow` in YAML) for a week and
   read the near-miss column on each trace to verify the policy
   behaves as intended.
5. Promote to enforcement (`mode: enforcement`).

Policy mode is authoritative for that policy's contribution. This makes step 4
safe under the proxy's default call-site mode:

| Policy YAML | Call-site mode | Matching deny/escalate |
|---|---|---|
| `shadow` | `shadow` | observed as `allowed_shadow` |
| `shadow` | `enforcement` | observed as `allowed_shadow` |
| `enforcement` | `shadow` | enforced |
| `enforcement` | `enforcement` | enforced |

With multiple policies, enforcement-policy effects are resolved separately and
still apply. A shadow policy can never cancel an enforcement policy's gate.

### Deploying

Drop the new file into `-policy-dir` and either restart the proxy
or send `kill -HUP $(pidof tg-proxy)` / `POST /reload`. Validation
runs on every load; if any file fails, the OLD policy set stays
live. There is no half-load state.

### Retiring a policy

Set `status: archived` and reload. Archived policies are skipped at
evaluation (only `approved` policies are evaluated), but the file
stays in place so the policy history remains reviewable in version
control. Delete the file once you've confirmed nothing references
it.

## Backup and recovery

### Audit chain

The audit log is the legal record. Treat it like any other
append-only ledger:

- **Storage** - on a filesystem with atomic writes
  (ext4, xfs, zfs, btrfs all fine). The proxy uses `O_APPEND`
  which is atomic at the page level.
- **Rotation** - `-audit-rotate-bytes` rotates the active file
  when it crosses the cap. Rotated files are named
  `<auditPath>.1`, `<auditPath>.2`, ... `tg verify` reads the
  rotation set in order.
- **Off-host backup** - `cron` an rsync to a separate host every
  hour. The hash chain links across rotations, so `tg verify` on
  the backup is the same operation as on the live host.
- **Verification cadence** - `tg verify` once a day at minimum. If
  it returns `intact: false` with `exit 5`, you have an
  on-disk-tamper or a corrupted write. Stop the proxy (`tg-proxy`
  refuses to start with a tampered tail anyway) and triage.

### Disaster recovery

If the audit log is destroyed or corrupted past the tail:

1. Stop `tg-proxy` (it refuses to start without a verifiable tail).
2. Restore the most recent verified backup.
3. Start `tg-proxy` - it resumes the chain from the restored tail.
4. The gap between the restored tail and the destroyed live tail is
   PERMANENTLY lost from the audit record. There is no way to
   reconstruct decisions made between the restore point and the
   crash.

This is the standard append-only-ledger recovery semantic: gaps are
gaps. The system is fail-safe (decisions made after the gap are
hashed and chained correctly), not fail-recoverable.

## Upgrade path

Tool Guard follows semver. Between minor versions the canonical
trace schemas are immutable. Current writers stamp
`CanonicalTraceVersion = v2`; records written before the on-record
`_canonical_v` marker are interpreted with the byte-identical v1 encoder.
Mixed v1/v2 chains remain `tg verify`-able across an upgrade.

To upgrade:

1. `git pull && make build`.
2. **Lint every policy file the new binaries will load** (`tg lint` on
   each file in every `-policy-dir`/`-policy` path) — *before* stopping
   the old proxy. As of 0.7.0 the loader is strict: an unknown or
   misspelled field, a removed field (`deep_evaluation`), or a second
   YAML document in any one file is a load error that fails the whole
   policy set. `tg-proxy` refuses to start on a failed load, but
   `tg hook` without `-fail-closed`/`-fail-closed-tools` enforces
   **no policy at all** when the load fails — a deny that worked under
   0.6.0 becomes an allow. Fix every lint error first.
3. Stop the old proxy.
4. Start the new proxy. It resumes the chain from the same tail.

Migration steps for 0.6.0 → 0.7.0: remove any `deep_evaluation` block
(move semantic checks to a rule with an `llm_classify` condition), split
multi-document files into one file per policy, correct every
unknown-field error `tg lint` reports, and optionally declare
`schema_version: 1` (files that omit it load as version 1). Within a
schema version, minor releases may add new condition forms (e.g.
`llm_classify` shipped in 0.1.x) and existing policies continue to
load.

## Common operational issues

| Symptom | Likely cause | Action |
|---|---|---|
| Proxy refuses to start, "audit-log tail integrity check failed" | Audit log was tampered or corrupted | Run `tg verify` to locate the failure line; restore from backup; start with `-audit-log` pointing at the restored file |
| Proxy returns 503 on every `/evaluate` | `-fail-closed=true` and no policies loaded | Check `-policy-dir` exists and contains a valid `*.yaml` |
| Every `llm_classify` rule times out | Ollama unreachable; check `-ollama_url` in policy or that Ollama is running on the configured endpoint | `curl http://localhost:11434/api/tags` |
| Latency suddenly 10x worse | Cold-start of a freshly-pulled Ollama model | First call after model swap is ~5-20s; subsequent calls are ~600ms |
| Escalation poll returns 404 | The proxy restarted (in-memory store) or the entry expired | Restart agent; the agent's next call will re-evaluate |
| Rate limit fires on the wrong agent | Multiple agents share the same `agent_id` | Make the agent_id unique per logical agent identity |

For anything not on this list, file an issue with the audit log
line and the proxy stderr output.
