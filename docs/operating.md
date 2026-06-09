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
Description=Tool Guard Policy Firewall
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

### Docker / Kubernetes

The shipped `Dockerfile` produces a distroless-nonroot image with
`tg-proxy` as the default entrypoint. Multi-stage; final image is
~10 MB statically linked.

```sh
docker build -t ghcr.io/dimaggi-ai/tool-guard-core:0.1.0 .
docker run --rm \
  -p 9090:9090 \
  -v "$(pwd)/policies:/policies:ro" \
  -v "$(pwd)/audit:/var/lib/tg" \
  ghcr.io/dimaggi-ai/tool-guard-core:0.1.0 \
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
the on-disk audit chain. It scales horizontally — N proxies
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
-version
    print build version and exit
```

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
2. `tg lint -policy <file>` — fix any error-severity findings.
3. `tg evaluate -policy <file> -call <envelope.json>` — sanity
   check against representative tool calls.
4. Stage in shadow mode (`mode: shadow` in YAML) for a week and
   read the near-miss column on each trace to verify the policy
   behaves as intended.
5. Promote to enforcement (`mode: enforcement`).

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

- **Storage** — on a filesystem with atomic writes
  (ext4, xfs, zfs, btrfs all fine). The proxy uses `O_APPEND`
  which is atomic at the page level.
- **Rotation** — `-audit-rotate-bytes` rotates the active file
  when it crosses the cap. Rotated files are named
  `<auditPath>.1`, `<auditPath>.2`, ... `tg verify` reads the
  rotation set in order.
- **Off-host backup** — `cron` an rsync to a separate host every
  hour. The hash chain links across rotations, so `tg verify` on
  the backup is the same operation as on the live host.
- **Verification cadence** — `tg verify` once a day at minimum. If
  it returns `intact: false` with `exit 5`, you have an
  on-disk-tamper or a corrupted write. Stop the proxy (`tg-proxy`
  refuses to start with a tampered tail anyway) and triage.

### Disaster recovery

If the audit log is destroyed or corrupted past the tail:

1. Stop `tg-proxy` (it refuses to start without a verifiable tail).
2. Restore the most recent verified backup.
3. Start `tg-proxy` — it resumes the chain from the restored tail.
4. The gap between the restored tail and the destroyed live tail is
   PERMANENTLY lost from the audit record. There is no way to
   reconstruct decisions made between the restore point and the
   crash.

This is the standard append-only-ledger recovery semantic: gaps are
gaps. The system is fail-safe (decisions made after the gap are
hashed and chained correctly), not fail-recoverable.

## Upgrade path

Tool Guard follows semver. Between minor versions the canonical
trace schema is locked at `CanonicalTraceVersion = v1`. A future
v2 schema bump will be opt-in via build flag; existing v1 chains
will remain `tg verify`-able forever.

To upgrade:

1. `git pull && make build`.
2. Stop the old proxy.
3. Start the new proxy. It resumes the chain from the same tail.

There is no migration step. Policy files do not change shape between
patch versions; minor versions may add new condition forms (e.g.
`llm_classify` shipped in 0.1.x) but existing policies continue to
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
