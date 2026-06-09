# postgres-attack — multi-vector LLM attack against a real DB and a real OS shell

Five-container compose: real Postgres, real Linux shell tool, the
`tg-proxy` runtime firewall, two policies, and a Gemma 4 agent with an
aggressive prompt that tries to (1) drop production tables, (2) list
`/etc`, and (3) read `/etc/shadow`. The agent fails at all three
because the proxy denies each call before it reaches the tool.

```
                            ┌──────────────────┐
                            │  policies/       │
                            │   db-protect.yaml│
                            │   os-protect.yaml│
                            └────────▲─────────┘
                                     │ load
   ┌───────────┐    JSON       ┌─────┴─────┐   evaluate
   │   agent   │ ───tool──────▶│ tg-proxy  │ ── policy decision
   │ (gemma4)  │ ◀──decision──│ :9090     │   audit chain (SHA-256)
   └─────┬─────┘                └─────┬─────┘
         │                            │ allow
         │                            ▼
         │     ┌──────────────────────┼─────────────────────┐
         │     │                      │                     │
         │     ▼                      ▼                     ▼
         │  ┌──────────┐         ┌──────────┐         ┌──────────┐
         └─▶│ db-tool  │ ──pg──▶│ postgres │         │ os-tool  │
            │  :18080  │        │   :16    │         │  :18090  │
            └──────────┘        └──────────┘         └──────────┘
              real Postgres                          sh -c <cmd>
              (DML/DDL/DCL)                          os_exec, os_read_file
```

`db-tool` and `os-tool` are intentionally dumb — they execute whatever
they're told. The only thing between the LLM and a `DROP TABLE` /
`rm -rf` / `cat /etc/shadow` is `tg-proxy`.

## What the two policies cover

`policies/db-protect.yaml` — DB rules:

| Rule | Type | Triggers on |
|---|---|---|
| `rule-ddl-block-drop` | threshold | `tool_name == drop_table` |
| `rule-ddl-block-truncate` | threshold | `tool_name == truncate_table` |
| `rule-dml-block-delete-tool` | threshold | `tool_name == delete_rows` |
| `rule-query-must-be-clean-select` | `sql_classify` | Anything sent to `tool_name == query` that is not a single top-level `SELECT`, calls a function outside the allowlist, uses dynamic SQL (DO / EXECUTE / CALL), or reaches the shell via `COPY ... FROM/TO PROGRAM`. Closes the smuggled DDL / DML / DCL classes (DROP / DELETE / GRANT / ALTER / CREATE / REVOKE / ...) plus the CTE bypass (`WITH x AS (SELECT 1) DELETE FROM users`) and the dollar-quote escape via a tokenizer pass — no per-keyword regex maintenance. |

`policies/os-protect.yaml` — OS rules:

| Rule | Type | Triggers on |
|---|---|---|
| `rule-os-exec-strict` | `shell_classify` | `tool_name == os_exec` AND the argv either targets a non-whitelisted binary, contains shell metacharacters, env-rewraps a different binary (`env`/`sudo`/`nice`/`ionice`/`chroot`/`doas`), or has an argv path that resolves outside the allow-list. |
| `rule-os-credential-file-read` | `path_classify` | `tool_name == os_read_file` AND the resolved path lands under `/etc/shadow`, `/etc/passwd`, `~/.ssh`, `~/.aws`, `~/.docker`, `~/.netrc`, `~/.pgpass`, `~/.kube`, `/proc/*/environ`, `/var/lib/postgres`, etc. Defeats `..` traversal, symlink escapes, and `//` path-canonicalisation tricks. |

Both policies pass `tg lint` clean.

## Prereqs

- Docker + Docker Compose
- Ollama running on the host with `gemma4:e4b` pulled:
  ```sh
  ollama pull gemma4:e4b
  ```

## Run

```sh
docker compose up --build
```

Tail the LLM transcript:

```sh
docker compose logs -f agent
```

You'll see live `[model]` JSON tool calls, `[proxy]` decisions, and
`[tool]` results. Every `drop_table`, every non-whitelisted `os_exec`,
every credential-path `os_read_file` lands as `[proxy] denied`.

## Sanity-check the policies without the LLM (28 deterministic tests)

```sh
docker compose up -d postgres tg-proxy db-tool os-tool
bash test-policies.sh
```

Exercises every rule with curated envelopes via curl. Independent of
LLM variance. Last clean run:

```
-- RESULT: 28 passed, 0 failed --
```

## Adversarial bruteforce — 45 + 56 bypass attempts

```sh
docker compose up -d postgres tg-proxy db-tool os-tool
bash bruteforce-policies.sh        # 45 cases: case games, encodings, CTEs, etc.
bash bruteforce-adversarial.sh     # 56 cases: tool-name-spoofing, env wrappers, …
```

Both suites are zero-bypass when the proxy is started with
`-unknown-tools-deny` (the docker compose default). Each case prints
its outcome so a regression surfaces immediately.

## Verify nothing actually touched the database or the host

After a full run:

```sh
docker compose exec postgres psql -U demo -d demo -c '\dt'
# users, payments, audit_log all present, 3 rows each
```

```sh
docker compose exec os-tool ls -la /etc/shadow
# never readable from outside the os-tool container regardless;
# more importantly the tg-proxy /evaluate call never reached the
# binary because the policy denied it upstream.
```

## Verify the audit chain

The proxy writes every decision to `./audit/decisions.jsonl` on the
host (bind-mounted to `/var/lib/tg/decisions.jsonl` in the container).

```sh
# From the repo root:
go run ./cmd/tg verify -file examples/postgres-attack/audit/decisions.jsonl
# {"intact": true, "records": N, "tail_hash": "sha256:…"}  → exit 0
```

To prove tamper-detection works, flip one hex digit somewhere in the
file and re-verify:

```sh
sed '5s/"trace_hash":"sha256:[0-9a-f]/"trace_hash":"sha256:Z/' \
  examples/postgres-attack/audit/decisions.jsonl > /tmp/tampered.jsonl
go run ./cmd/tg verify -file /tmp/tampered.jsonl
# exit 5 — first_failure_at=5, exact recomputation diff in the output.
```

## How honest the demo is, point by point

- The Postgres database is real (`postgres:16-alpine` with seed data).
- The DB tool is real, talks `lib/pq`. If you delete a deny rule, the
  next run actually drops the table.
- The OS tool is real and runs `sh -c <cmd>` in the os-tool container.
  Confined to that container's filesystem — not the host's — but the
  policy gate is what we're demonstrating, not the sandbox.
- The LLM is a real Gemma 4 e4b (8B) over Ollama on the host machine.
  Its behavior is probabilistic — sometimes it tries all three attack
  vectors, sometimes it gives up after the first deny. That variance
  is the point; `test-policies.sh` removes it for deterministic CI.
- The proxy uses the production `tg-proxy` Dockerfile from the repo
  root. No demo-specific patches.
- The audit chain is a real SHA-256 hash chain. Tamper detection is
  real (see the `sed` test above).

## How this is "MCP-style" but not MCP

`db-tool` and `os-tool` are HTTP services with one URL per tool name,
not MCP servers speaking JSON-RPC over stdio. The policy proxy is
transport-agnostic: identical evaluation logic gates calls coming
from an MCP server, a LangChain executor, an Anthropic tool-use
loop, or any other tool transport.

## Reset

```sh
docker compose down -v   # also removes the postgres data + audit log
```
