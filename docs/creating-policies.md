# Creating Policies

A Tool Guard policy is a YAML file with three required sections:
identity (`policy_id`, `name`, `version`, `status`, `mode`), a
**scope** that says which tool calls the policy applies to, and a
list of **rules** that say what to do.

## Anatomy

```yaml
policy_id: pol-refund-cap          # unique within the loaded set
name: refund-cap                   # human label
description: >
  Allow refunds under $500; deny above.
version: 1
status: approved                   # draft | review | approved | archived
mode: enforcement                  # enforcement | shadow

scope:
  tool_names: [issue_refund]       # match by tool_name AND/OR
  tool_groups: [monetary_outflow]  # by tool_group

rules:
  - rule_id: rule-amount-cap
    name: Single refund amount limit
    rule_type: threshold
    conditions:
      field: amount
      operator: gt
      value: 500
    effect: deny
    effect_config:
      severity: high
      suggested_response: "Refunds over $500 require supervisor approval."
    citation:
      document_id: doc-refund-sop
      section: "2.3"
      excerpt: "Individual refund transactions exceeding $500 require supervisor approval prior to processing."
```

`tg lint -policy <file>` validates the shape and runs eight
checks - warnings and errors (see [`tg lint` heuristics](#tg-lint-heuristics)).
A policy that lints with `error`-severity findings will be REFUSED
by `tg-proxy` at load.

## Scope

`scope.tool_names` and `scope.tool_groups` are independently
matched: either the envelope's `tool_name` is in `tool_names`, OR
its `tool_group` is in `tool_groups`. A policy with empty scope
matches every envelope - `tg lint` warns about this as
`policy-scope-leak`.

The recommended pattern is BOTH a `tool_names` allowlist AND a
`tool_groups` allowlist. The lint heuristic `scope-no-tool-group`
catches tool-substitution bypasses (an attacker pivots to a sibling
tool in the same group).

## Modes

- `enforcement` - the decision returned to the agent is applied.
- `shadow` - the decision is computed and audited but the agent is
  always told `allowed`. Useful for rolling out a new rule and
  watching how it would have behaved against real traffic.

A near-miss flag on the trace records which mode the rule was
operating in and what the "would-be" decision would have been.

## Effects

| Effect | Behaviour |
|---|---|
| `allow` | Pass-through; trace is still audited |
| `flag` | Pass-through; severity recorded; useful for observation |
| `escalate` | Returns 202 Accepted; agent gets a `poll_url`; operator approves / denies via `/escalations/<id>/approve|deny` |
| `deny` | Returns 200 with `denied`; agent is expected not to call the tool |

Severity hierarchy: `deny` > `escalate` > `flag` > `allow`. When
multiple rules fire, the strongest effect wins.

## Conditions - the leaf shapes

### Field comparison

```yaml
conditions:
  field: parameters.amount
  operator: gt
  value: 500
```

Operators:

| Operator | Notes |
|---|---|
| `eq`, `neq` | Equality; nil values are rejected at load time. |
| `gt`, `gte`, `lt`, `lte` | Numeric comparison. String values that parse as numbers are coerced. |
| `gt_field`, `lt_field` | Compare against another field of the envelope. |
| `in` | Value is a list; field's value must be a member. |
| `contains` | Substring match. |
| `regex` | Go RE2; pattern compiled at policy load. No backreferences / lookaround. |

### SQL classifier

```yaml
conditions:
  sql_classify:
    field: parameters.sql
    dialect: postgres                 # postgres | mysql | sqlite | mssql
    require:
      top_level_kinds: [SELECT]       # allow only single-stmt SELECT
      no_dynamic_sql: true            # forbid DO / EXECUTE / CALL
      no_program_exec: true           # forbid COPY ... FROM/TO PROGRAM
      allowed_functions: [count, sum, avg, min, max, now, lower, upper, length, coalesce]
      denied_tables: [audit_log, secrets]  # prefix match
      allowed_tables: [users, orders]
```

Closes the structured-DDL-smuggle / DML-via-SELECT / function-exec
bypass families. See `examples/postgres-attack/policies/db-protect.yaml`
for a full bundle.

### Path classifier

```yaml
conditions:
  path_classify:
    field: parameters.path
    require:
      clean_first: true                # normalise `..`, `.`, `//` first
      absolute_only: true              # reject relative paths
      allowed_canonical_prefixes: [/var/log/]   # canonical path must start here
      deny_shell_metas: true           # ; | & $() ` deny
      include_backslash: true          # Linux-only mode treats \ as meta
      resolve_symlinks: true           # EvalSymlinks before matching
      deny_on_resolve_failure: true    # unresolvable path → deny (write tools)
      max_path_length: 4096
```

Closes traversal / symlink / shell-meta bypass families on
filesystem-path tools.

### Shell classifier

```yaml
conditions:
  shell_classify:
    field: parameters.argv             # MUST be a parsed argv list
    require:
      argv0_allowlist: [uptime, date, whoami, df, pwd]
      # Path-shaped argv elements are filepath.Clean'd and matched
      # against these prefixes; ** is a deep glob.
      denied_argv_paths: [/etc/, /root/, /home/*/.ssh/]
      resolve_symlinks: true
      argv_env_pattern_deny: '^(BASH_FUNC_|LD_PRELOAD|PATH=)'
      argv_deny_patterns: ['(?i)\\b(rm|dd|mkfs|wget|curl)\\b']
```

The tool MUST exec argv directly, never `sh -c`. The classifier
treats argv[0] as the binary and argv[1:] as its arguments. Closes
shell-meta / env-wrap / interpreter-substitution bypasses (`env`,
`sudo`, `nice`, `chroot` re-launching arbitrary binaries).

### LLM classifier (multimodal)

```yaml
conditions:
  llm_classify:
    prompt_field: parameters.prompt
    image_url_field: parameters.source_image_url   # optional; multimodal
    model: gemma4:e4b
    ollama_url: http://localhost:11434             # optional; default localhost
    timeout_seconds: 30
    forbidden:
      - csam
      - real_person_likeness
      - weapons
      - self_harm
      - copyrighted_style
      - extremist_content
```

The classifier asks Ollama-served Gemma 4 to assign the prompt to
one of the forbidden labels or `safe`. Any non-`safe` verdict fires
the rule. Empty model responses are treated as `model_refused`
(fail-closed). Confidence below 0.6 is `ambiguous` (also
fail-closed). Image URLs are fetched through an SSRF-hardened client.

See [content-gen-bundle.md](content-gen-bundle.md) for a full
walk-through.

## Condition trees

Compose with `and`, `or`, `not`:

```yaml
conditions:
  and:
    - field: tool_name
      operator: eq
      value: issue_refund
    - or:
        - field: amount
          operator: gt
          value: 500
        - field: parameters.reason
          operator: regex
          value: '\$[0-9,]{4,}'
    - not:
        field: context.verified.justification.verified
        operator: eq
        value: true
```

`not:` may wrap a leaf condition (as above) but **not** a classifier
(`sql_classify` / `path_classify` / `shell_classify` / `llm_classify`).
Classifiers are fail-closed - they fire on malformed or adversarial input
so a deny rule trips - and negating one inverts that into fail-OPEN.
`ValidatePolicy` rejects any classifier under a `not:` node; express the
allowed set positively (e.g. `require.top_level_kinds: [SELECT]`) instead.

`ValidatePolicy` refuses condition trees deeper than 64 nodes
(stack-exhaustion defence).

## tg lint heuristics

| Rule | Severity | Catches |
|---|---|---|
| `policy-scope-leak` | warn | Empty scope - policy matches every call |
| `scope-no-tool-group` | warn | Tool-substitution bypass surface |
| `amount-without-semantic-check` | warn | Free-text amount fragmentation; suppressed when a compiling regex / contains rule on a non-amount free-text field is present |
| `rule-missing-citation` | warn | Auditor traceability gap |
| `rule-id-collision` | error | Two rules share an ID |
| `invalid-regex-syntax` | error | Regex that doesn't compile in RE2 |
| `unknown-operator` | error | Operator the engine cannot evaluate |
| `structural-validation` | error | Empty / multi-form condition, bad operator/value type, oversize glob, bad LLM-classify shape |

Run `tg lint -policy <file>` after every edit. The CI workflow
includes a lint gate.

## Effect config

```yaml
effect_config:
  severity: critical              # low | medium | high | critical
  escalate_to: approver           # role label, used by the approver UI
  timeout_minutes: 30             # escalation expiry
  suggested_response: "Refunds over $500 require supervisor approval."
```

`timeout_minutes` on an `escalate` effect overrides the proxy's
default escalation timeout (`-escalation-default-timeout-min`).

## Citations

Every rule should reference the policy document it implements:

```yaml
citation:
  document_id: doc-finance-sop
  section: "3.1"
  excerpt: >
    Per the FY26 Finance SOP, individual purchase orders exceeding
    $10,000 require written CFO approval before submission.
```

This is what the auditor sees on the trace - the WHY behind the
decision. `tg lint` warns on rules with missing citations.

## Example policy bundles

| Bundle | Surface |
|---|---|
| `examples/postgres-attack/policies/` | SQL + shell + path for DB-tool agents |
| `examples/finance-cfo/policies/` | Procurement, wires, expenses |
| `examples/business-ops/policies/` | Data export, mass communication, support comp |
| `examples/content-gen/policies/` | Image / audio / text generation with Gemma 4 |
| `examples/sample-app/policies/` | The Quick Start refund policy |

Each bundle ships a `test-policies.sh` curl-driven suite that
asserts the policy's correctness against a live proxy. Use them as
templates for your own policies.

## Reloading at runtime

`POST /reload` (or `kill -HUP $(pidof tg-proxy)`) re-reads
`-policy-dir`. Validation runs on every load; if any file fails,
the OLD policy set stays live and the proxy logs the error. There is
no half-load state.

## Validation surface

`ValidatePolicy` (run on every load) refuses:

- empty / multi-form condition nodes
- nil values on `eq` / `neq`
- numeric operator on a non-numeric value
- regex that doesn't compile
- glob with > 2 `**` segments
- LLM-classify with empty `forbidden` list, `safe` as a forbidden
  label, duplicates, comma/newline/quote in a label, > 64 labels,
  bad `ollama_url` scheme, `timeout_seconds` outside `[0, 120]`

A policy that fails any of these gates is rejected at load; the
previously loaded policy set stays live.
