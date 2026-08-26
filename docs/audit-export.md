# Exporting audit records

`tg export` streams Tool Guard's append-only audit log as JSON Lines (JSONL):
one complete decision trace per line, with no array wrapper. It reads the
existing audit store and never modifies, truncates, or rotates it.

```bash
tg export -file /var/lib/tool-guard/decisions.jsonl --format jsonl
```

The command discovers rotated siblings through the same rules as `tg verify`
and reads them oldest-first. Before writing any record to stdout, it verifies
the entire captured rotation set and its SHA-256 links. A missing, malformed,
or tampered source exits non-zero with no partial export.

## Command contract

```text
tg export -file DECISIONS.jsonl [-format jsonl]
          [-since RFC3339] [-until RFC3339]
          [-policy ID] [-action ACTION]
```

| Option | Meaning |
|---|---|
| `-file` | Active audit path. Required. Numbered rotated siblings are included automatically. |
| `-format` | Output format. `jsonl` is the default and currently the only supported value. |
| `-since` | Include records whose `timestamp` is equal to or later than this RFC 3339 timestamp. |
| `-until` | Include records whose `timestamp` is earlier than this RFC 3339 timestamp. The boundary is exclusive. |
| `-policy` | Include a record when any `rule_results[].policy_id` exactly matches. Repeat the option or comma-separate IDs for OR. |
| `-action` | Match `action_taken`: `allowed`, `denied`, `escalated`, `flagged`, or `allowed_shadow`. Repeat or comma-separate for OR. |

Different filter dimensions combine with AND. This example selects denied or
escalated decisions that matched either policy during a half-open UTC window:

```bash
tg export -file /var/lib/tool-guard/decisions.jsonl \
  --since 2026-08-25T00:00:00Z \
  --until 2026-08-26T00:00:00Z \
  --policy pol-refund-cap,pol-sanctions \
  --action denied --action escalated
```

An intact source with no matching records is successful and writes an empty
stream. Policy IDs are case-sensitive. Action values are normalized to lower
case. Timestamps accept RFC 3339 fractional seconds and are compared as
instants.

Exit status is `0` for a successful export (including no matches), `1` for a
source, integrity, decoding, or output error, and `2` for invalid arguments.
Diagnostics go to stderr; stdout contains JSONL only.

## Record schema and version stamps

Every line is the complete JSON representation of a `DecisionTrace`, not a
projection. Its major field groups are:

| Group | Fields |
|---|---|
| Identity and call | `trace_id`, `timestamp`, `org_id`, `envelope_id`, `agent_id`, `session_id`, `tool_name`, `tool_group` |
| Result | `decision`, `action_taken`, `decision_reason`, `mode`, counters, `rule_results`, citation and escalation fields |
| Integrity | `trace_hash`, `previous_trace_hash`, `signed_by` |
| Provenance | `engine_version`, `policy_set_hash`, `schema_version` |
| Evidence and timing | redacted parameters, context snapshot, evaluation duration, and optional model-usage/deep-evaluation fields |

New records use canonical audit schema `v2`. Their `engine_version`,
`policy_set_hash`, and `schema_version` values are inside the canonical hash,
so changing a version stamp breaks verification. `policy_set_hash` is a
`sha256:<64 lowercase hex characters>` digest of the normalized loaded policy
set. Legacy v1 records omit all three provenance fields; mixed v1/v2 chains
remain readable and verifiable. Consumers should treat unknown fields as
additive and branch on `schema_version`, interpreting an absent value as the
legacy v1 representation.

The exporter preserves each selected source JSON line byte-for-byte (apart
from omitting blank lines and writing a terminating newline). An unfiltered
export is therefore a portable copy that `tg verify` can check again. A
filtered export deliberately retains each record's original
`previous_trace_hash`; when filters skip an intermediate record, the result is
not a standalone contiguous chain. Its integrity guarantee comes from the
full source verification performed before selection.

## Snapshot and concurrent writes

At startup, the exporter opens the rotation set, captures each file's length,
and verifies those exact byte ranges. Records appended after that snapshot are
left for the next run. If a captured file shrinks during verification, export
fails. Keep normal audit files append-only and coordinate external rotation
with the proxy; the exporter does not lock or mutate the store.

## Standard pipeline examples

Count exported decisions with `jq`:

```bash
tg export -file /var/lib/tool-guard/decisions.jsonl \
  --since 2026-08-25T00:00:00Z \
  | jq -s 'group_by(.action_taken) |
      map({action: .[0].action_taken, count: length})'
```

Forward each intact JSON record to the host's configured syslog pipeline:

```bash
tg export -file /var/lib/tool-guard/decisions.jsonl |
while IFS= read -r record; do
  logger -t tool-guard-audit -- "$record"
done
```

Configure the host's syslog daemon or collector to forward the
`tool-guard-audit` facility to the destination SIEM. The loop is intentionally
generic: Tool Guard does not embed credentials, vendor SDKs, or delivery
retries. For incremental scheduled exports, store the last successfully
delivered timestamp externally and pass it back with `--since`; downstream
deduplication should use `trace_id` because `--since` includes its boundary.
