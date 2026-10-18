# CLI Reference

`tg` is the one-shot command-line interface for policy authoring, local
evaluation, coding-agent protection, and offline audit workflows. Run
`tg <command> -h` for command-specific flags.

The command list below is checked against both the CLI help text and the
dispatch switch in CI, so a command cannot be added or removed without the
reference changing in the same pull request.

| Command | Purpose |
|---|---|
| `tg evaluate` | Evaluate one JSON tool call against one YAML policy or a policy directory/set. |
| `tg simulate` | Replay JSONL tool calls against one policy or a policy directory. |
| `tg coverage` | Report which policy rules a JSONL call set exercises. |
| `tg hook` | Enforce policies as a coding-agent pre-tool hook. |
| `tg protect` | Preview or install managed coding-agent protection. |
| `tg status` | Inspect managed coding-agent protection. |
| `tg unprotect` | Preview or remove managed coding-agent protection. |
| `tg prune` | Copy a closed audit log with an eligible prefix replaced by a checkpoint. Dry-run by default. |
| `tg verify` | Verify a hash-chained audit log and its rotations offline. |
| `tg export` | Verify, filter, and stream audit records as JSONL. |
| `tg lint` | Validate a policy and report authoring hazards. |
| `tg benchmark` | Measure deterministic evaluation latency on the local host. |
| `tg version` | Print build and Go toolchain version information. |

Exit codes and complete examples live with the relevant workflows in
[Getting Started](getting-started.md), [Creating Policies](creating-policies.md),
[Audit Export](audit-export.md), and [Coding-agent Protection](protect.md).

For retention flags and checkpoint limits, see [Audit Pruning](audit-prune.md).

Both `tg verify` and `tg export` reject pruned chains by default:

- `-allow-pruned` accepts an unsigned, unpinned checkpoint for internal consistency checks.
- `-checkpoint-hash sha256:<64 lowercase hex>` requires a matching checkpoint
  and implies `-allow-pruned`. Use a pin from a trusted copy stored elsewhere;
  it establishes checkpoint identity, not deleted content.

Malformed or explicitly empty pins exit 2. Rejected chains exit 5 for
`tg verify` (with a JSON report) and 1 for `tg export` (without exported records).
Success exits 0; operational failures exit 1.
