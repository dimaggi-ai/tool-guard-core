# CLI Reference

`tg` is the one-shot command-line interface for policy authoring, local
evaluation, coding-agent protection, and offline audit workflows. Run
`tg <command> -h` for command-specific flags.

The command list below is checked against both the CLI help text and the
dispatch switch in CI, so a command cannot be added or removed without the
reference changing in the same pull request.

| Command | Purpose |
|---|---|
| `tg evaluate` | Evaluate one JSON tool call against one YAML policy. |
| `tg simulate` | Replay JSONL tool calls against one policy or a policy directory. |
| `tg coverage` | Report which policy rules a JSONL call set exercises. |
| `tg hook` | Enforce policies as a coding-agent pre-tool hook. |
| `tg protect` | Preview or install managed coding-agent protection. |
| `tg status` | Inspect managed coding-agent protection. |
| `tg unprotect` | Preview or remove managed coding-agent protection. |
| `tg verify` | Verify a hash-chained audit log and its rotations offline. |
| `tg export` | Verify, filter, and stream audit records as JSONL. |
| `tg lint` | Validate a policy and report authoring hazards. |
| `tg benchmark` | Measure deterministic evaluation latency on the local host. |
| `tg version` | Print build and Go toolchain version information. |

Exit codes and complete examples live with the relevant workflows in
[Getting Started](getting-started.md), [Creating Policies](creating-policies.md),
[Audit Export](audit-export.md), and [Coding-agent Protection](protect.md).
