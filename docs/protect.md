# Protect a coding agent

`tg protect` safely manages a coding agent's pre-tool hook. The first native
target is Claude Code 2.1.139 or newer; that version introduced shell-free
exec-form hooks. Codex, Junie, `agy`, and MCP wrapping are not yet native
targets.

## Preview, apply, and verify

```sh
tg protect claude
tg protect claude -apply
tg status claude
```

Preview is the default. It prints the target paths and complete proposed JSON
without writing anything. `-apply` performs the change.

The managed hook stores the current absolute `tg` executable in `command` and
the following values in a separate `args` array:

```text
hook -policy <absolute-policy> -agent-id tool-guard-claude \
  -protect-path <absolute-selected-settings.json> \
  -protect-path <absolute-pristine-backup> \
  -protect-path <absolute-managed-state> \
  -protect-path <absolute-audit-directory> \
  -protect-self \
  -fail-closed-tools bash,write,edit,notebookedit \
  -audit-log <absolute-audit-log>
```

The default installation creates:

| Artifact | Default path |
|---|---|
| Claude settings | `~/.claude/settings.json` |
| Starter policy | `~/.config/tool-guard/policies/coding-agent-baseline.yaml` |
| Audit chain | `~/.config/tool-guard/audit/claude.jsonl` |
| Pristine backup | `~/.claude/settings.json.tool-guard.bak` |
| Managed state | `~/.claude/settings.json.tool-guard-state.json` |

This exec form does not depend on Bash, PowerShell, or shell quoting, including
when paths contain spaces. A default-profile install detects Claude Code and
refuses versions older than 2.1.139. Passing an explicit `-config` is the
advanced/test-profile path and bypasses local Claude installation detection.

Configuration and state writes are atomic. On POSIX systems files are mode
`0600` and Tool Guard-created parent directories are mode `0700`. On Windows,
files inherit the user-profile ACLs; Go permission bits do not create Windows
ACLs. The selected binary must exist and be executable; the selected policy
must parse and pass engine validation before the hook is activated.

## Safety and reversibility

- Existing settings and unrelated hook entries are preserved.
- Repeating `protect ... -apply` adds no duplicate entry.
- The first pre-install backup is never overwritten.
- The generated protected paths block writes to Claude settings, managed state,
  the pristine backup, and the audit directory (including rotation siblings).
- `-protect-self` additionally blocks the agent from writing its policy source.
- Consequential tools fail closed if policy loading or evaluation fails.
- Every hook decision is appended to the hash-chained audit log.

Rollback is also preview-first:

```sh
tg unprotect claude
tg unprotect claude -apply
```

If the settings file is unchanged since installation, Tool Guard restores the
original bytes and permissions from the pristine backup. If settings changed
after installation, it removes only its managed command and preserves those
later user changes. If the managed marker is missing, rollback refuses to
alter the file.

## Overrides

Use explicit paths for testing or a custom policy:

```sh
tg protect claude \
  -config /absolute/path/settings.json \
  -policy /absolute/path/policy.yaml \
  -tg /absolute/path/tg
```

All generated command paths are absolute. `status` accepts `-config`, verifies
that the managed executable and policy remain usable, and reports
`executable_ok` and `policy_ok`. Both mutating verbs require `-apply`.
