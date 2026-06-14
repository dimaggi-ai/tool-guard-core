# coding-agent-guard: one policy, three coding agents

Wire Tool Guard Core into the **PreToolUse hooks** of three AI coding agents
so a single `policy.yaml` decides, in real time, which shell commands the
agent is allowed to run:

| Agent | Hook config | Shell tool | How it blocks |
|-------|-------------|------------|---------------|
| **Claude Code** | `~/.claude/settings.json` | `Bash` | exit code 2 + stderr |
| **OpenAI Codex** | `~/.codex/hooks.json` | `Bash` | exit code 2 + stderr |
| **Google Antigravity** (`agy`) | `~/.gemini/config/hooks.json` | `run_command` | stdout `{"decision": ...}` |

Claude Code and Codex speak the same hook protocol, so they share one
adapter; Antigravity reads its decision from stdout, so it gets a thin
adapter of its own. **The policy engine and the policy file are identical for
all three.** That is the whole point: you author one set of rules, and every
agent on the machine inherits the same guardrail.

```
        Claude Code ─┐
        OpenAI Codex ─┤   anthropic-hook.sh ─┐
                      │                       ├─►  tg evaluate ──►  policy.yaml
        Antigravity ──┘   antigravity-hook.sh ┘        (Tool Guard Core engine)
```

## What it stops

The bundled `policy.yaml` is a "machine guard" - the general form of what a
`git push` gate does, applied to every shell command:

- recursive `rm` of `/`, a top-level system dir, or `$HOME`/`~` — in **any**
  flag spelling (`rm -rf /`, `rm -r -f /`, `rm --recursive --force /`,
  `rm -fR /home`, `/bin/rm -rf /`, `rm -rf "/"`)  ->  **denied**, never runs
- any other recursive or forced `rm` (`rm -rf ./build`, `rm -rf $HOME/x`,
  `rm -f file`)  ->  **escalated**, held for a human
- `git push` / `reset --hard` / `clean -f` / `rebase` / `filter-repo` ...  ->  **escalated**
- everything else (`ls`, `go test`, `cat`, `rm file.txt`, `rmdir x`, ...)  ->  **allowed**

The deny rule matches on *intent* (an `rm` + a recursive flag in any form + a
root/home target), not one exact string, so the obvious flag-spelling variants
cannot slip past it. And the escalate rule fires on **any** recursive-or-forced
`rm`, so even a delete shape the deny rule does not recognize is still held for
a human — it is never silently allowed.

The four Tool Guard effects map onto each agent's native decision model:

| Engine effect | Claude Code / Codex | Antigravity |
|---------------|---------------------|-------------|
| `deny`        | block (exit 2)      | `{"decision":"deny"}` |
| `escalate`    | block (exit 2)      | `{"decision":"ask"}`  (asks the human) |
| `allow`       | pass (exit 0)       | `{"decision":"allow"}` |

Antigravity has a native "ask the user" decision, so `escalate` maps to it
exactly; Claude Code and Codex block on `escalate` and surface the reason to
the model on stderr.

## Try it in 10 seconds (no agent, no network)

```bash
./run.sh
```

This feeds a battery of commands to both adapters exactly as the agents would
and prints the decision each agent would make:

```
  COMMAND                            ENGINE       Claude/Codex       Antigravity
  ---------------------------------- ------------ ------------------ --------------
  rm -rf /                           denied       BLOCK (exit 2)     deny
  rm -r -f /                         denied       BLOCK (exit 2)     deny
  rm --recursive --force /           denied       BLOCK (exit 2)     deny
  rm -fR /home                       denied       BLOCK (exit 2)     deny
  rm -rf /tmp/scratch/build          escalated    BLOCK (exit 2)     ask
  rm -rf $HOME/projects              escalated    BLOCK (exit 2)     ask
  git push origin main --force       escalated    BLOCK (exit 2)     ask
  git clean -fdx                     escalated    BLOCK (exit 2)     ask
  ls -la /home                       allowed      allow (exit 0)     allow
  go test ./...                      allowed      allow (exit 0)     allow
```

It is pure, deterministic policy evaluation: no Docker, no LLM, no API key.

## Install into your agents

```bash
./install.sh                 # auto-detect claude / codex / agy on PATH
./install.sh claude codex    # or pick a subset
./install.sh --uninstall     # restore the originals
```

The installer builds `tg`, writes the hook into each agent's config with an
absolute path, and is **idempotent and non-destructive**: it merges alongside
any hooks you already have and backs up every file it touches
(`*.bak-toolguard`). Then ask your agent to do something dangerous:

> *"delete the build directory with rm -rf"*  ->  the agent's command is held
> for your approval instead of wiping the directory.

If you prefer to wire it by hand, the ready-to-merge snippets are in
[`config/`](./config) - replace `__HOOK_DIR__` with the absolute path to
[`hooks/`](./hooks).

## The hook contract, per agent

All three agents hand the hook a JSON object on stdin. The only differences
are where the shell command lives and how the hook signals a block:

**Claude Code / Codex** (`hooks/anthropic-hook.sh`)

```jsonc
// stdin
{ "tool_name": "Bash", "tool_input": { "command": "rm -rf /tmp/x" } }
// block: exit 2, reason on stderr   |   allow: exit 0
```

**Antigravity** (`hooks/antigravity-hook.sh`)

```jsonc
// stdin
{ "toolCall": { "name": "run_command", "args": { "CommandLine": "rm -rf /tmp/x" } } }
// stdout decides:
{ "decision": "deny" | "ask" | "allow", "reason": "..." }
```

Each adapter normalizes its input into a Tool Guard call envelope, runs
`tg evaluate -policy policy.yaml -mode enforcement`, and translates the
engine's `decision` field back into the agent's signal. That is all an
adapter does - the policy logic lives entirely in the engine.

## Customizing the policy

Edit [`policy.yaml`](./policy.yaml) and the guard changes immediately - no
agent restart. Rules are plain regex/threshold/classifier conditions over the
command string (`parameters.command`). See
[`../../docs/creating-policies.md`](../../docs/creating-policies.md) for the
full condition reference, and run `tg lint -policy policy.yaml` to validate.

Want to gate by content rather than command shape (secrets, SQL, paths)? The
engine ships `regex`, `threshold`, `sql_classify`, `shell_classify`,
`path_classify`, and `llm_classify` conditions; this example uses `regex` for
determinism and zero dependencies.

## Fail-closed by default

If `tg` or `jq` is missing, the input is unreadable, or the engine returns no
decision, **both adapters fail closed** (block) — a broken security guard must
never silently disable itself. The block message says exactly that and how to
recover (build `tg`, install `jq`). A tool call with *no command to evaluate*
(an empty/absent command, or a non-shell tool) is out of scope, not an error,
and is always allowed.

If you would rather a tooling glitch never wedge your agent, set `TG_FAIL=open`
to allow-on-error instead. Both adapters honor `TG_FAIL`, `TG_BIN`, and
`TG_POLICY`.

## Why hooks (and how this relates to the proxy)

Tool Guard Core has two front doors to the same engine:

- **`tg-proxy`** - an HTTP gateway that sits in front of tool/MCP calls (see
  the other examples in this directory). Best for server-side agents and MCP
  tools.
- **hooks** (this example) - the engine invoked in-process by a local coding
  agent, before it runs a shell command. Best for developer machines.

Same policies, same audit semantics, same decisions - two integration points.

## Files

```
coding-agent-guard/
├── policy.yaml                  the machine guard (deny/escalate/allow rules)
├── run.sh                       offline demo: all 3 agents, no agent needed
├── install.sh                   wire/unwire the hook into installed agents
├── hooks/
│   ├── anthropic-hook.sh        Claude Code + Codex adapter (exit-code protocol)
│   └── antigravity-hook.sh      Antigravity adapter (stdout-decision protocol)
└── config/
    ├── claude-code.settings.json   merge into ~/.claude/settings.json
    ├── codex.hooks.json            install at ~/.codex/hooks.json
    └── antigravity.hooks.json      install at ~/.gemini/config/hooks.json
```
