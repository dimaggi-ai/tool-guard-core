# Harness support matrix

This file is the only place a harness support claim may be sourced from.
`TestSupportMatrixMatchesCorpus` fails if it disagrees with
`testdata/hookconformance/`, and `TestDocsHarnessClaimsAreVerified` fails if
`README.md` or `docs/*.md` asserts support for a harness that is not `verified`
here.

Support means: the hook payload shape was captured from a real install of that
harness on this host, and the captured payload is replayed through the real
`tg hook` decision path by `TestHookConformance`. A synthetic payload that
merely looks like a harness proves fixture compatibility, not harness support.

| Harness | Version | Status | Captured | What was captured | Deployment condition | Decision honoured end-to-end |
|---|---|---|---|---|---|---|
| Claude Code | 2.1.316, 2.1.321 | verified | 2026-11-09 | PreToolUse payloads for `Read`, `Write`, `Bash` at both versions | End-to-end: shell write, allowed control, native write tool, escalation probe | yes |
| OpenAI Codex CLI | 0.166.0 | verified | 2026-11-09 | `PreToolUse` for `Bash` (`command`). File writes went through `Bash` (`printf … > file`), not an `apply_patch` tool, in these runs | Hooks are **not** dispatched until the hook is trusted. `codex exec` with an untrusted hook ran the command with no hook invocation at all; with `--dangerously-bypass-hook-trust` the hook fired. Config is `{"hooks":{"PreToolUse":[…]}}` in `~/.codex/hooks.json`; `CODEX_HOME` honoured. The example installer previously wrote a top-level `PreToolUse` key, which this CLI does not read; corrected 2026-11-09 | yes, 2026-11-09: a `-protect-path` write was denied and the file was never created |
| Antigravity CLI (`agy`) | 1.5.3 | verified | 2026-11-09 | `PreToolUse` for `run_command` (`CommandLine`, `WaitMsBeforeAsync`, `toolSummary`), `write_file` (`Path`, `Content`, `Overwrite`), `read_file` (`Path`) — a `toolCall` envelope with PascalCase arg names, not `tool_name`/`tool_input` | `.agents/hooks.json` in the workspace, a named-hook map. Headless `--print` auto-denies tools it cannot prompt for unless `--dangerously-skip-permissions` or an allow-rule is set. It reads a top-level `{"decision","reason"}` object, so `tg hook -dialect antigravity` (or auto-detection) is required: a Claude-shaped answer is rejected with a protojson error and the tool does not run | yes, 2026-11-09: a `-protect-path` write was denied and the file was never created |
| Gemini CLI | 0.34.0 | cannot verify | 2026-11-09 | Nothing. The CLI refuses to run: "This client is no longer supported for Gemini Code Assist for individuals. To continue using Gemini, please migrate to the Antigravity suite of products." | Not exercisable on this host. Do not claim Gemini CLI support | no — the CLI cannot be started |
| OpenCode | 1.19.3 | not supported | 2026-11-09 | Nothing. No `PreToolUse` hook surface was found; OpenCode exposes a plugin API, which is a different integration | Would need a plugin, not a hook | no — no hook surface to install into |
| Cursor, GitHub Copilot, Windsurf, Continue.dev, Cline, Aider | — | not supported | — | Nothing. Not installed here, no capture | Do not claim support | no |

## Which decisions each harness was shown to honour

Measured 2026-11-09 with `verify-harnesses.sh`: the harness is asked to write a
file, and the assertion is whether the file exists afterwards. Every row had a
working allowed control in the same run, so the same harness and the same
capability did write an unprotected file minutes earlier.

| Harness | `deny` on a shell redirect | `deny` on a native write tool | escalation |
|---|---|---|---|
| Claude Code 2.1.321 | honoured, file never created | honoured, file never created | honoured: hook answered `ask`, the escalated command did not run |
| Codex CLI 0.166.0 | honoured, file never created | no distinct write tool; writes arrive as shell commands | **not honoured** — measured twice, probe policy and evidence retained in-repo |
| Antigravity CLI 1.5.3 | honoured, file never created | honoured, file never created | **not enforceable headless**: with `--dangerously-skip-permissions` the harness runs the call on both `ask` and `force_ask`; without the flag it runs nothing at all, guard-allowed writes included |

Antigravity escalation: measured across four runs, because one run was not
representative and an earlier version of this file drew a conclusion from it.

`examples/coding-agent-guard/probe/escalate-probe.yaml` (checked in) escalates a
harmless marker command; `verify-harnesses.sh` runs each configuration twice,
once as an allowed control and once as the escalated probe, and keeps the
payloads, decisions and harness output under `var/verify/<stamp>/`.

| Configuration | allowed control (guard said allow) | escalated probe (guard said `force_ask`) |
|---|---|---|
| with `--dangerously-skip-permissions` | wrote the file, 4 of 4 runs | **the call ran, 4 of 4 runs** — the flag auto-approves the permission request |
| without the flag | wrote the file, 3 of 4 runs | the call did not run, 4 of 4 runs |

What follows, stated at that resolution:

- escalation is **not enforceable** when the auto-approve flag is set: the
  harness decides, and it decided to run. `ask` and `force_ask` behave the same
  there.
- without the flag, `force_ask` stopped the escalated call in every run, and in
  three of them the allowed control proves the difference was the decision and
  not the harness refusing to act.
- the fourth run is why this row keeps a caveat: there the harness wrote nothing
  at all, including the file the guard had allowed, and printed no output. A run
  like that cannot separate guard from harness, so the enforcement claim is
  reported with its count rather than as an unconditional property. Interactive
  Antigravity, where a human can answer the prompt, is the setting this mapping
  is designed for; headless is where it degrades.
- `-antigravity-escalation ask` selects the harness's own `ask`, which the
  measurements show is weaker: with the flag it never stopped a call.
- the `deny` row is unaffected by all of this: `deny` stopped the call in every
  run, with a passing allowed control in the same run.

A claim this file previously carried, and then withdrew too eagerly: an
escalated Antigravity call is refused without the flag. The withdrawal was based
on one run whose allowed control was broken. Repeated measurement restored the
result, so the row now states what was seen and how often, and
`TestDocsStateMeasuredHarnessCaveats` pins both halves of it.


### Codex CLI: escalation is a no-op, measured

The Codex documentation fetched 2026-11-09 says `permissionDecision: "ask"` is
"parsed but not supported yet" and that Codex continues the tool call. That is a
documentation claim, so it was measured instead of quoted. Against Codex CLI
0.166.0, with a probe policy that escalates any command carrying
`ESCALATE_PROBE_MARKER` (probe policy kept out of the shipping set; the point is
the harness behaviour, not the rule):

- the hook was invoked and answered `ask`;
- Codex ran the command anyway and the target file appeared.

The same probe policy against Claude Code 2.1.316 produced one hook call
answering `ask` and the command did **not** run. Same rule, same shell path,
opposite outcome, so the difference is the harness.

Consequence: on Codex CLI 0.166.0 an escalation policy stops nothing. Use deny
rules there. `tg hook` does not silently turn an escalation into a deny for the
Claude-shaped dialect, because Claude Code does honour `ask` and a blanket
mapping would change what an operator's `escalate` rules mean for them.

### Codex CLI: an untrusted hooks.json gives no protection and no error

Measured 2026-11-09 with 0.166.0: a `hooks.json` that is present but has not
been made trusted is **never invoked**. The command ran and the file appeared,
with no warning. The verification script runs a `--dangerously-bypass-hook-trust`
so its denial checks are reproducible, which is exactly why it also runs the
untrusted preflight: an installed hooks.json is not an enforced hooks.json.
`install.sh` must tell the operator to persist trust.

### Shell writes to agent instruction files are not covered by the context-files policy

A shell redirect at `AGENTS.md` is **allowed** by
`coding_agent_context_files.yaml`, and that is the policy working as documented:
it is scoped to the `filesystem_writes` tool group, and a shell command is not
in that group. Do not describe that policy as protecting instruction files from
a shell command. `-protect-path` is the mechanism that covers shell writes to a
named path.

## What "verified" does not cover

- Codex escalation is measured and NOT honoured (above). It is not claimed.
- Tool names beyond those captured for each harness are unclassified and land in
  the `shell` group unless `-unknown-tools-deny` is set.
- PowerShell cmdlets are not understood. `Set-Content`, `Out-File` and
  `Remove-Item` escalate rather than deny.

## The run behind the rows above

`verify-harnesses.sh` writes `provenance.json` next to its records so a claim
can be tied to a build rather than to a sentence. For the run that produced the
table:

| Field | Value |
|---|---|
| Tool Guard commit | `3b26f0b5a8568b182c60f820439340b468fe5d2f` |
| Working tree | dirty — the changes described in `CHANGELOG.md` under Unreleased were uncommitted at run time |
| `tg` binary sha256 | `e5e73dee414f22030ba174af3dfd08eb56a89ab93e01826f6d97ce0d10ec65a3` |
| Harness versions | Claude Code 2.1.316, Codex CLI 0.166.0, Antigravity CLI 1.5.3 |
| Run log | `/tmp/tgharness/verify10.log` |
| Per-call payload and decision records | `/tmp/tg-harness-verify/records/NNNN.json` |

The `records/NNNN.json` files pair each captured payload with the exact decision
`tg hook` returned, which is what distinguishes a denial the harness acted on
from a harness that simply never dispatched the call. They live under `/tmp` and
are not checked in; re-run the script to regenerate them against your own build.

## Reproducing the end-to-end check

    make build
    TG=$PWD/bin/tg ./examples/coding-agent-guard/verify-harnesses.sh

It installs the hook into a scratch config for each harness, asks the harness
to write to a protected path, and asserts the file does not exist. It costs
API calls and is a maintainer-run check, not a CI job.

## Capture procedure

A capture is reproducible with the capture-only hook: a script that writes
stdin to a file and exits 0 with no output, so the harness continues its own
permission flow. Per harness:

1. Point the harness at an isolated config (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`,
   or a workspace `.agents/hooks.json`) so no user configuration is touched.
2. Register the capture script as the `PreToolUse` / `BeforeTool` handler with
   a matcher that matches every tool.
3. Run one headless turn that forces a shell call, a file write and a file
   read.
4. Record the harness name, `--version` output, and date in the case, and
   sanitise session ids, transcript paths, model names and tool-use ids to
   `cap-*` while leaving tool names, parameter names and their casing exactly
   as emitted.

Captures go stale. Re-run this procedure when a harness updates, and delete
the `verified` row rather than leaving it pointing at an old version.

## Evidence

Every claim above is reproducible on the build host and leaves a record.

| Claim | How to reproduce | Record |
|---|---|---|
| Harness versions | `claude --version`, `codex --version`, `agy --version`, `gemini --version`, `opencode --version` | terminal output |
| Captured payload shapes | the capture-only hook procedure below | `testdata/hookconformance/*.json`, one case per captured call, each naming harness, version and capture date |
| Decision reached on a captured payload | `go test ./cmd/tg -run TestHookConformance -v` | test output |
| Codex hook trust requirement | `codex exec` with and without `--dangerously-bypass-hook-trust`, hook registered in an isolated `CODEX_HOME` | the hook runs in one case and not the other |
| Antigravity rejects a Claude-shaped answer | run `verify-harnesses.sh` against a `tg` built before `-dialect` existed | the CLI prints `proto: (line 1:2): unknown field "hookSpecificOutput"` and the tool does not run |
| Denial stops the call end to end | `TG=$PWD/bin/tg ./examples/coding-agent-guard/verify-harnesses.sh` | `PASS` per harness plus payload and decision captures under `/tmp/tg-harness-verify` |

The Gemini CLI refusal text is the CLI's own stderr, quoted verbatim.
