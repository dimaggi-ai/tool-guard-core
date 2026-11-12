# Coding-agent guard

One Tool Guard hook for three coding agents: Claude Code, OpenAI Codex CLI and
Antigravity CLI. `install.sh` writes a `PreToolUse` hook into the config file
of each agent you name. Before the agent runs a tool, it calls the hook. The
hook runs `tg hook` with five policies and returns one decision: allow, deny,
or a request for approval.

What an agent does with a decision differs by agent and by version. Read
[docs/support-matrix.md](../../docs/support-matrix.md) before you rely on this
example. It lists what was measured, and on which version.

## Install

    make build                                   # from the repository root
    ./examples/coding-agent-guard/install.sh     # every agent found on PATH
    ./examples/coding-agent-guard/install.sh claude codex
    ./examples/coding-agent-guard/install.sh codex --protect /abs/path/one --protect /abs/path/two
    ./examples/coding-agent-guard/install.sh --uninstall claude

The installer needs `jq`. Before it changes a config file for the first time,
it copies the file to a file with the suffix `.bak-toolguard` next to it.
`--uninstall` puts that copy back, so a change made to the config file after
the first install is lost. When no copy exists, `--uninstall` removes the
installer's own entry and keeps the rest of the file. When `--uninstall`
cannot write a config file, it says so, keeps the copy, goes on with the
other agents and ends with exit code 1. When it restored a config file and
cannot remove the copy, it says so, goes on and ends with exit code 1.
Without a copy, a config file that `--uninstall` cannot edit stays as it
was, and the run ends with exit code 1. When `jq` cannot edit a config file, or the
result is not one JSON object, the installer stops with exit code 1 and
leaves the file as it was. The installer checks every config file you named
before it changes the first one. It also checks that it can write to the
directory of each file. A run that stops on one of them changes no
config file and leaves no backup. A config file of 0 bytes is treated as `{}`.
`install.sh claude` also stops with exit code 1 when `settings.json` sets
`disableAllHooks` to `true`. The Claude Code settings reference lists that
setting as turning off hooks.
`install.sh codex` also stops with exit code 1, before it changes the file,
when `hooks.json` has a top-level `PreToolUse` key with an entry that is not
from this installer. Codex CLI 0.166.0 loads no hook from such a file, and
the entry is not the installer's to move.

| Agent | Config file the installer changes | Hook it names |
|---|---|---|
| Claude Code | `~/.claude/settings.json` | `hooks/claude-code-hook.sh` |
| OpenAI Codex CLI | `~/.codex/hooks.json` | `hooks/codex-hook.sh` |
| Antigravity CLI | `~/.gemini/config/hooks.json` | `hooks/antigravity-cli-hook.sh` |

When `CLAUDE_CONFIG_DIR` or `CODEX_HOME` is set, the installer uses that
directory in place of `~/.claude` or `~/.codex`. No run shows that Antigravity
CLI reads `~/.gemini/config/hooks.json`: the release run used a workspace
`.agents/hooks.json`.

Each of the three files is a short wrapper with one command. It starts `hooks/guard-hook.sh`
with the name of the agent. The config file holds the absolute path of the
wrapper and no arguments.

**Codex needs one more step.** Codex does not call a hook it has not been made
to trust. Start `codex` and accept the hook when it asks. Until then the hook
is not called, and `codex exec` prints nothing about it. On Codex CLI 0.166.0 an
interactive start shows "Hooks need review" with three choices: "Review
hooks", "Trust all and continue" and "Continue without trusting (hooks won't
run)". The third choice leaves the guard off.

If you copy `config/codex.hooks.json` by hand, delete its `_comment` key.
Codex CLI 0.166.0 rejects a `hooks.json` that has it: it warns
`unknown field _comment` on start and loads no hook. `install.sh codex` does
not write that key. The review prompt above and this rejection were each seen in one
interactive start on 2026-11-10. They are not part of the harness run in
`docs/support-matrix.md`.

## What the hook does

`hooks/guard-hook.sh` runs:

    tg hook -policy-dir policies -mode enforcement -dialect <claude|antigravity> -escalate-as <ask|deny> ...

It always exits 0 and always prints one JSON decision. When the `tg` binary or
the policy directory is missing, or `tg` prints no decision, it prints a deny.

The `policies/` directory holds five files:

| File | What it does |
|---|---|
| `coding_agent_shell.yaml` | Denies a recursive `rm` of a root, home or system path. Escalates other recursive or forced `rm` commands, and outbound or history-rewriting git commands such as `git push`. It is a copy of `policy.yaml`. |
| `coding_agent_writes.yaml` | Keeps file writes off system paths, caps the size of a write and refuses private-key material. |
| `coding_agent_egress.yaml` | For the tools `http`, `fetch` and `webfetch` and the group `network_egress`: blocks the cloud metadata endpoint and requires https. It does not read shell commands, so `curl` in a shell tool is outside it. |
| `coding_agent_secret_egress.yaml` | Denies a call that carries a value in a known key format to a host that is not listed in the file, and some `curl`, `wget`, `nc`, `ncat`, `scp`, `sftp` and `rsync` commands that name a dotenv file. |
| `coding_agent_context_files.yaml` | Escalates a write to an agent instruction or permission file. Denies a write whose content carries a known key format. |

Each file states its limits in its `description`. Read them. The secret
policies match listed key formats only. They are not a secret scanner. The
four files other than `coding_agent_shell.yaml` are copies of the files in
the repository `policies/` directory. A test fails when a copy differs from
its source.

## Escalations

A policy rule can escalate a call instead of denying it. The hook returns an
escalation to the agent in one of two ways:

- as a request for approval (`ask`, or `force_ask` for Antigravity CLI), or
- as a denial.

The Claude Code and Antigravity CLI wrappers return a request for approval.
The Codex wrapper returns a denial. To change this for one agent, set
`TG_ESCALATE_AS=deny` or `TG_ESCALATE_AS=ask` in the environment the agent
starts in.

Whether an agent stops and waits after a request for approval is a property
of that agent, its version and the flags it was started with. The table in
`docs/support-matrix.md` records it. If nobody will be there to answer, set
`TG_ESCALATE_AS=deny`.

## Protected paths

The hook denies a write to each of these paths when a write tool makes it, or
when a shell command makes it in a form the hook reads:

- this example's `hooks/` directory and the policy directory,
- the state directory (`~/.tool-guard` by default),
- the three config files in the table above,
- every path you passed to `install.sh --protect`. The installer writes them,
  one per line, to `~/.tool-guard/protect-paths`. You can edit that file.

`TG_PROTECT_BASELINE=0` turns off all of these except the paths in the
`protect-paths` file.

For a shell command the hook reads the command text. It does not run it. It
applies two rules.

**Rule 1: the command names a protected path.** The hook denies the command
unless every program in it is one of these read-only programs: `cat`, `ls`,
`head`, `tail`, `grep`, `egrep`, `fgrep`, `wc`, `stat`, `diff`, `cmp`,
`echo`, `printf`, `true`, `false`, `test`, `[`, `pwd`, `jq`, `sha256sum`,
`sha1sum`, `md5sum`, `readlink`, `realpath`, `basename`, `dirname`, `cut`,
`tr`, `nl`, `od`, `tac`, `du`, `df`, `cd`, `pushd` and `popd`.

Two more programs count as read-only when their words cannot name an output
file. `sort` counts when no word starts with `--` and no option holds `o` or
`T`. `uniq` counts when it has at most one file name and no `--`. Neither
counts when one of its words holds `{`, `*`, `?` or `[`, because bash can
turn such a word into an option or into a second file name. So
`ls ~/.claude/* | sort` is allowed, and `sort -o FILE` and
`uniq ~/.claude/*` are not.

So `python3 edit.py ~/.claude/settings.json` and
`git checkout ~/.claude/settings.json` are denied, and
`cat ~/.claude/settings.json` is allowed. The rule reads the text and not
what the command does with it, so
`git commit -m "change ~/.claude/settings.json"` is denied too. A shell with
`-c` and no other option counts as read-only when the command it runs does. A command that sets a variable or
starts the program through a wrapper, as in `PATH=/x cat FILE` or
`env cat FILE`, does not count as read-only.

The text names a path when it holds the path in one of these six ways:

- written in full, or with `~`, `$HOME` or `${HOME}` for the home directory,
- inside quotes, or with a backslash before a character,
- with `\xHH`, `\NNN` or `\uHHHH` in place of a character,
- as a brace list such as `settings.{json,x}`,
- as a file name pattern with `*`, `?`, `[` or `**` that matches the path,
- as a relative path under a directory that the command also names and that
  is above the protected path, for example
  `cd ~/.claude && python3 edit.py settings.json`.

A word that starts with `~+`, `~-` or `~NAME` also counts as the name of a
protected path. bash reads such a word under the current directory, the
directory before it or the home directory of the user `NAME`, and the hook
does not know that directory. So `uniq x ~+/settings.json` is denied and
`cat ~+/settings.json` is allowed. A word that holds `/proc/NAME/cwd` counts
in the same way, and a redirection to such a word is denied. The same is
true for a word that holds `/dev/fd/N/` or `/proc/NAME/fd/N/` before a file
name. A word that holds `/proc/NAME/root` counts in the same way.

The hook follows symbolic links, also a link that stands before `..`. So
`/var/run/../etc/x` is read as `/etc/x` where `/var/run` is a link to `/run`.
A write tool path is read in the same way. The hook follows a link that exists
when the hook runs. A link that `ln` makes in the same command does not exist
at that time, so the hook cannot follow it. The hook denies a command that
makes a link to a protected path or to a directory above one, and that also
runs a program that is not read-only or writes with a redirection, as in `ln
-s ~/.claude l && echo x > l/settings.json`. The same is true for an `ln` in a
text that the command runs or can run: the argument of `bash -c`, the words of
`eval`, a command substitution, a quoted word, and the words after `echo` or
`printf`. It is also true for an `ln` after `busybox`, after `xargs`, and
after a program that is not read-only, as in `flock FILE ln -s ~/.claude l && echo x > l/settings.json`. A
link to `/dev/fd` or to a path under `/proc` counts as a link to a protected
path. A link that `ln` makes with a word from a variable or from a command substitution counts in the same way, as in `c="ln -s $HOME l"; $c`, because the hook cannot read the target. The hook also denies a command that makes a link with `ln`, holds `..`
after the name of the link, and runs a program that is not read-only or writes
with a redirection, as in `ln -s ~/proj l && echo x >
l/../.claude/settings.json`. The same is true when one word holds the name of
the link and another word holds `..`, as in `cd l/sub && echo x > ../../f`.
The hook also denies such a command when no other program writes and the
command runs `ln` two times or more, as in `ln -s ~/proj l && ln -sf f
l/../.claude/settings.json`. The hook also denies a harmless command of this
form, as in `ln -s dist public && cd public/assets && cp ../logo.png .`. A
text after `echo`, `printf`, `git commit` or `git tag` does not count when the
command has no pipe, no input redirection, no `$`, no backtick, and names no
shell, `eval`, `source` or `.`. The hook does not see an `ln` that runs under
another name, such as an alias or a copy of the program. It also does not see an `ln` that the command builds from parts: from more than one variable, as in `x=ln; y=-s; z=$HOME; $x $y $z l`, with a separator other than a space (`IFS=,`), with a default value (`${x:-ln -s $HOME l}`), with `printf -v`, or with a change of the text of a variable (`${c//X/}`). It compares a file
name pattern with the files that exist, so a pattern that matches a link to a
protected directory counts.

The hook does not expand a brace list that makes more than 64 words. Such a
list counts as the name of a protected path when one of its words can be the
path. When the comma lists of one word make more than 4096 words, the word
counts as the name of a protected path. A command
that holds the word `nocaseglob` counts in the same way, because that shell
option makes a pattern match without letter case.

The hook reads a relative path under the working directory that the harness
sends with the call (`cwd` or `workdir`). When the harness sends none, it
uses the directory of the hook process.

The check of one call has a limit of 10 seconds. A check that does not end
in that time denies the call.

When the text names a protected path, the hook also denies a command that
holds a comment (`#`), a here-document, `${...}`, `$((...))`, `case` or a
carriage return. It does not read these as bash does.

**Rule 2: a known way to write.** It checks twelve forms:

- an output redirect,
- the commands `rm`, `cp`, `mv`, `tee`, `truncate`, `ln`, `install`, `chmod`,
  `chown`, `chgrp`, `mkdir`, `rmdir`, `touch`, `shred`, `unlink`, `link`,
  `sed -i` and `dd of=`,
- a path that starts with `~`,
- a path built from a variable or a command substitution, which it denies,
  and any other word of one of these commands that holds a variable, as in
  `sed -i "s/$OLD/$NEW/" FILE`, because the hook cannot tell which word is
  the file,
- the command that `sh`, `bash`, `zsh`, `dash`, `ksh`, `ash`, `mksh`,
  `rbash` or `fish` runs with `-c`, also
  when `-c` is part of an option group such as `-lc` or `-ce`. When the name
  of the program in that command comes from a variable, the hook denies the
  call,
- `cp`, `mv`, `ln` or `install` with a directory and a file name that
  together make one of the paths: a file with the protected name copied
  into its directory, or a directory copied to a place above one of the
  paths,
- `rm`, `mv`, `rmdir`, `ln`, `chmod`, `chown` or `chgrp` on a directory above
  one of the paths, for example `mv ~/.claude ~/.claude-old`,
- a command that follows a shell keyword such as `if`, `then`, `do`, `{` or
  `!`,
- a command that follows one of these wrappers: `env`, `sudo`, `doas`,
  `nice`, `ionice`, `nohup`, `setsid`, `stdbuf`, `timeout`, `chroot`,
  `command`, `exec`, `xargs`, `time`, `proxychains`, `proxychains4` and
  `builtin`,
- a brace list such as `rm ~/.claude/{a,b}`, and a file name pattern with
  `*`, `?` or `[` that matches one of the paths,
- a shell that reads its commands from standard input, such as
  `echo 'rm FILE' | bash`: the hook denies the call when a word of the whole
  command names one of the paths, or is a quoted command that touches one,
- a relative path after `cd DIR` or `pushd DIR` in the same command, when
  `DIR` is written in the command. The hook reads the path under `DIR`, also
  a path with `..`, as in `cd ~/proj && echo x > ../.claude/settings.json`.

The hook does not check how a command uses a directory that it names, so
`ls ~/.tool-guard > list.txt` is denied too.

These two rules are the whole check. The hook does not see a write when the
command text does not name the path and the write is not one of the twelve
forms. In each of these examples a program outside the lists changes a
protected file: it gets the path from a variable other than `HOME`, from the
output of another command, from a file, or from its input (`xargs`), or it
builds the path from parts (`printf`, `eval`). It
reaches the file through a hard link, or through a symbolic link that a
program other than `ln` makes in the same command. It goes to a directory
that the command text does not name, as in `cd $DIR`, and writes a relative
path there. It
changes a whole directory above the path, as in `find ~/.claude -delete`.
The hook does not read a script that a shell runs from a file. Other ways can
exist that are not in this paragraph. An agent that can run a shell can
change a protected file in one of these ways.

On macOS and Windows the hook compares a path with a protected path without
letter case, so `echo x > ~/.CLAUDE/settings.json` is denied there. On another
system it does this when it finds that the directory of the protected path
ignores letter case. A letter such as `é` has two byte forms that macOS reads
as one name. The hook reads them as two names, so it does not see a
protected path that is written in the other form.

## Environment variables

Set these in the environment the agent starts in. All are optional.

| Variable | Meaning | Default |
|---|---|---|
| `TG_BIN` | Path of the `tg` binary | `bin/tg` in this repository |
| `TG_POLICIES` | Policy directory | `policies/` next to this file |
| `TG_POLICY_FILE` | One policy file. When set, it replaces `TG_POLICIES` | not set |
| `TG_STATE_DIR` | State directory | `~/.tool-guard` |
| `TG_AUDIT_LOG` | Audit log file | `<state dir>/hook-audit-<UTC date>.jsonl` |
| `TG_PROTECT_FILE` | File of protected paths, one absolute path per line | `<state dir>/protect-paths` |
| `TG_PROTECT_BASELINE` | `0` turns off the built-in protected paths | `1` |
| `TG_ESCALATE_AS` | `ask` or `deny` | `deny` for Codex, `ask` for the other two |
| `TG_AGY_ESCALATION` | `force_ask` or `ask`: the word a request for approval takes for Antigravity CLI | `force_ask` |
| `TG_UNKNOWN_TOOLS_DENY` | `1` denies a tool that no loaded policy names | `0` |

## Audit log

Every decision that `tg hook` makes is appended to the audit log as one
hash-chained record. When the wrapper cannot create the log directory, it
runs `tg hook` without an audit log. A denial that the wrapper prints by itself, because `tg`
or the policy directory is missing or `tg` printed no decision, is not in the
log. The wrapper writes one line to stderr for it. Check a log file with:

    ./bin/tg verify -file ~/.tool-guard/hook-audit-<UTC date>.jsonl

## Check it against your own install

    ./examples/coding-agent-guard/verify-harnesses.sh

This starts each installed agent with a prompt that asks for a write, and
records whether the write happened. It makes paid model calls. It uses the wrappers and policies of this example and the config templates
in `config/`, with temporary config directories, so it does not change your
own config files. For
Antigravity CLI it puts the config file in a temporary workspace, at
`.agents/hooks.json`, and not at `~/.gemini/config/hooks.json`. It
does not copy your sign-in files for Claude Code and Codex: the temporary
config directory holds a symbolic link to each file, and the script removes
the directory when it ends. It keeps a `manifest.json`, reduced hook records
and filtered agent output under `var/verify/`. The first lines of
`verify_harnesses.py` list its environment variables.

`make verify-harnesses` is the release form of the same run. It sends every
stage three times. The table in `docs/support-matrix.md` comes from its
`manifest.json`. To send every stage more than once in your own run, set
`TG_VERIFY_REPEAT` to a number from 1 to 9.

## Other files in this directory

- `run.sh` is an offline demo. It sends a list of shell commands to the three
  wrappers and prints the decision each wrapper returns. It needs no agent
  and makes no model call.
- `hooks/legacy/` holds the adapters that earlier versions installed. They
  call `tg evaluate` with `policy.yaml`. `install.sh` does not install them.
- `hooks/anthropic-hook.sh` and `hooks/antigravity-hook.sh` are at the paths
  that an earlier `install.sh` wrote into config files. They use one policy
  file (`TG_POLICY`, default `policy.yaml`) and no built-in protected paths.
  The first returns an escalation as a denial. The second returns it as
  `force_ask`. An old config file calls them for `Bash` (Claude Code) or
  `run_command` (Antigravity CLI) only, and Codex CLI 0.166.0 loads no hook
  from an old Codex `hooks.json`. Run `install.sh` again to move to the
  wrappers above.

## Limits

- The hook sees the tool calls that the agent sends to it. A tool the agent
  runs without calling the hook is not checked.
- A tool name that `tg hook` does not know is treated as a shell tool: the
  shell policies read its `command`. The protected-path rules for shell
  commands read it too. They deny the call only when the text names a
  protected path, because the command of such a tool can be text in another
  language. The hook reads a command under the key `command`, `cmd`,
  `script`, `commandLine`, `cmdline`, `shellCommand`, `commandString`,
  `terminalCommand` or `bashCommand`, in any letter case and with or without
  `_`. It does not read a command under another key, such as `input` or
  `args`.
  `TG_UNKNOWN_TOOLS_DENY=1` denies a call to a tool that no loaded policy
  names.
- `coding_agent_context_files.yaml` covers write tools. A shell command that
  writes to an instruction file is not covered by that policy.
- This example is a policy check at one hook. It is not a sandbox.
