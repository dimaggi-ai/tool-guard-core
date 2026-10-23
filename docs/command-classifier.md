# Inactive advisory command classifier

`pkg/commandclassify` classifies a complete command **string** as
`read_only_candidate` or `escalate`. A candidate means only that the string fits
this documented literal read grammar. It is **never permission**, an execution
request, an authenticated identity, or a guarantee that an operation is safe.
Nothing imports or wires this package into the existing engine, CLI, hooks,
policies or settings. Existing argv classification and protected-path detection
remain unchanged.

```go
result := commandclassify.Classify("gh pr list --state open --limit 20")
// result.Decision == commandclassify.ReadOnlyCandidate
// No command is executed. An independent authority still decides any action.
```

## Proposed exported API and compatibility

**Unreleased; independent API review and release remain pending.** The package
adds a public import path, `github.com/dimaggi-ai/tool-guard-core/pkg/commandclassify`,
and therefore adds support surface even though no installed call site uses it.
The complete exported surface in this candidate is:

| Export | Shape / meaning |
| --- | --- |
| `Classify` | `func Classify(input string) Result`; bounded, stateless syntax classification |
| `Decision` | Defined string type |
| `ReadOnlyCandidate`, `Escalate` | Typed `Decision` constants: `"read_only_candidate"`, `"escalate"`; neither grants permission |
| `MaxInputBytes`, `MaxWords`, `MaxWordBytes` | Untyped integer constants: `8192`, `128`, `1024` |
| `Span` | Struct with `Start int`, `End int`; half-open original-input byte offsets |
| `Word` | Struct with `Value string`, `Span Span`; decoded literal and source range |
| `Result` | Struct with `Decision Decision`, `Reason string`, `Span Span`, `Words []Word`, `Command string` |

The exported fields carry JSON names `start`/`end`, `value`/`span`, and
`decision`/`reason`/`span`/`words`/`command`, respectively; `words` and `command`
use `omitempty`. These fields and diagnostic output are part of the proposed
consumer-facing surface, not authenticated evidence or a permission protocol.
There are no exported methods or variables beyond the declarations listed above.

This is additive: no existing exported symbol is removed or changed, no existing
consumer migration is required, and no engine, CLI, hook, policy, dependency or
installed behavior changes. A new caller must explicitly import the package and
keep authorization separate; this proposal does not authorize such an integration.
The accepted syntax remains the narrow **gh 2.57.0** slice and fixed bounds below,
not a general shell parser or future CLI compatibility promise.

The hosted API check reports `package .../pkg/commandclassify: added`. Its reviewed
baseline is intentionally unchanged pending the review sequence in
[Go API stability](api-stability.md) and [Releasing](../RELEASING.md).
Documentation of this impact is not approval to refresh `api/go-api.current`,
release the package, activate a control or claim the API gate passes.

## Supported slice

The source is the installed GitHub CLI **2.57.0 (2024-09-16)** help for the six
commands below, captured on 2026-10-23. Its help documents `ls` as an alias for
`list` in all three resources. Current upstream manuals are linked for readers;
this implementation deliberately pins the older observed help vocabulary rather
than silently accepting future CLI additions.

| Command | Positional arguments in this slice | Accepted options |
| --- | --- | --- |
| [`gh pr view`](https://cli.github.com/manual/gh_pr_view) | Optional positive PR number | `--repo`/`-R`, `--comments`/`-c`, `--json` |
| [`gh pr list`](https://cli.github.com/manual/gh_pr_list) / `ls` | None | `--repo`/`-R`, `--json`, `--state`/`-s`, `--limit`/`-L`, `--label`/`-l` |
| [`gh issue view`](https://cli.github.com/manual/gh_issue_view) | One positive issue number | `--repo`/`-R`, `--comments`/`-c`, `--json` |
| [`gh issue list`](https://cli.github.com/manual/gh_issue_list) / `ls` | None | `--repo`/`-R`, `--json`, `--state`/`-s`, `--limit`/`-L`, `--label`/`-l` |
| [`gh repo view`](https://cli.github.com/manual/gh_repo_view) | Optional exact repository | `--json` |
| [`gh repo list`](https://cli.github.com/manual/gh_repo_list) / `ls` | Optional owner | `--json`, `--limit`/`-L`, `--visibility`, `--archived`, `--no-archived`, `--fork`, `--source` |

Value-taking options may appear before or after the resource, verb or selector; every option
and value is consumed before command-specific validation. Local help-only probes exercised several placements; they are not
execution-path validation. Long `--flag=value` and separate `--flag value`/`-R value`
forms are supported. Boolean flags are bare and must appear after the verb. The pinned
[Cobra 1.8.1 command discovery](https://github.com/spf13/cobra/blob/v1.8.1/command.go)
strips value-taking flags while finding subcommands; a parent may not yet know
a child boolean flag. The pinned
[pflag 1.0.5 parser](https://github.com/spf13/pflag/blob/v1.0.5/flag.go)
supports interspersed flags. These versions are recorded in
[gh 2.57.0 go.mod](https://github.com/cli/cli/blob/v2.57.0/go.mod). Combined short flags, attached
short values, `--`, repeated options (including a long/short pair), and conflicting
`--fork`/`--source` or `--archived`/`--no-archived` escalate. Repeated labels also
escalate even though the CLI supports them; this is a conservative first slice.

Values are bounded and checked:

- An exact repository is `OWNER/REPO` or `github.com/OWNER/REPO`. The owner uses
  1–39 ASCII alphanumeric/hyphen characters, without edge or repeated hyphens.
  The repository uses 1–100 ASCII alphanumeric/dot/underscore/hyphen characters
  and starts with an alphanumeric character. Other hosts, URLs and relative
  paths escalate. This is a conservative syntax subset, not repository existence
  or authorization validation.
- A PR/issue number is canonical positive decimal, at most 2,147,483,647. A limit
  is canonical decimal 1–1,000. These are parser resource bounds, not a grant of
  permission or a statement of the server's maximum.
- PR list state is `open`, `closed`, `merged` or `all`; issue list omits `merged`.
  Repository visibility is `public`, `private` or `internal`.
- JSON fields are nonempty, unique, comma-separated exact names from that
  command's pinned help. Command-specific field sets live in `classify.go`.
- A label is one nonempty literal value, at most 256 bytes, without edge
  whitespace, an initial hyphen, comma or decoded double-quote characters.
  The pinned [pflag string-slice parser](https://github.com/spf13/pflag/blob/v1.0.5/string_slice.go)
  uses CSV; lists and CSV quoting are deliberately unsupported here rather than
  partially interpreted. Ordinary/spaced labels and quoted shell-looking literal
  text remain supported.

Every other form escalates, including `gh api` (even GET), mutations, custom
aliases, `gh pr diff/checks/status`, cloning, branch/URL selectors, `--web`,
`--jq`, `--template`, search expressions and options not listed above. The result
is intentionally incomplete for legitimate CLI use; `escalate` is not a claim
that a command is malicious.

## Whole-input parsing and source evidence

The parser does not reuse the existing permissive detector tokenizer. It does
not execute commands, import a shell, read configuration, consult the filesystem
or environment, or contact the network. It is nonrecursive, with zero supported
nesting depth. Bounds are 8,192 input bytes, 128 words and 1,024 decoded bytes per
word. Exceeding any bound escalates, including trailing whitespace beyond the
input limit. ASCII space/tab separate words; other controls, NUL, DEL and
non-ASCII bytes escalate even inside quotes.

Single and double quotes and a small explicit backslash escape set preserve
literal values and the original source spans. Unclosed quotes and escapes fail.
Unquoted operators, redirections, substitutions, variables, globbing, comments,
braces, parentheses, history/tilde expansion, unquoted leading `=` (zsh
EQUALS expansion) and unquoted `^` (extended globbing) fail at the first
unsupported byte. Double quotes still reject `$`, backticks and `!`; an escaped
literal dollar is allowed. Single-quoted `'$(literal)'`, or quoted `"semi;colon"`,
are data rather than executable shell syntax. No text after a supported command
is ignored. Assignments, wrappers and custom executable paths fail because the
first raw word must be exactly `gh`.

`Result.Reason` gives an explicit reason. `Result.Span` and each `Word.Span` are
half-open byte offsets into the original input, including original quotes and
escapes. A successful result spans the whole input; refusal spans identify the
unsupported byte, word, value or argument range. These are diagnostic fields,
not authority tokens. Classification is stateless: correcting a refused string
requires a fresh classification and cannot inherit an earlier decision.

The package cannot establish what an executable named `gh` actually resolves
to. A shell function, executable replacement, CLI configuration, credential scope,
pager, extension, repository hook or future CLI behavior remains external and
unverified. A later integration must independently validate executable/context,
apply existing deterministic policy and permissions, and retain original input.
No such integration or permission change is included here.

## Reproducible checks and limits

All corpus entries are original synthetic examples. Tests parse strings only;
**never execute the corpus**. Source-derived JSON field names and option semantics
are attributed to the GitHub CLI help above. No private transcripts, real
organization repositories or private audit records are included in the corpus.

```sh
go test -race ./pkg/commandclassify
go test ./pkg/commandclassify -run '^$' -fuzz FuzzClassify -fuzztime 10s -parallel 2
go vet ./pkg/commandclassify
```

The package tests include success, refusals, exact spans, corrected retries,
concurrent independent calls, parser bounds and malformed-input fuzzing. Existing
engine/protected-path tests remain regression checks. Repository import searches
must confirm no runtime call site is added before any review of this slice.

The raw 276-command historical corpus is unavailable. Full historical replay is
**unrun**. Older summary labels also contain commands outside this slice (for
example clone/diff/checks/status) and cannot serve as a read-only oracle. The
synthetic corpus is not a replacement for that missing dataset. No permission
prompt reduction, safety rate, production qualification or performance advantage
is claimed from these tests.

Cross-tool review, independent verification and a separate human activation
decision remain open. This inactive classifier does not change any live behavior.
