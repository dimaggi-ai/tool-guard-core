# Changelog

All notable changes to Tool Guard Core are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

- **Fixed: `canonicalCandidates` (`pkg/engine/protect.go`) mishandled
  POSIX-absolute shell-command paths on Windows**, silently disabling
  `-protect-paths`/`-protect-self`'s shell-command coverage on that
  platform. `filepath.IsAbs("/protected/f")` returns `false` on Windows
  (it requires a drive letter), so the check wrongly treated an
  already-absolute POSIX path as relative and joined it onto the working
  directory — corrupting it into something that could never match a
  `/`-prefixed policy prefix again. Every case in
  `shell_tokenize_test.go`'s protected-path suite was silently not firing
  on `windows-latest`, hidden until the 0.5.2 `.gitattributes` fix (above)
  stopped `gofmt` from failing that CI job at an earlier step, before
  these tests ever ran. Now gated on a POSIX-absolute check
  (`strings.HasPrefix(p, "/")`) that runs `path.Clean` (GOOS-independent)
  instead of `filepath.Clean` for those inputs — `filepath.Clean` treats a
  leading `//` as a Windows UNC-path prefix and mangles a plain POSIX
  double-slash input (`//etc//shadow`) instead of collapsing it, a second
  real Windows CI failure caught after the first fix. `path.Clean` has no
  concept of UNC paths, sidestepping that ambiguity entirely rather than
  trying to reverse it afterward. Verified: native build/vet/race pass,
  `GOOS=windows` cross-compiles and vets clean, `make test-postgres-full`
  (129 checks) still zero bypasses.

- **Fixed the same bug class in two more call sites, found by a repo-wide
  sweep for `filepath.IsAbs`/`filepath.Clean` after the fix above**:
  `evalPathClassify` (`pkg/engine/path_classify.go`, backs `path_classify`
  and `write_classify`'s deny/allow-prefix checks) and
  `evalShellClassify`'s `DeniedArgvPaths` check
  (`pkg/engine/shell_classify.go`). The `shell_classify` instance was
  worse than a corrupted comparison — `!filepath.IsAbs(arg)` on Windows
  `continue`d past an already-absolute POSIX argv path entirely, skipping
  the deny check outright rather than just failing to match. Both fixed
  with the identical POSIX-absolute-gated pattern. `write_classify`
  reuses the already-fixed `canonicalCandidates`, so it needed no
  separate change. `cmd/tg/hook.go`'s two `filepath.Clean` call sites are
  unaffected by design — they operate on operator-supplied local
  filesystem paths for the machine running `tg hook`, which are correctly
  OS-native, not POSIX shell-command text.

- **Fixed a test-fixture bug (not production code) that was ALSO hidden
  behind the same gofmt failure**: four `cmd/tg` tests
  (`TestHook_ProtectPaths_ArrayParam`, `TestHook_ProtectSelf_DeniesWriteToOwnPolicyDir`,
  `TestHookIntegration_ProtectPaths_DenyBeforePolicy`,
  `TestHookIntegration_ProtectSelf`) build their PreToolUse JSON stdin
  fixture by raw string concatenation of a real `t.TempDir()` path. On
  Windows that path is backslash-separated, and embedding it unescaped
  into a JSON string literal produces genuinely invalid JSON (e.g. a
  literal `\A` from `...\AppData\...` is not a valid JSON escape) — the
  hook correctly treats the unparseable stdin as fail-open (`allow`) by
  default, which is why these tests got `"allow"` instead of the expected
  `"deny"`. Fixed by `filepath.ToSlash`-ing the path before embedding;
  forward slashes need no JSON escaping and Go's Windows path functions
  accept `/` as an input separator, so this changes nothing about what
  path is under test. Two of the four (`TestHookIntegration_*`) are
  behind `//go:build integration` and hadn't even been reached by CI yet
  — the unit-test-level failures above were still blocking that step.

- **Fixed two more layers, uncovered only after the fixes above let
  Windows CI reach the "Integration tests" step for the first time**:
  1. `cmd/tg/integration_test.go` and `cmd/tg-proxy/integration_test.go`
     built their test binaries as `tg`/`tg-proxy` (no extension).
     Windows requires a `.exe` extension to recognize and execute a file,
     even via a full absolute path — `os/exec` failed every single
     integration test with "executable file not found in %PATH%" despite
     the binary having just built successfully. Fixed by appending
     `.exe` on `runtime.GOOS == "windows"`.
  2. Five `cmd/tg-proxy` integration test files used
     `syscall.SysProcAttr{Setpgid: true}` and `syscall.Kill(-pid, …)` to
     start the test proxy in its own process group and tear down the
     whole tree — both POSIX-only; the struct field and the function
     don't exist on Windows at all, so these files never even
     **compiled** for Windows before now, a platform break invisible
     until Windows CI got this far. Split into
     `integration_proc_unix.go` / `integration_proc_windows.go`
     (`setNewProcessGroup`/`killProcessTree`, `//go:build integration &&
     (!windows|windows)`); Windows just kills the direct child, adequate
     for this test harness since `tg-proxy` doesn't fork further
     children here.

  Verified: `GOOS=windows go vet -tags=integration ./cmd/tg/...
  ./cmd/tg-proxy/...` now compiles clean (previously a hard compile
  error), full local gate (build/vet/race/gofmt/govulncheck/coverage/
  integration tests) still clean natively, `make test-postgres-full`
  still 129/129 zero bypasses.

## [0.5.2] — 2026-07-26

Bug-fix release. No breaking changes; no new required config.

- **`matchesScope`'s `tool_names` check is now case-insensitive** (`pkg/engine`).
  Found via a real dogfood deployment: a policy scoped to lowercase
  `tool_names: [bash]` never matched Claude Code's own tool name (`Bash`,
  capitalized) — `MatchPolicies` returned zero matches for every call
  regardless of content, so an `enforcement`-mode policy with a real
  `deny-rm-root` regex rule silently never fired and the call evaluated as
  allowed. `env.ToolName` is untrusted, externally-sourced data, and
  different agent frameworks capitalize their own tool names inconsistently,
  so a policy author shouldn't have to enumerate every casing variant to
  avoid a silent no-match gap. `matchesScope` now compares `tool_names`
  with `strings.EqualFold` instead of exact `==`.

  **`ToolNameKnown` (backs `-unknown-tools-deny`) deliberately stays
  exact-match.** An earlier version of this fix made both functions
  case-insensitive; that was wrong and caught by `make test-postgres-full`
  before release — `examples/postgres-attack`'s "Tool-name variant
  spoofing" cases (`DROP_TABLE`, `Drop_Table` vs. a declared
  `drop_table`) went from correctly denied (unrecognized tool name, fail
  closed) to incorrectly allowed, because case-insensitivity made the
  spoofed variant register as "known". `matchesScope`'s job is applying an
  already-declared policy's own rules to a real call, where
  case-insensitivity closes a real gap; `ToolNameKnown`'s job is the
  opposite — proving a name was EXACTLY, deliberately declared, or failing
  closed — and case-variant spoofing is exactly the class of thing that
  fail-closed default exists to catch. `OrgIDs`/`AgentIDs` and
  `ToolGroups` are unaffected everywhere (real identifiers and
  operator-assigned constants, not raw agent-supplied tool names).

  Regression tests in `pkg/engine/matcher_test.go`:
  `TestMatchesScope_AllPaths`'s new case-insensitivity cases,
  `TestToolNameKnown_ExactMatchOnly` (pins the exact-match requirement as a
  security regression guard). `pkg/engine` coverage 86.8% → 87.4%.
  `make test-postgres-full` (129 checks) passes with zero bypasses. See
  `docs/creating-policies.md`'s Scope section for the documented matching
  contract.

- **CI: fixed a Windows `gofmt` false-positive that had been silently
  failing `main` since the 0.3.0 release (2026-07-14, undetected across
  0.3.0/0.4.0/0.5.0).** No `.gitattributes` existed, so GitHub's
  `windows-latest` runner checked out `.go` files with CRLF line endings
  (Windows Git's default), and `gofmt -l` correctly flagged every file as
  unformatted as a byte-level artifact of that — not a real formatting
  problem. Added `.gitattributes` (`* text=auto eol=lf`) to force LF on
  checkout regardless of platform.

- **CI/toolchain: bumped Go from 1.25.11 to 1.25.12**, which fixes
  `GO-2026-5856` (an Encrypted Client Hello privacy leak in `crypto/tls`),
  caught by `govulncheck` and reachable from `cmd/tg-proxy`, `cmd/tg`,
  `examples/mcp-server`, and `pkg/llmguard` (anything making a TLS
  connection). Updated `go.mod`'s `toolchain` directive and every
  `go-version` pin in `.github/workflows/ci.yml`.

## [0.5.0] — 2026-07-26

"The control holds" — Reliability, Accountability, and the first SDK. Makes
error paths and the audit trail behave the way an *enforcing* deployment
needs, ships a Python SDK for universal agent-framework coverage, and lands
partial progress on five items from the public 1.0 roadmap. No breaking
changes; no new required config.

- **Release-gate hardening.** Added complete behavioral coverage for audit-log
  rotation-set discovery (numeric ordering, active-file placement, crash-gap
  recovery, ignored lookalikes, and filesystem errors), lifting `pkg/audit`
  coverage from 68.5% to 90.2%. The coding-agent write and egress policies now
  include capability groups (`filesystem_writes`, `network_egress`), the hook
  maps the corresponding tool names to those groups, and the write policy
  explicitly denies edits to shipped policy and standard audit-log paths.

- **Python SDK (`toolguard`) — universal agent coverage.**
  Drop-in adapters for LangChain, AutoGen, native OpenAI/Anthropic tool use,
  and MCP; CLI and HTTP-proxy backends.  Shipped at `sdk/python/` as package
  `toolguard` v0.1.0 (pre-1.0, not yet published to PyPI — install from
  source).  Hardened by an adversarial review before landing — see below for
  what that changed.
  - `toolguard.ToolGuard` — policy decision client (CLI: `tg evaluate`; proxy:
    `POST /evaluate`).  Stamps `framework="sdk"` and
    `integration_type="sdk"` on every envelope so `tg coverage` counts
    SDK-governed agents.  Fails closed: an unrecognized `tg evaluate` exit
    code or an unparseable/malformed response body raises rather than
    defaulting to allowed — there is no principled decision to fall back
    to in either case.
  - `toolguard.adapters.langchain.ToolGuardCallbackHandler` — LangChain
    `BaseCallbackHandler` that intercepts `on_tool_start`; raises
    `ToolDenied`/`ToolEscalated` to abort the chain.  Sets
    `raise_error=True` so LangChain's dispatcher actually propagates the
    exception instead of catching and logging it — a handler that doesn't
    set this raises into a black hole, and the tool runs anyway.
  - `toolguard.adapters.autogen.guarded` — decorator for AutoGen /
    generic function-calling agents; returns an error dict on deny/escalate
    so the conversation loop can surface the refusal.
  - `toolguard.adapters.native.guard_tool_calls` — evaluates OpenAI
    `tool_calls` and Anthropic `content[type=tool_use]` blocks; returns
    `(allowed, denied)` lists with pre-built `tool_result` error shapes.
  - `toolguard.adapters.mcp.guard_mcp_tool` — decorator for MCP
    `call_tool` handlers.
  - Shadow-mode aware: every adapter and `ToolGuard.evaluate()` branch on
    `action_taken`, not `decision` — in shadow mode the engine keeps
    `decision="denied"` (what would have happened) with
    `action_taken="allowed_shadow"` (what actually happened, since shadow
    mode never enforces). Branching on `decision` alone would make a
    shadow-mode deployment enforce through the SDK, which shadow mode
    exists specifically to never do; proven by
    `TestProxyShadowModeContract` (`sdk/python/tests/test_contract.py`),
    which builds and runs a real `tg-proxy` in shadow mode and asserts
    `evaluate()` does not raise — not a one-time manual check, an
    automated regression test that fails loudly if this ever breaks again.
  - 137 pytest tests (includes a real-dispatcher LangChain integration
    test — `langchain-core` is now a `dev` extra specifically so this
    runs through LangChain's actual callback manager, not a direct method
    call — and the real-`tg-proxy` shadow-mode contract test above); 95%
    line coverage; the CLI-mode contract test builds `tg` from source and
    asserts SDK decisions match the engine directly. `TG_CONTRACT_REQUIRED=1`
    (set in CI) turns a broken prerequisite (missing `go`, failed build)
    for either contract test into a hard CI failure instead of a silent
    skip of the tests that prove the SDK matches the real engine.
  - `make sdk-test` target, now wired into CI (`.github/workflows/ci.yml`,
    Python 3.10 and 3.12).

- **Stress suite for `tg-proxy`.** A different concern from `tg benchmark`
  (single-goroutine in-process latency probe) and `battle-test` (LLM
  adversarial-bypass harness) — this checks that concurrency doesn't
  compromise correctness, not just how fast it goes.
  - `cmd/stress-test` fires a realistic allow/deny mix against a running
    `tg-proxy` at increasing concurrency levels, reporting throughput and
    p50/p95/p99 latency, then runs a brief overload phase that verifies
    the proxy fails *closed* (rejects cleanly) rather than *open* (a 200
    with the wrong decision, or a hang) when genuinely overwhelmed.
  - After every phase, shells out to `tg verify` to confirm the audit
    hash chain written by hundreds of concurrent goroutines racing
    through the audit-log mutex is still intact — the one
    product-specific correctness property a generic load-test tool
    would never think to check.
  - Native Go fuzz tests (`cmd/tg-proxy/fuzz_test.go`) for the two
    untrusted-bytes entry points that had zero fuzz coverage before:
    the `/evaluate` JSON envelope decode and policy YAML parsing.
  - `make stress` target (`scripts/run-stress.sh`) runs the whole thing
    end to end: builds the binaries, starts a real `tg-proxy`, runs the
    load/overload/audit-chain checks, then fuzzes for `$FUZZTIME`
    (default 15s) per target.
  - `-floor-concurrency`/`-floor-min-rps`/`-floor-max-p99` flags assert a
    published throughput/latency floor at a fixed concurrency level and
    fail the run if it isn't met.
  - 30s-per-target fuzzing now runs on every PR (`.github/workflows/ci.yml`,
    Linux only — the fuzzed code has no OS-specific paths, so running it
    on all three OSes would triple CI time for no extra signal). The full
    load/overload/audit-chain suite plus the published floor
    (2000 req/s, 200ms p99 at concurrency=50) and 2-minute-per-target
    fuzzing run nightly instead (`.github/workflows/nightly-stress.yml`,
    03:17 UTC + manual dispatch) — GitHub-hosted runners showed real
    throughput variance (~10k-27k req/s for identical code, same
    machine, different runs) that would make per-PR floor gating flaky
    rather than meaningful; a nightly cadence still catches a genuine
    regression within a day without blocking anyone's PR on CI noise.

- **Public conformance corpus** (`testdata/conformance/`). 18 fixed
  input/output pairs — one JSON file per scenario — covering every
  shipped policy (`refund_cap`, `refund_cap_strict`, `refund_velocity_cap`,
  `coding_agent_egress`, `coding_agent_writes`, `llm_token_spend_guard`)
  across allow/deny/escalate/flag outcomes and boundary conditions. Each
  case pins an envelope and policy file to an expected
  `decision`/`action_taken` pair, so a change to engine or policy
  semantics that silently flips a real-world outcome breaks a test, not
  just an internal unit assertion. `cmd/tg/conformance_test.go` runs the
  whole corpus through the same `engine.Evaluate` path a real deployment
  uses; already covered by the existing CI matrix (no new workflow
  needed). `make conformance` runs it directly.

- **Policy compatibility regression net** (`testdata/policy-compat/`, `cmd/tg/policy_compat_test.go`). A partial step toward the "frozen policy
  schema" 1.0 roadmap item: exact policy YAML snapshots taken from every
  past release tag (`v0.2.0`, `v0.3.0`, `v0.4.0`), re-run through the
  conformance corpus against the *current* engine. Asserts an old,
  unmodified policy file still produces the exact decision it always has
  — if a future engine or loader change would silently change that,
  `TestPolicyCompat` fails instead of the break shipping quietly. Not a
  real schema-versioning system yet (no version field, no migration
  step) — see `testdata/policy-compat/README.md` for scope and how to
  add the next version's snapshot. `make policy-compat` runs it
  directly; already covered by the existing CI matrix, no new workflow
  needed.

- **Release provenance attestation** (`.github/workflows/release.yml`).
  Every tagged release now runs `actions/attest-build-provenance` against
  GoReleaser's archives and `checksums.txt`, producing a verifiable,
  GitHub-hosted-Sigstore-backed attestation tying those exact bytes to
  this repo, commit, and workflow run
  (`gh attestation verify <file> --repo dimaggi-ai/tool-guard-core`).
  This is **provenance**, not **reproducibility** — it proves the
  release bytes came from this CI unmodified, not that rebuilding from
  source deterministically reproduces them bit-for-bit (that needs a
  separate rebuild-and-diff verifier this repo doesn't have yet).
  Container images (ghcr.io) are explicitly out of scope for this pass
  and remain unsigned, as already noted in `.goreleaser.yaml`.

- **Internal review process, documented** (`docs/REVIEW-PROCESS.md`). A
  partial step toward the "independent review" 1.0 roadmap item: the
  adversarial self-review pattern that found the SDK bugs above (real
  dispatcher vs. direct call, allowlist vs. denylist, fail-closed on
  unhappy paths, claim-honesty check) formalized as a repeatable
  six-point checklist plus a findings log, wired into `RELEASING.md`'s
  pre-tag checklist. Explicitly **not** labeled "independent" anywhere —
  this is maintainer self-review, not third-party audit; a genuinely
  independent review is still open.

- **`tg-proxy` denies (and audits) a per-request evaluator panic, always.**
  Before this, a panic inside the engine during `/evaluate` had NO recovery
  path at all — it unwound into `net/http`'s own per-connection recover,
  which just drops the connection: no decision, no audit trace, no counter.
  That is worse than fail-open (there is at least a record when the engine
  runs to completion) and directly contradicted `-fail-closed`'s promise.
  `safeEvaluate` recovers the panic and denies unconditionally — deliberately
  **not** gated behind `-fail-closed` the way "no policies loaded" and
  "audit append failed" are: those are well-defined, intentional
  configuration states an operator can reason about; a mid-evaluation panic
  isn't a state, it's a crash, and there is no principled decision to fall
  back to.
- **`tg hook`'s docs and `-h` usage now explicitly recommend
  `-fail-closed-tools` (or `-fail-closed`) for any enforcing deployment.**
  The flag default is unchanged (still opt-in — no breaking change), but
  without one, an internal error fails OPEN by default, which suits local
  dev and is not what a real deployment wants.
- **`tg-proxy`'s startup audit-chain check now walks the FULL chain, not
  just the tail.** The existing tail check only proved the *last* record
  was internally self-consistent; a tampered record in the *middle* of the
  file — whose neighbors' `previous_trace_hash` links no longer line up,
  but which itself still carries a valid hash for its own (possibly forged)
  content — was invisible to it. Startup now replays the entire rotation
  set, oldest file first, through the same streaming verifier `tg verify
  -file` uses, and refuses to start if any link is broken anywhere.
  (Append-only writes were already true via `O_APPEND`; this closes the
  "detect tampering on restart" half of the tamper-resistance promise. An
  "optional external ship" of audit records to a remote sink — the third
  piece the roadmap named — is not yet implemented.)
- **`tg hook -unknown-tools-deny`** — mirrors `tg-proxy`'s existing flag,
  now available at the coding-agent enforcement point that didn't have it.
  Denies any `tool_name` not declared in `scope.tool_names` of some loaded
  ENFORCEMENT policy (shadow-mode declarations don't count — nothing is
  actually enforcing on them yet), closing the gap where a new tool the
  agent starts calling matches no policy and is silently ungoverned. The
  shared check (`engine.ToolNameKnown`) moved from a `tg-proxy`-private
  function to `pkg/engine` so both entry points can't drift apart.
- **`tg hook -mode shadow` now actually observes instead of enforcing.**
  `evalHook` (`cmd/tg/hook.go`) branched on the engine's `Decision` (what
  WOULD happen) instead of `ActionTaken` (what actually happens) — the
  exact bug class this release's SDK fixes exist to close, present in the
  flagship coding-agent enforcement point itself. A shadow-mode policy
  sets `Decision=denied` alongside `ActionTaken=allowed_shadow`, but the
  hook emitted `permissionDecision: "deny"` regardless — since a
  PreToolUse `"deny"` IS enforced by the calling agent (Claude Code,
  Codex, etc.), `tg hook -mode shadow` silently enforced every policy
  instead of only observing near-misses. Found by an adversarial review
  pass run specifically to check whether the SDK's decision-vs-
  action_taken fix pattern was applied everywhere it needed to be — it
  wasn't. Fixed to switch on `ActionTaken`; regression-tested by
  `TestHook_ShadowMode_ObservesDoesNotEnforce`, confirmed to fail against
  the pre-fix code before landing the fix.
- **Real, quote-aware shell tokenizer replaces the "best-effort" scanner**
  behind `-protect-paths`/`-protect-self`'s shell-command detection
  (`shellTouchesProtected`). The old scanner used unquoted `strings.Fields`
  splitting and a one-pair `unquote()`; quoting, command substitution, and
  variable expansion all slipped through, and a quoted separator wrongly
  split one command into two. The new tokenizer is a real POSIX-shell-like
  grammar (quotes, backslash escapes, operators, redirections) that is a
  strict superset of the old scanner's detection, plus:
  - **Fails closed on unresolved expansion.** `$(...)`, `` `...` ``, `$VAR`,
    `${VAR}` are never evaluated — this is a deterministic, offline control
    with no access to the agent's real shell environment, so it cannot
    know what they expand to. A word carrying an unresolved expansion that
    lands in a redirect-target or mutating-command-argument position is
    treated as a hit, because it cannot be proven safe.
  - **Recurses into command substitution for side effects.** A write hidden
    inside a substitution whose *output* is discarded or reassigned
    (`echo $(rm /protected/f)`, `x=$(rm /protected/f)`) still executes the
    inner `rm` — the tokenizer now catches that, depth-bounded.
  - Found via an independent adversarial review during development (Codex
    was unavailable; Opus reviewed instead) and fixed before landing: an
    ANSI-C `$'...'` quote swallowing a trailing real redirect; a glued
    path-carrying option (`cp -t/protected`, `--target-directory=/protected`)
    bypassing literal-argument matching; and the command-substitution
    side-effect case above.
  - Documented, considered (not missed) limits: an unresolved `argv[0]`
    (`$CMD ...`) is not classified as mutating (leading `NAME=val`
    assignments ARE stripped first); `~` and glob expansion, `#` comments,
    and heredoc bodies are not specially parsed. The robust operator-side
    control — keep bash out of the write-capable policy scope; rely on the
    unconditional `-protect-paths` — is unaffected by any of this and
    still the recommended posture for anything that matters.

## [0.4.0] — 2026-07-20

Windows correctness fix for the path-comparison primitive four features
share, plus a release-process guard against the exact failure mode that let
v0.3.0's GitHub Release ship while `main` sat two days behind the tag. No new
policy surface.

- **`matchPathPrefix` now normalizes Windows-shaped paths before comparing.**
  `path_classify`, `write_classify`, `shell_classify`'s argv path lists, and
  `-protect-self`/`-protect-paths` all compare a canonicalized runtime
  candidate (OS-native separators — `\` on Windows) against a policy-authored
  prefix (conventionally `/`). Without normalization those never matched on
  Windows: an allow-list failed closed on everything (safe but useless), and
  — more seriously — a **deny-list failed open on everything, silently**.
  The fix is gated on the operand actually being shaped like an absolute
  Windows path (drive-letter or UNC), not an unconditional `\`→`/` rewrite:
  `\` is a legal literal character in a Unix filename, so an unconditional
  rewrite would misclassify a sibling file (e.g. `documents\secrets.txt`) as
  living inside an allowed `documents/` directory it never touches. Both
  directions are covered by new tests exercising hand-built backslash paths,
  so the regression is caught on any CI runner, not only a Windows one.
- **`windows-latest` added to the CI matrix.** Runs with `shell: bash`
  forced repo-wide in the workflow (Windows' default `pwsh` can't parse the
  bash syntax the existing gofmt/coverage steps use); `windows-latest` ships
  Git for Windows, which provides `bash`/`awk` on PATH.
- **`release.yml` now refuses to publish a release whose tag isn't reachable
  from `main`.** This is the first step of the workflow, before any
  build/publish work. It directly guards against the v0.3.0 incident: the
  tag was cut from a long-lived `release/vX.Y.Z` branch, and nobody
  fast-forwarded `main` to it, so the GitHub Release existed and worked while
  `main` — and every `blob/main/...` link the Release's own body points to
  (CHANGELOG.md, Release-Notes.md, README) — still showed the previous
  version. See the new [RELEASING.md](RELEASING.md) for the required order.

No breaking changes. Everything above is either a correctness fix
(Linux/macOS behavior is unchanged) or process tooling.

## [0.3.0] — 2026-07-12

Driven by our own machine-guard audit log (3,635 real tool calls: 67% bash,
then file writes and http — with file-writes and egress passing *ungoverned*).
0.3.0 extends the deterministic engine to cover them. No breaking changes; the
Enterprise boundary is unchanged (deny-only, no redaction/inference/signing).

- **`write_classify` condition leaf** — governs file-writing tools
  (write/edit/notebookedit/apply_patch/multiedit): `allowed_path_prefixes` /
  `denied_path_prefixes` (component-boundary + `*`/`**` wildcards, reusing the
  0.2.0 path canonicalization — absolute + unconditional symlink resolution,
  and array/nested edit shapes), `max_bytes` (runaway-write ceiling), and
  `denied_content_regex` (literal deny, **never** redaction). Fail-closed: a
  write whose path can't be confirmed inside the allow-list fires the rule —
  every canonical candidate (the lexical form and the symlink-resolved form)
  must independently match an allowed prefix, so a write through a symlink
  that only *looks* like it's inside the allowed root cannot escape it.
- **`http_classify` condition leaf** — governs the egress surface for
  http/fetch tools: `allowed_hosts` / `denied_hosts` (exact or `.suffix`
  match), `allowed_schemes`, `allowed_methods` / `denied_methods`,
  `allowed_ports` / `denied_ports`. Reads `parameters.url` (as `sql_classify`
  reads `parameters.sql`). Fail-closed on a missing/unparseable URL when an
  allow-list is set. Egress is one of the surfaces agents touch most and
  policies cover least — this closes that coverage gap.
- **`tg hook -audit-log PATH`** — the hook path now appends every decision to
  a SHA-256 hash-chained JSONL log (verify with `tg verify`), so the
  coding-agent guard leaves a tamper-evident record like `tg-proxy` does. Tail
  read keeps appends O(1) per call. Best-effort: an audit failure never
  changes the decision.
- **`tg coverage` verb** — measures what fraction of an agent's tool calls have
  ANY governing policy (scope-match), versus what passes only because nothing
  governs it. Reads a JSONL of envelopes *or* decision traces, so it runs
  straight against an existing audit log. Reports a coverage %, a per-tool
  breakdown, and the biggest ungoverned tools (the coverage gaps).
  `-min-coverage PCT` exits 3 for a CI gate; `-json` for machines. This is the
  metric the 0.3.0 spine is about — pointed at our own audit log it shows the
  gap 0.3.0 closes (http + apply_patch went from ungoverned to governed).
- Both new leaves are fail-closed classifiers and are refused under a `not:`
  node (negating a fail-closed check flips it fail-open), consistent with the
  other classifiers.

Deferred to a later 0.3.x: SQL-in-bash extraction (a false-negative machine
that would create illusory safety).

## [0.2.0] — 2026-07-02

Adds a rolling-window velocity mitigation for the one attack class the
0.1.0 battle-test left open (amount fragmentation), five new deterministic
operators, a batch policy-simulation verb, a first-class coding-agent hook
verb (`tg hook`), unconditional self-protection for policy files and audit
logs (`-protect-paths` / `-protect-self`), and a new lint heuristic that
flags write-scoped policies with no in-band path guard. No breaking changes —
every 0.1.0 policy and audit chain evaluates and verifies identically. The
Enterprise boundary is unchanged: no signing, no PII redaction, no semantic
classification beyond the existing opt-in `llm_classify`.

### `tg hook` — first-class PreToolUse guard for coding agents (`cmd/tg`)

- New `tg hook` verb replaces the hand-rolled `jq` shell adapters in
  `examples/coding-agent-guard/hooks` with a single binary that speaks the
  hook JSON contract Claude Code, OpenAI Codex, and Antigravity share.
- Reads one `{"tool_name":"…","tool_input":{"command":"…","file_path":"…",
  "path":"…"}}` JSON object from stdin, evaluates it against `-policy-dir`
  or `-policy`, and writes
  `{"hookSpecificOutput":{"hookEventName":"PreToolUse",
  "permissionDecision":"deny|ask|allow","permissionDecisionReason":"…"}}`
  to stdout. **Always exits 0** — a PreToolUse hook signals via JSON, never
  via exit code.
- Decision mapping: engine `denied` → `deny`, `escalated` → `ask`,
  everything else → `allow`.
- **Fail-open by default** (`-fail-closed` flips to deny globally;
  `-fail-closed-tools bash,write,edit,notebookedit` denies only for the
  named tools on error — the careful-operator default for coding agents).
  **Unattributable input** (malformed / oversized / unreadable stdin, where
  the tool can't be identified) fails **closed** whenever any fail-closed mode
  is engaged — an unparseable PreToolUse payload can't be proven
  non-destructive; only the pure default (no fail-closed flags) fails open on
  such input. stdin is capped at 1 MiB and read errors are surfaced, not
  silently treated as an empty call.
- The full `tool_input` is forwarded as parameters (not just three
  cherry-picked fields), so a write hidden in an array/nested-edit param is
  still seen by protected-path checks and policies.
- `-protect-paths` / `-protect-self` are wired here as well (see next
  section); they fire before policy evaluation.
- Usage:
  ```
  tg hook (-policy-dir DIR | -policy FILE) [-mode shadow|enforcement]
          [-agent-id NAME] [-fail-closed] [-fail-closed-tools bash,write,edit]
          [-protect-paths P1,P2] [-protect-self]
  ```

### `-protect-paths` / `-protect-self` — self-protection outside the policy (`cmd/tg` + `cmd/tg-proxy`)

An important insight from dogfooding: **any protection written inside a
policy is useless because the agent can just edit the policy**. The only
reliable self-protection is outside the policy, at operator-flag level.

- `engine.ViolatesProtectedPaths(env, prefixes)` is the shared primitive:
  it applies an unconditional pre-policy deny when a write-capable tool
  targets any of the supplied path prefixes. Runs before (and independently
  of) policy evaluation — a policy cannot disable it.
- **Canonicalization (hardened via adversarial review):** both the candidate
  path and every protected prefix are made absolute (relative paths resolve
  against the process CWD) and symlink-resolved on their longest existing
  ancestor, then matched in every combination. This closes the relative-path
  (`file_path: "policy.yaml"`) and symlink-traversal (`/tmp/link/x` where
  `/tmp/link → /protected`) bypasses. Array and one-level-nested edit params
  are extracted, not just flat `file_path`/`path`. (Byte-exact matching —
  case-insensitive filesystems and percent-encoded forms are out of scope.)
- **Write-capable tools** covered: `write`, `edit`, `notebookedit`,
  `multiedit`, `create`, and any unknown tool carrying a `file_path` / `path`
  parameter.  **Read-only tools** (`read`, `glob`, `grep`, `ls`, …) are
  explicitly excluded so protecting the policy directory does not break the
  agent's ability to read it.
- **Shell tools** (`bash`, `shell`, `run_command`, …) receive a
  best-effort heuristic covering redirect targets (`echo x > /protected/f`),
  `rm`, `tee`, `sed -i`, `dd of=`, `cp`, `mv`, and several others.
  **Known limitation:** quoting, variable expansion (`$VAR`), and command
  substitution (`$(…)`) are not resolved. An agent sophisticated enough to
  exploit those forms should have bash scoped out of the write-capable policy
  entirely, or the operator should rely on `-protect-paths` (which fires
  unconditionally regardless of policy content).
- `tg hook` flags:
  - `-protect-paths P1,P2` — comma list of path prefixes to protect.
  - `-protect-self` — automatically protects the `-policy-dir` / the
    directory containing `-policy`, and `$HOME/.claude`.
- `tg-proxy` flags:
  - `-protect-paths P1,P2` — same semantics.
  - `-protect-self` — protects `-policy-dir`, the `-audit-log` path, and the
    running binary's directory.
- When a violation is detected, the proxy returns **HTTP 403** with
  `decision=denied` and records a boundary-deny trace in the hash-chained
  audit log so `tg verify` remains intact.

### `writable-scope-no-self-protection` lint heuristic (`cmd/tg lint`)

- New lint heuristic (severity **warn**) fires when a policy's scope admits
  write-capable tools (`write`, `edit`, `notebookedit`, `bash`, `shell`,
  `run_command`, or an empty scope that matches everything) but no deny- or
  escalate-rule in the policy uses a `path_classify` leaf.
- The in-policy path guard is the best a policy author can do to protect
  sensitive paths; the robust fix is operator-side (`-protect-paths` /
  `-protect-self`) which the agent cannot edit away.  The lint heuristic is
  advisory (not an error) because many shell policies gate by regex
  intentionally.
- Does **not** fire on `policies/refund_cap.yaml` or
  `policies/refund_cap_strict.yaml` — both are scoped to `issue_refund` /
  `process_return`, which are not write-capable tools.
- Suppress it by adding a `path_classify` deny or escalate rule covering the
  policy dir and audit log, or by running the proxy / hook with
  `-protect-paths` / `-protect-self`.

### Velocity tracking — closes amount fragmentation (`tg-proxy`)

- New `-velocity-track` flag makes `tg-proxy` maintain a per-key sliding
  window of monetary actions and inject the trailing 1h/24h sum + count
  into `context.verified.agent_velocity.*` before evaluation. A policy
  then closes the bypass with an ordinary threshold rule
  (`field: context.verified.agent_velocity.monetary_sum_1h, operator: gt`),
  so **no new condition type or engine change** was needed — the schema
  already carried these fields; nothing computed them until now.
- The injected sum **includes the prospective call**, so a `> cap` rule
  denies the call that crosses the line. Only calls that actually proceed
  (allow / flag) are recorded into the window; denied and escalated
  attempts never inflate it.
- The proxy **never overwrites** a caller-supplied `agent_velocity` block
  — a deployment with a real ledger stays authoritative. `-velocity-track`
  is the out-of-the-box default for deployments that have none.
- `-velocity-key-by agent_id|session_id|org_id` (default `agent_id`).
  State is in-memory, bounded (100k keys, 30-min idle eviction) exactly
  like the rate limiter, and does not survive a restart. New
  `tg_proxy_velocity_keys` metric.
- The window aggregates on **server wall-clock time, not the client-supplied
  envelope timestamp** — an agent controls the envelope, so timing off it
  would let fragmented calls claim fake far-apart timestamps and dodge the 1h
  window. (Regression: `TestVelocity_IgnoresClientTimestamp`.)
- This is the mitigation the 0.1.0 battle-test flagged as missing
  (`docs/battle-test-results.md`: amount fragmentation, "no shipped
  mitigation"). New example policy `policies/refund_velocity_cap.yaml`
  (1h $ cap + 24h count ceiling, lint-clean). End-to-end integration test
  proves 10×$500 refunds allow to exactly $5,000 then deny, with
  independent per-agent windows and caller-supplied ledgers honored.

### New deterministic operators — `pkg/engine`

- `not_in`, `not_contains`, `starts_with`, `ends_with`, `exists`.
- `not_in` / `not_contains` fail **closed** on a missing field (an absent
  value is trivially "not in the allowlist" / "does not contain X"), so a
  deny rule cannot be dodged by omitting the field. Positive operators keep
  the historical no-fire-on-missing behavior. `exists` decides purely by
  presence (`value: true` = must exist, `false` = must be absent).
- Lets policies express a tool-substitution allowlist
  (`tool_name not_in [approved…] → deny`) or a required-justification gate
  (`parameters.reason exists false → deny`) without regex gymnastics.
- Registered across all four coupling points (domain constant, engine
  eval, load-time operand validation, CLI `unknown-operator` allowlist);
  the existing AST-coupling test guarantees none were missed.

### `tg simulate` — batch policy dry-run (CLI)

- `tg simulate (-policy-dir DIR | -policy FILE) -calls CALLS.jsonl` runs a
  whole policy set against a JSONL stream of envelopes and reports the
  decision breakdown, per-rule fire counts, and example envelope_ids per
  non-allow decision. Answers "what would this policy set do to yesterday's
  traffic?" before deploying, using the exact `engine.Evaluate` the proxy
  and `tg evaluate` use — so a simulate verdict cannot diverge from a live
  one.
- `-json` for machine-readable output, `-mode shadow|enforcement`,
  `-examples N`, and `-fail-on-deny` (exit 3 if any call denies — lets CI
  gate a policy change that would start denying real traffic). Malformed
  input lines are counted and skipped, never fatal. Reads stdin with
  `-calls -`.

### Tests

- `pkg/engine/operators_v2_test.go` — every new operator incl. the
  missing-field contract and a composite tool-substitution guard.
- `cmd/tg-proxy/velocity_test.go` — window aggregation, 24h pruning, hard
  per-key cap, keyed bounding/eviction.
- `cmd/tg-proxy/velocity_integration_test.go` — amount-fragmentation
  blocked end-to-end; independent windows; caller-supplied velocity
  honored.
- `cmd/tg/simulate_test.go` — decision/rule counting, exit-code contract,
  policy-dir loading, validation of a bad policy.
- Full suite green under `-race -count=1`, including the integration tag.

## [0.1.0] — 2026-06-09

Initial public release.

### Multimodal content-safety classifier — `pkg/llmguard` (new)

- New `llm_classify` condition type lets policies ask a local
  Ollama-served model (Gemma 4 multimodal by default) whether a
  generative prompt — text only or text+image — falls into a
  policy-configured forbidden category.
- The classifier prompt is deliberately framed as a routing /
  tagging task rather than "content safety" so the model classifies
  rather than refuses; an empty response is interpreted as
  `model_refused` and fires the deny.
- Fail-closed by default: timeout, network error, image-fetch
  failure, parse error, ambiguous response (confidence < 0.6), or
  unknown-label injection all deny.
- New example bundle `examples/content-gen/` covering image, audio,
  and text generators with three lint-clean policies and 16
  deterministic E2E assertions against a real Gemma 4 e4b. Average
  classifier latency ~600 ms.
- The classifier is single-model (one local Gemma). Multi-model
  ensemble voting and voice-print matching do not exist in any
  edition; PII redaction, compliance mappings, and evidence packs
  ship in the separate Tool Guard Enterprise platform, not in this
  repo — see docs/oss-vs-enterprise.md for the boundary.


### `tg-proxy` — runtime HTTP service

- Single binary that loads YAML policies from `-policy-dir`, exposes
  `POST /evaluate`, and writes every decision to a SHA-256
  hash-chained JSONL audit log.
- Operational endpoints: `GET /healthz` (liveness), `GET /readyz`
  (readiness, gated on at least one policy when `-fail-closed=true`),
  `GET /policies` (loaded set), `GET /metrics` (plain-text counters),
  `POST /reload` (also fires on `SIGHUP`).
- Audit log writer holds a mutex around the chain link so concurrent
  evaluations cannot interleave; `fsync` after every append.
- Resumes the chain tail across restarts by scanning the existing log
  on boot.
- Integration tests build the binary in a temp dir, launch it on a
  random free port, and assert the full HTTP contract.

### End-to-end sample app

- `examples/sample-app/` ships a Go refund tool, a hand-coded Go
  agent, and a `run.sh` that brings up the whole stack (`refund-tool`
  ← `tg-proxy` ← `agent`) with a strict policy, prints the live
  allow / deny / escalate flow, and runs `tg verify` on the resulting
  audit chain. `make sample` runs it.

### Real-LLM demo

- `examples/ollama-agent/` ships a Go agent that drives a local
  Ollama model (Gemma 4 e4b by default) through a real tool-use
  conversation. The model emits tool calls, `tg-proxy` evaluates,
  and on a block the model receives the policy note and adapts in
  the next turn — demonstrates the firewall behaviour against a
  genuine LLM, not a hand-coded loop. `make sample-ollama` runs it.

### Integration guide

- `docs/integration.md` covers running `tg-proxy` (with systemd unit
  and Kubernetes manifest), embedding the library in a Go service,
  and wiring the policy decision point into MCP servers, LangChain
  callbacks, AutoGen executors, and the Anthropic / OpenAI native
  tool-use loops.

### Engine — deterministic policy evaluation

- `pkg/engine.Evaluator` evaluates an `ActionEnvelope` against a slice of
  `Policy` and returns an `EvaluationResult` with decision, action taken,
  triggered rules, and primary citation.
- Operators: `eq`, `neq`, `gt`, `gte`, `lt`, `lte`, `in`, `contains`,
  `regex`, plus field-to-field `gt_field` / `lt_field`.
- Condition trees with `and` / `or` / `not` branches.
- Effects: `allow`, `flag`, `escalate`, `deny`. Severity
  hierarchy resolves competing rules deterministically. (There is
  no `redact` effect; scrub free text before it reaches the proxy.)
- Shadow mode preserves the would-be decision as a near-miss while
  letting the call proceed.
- Numeric coercion from string parameters (`"500.00"` → `500.0`) so
  agent SDKs that serialize numbers as strings cannot silently bypass
  amount-threshold rules.
- Zero I/O, zero external dependencies, safe for concurrent use.

### Audit — tamper-evident chain

- `pkg/audit.CanonicalTraceBytes` serializes a `DecisionTrace` to a
  byte-stable representation (locked at `CanonicalTraceVersion = "v1"`).
- SHA-256 hash chain with explicit `previous_trace_hash` linkage.
- `pkg/audit.VerifyChainFromReader` replays a JSONL stream and reports
  the first failure point. No database required.
- Timestamps are normalized to UTC before hashing so chains produced in
  one time zone verify identically in another.

### CLI — `tg`

Four verbs, documented exit codes:

| Verb | Exit |
|---|---|
| `tg evaluate` | 0 allow · 3 deny · 4 escalate · 0 allowed_shadow |
| `tg verify`   | 0 intact · 5 chain-broken |
| `tg lint`     | 0 no error · 6 error-severity findings present |
| `tg benchmark`| 0 always |
| All verbs | 1 internal error · 2 usage error |

Lint heuristics shipped (8):

- `structural-validation` — schema / shape errors (bad operator, malformed condition tree)
- `policy-scope-leak` — empty scope, runs on every call
- `scope-no-tool-group` — narrow scope vulnerable to tool substitution
- `amount-without-semantic-check` — structured-amount-only bypass risk
- `rule-missing-citation` — auditor traceability
- `rule-id-collision` — duplicate rule_id (breaks by-ID lookup)
- `invalid-regex-syntax` — regex that does not compile
- `unknown-operator` — operator the engine cannot evaluate

### Battle-test — real adversarial runs

- `cmd/battle-test/` drives a local LLM (Gemma 4 e4b via Ollama today)
  through three adversarial scenarios against the engine.
- `-temperature` and `-seed` flags for deterministic mode (regression /
  CI runs); defaults keep variety for surfacing new bypass shapes.
- Canonical results published in [`docs/battle-test-results.md`](docs/battle-test-results.md):
  5/5 blocked on direct semantic smuggling; 5/5 bypassed on tool
  substitution (mitigated by `tg lint scope-no-tool-group`) and
  amount fragmentation (no shipped mitigation — keep enforceable
  values in structured fields the policy reads).

### Documentation and hygiene

- `README.md` with quick start, scope boundary, real benchmark
  numbers, and pointers to both demo runners.
- Per-package `doc.go` for godoc / pkg.go.dev.
- `Dockerfile` (multi-stage, distroless-nonroot) at the repo root with
  `-ldflags` version injection.
- `tg version` and `tg-proxy -version` print the build tag via
  `runtime/debug.ReadBuildInfo`.
- `SECURITY.md` private disclosure policy with the HTTP attack surface
  enumerated.
- `CONTRIBUTING.md` contributor guide with the AST-coupling rule for
  new operators and the lint-heuristic naming convention.
- Apache 2.0 LICENSE and NOTICE.
- `.github/workflows/ci.yml` runs `vet + build + race + integration +
  coverage-floor` on Ubuntu and macOS, plus `govulncheck`.

### Example policies — notable changes

- `policies/refund_cap_strict.yaml`: tightened the
  `rule-reason-amount-consistency` regex from `\$?[1-9][0-9]{3,}` to
  `\$[0-9,]{3,}`. The original false-positived on any 4-digit run
  (e.g. order numbers like `ORD-9912`); the tighter version requires a
  `$` sign so it catches the amount-fragmentation pattern without
  collateral damage on order IDs / customer IDs. The
  `examples/ollama-agent/` demo demonstrates the correct behaviour
  against this rule.

### Semantic SQL classifier — `pkg/sqlguard`

- Four-dialect SQL classifier (`postgres`, `mysql`, `sqlite`, `mssql`)
  exposed through the `sql_classify` condition leaf. Pure-Go
  tokenizer-based `lite` implementation is the default; strict variants
  (`pg_query_go`, `tidb/parser`, `rqlite/sql`) are opt-in via the
  `pg_strict` / `mysql_strict` / `sqlite_strict` build tags and override
  the same dialect name through registry last-write-wins.
- `Require` predicates: `top_level_kinds`, `denied_top_level_kinds`,
  `no_dynamic_sql`, `no_program_exec`, `allowed_functions`,
  `no_functions`, `allowed_tables`, `denied_tables`,
  `allowed_function_classes`, `denied_function_classes`.
- Closes the CTE bypass class: `WITH x AS (SELECT 1) DELETE FROM users`
  is correctly classified as `DELETE`, not `SELECT`. Restricted
  Postgres dollar-quote tags to `[A-Za-z_][A-Za-z0-9_]*` per PG
  grammar. Unclosed comments / dollar-quotes at EOF surface as
  `UnclosedConstructError` and the classify call fails closed.
- Table extraction pass walks the tokenizer output, excludes CTE names,
  and feeds the `allowed_tables` / `denied_tables` predicates.
- Function-class registry loadable from a `tools.yaml` file via
  `-tools-yaml` (e.g. group `pg_read`, `pg_write`, `pg_admin` and
  match `allowed_function_classes` / `denied_function_classes`).

### Path / shell classifiers — `pkg/engine`

- `path_classify` predicate (`require:` block) with `clean_first`,
  `absolute_only`, `allowed_canonical_prefixes` /
  `denied_canonical_prefixes`, `deny_shell_metas` (with `include_backslash`
  for Linux-only mode), `resolve_symlinks`, `deny_on_resolve_failure`, and
  `max_path_length`.
- `shell_classify` predicate (`require:` block) with `argv0_allowlist`,
  `denied_argv_paths` for argv path arguments, `argv_deny_patterns`,
  `max_argc`, `resolve_symlinks` for symmetry, and `argv_env_pattern_deny`
  (default catches `env`/`sudo`/`nice`/`ionice`/`chroot`/`doas` envelopes
  used to relaunch a different binary).

### Diagnostic detail in audit chain

- `EvalConditionWithDetail` propagates the classifier's "why" string
  (`"sql_classify: top-level DELETE not in [SELECT]"`) into
  `RuleResult.Details` for the matched rule. AND-branch carries detail
  from the deepest informative sub-condition.

### Hardening — `tg-proxy`

- Per-agent token-bucket rate limiter (`-rate-limit-rps`,
  `-rate-limit-burst`, `-rate-limit-key-by`) with a bounded map
  (100k cap) and a 30-min idle eviction sweep.
- Approval flow with bounded escalation store (10k cap, LRU eviction of
  oldest resolved entries) and constant-time approver-token compare
  (`crypto/subtle.ConstantTimeCompare`).
- `-unknown-tools-deny` flag closes the tool-name-spoofing bypass class
  (`drop_tables`, `DROP_TABLE`, `drop_table_v2`); shadow-mode-aware so
  observed-only policies don't accidentally satisfy the gate.
- `-max-envelope-depth` (default 32) rejects pathologically nested
  JSON envelopes before the decoder runs.
- Audit log rotation via `-audit-rotate-bytes`; three fsync modes
  (`every` / `interval` / `none`) via `-audit-sync-mode`. `tg verify`
  walks the rotation set.

### `tg-proxy` source split

- `cmd/tg-proxy/main.go` split into `handlers.go`, `policy_loader.go`,
  `audit_chain.go`, `helpers.go`, `escalation.go`,
  `escalation_handlers.go`, `ratelimit.go`. main.go drops to ~300 LoC
  of startup/wiring.

### Engine validation

- `engine.ValidatePolicy` rejects nil operands for `eq` / `neq` and
  caps `**` wildcards at 2 per pattern to defeat glob amplification.
- Regex compile cache (`pkg/engine/regex_cache.go`) — patterns are
  compiled once at first use and reused across evaluations. The
  `tg_proxy_regex_cache_size` metric exposes the working set.

### Tests

- `pkg/audit` 87%+ statement coverage.
- `pkg/engine` 87%+ statement coverage.
- `pkg/sqlguard/lite` 66%+ — covers every attack class in the
  battle-test catalogue plus the CTE / dollar-quote / table-extraction
  regression tests.
- `pkg/sqlguard/mssql` 90%+.
- 28-assertion deterministic policy correctness suite
  (`examples/postgres-attack/test-policies.sh`) — every rule in
  both example policies exercised end-to-end against the proxy.
- 45-case and 56-case adversarial bruteforce suites
  (`bruteforce-policies.sh` + `bruteforce-adversarial.sh`) — 0
  bypasses with `-unknown-tools-deny` enabled.
- AST-coupling test guarantees new `domain.Operator` constants are
  registered with the CLI's `unknown-operator` allowlist.
- Golden tests pin lint warning names against the README and the public
  example policy. `TestGolden_LintStrictPolicyClean` pins the README's
  promise that `policies/refund_cap_strict.yaml` lints clean.
- Integration tests shell out the built `tg` binary and assert the exit
  code contract end-to-end.
- All tests pass with `-race -count=1`.

### Known limitations

- Qwen 3.x multilingual adversarial scenarios are not implemented;
  only Gemma 4 e4b is wired today.
- There is no gRPC variant of `tg-proxy`; the proxy exposes only
  the REST endpoints documented above.
- Strict SQL dialect parsers (pg_query_go, tidb/parser, rqlite/sql)
  are opt-in via build tags and add cgo / binary size. The default
  pure-Go `lite` tokenizer covers every attack class in the
  documented battle-test catalogue; the strict variants are for
  operators who already accept those build-time costs.

[Unreleased]: https://github.com/dimaggi-ai/tool-guard-core/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/dimaggi-ai/tool-guard-core/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/dimaggi-ai/tool-guard-core/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/dimaggi-ai/tool-guard-core/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/dimaggi-ai/tool-guard-core/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dimaggi-ai/tool-guard-core/releases/tag/v0.1.0
