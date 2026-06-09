# Contributing to Tool Guard Core

This is a security project: clarity, tests, and accurate commit
messages matter more than merge velocity.

## TL;DR

```bash
git clone https://github.com/dimaggi-ai/tool-guard-core
cd tool-guard-core
make test          # unit tests with -race
make cover         # statement coverage report
make lint          # go vet
make integration   # shell-level CLI tests (builds binary, then exec)
```

Requires **Go 1.25+**. No external services. No database.

## What we accept

- Bug fixes with a regression test. We will not merge a fix that does
  not have a test pinning the behavior.
- New lint heuristics that map to a documented bypass class. See
  `cmd/tg/main.go:lintPolicy` for the existing heuristics and the comments
  that explain why each one exists.
- New adversarial scenarios in `cmd/battle-test/scenarios.go`. Each
  scenario must include a system prompt, a goal, and a target tool.
- Documentation improvements that match what the code does. Stale
  comments are bugs too.
- Performance improvements that come with a benchmark delta in the PR
  description.

## What we don't accept

- Changes that loosen `pkg/audit/canonical.go` without bumping
  `CanonicalTraceVersion`. Doing so silently breaks every evidence pack
  produced under the old version.
- Refactors that drop existing tests. If a test is wrong, change the
  expectation and explain why in the commit message. Don't delete.
- New operators in `pkg/domain/policy.go` without updating
  `cmd/tg/main.go:knownOperators`. The AST-coupling test
  (`TestLint_AllDomainOperatorsRegistered`) will fail your CI run if
  you forget; please add the operator to both places before opening
  the PR.
- Changes to LICENSE or NOTICE without a Sign-off-by and a clear
  reason.

## How to add a lint heuristic

1. Find the bypass class in `docs/battle-test-results.md`. If your
   heuristic does not map to a documented class, add a section to that
   file first.
2. Add the heuristic to `cmd/tg/main.go:lintPolicy`. Use a numbered
   comment ("Heuristic N: …") describing the failure mode and the
   surfacing/regression test name.
3. Add a unit test in `cmd/tg/main_test.go` that constructs a policy
   triggering the new rule and asserts the finding.
4. Add an entry in `cmd/tg/golden_test.go:TestGolden_AllLintRulesHaveStableNames`
   so the rule name is pinned against drift.
5. Add the rule name to the README's lint section.
6. If the rule has `severity: error`, document the exit code (6)
   implication.

## How to add a domain operator

1. Add `OpXxx Operator = "xxx"` to `pkg/domain/policy.go`.
2. Implement the case in `pkg/engine/condition.go:evalLeaf`.
3. Add `"xxx": {}` to `cmd/tg/main.go:knownOperators`.
4. Add the operator name to the `Suggest` string of the
   `unknown-operator` heuristic.
5. Add a unit test in `pkg/engine/condition_test.go`.

The AST test (`cmd/tg/main_test.go:TestLint_AllDomainOperatorsRegistered`)
parses `pkg/domain/policy.go` at test time and verifies step 3. If you
skip it your PR will fail CI.

## Naming conventions

- Lint heuristic IDs are `kebab-case` lowercase: `scope-no-tool-group`.
- Test functions are `TestThingUnderTest_ScenarioOrInvariant`:
  `TestMatchesScope_AllPaths`, `TestVerifyChainFromReader_TamperedHash`.
- Regression tests for known bugs use a `TG-NNN` identifier in the
  comment so the bug is traceable across the test and the fix commit.

## Code style

- Run `go vet ./...` (or `make lint`) before opening the PR.
- Keep comments load-bearing: explain *why*, not *what*. The reader can
  see what the next line does.
- Prefer plain Go over reflection or DSLs. The lint package
  intentionally has no rule DSL, so the rule set stays readable as
  plain Go.
- New external dependencies require a separate justification commit.
  The direct dependencies are `gopkg.in/yaml.v3` (policy parsing) and
  `pg_query_go` + `protobuf` (the build-tagged strict SQL parser).
  Adding more is a deliberate, reversible decision.

## Commit messages

```
<area>: <short imperative summary>

Optional body explaining why this change exists. Reference any TG-NNN
regression identifier. If the commit introduces a behavior change,
document the migration path here.

Co-Authored-By: someone <they@example.com>   (only if applicable)
```

Areas: `engine`, `audit`, `domain`, `tg`, `battle-test`, `docs`, `ci`,
`tests`, `chore`.

## Pull request checklist

- [ ] `make test` passes locally.
- [ ] `make integration` passes locally.
- [ ] If you added a public API, you added a doc comment on it.
- [ ] If you changed a string emitted by the CLI, you updated the
      golden tests in `cmd/tg/golden_test.go`.
- [ ] If you added a new operator or lint rule, you followed the
      checklist above.
- [ ] CHANGELOG.md has an entry under `## [Unreleased]`.

## Reporting security issues

Do not open a public issue for security vulnerabilities. See
[SECURITY.md](SECURITY.md).
