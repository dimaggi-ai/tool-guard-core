# PR64 classifier review follow-up

This follow-up adds tests and operating documentation to existing classifier
source. It changes no classifier, policy, hook, installer, dependency or
activation setting.

## Imported review tests

`pkg/engine/command_classify_review_test.go` reproduces Ronnie
(`mutebironald`)'s Go code supplied on 18 November 2026 in task 75 comment
6976396893, without changing its command strings or assertions. Its two test
functions and 21 named subtests account for the 23 passing test events in the
reviewer's log; these are not 23 separate functions. The imported file SHA-256 is
`9779876422db91b8ebe3633fdf66509519cb67ab8f52244515b2dd644b2dfc54`.
It uses the existing `commandReadCondition` helper. Commands are synthetic
strings passed to the classifier/condition; the tests do not execute them.
The separate mixed-read test pins whole-command classification and condition
behavior for supported `ls`/`pwd` plus a supported `gh` read: dispatch
classification is verified-read, while the stricter condition still matches.

## Historical mutation results, not a fresh campaign

Ronnie reported 602 mutants: 332 killed, 226 surviving and 44 that did not compile.
The 44 non-compiling mutants are not survivors; the earlier 270-survivor account
was incorrect. Of 226 survivors, 113 changed an answer on his corpus and 65 of
those admitted commands that should escalate. With his added tests, no
surviving mutant admitted more, 91 of 113 were killed, and 22 only made the
classifier stricter. Matching by description and line caused the rerun to
include 241 mutants. These numbers are attributed historical results, not a
new mutation campaign or a production safety guarantee.

## Scope and unfinished work

The original scope review covered 2960fc4. The merge-head 0e7fcf4 and merged
commit dc99b00 share a tree, but 45 intervening commits and 220 changed files
between 2960fc4 and 0e7fcf4 were outside that narrow scope review. The reviewer's
classifier/hook runs at dc99b00 are behavior evidence, not a retrospective
review of those changes.

Historical replay remains a separate unmet work item. The promised 276-command
corpus and custody authorization were not available in this follow-up. Do not
substitute synthetic tests, reconstruct private commands or label this task as
historical replay completion. Its source/custody and sanitized replay criteria
must be tracked separately; no private records are copied here.

Real-client behavior, native Windows/Linux qualification, installed hooks and
any policy activation remain separate from these source regressions. Exact-base
and candidate test commands/results belong in the PR receipt. Test success does
not grant runtime authority or change existing permission controls.
