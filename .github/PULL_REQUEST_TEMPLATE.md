<!--
Thanks for opening a PR! A few things to check before requesting review:

1. Does `make build && make test && make integration` pass locally?
2. Does `make lint` (go vet) pass?
3. If you touched a classifier, did you add an attack-class test for the
   bypass class it closes?
4. If you renamed or removed an exported symbol, is the migration
   documented in CHANGELOG.md [Unreleased]?
5. For new lint heuristics, did you add a golden test pinning the rule
   name (see cmd/tg/golden_test.go)?
-->

## What this PR does

<!-- One paragraph. What surface changed, what behaviour is different. -->

## Why

<!-- The motivation. If this is a bypass fix, what envelope demonstrates
     it. If a new feature, what policy YAML now becomes expressible.
     If a refactor, what existing pain it removes. -->

## How to verify

<!-- The exact commands a reviewer should run. If a bypass fix, a
     curl + expected JSON response that proves it now fires. -->

```sh

```

## Checklist

- [ ] `make build && make test && make integration` pass locally
- [ ] `make lint` passes
- [ ] CHANGELOG.md [Unreleased] updated if user-visible
- [ ] New attack-class test added if this closes a bypass class
- [ ] Public docs updated if public API changed
- [ ] Followed CONTRIBUTING.md naming + commit-message conventions

## Related issues

<!-- Closes #123, refs #456 -->
