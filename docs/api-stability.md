# Go API stability

Tool Guard checks every pull request against a committed export-data baseline
using Go's `golang.org/x/exp/apidiff` tool.

## Compatibility scope

Every importable Go package below `pkg/` is part of the reviewed public API:

- `pkg/audit`
- `pkg/domain`
- `pkg/engine`
- `pkg/llmguard`
- `pkg/policyload`
- `pkg/sqlguard` and its dialect subpackages

Commands under `cmd/`, executable examples, tests, and unexported identifiers
are outside the Go library compatibility promise. This repository is still
pre-1.0, so a reviewed breaking change can be accepted, but it must never land
silently.

## CI gate

Run the same check as CI with:

```bash
make api-check
```

The gate fails on additions as well as incompatible changes. That is
intentional: a new exported identifier also becomes support surface and needs
review.

## Accepting an intentional change

1. Read the `apidiff` report from `make api-check`.
2. Document the compatibility and migration impact in the issue, PR, and
   release notes. Avoid a new exported symbol when an existing API suffices.
3. Obtain the normal review required by `RELEASING.md`.
4. Refresh the baseline with `make api-update` and commit
   `api/go-api.current` in the same PR.
5. Re-run `make api-check`; it must be green.

Never refresh the baseline only to silence CI. The binary baseline is generated
export data; the human-reviewable evidence is the `apidiff` report and the
documented disposition in the PR.
