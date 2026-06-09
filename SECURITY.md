# Security Policy

Tool Guard Core is a runtime policy firewall — a tool whose entire purpose
is to enforce security controls. We take vulnerabilities in it seriously.

## Supported Versions

Until this project reaches `v1.0.0`, only the latest tagged release on
`main` receives security fixes. Older `v0.x.y` tags are best-effort.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.** Public
disclosure of an exploitable bypass before a fix is available puts every
Tool Guard adopter at risk.

Email a private report to:

```
security@dimaggi.ai
```

Please include:

1. A short description of the issue.
2. A minimal reproduction — ideally a `policies/*.yaml` file plus a
   tool-call JSON that demonstrates the failure mode when fed to
   `tg evaluate` or `tg lint`.
3. The output (or absence of output) you observed vs. what you expected.
4. Your assessment of the impact (silent bypass, denial of service,
   audit-chain integrity break, etc).
5. Optional: a suggested fix.

We will acknowledge receipt within **3 business days** and aim to ship a
fix or mitigation within **30 days** of confirmation, faster for
audit-chain integrity issues.

## Disclosure Timeline

Once a fix is available we coordinate disclosure with the reporter. By
default we publish a CVE-style advisory on the GitHub Security tab when
the patched release ships. Reporters are credited unless they request
anonymity.

## Scope

**In scope (please report):**

- The deterministic policy engine in `pkg/engine` — any condition tree,
  scope matcher, or effect resolver that produces the wrong decision for
  a well-formed envelope.
- The audit chain in `pkg/audit` — any path by which two byte-equal
  traces produce different hashes, or a tampered chain verifies as
  intact, or a valid chain verifies as tampered.
- The `tg` CLI in `cmd/tg` — any exit code that contradicts the
  documented contract (0 allow, 3 deny, 4 escalate, 5 chain-broken,
  6 lint-error), any input that crashes the binary instead of returning
  a structured error, any JSON output that differs from the documented
  shape.
- The `tg-proxy` HTTP service in `cmd/tg-proxy` — any path that lets a
  caller bypass policy evaluation, observe other tenants' traces,
  desynchronise the hash chain on disk, or crash the process via a
  crafted request body. The 1 MiB request-body cap is part of the
  contract; reports of "I sent a 10 MiB body and the proxy paniced"
  are in scope; reports of "the proxy accepted my 1 MiB body" are not.
- The `cmd/tg lint` heuristics — any false negative (a hazard the
  README or docs claim the linter catches, silently missed).

**Out of scope:**

- Downstream consumers (your application's policies, your audit storage
  backend, your secret management). Tool Guard's job is to enforce; the
  surrounding system is yours.
- Behavior under deliberate misconfiguration (e.g. `FAIL_CLOSED=false`
  in your proxy embedding code, or an audit storage backend that loses
  writes).
- Performance issues that are not also correctness issues. File these
  as regular GitHub issues.

## Known Limitations We Are Not Hiding

The deterministic engine cannot catch every adversarial pattern. See
[`docs/battle-test-results.md`](docs/battle-test-results.md) for the
published bypass table run live against Gemma 4. The two classes the OSS
engine does NOT block on its own:

- **Tool substitution** — an agent pivots from `issue_refund` to a
  sibling tool the policy author forgot to scope. Mitigation: `tg lint`
  warns with `scope-no-tool-group`.
- **Amount fragmentation** — an agent passes `amount: 100` but writes
  `"refund of $1000"` in the free-text reason field. The deterministic
  engine reads structured fields only. Mitigation: keep values that
  matter in structured fields the policy reads; free text is
  unenforced.

These are not vulnerabilities — they are documented limits of a
deterministic policy engine. Don't report them as security issues.
**Do** report a case where the engine misses a structured-field bypass
the README or docs claim it blocks.
