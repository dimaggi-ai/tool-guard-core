# Tool Guard Core - Documentation

Comprehensive reference docs for installing, configuring,
authoring policies for, and operating Tool Guard Core.

## Start here

- [**Getting Started**](getting-started.md) - install, build, run
  your first policy in 5 commands.
- [**Architecture**](architecture.md) - how the engine, the audit
  chain, and the classifiers fit together.
- [**Creating Policies**](creating-policies.md) - full YAML schema
  with every operator and classifier.

## Operating

- [**Operating tg-proxy in production**](operating.md) - systemd unit, Kubernetes manifest, flag reference, metrics,
  policy lifecycle, backup, disaster recovery.
- [**Integration guide**](integration.md) - wiring the proxy into
  MCP servers, LangChain callbacks, AutoGen executors, native
  Anthropic / OpenAI tool-use loops.
- [**Escalation flow**](escalation.md) - the human-in-the-loop
  approval path, token configuration, audit semantics.

## Specific bundles

- [**Content-gen bundle walk-through**](content-gen-bundle.md) - the
  multimodal Gemma 4 classifier surface (image / audio / text gen).

## Policy assertion suites (CI)

- [**Policy protection in CI**](../.github/workflows/policy-protection.yml) - each push runs the no-LLM bundle suites against a live `tg-proxy`:
  finance (18), business-ops (26), and SQL/shell/path (28 + 45 + 56,
  all blocked in this suite). Reproduce locally with `make
  test-finance`, `make test-business`, `make test-postgres-full`, or
  `make test-policies` for all the no-Docker suites at once.

## Reference

- [**Battle-test results**](battle-test-results.md) - real adversarial
  numbers from Gemma 4 attacking a Tool Guard policy.
- [**Core vs Enterprise**](oss-vs-enterprise.md) - what ships in
  this repo, what the Enterprise platform adds, and what exists in
  neither edition.

## External

- [README](../README.md) - quick start + value prop.
- [CHANGELOG](../CHANGELOG.md) - release notes.
- [SECURITY](../SECURITY.md) - private vulnerability disclosure.
- [CONTRIBUTING](../CONTRIBUTING.md) - contributor guide.

---

Each page is self-contained; the order above is a suggested reading
path. If you find anything inaccurate or outdated, open an issue or PR.
