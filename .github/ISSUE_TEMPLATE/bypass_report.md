---
name: Policy bypass report
about: A tool call that should have been denied but reached the tool
title: "[BYPASS] "
labels: bypass, security
---

> ⚠️ **If this bypass involves a real production system, sensitive data,
> or active exploitation, DO NOT open a public issue. Email
> security@dimaggi.ai instead — see [SECURITY.md](../../SECURITY.md).**

## The bypass

<!-- A short description of what the agent / attacker did and why it
     should have been caught. -->

## The policy in force

```yaml
# Paste the policy YAML (or the relevant rule) that you expected to
# fire. Redact identifiers if needed.
```

## The envelope that bypassed

```json
{
  "envelope_id": "...",
  "tool_name": "...",
  "tool_group": "...",
  "parameters": { }
}
```

## Tool Guard's decision

<!-- The full `EvaluationResult` returned by `tg evaluate` or
     `POST /evaluate`. -->

```json

```

## Expected decision

<!-- What you expected to see and which rule should have caught it. -->

## Reproduce on a fresh checkout

```sh

```

## Environment

- Tool Guard version:
- Go version:
- Classifier(s) involved (sql_classify / path_classify / shell_classify / llm_classify):
- If `llm_classify`: Ollama model + version (`ollama show <model>`):

## Anything else

<!-- Bypass class (semantic smuggling / amount fragmentation / tool
     substitution / encoding / etc.), related bypasses, links to
     adversarial prompts. -->
