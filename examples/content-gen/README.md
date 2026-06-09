# content-gen — multimodal content-safety bundle

Three policies that close the **generative-AI tool surface**: image,
audio, and text generators. Each uses a hybrid approach — a fast
deterministic regex prefilter, then a Gemma 4 classifier (via local
Ollama) for the semantic gate.

| Policy | Tools gated | What it catches |
|---|---|---|
| `policies/image_gen_guard.yaml` | `generate_image`, `image_to_image`, `edit_image`, `inpaint_image` | CSAM, real-person deepfakes, weapons, copyrighted style (Studio Ghibli, Disney, Pixar), self-harm imagery, extremist content |
| `policies/audio_gen_guard.yaml` | `generate_audio`, `text_to_speech`, `clone_voice`, `generate_music`, `generate_song` | Voice cloning of named public figures, copyrighted lyrics, threats/harassment, self-harm, extremist audio, CSAM audio |
| `policies/text_gen_guard.yaml` | `generate_text`, `complete_chat`, `brainstorm`, `summarise` | Weapons instructions, self-harm instructions, extremist content, bio/chem synthesis, CSAM, hacking instructions |

All three policies lint clean (`tg lint`). 16 deterministic assertions
in `test-policies.sh` exercise every rule against a real Gemma 4.

## Why this bundle exists

Every other example bundle in this repo protects a **structured** tool
surface (SQL, shell, money, customer data, mass email). Generative AI
tools are different:

1. **The attack surface is unbounded**. Any free-text prompt can ask
   for any forbidden category. Regex denylists alone are brittle (the
   battle-test catalogue shows Gemma 4 paraphrasing past regex 60%+
   of the time).

2. **The risk is qualitatively different**. CSAM, deepfakes of
   politicians, copyrighted material, voice clones of CEOs — these
   are CVE-grade incidents, not policy violations.

3. **Off-the-shelf "model safety" is opaque and inconsistent**. The
   image generator's own safety tuning is internal to the vendor,
   un-auditable, and varies across models (Flux vs SD 3.5 vs DALL-E).
   Tool Guard runs an OPERATOR-CONTROLLED gate, OUTSIDE the
   generator, and writes every decision to the hash-chained audit
   log.

## Architecture

```
   ┌────────┐  prompt   ┌──────────┐  llm_classify   ┌──────────┐
   │ agent  │──────────▶│ tg-proxy │ ────────────────▶│  Gemma 4 │
   │ (LLM)  │  result   │          │ ◀── verdict ────│ via local │
   └────────┘ ◀─────────│          │                  │  Ollama  │
                        │          │  allow only      └──────────┘
                        │          ▼
                        │   image / audio / text generator
                        └──────────────────────────────────────
```

The classifier framing is deliberately a "routing" task, not "safety"
— this avoids Gemma's own safety filter refusing to engage. Empty
responses (Gemma's built-in refusal signal) are interpreted as
`model_refused` which fires deny (consistent with fail-closed).

## Run locally — two options

### Option A: standalone (just the proxy + your local Ollama)

```sh
# 1. From the repo root: build binaries and pull a multimodal Gemma.
make build
ollama pull gemma4:e4b

# 2. Start tg-proxy with the content-gen policies.
./bin/tg-proxy \
  -listen 127.0.0.1:19090 \
  -policy-dir ./examples/content-gen/policies \
  -audit-log /tmp/content-decisions.jsonl &

# 3. Run the 16 deterministic assertions against the live proxy.
bash examples/content-gen/test-policies.sh

# 4. Verify the resulting audit chain.
./bin/tg verify -file /tmp/content-decisions.jsonl
```

Expected outcome:

```
── RESULT: 16 passed, 0 failed ──
```

### Option B: full docker-compose stack (proxy + mock tools + ollama)

The docker-compose stack proves the **complete** flow end-to-end:
denied tool calls never reach the (mock) generator's logs.

```sh
# 1. Pull the Gemma model on the host (cached in a named volume).
ollama pull gemma4:e4b

# 2. Bring up the three-service stack:
#    - ollama        : runs the Gemma model
#    - tg-proxy      : the policy firewall (port 19091)
#    - tools         : mock image/audio/text generators (port 18091)
cd examples/content-gen
docker compose up --build

# 3. In another shell, run the assertion suite against the dockerised proxy.
#    (You are already in examples/content-gen/ from step 2.)
PROXY=http://127.0.0.1:19091/evaluate bash test-policies.sh

# 4. The assertion suite POSTs directly to /evaluate; it does NOT proxy
#    calls through to the tools service. To demonstrate the end-to-end
#    DENY-BEFORE-EXECUTION pattern, run the MCP bridge example against
#    the same proxy — the bridge gates a tools/call through /evaluate
#    and refuses to invoke the upstream tool on a deny:
docker compose logs tools | head    # should be empty when only the suite ran
```

The `tools/` mock binary logs every call it ACTUALLY receives. The
suite above sends envelopes to `/evaluate` and never reaches the
tools service. To prove the full chain (agent → proxy → tool only
on allow), use the MCP bridge example (`examples/mcp-server/`)
which receives the agent's `tools/call`, gates it through
`tg-proxy /evaluate`, and on a deny returns an error to the agent
without invoking the upstream tool.

Per-call latency is ~600-700 ms (Gemma 4 e4b on commodity hardware).
For higher throughput swap to `gemma4:e2b` (~250 ms) or for higher
accuracy `gemma4:12b` (~2-3 s).

## Customising the forbidden taxonomy

Each `llm_classify` rule lists its forbidden categories under
`forbidden:`. The classifier is told these are the ONLY allowed
non-"safe" labels — anything else the model returns is treated as
`unknown_label` and fires deny (label-injection defence).

```yaml
- rule_id: rule-image-llm-classify
  conditions:
    llm_classify:
      prompt_field: parameters.prompt
      image_url_field: parameters.source_image_url  # optional, multimodal
      model: gemma4:e4b
      timeout_seconds: 30
      forbidden:
        - csam
        - real_person_likeness
        - weapons
        - self_harm
        - copyrighted_style
        - extremist_content
```

The `image_url_field` is only used by image-edit / inpaint flows
where the source image is part of the policy decision. Drop it for
pure text-to-image generators.

## Known gaps on this surface

This bundle gives you a working content-gen firewall with a single
local Gemma plus the regex prefilter, structural caps, and the
hash-chained audit of every decision. What it does NOT have:
multi-model arbitration, a hosted classifier service, and
voice-print matching (these exist in no edition); PII redaction and
evidence-pack export ship in Tool Guard Enterprise, not in this
repo -- see [docs/oss-vs-enterprise.md](../../docs/oss-vs-enterprise.md).

## What this is *not*

- A substitute for the generator vendor's own safety tuning. Tool
  Guard is a SECOND, OPERATOR-CONTROLLED gate — defence in depth.
- A perfect filter. A single model can be fooled by novel
  adversarial paraphrases -- run `cmd/battle-test` against your own
  policies to measure how badly, on your prompts.
- A replacement for human review on high-stakes content. The
  `escalate` effect routes ambiguous calls to an approver workflow
  rather than auto-allowing.
