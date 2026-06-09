// Package llmguard adds a local-LLM content classifier to the Tool
// Guard engine. Policies can use the [LLMClassify] condition to ask a
// Gemma 4 (or any Ollama-served) model whether a prompt — or, for
// multimodal models, an image URL plus the prompt — falls into a
// configured forbidden category (CSAM, real-person likeness, weapons
// instructions, self-harm, etc.).
//
// Architecture
//
//   - Pure HTTP client against Ollama's /api/chat endpoint.
//   - Multimodal: Gemma 4's e2b/e4b/12b vision variants accept image
//     bytes inline. The client base64-encodes the image; the policy
//     names which Ollama model to use.
//   - Fail-closed: timeout / network / decode errors deny the call.
//     The integrity argument is "we cannot prove the prompt is safe,
//     therefore it is unsafe."
//   - Deterministic output: the classifier prompt asks the model to
//     return strict JSON `{"category":"...","confidence":0.0}`; the
//     evaluator parses, refuses ambiguous answers.
//
// Scope
//
// This package ships a single classifier (one local Ollama, single
// model). Multi-model arbitration and managed hosting do not exist
// in any edition; PII redaction ships in the commercial Tool Guard
// Enterprise platform, not in this module — see
// docs/oss-vs-enterprise.md for the boundary.
package llmguard
