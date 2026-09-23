package engine

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
	"github.com/dimaggi-ai/tool-guard-core/pkg/llmguard"
)

// safeImageFetcher is the SSRF-hardened client used to fetch policy-
// supplied image URLs. Constructed lazily and reused across calls; the
// underlying *http.Client is safe for concurrent use.
var (
	safeImageFetcherOnce sync.Once
	safeImageFetcher     *llmguard.SafeFetchClient
)

func getSafeImageFetcher() *llmguard.SafeFetchClient {
	safeImageFetcherOnce.Do(func() {
		safeImageFetcher = llmguard.NewSafeFetchClient()
	})
	return safeImageFetcher
}

// llmClassifyClientCache memoises one llmguard.Client per Ollama
// endpoint so each /evaluate doesn't pay the cost of building a new
// HTTP client. Bounded — a hostile policy listing many distinct
// OllamaURL values cannot grow the map without bound.
var (
	llmClientCacheMu sync.Mutex
	llmClientCache   = map[string]*llmguard.Client{}
)

const llmClientCacheMaxEntries = 64

// llmHookMu protects llmClassifyHook against concurrent set/read from
// test goroutines and (eventually) operator reload paths.
var llmHookMu sync.RWMutex

// llmClassifyHook lets operators short-circuit the Ollama call —
// useful for tests, dry runs, or air-gapped environments. When set,
// the engine calls this function INSTEAD of dispatching to llmguard.
//
// The hook receives the prompt text, the optional image URL, and the
// forbidden-category list, and returns the classification verdict.
// Setting this to a stub allows the OSS test suite to exercise every
// llm_classify rule without a running Ollama.
//
// It is intentionally private: direct mutation bypasses llmHookMu and races
// with evaluation. Use SetLLMClassifyHook / GetLLMClassifyHook.
var llmClassifyHook func(ctx context.Context, prompt, imageURL string, forbidden []string, model string) (*llmguard.ClassifyResult, error)

// SetLLMClassifyHook sets the test hook under a mutex. Pass nil to
// clear.
func SetLLMClassifyHook(h func(ctx context.Context, prompt, imageURL string, forbidden []string, model string) (*llmguard.ClassifyResult, error)) {
	llmHookMu.Lock()
	llmClassifyHook = h
	llmHookMu.Unlock()
}

// GetLLMClassifyHook reads the current hook under a read-mutex.
func GetLLMClassifyHook() func(ctx context.Context, prompt, imageURL string, forbidden []string, model string) (*llmguard.ClassifyResult, error) {
	llmHookMu.RLock()
	h := llmClassifyHook
	llmHookMu.RUnlock()
	return h
}

func evalLLMClassifyWithDetail(s *domain.LLMClassify, fields map[string]interface{}) (bool, string) {
	if s == nil {
		return false, ""
	}
	// Resolve the prompt text from the envelope.
	rawPrompt, ok := resolveField(s.PromptField, fields)
	if !ok {
		return true, fmt.Sprintf("llm_classify: prompt field %q missing — fail closed", s.PromptField)
	}
	prompt, ok := rawPrompt.(string)
	if !ok {
		return true, fmt.Sprintf("llm_classify: prompt field %q is not a string (%T) — fail closed", s.PromptField, rawPrompt)
	}

	// Optional: image URL for multimodal classification.
	var imageURL string
	if s.ImageURLField != "" {
		if rawURL, ok := resolveField(s.ImageURLField, fields); ok {
			if u, ok := rawURL.(string); ok {
				imageURL = u
			}
		}
	}

	systemOne := s.Backend == domain.LLMBackendSystemOne
	model := s.Model
	if model == "" {
		model = "gemma4:e4b"
		if systemOne {
			model = llmguard.DefaultSystemOneModel
		}
	}
	timeout := time.Duration(s.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Test / dry-run hook path: skip the network call entirely.
	if h := GetLLMClassifyHook(); h != nil {
		res, err := h(ctx, prompt, imageURL, s.Forbidden, model)
		return interpretClassifyResult(res, err)
	}

	if systemOne {
		return evalSystemOneClassify(ctx, model, s.Forbidden, prompt)
	}

	endpoint := s.OllamaURL
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}
	classifier := getOrCreateClassifier(endpoint, model, s.Forbidden)

	// Multimodal path: fetch the image through the SSRF-hardened
	// client. Validation + dial-time private-IP block + no redirects
	// means an attacker-controlled URL cannot coerce the proxy into
	// hitting metadata endpoints or LAN services.
	imageBase64 := ""
	if imageURL != "" {
		b64, ferr := llmguard.FetchImageBase64(ctx, getSafeImageFetcher().HTTP, imageURL)
		if ferr != nil {
			// Don't include the URL in the audit detail — a
			// hostile policy could embed credentials or tokens.
			// Also don't propagate the underlying error message;
			// it can carry distinguishable DNS / TCP failure
			// modes useful for an internal port scan.
			return true, "llm_classify: image fetch failed — fail closed"
		}
		imageBase64 = b64
	}
	res, err := classifier.ClassifyPrompt(ctx, prompt, imageBase64)
	return interpretClassifyResult(res, err)
}

func interpretClassifyResult(res *llmguard.ClassifyResult, err error) (bool, string) {
	if err != nil {
		return true, fmt.Sprintf("llm_classify: %v — fail closed", err)
	}
	if res == nil {
		return true, "llm_classify: nil result — fail closed"
	}
	if res.Category == "safe" {
		return false, ""
	}
	// Every non-safe category fires the rule. Surface the reasoning
	// (the model's short justification) in the audit detail so an
	// operator can review WHY the call was denied.
	if res.Reasoning != "" {
		return true, fmt.Sprintf("llm_classify: category=%s confidence=%.2f reason=%s", res.Category, res.Confidence, res.Reasoning)
	}
	return true, fmt.Sprintf("llm_classify: category=%s confidence=%.2f", res.Category, res.Confidence)
}

func getOrCreateClassifier(endpoint, model string, forbidden []string) *llmguard.Classifier {
	llmClientCacheMu.Lock()
	defer llmClientCacheMu.Unlock()
	cli, ok := llmClientCache[endpoint]
	if !ok {
		// Cap reached: build a one-shot client and skip the cache.
		// Avoids unbounded growth from a hostile policy listing
		// many distinct OllamaURL values; the working set is
		// preserved for the legitimate endpoints already cached.
		if len(llmClientCache) >= llmClientCacheMaxEntries {
			return llmguard.NewClassifier(llmguard.NewClient(endpoint), model, forbidden)
		}
		cli = llmguard.NewClient(endpoint)
		llmClientCache[endpoint] = cli
	}
	return llmguard.NewClassifier(cli, model, forbidden)
}

// systemOneClients memoises one client per (base URL, API key) pair read
// from the environment, so a changed environment takes effect without a
// stale client.
var (
	systemOneClientMu sync.Mutex
	systemOneClients  = map[[2]string]*llmguard.SystemOneClient{}
)

func evalSystemOneClassify(ctx context.Context, model string, forbidden []string, prompt string) (bool, string) {
	cli, err := getSystemOneClient()
	if err != nil {
		return true, fmt.Sprintf("llm_classify: %v — fail closed", err)
	}
	res, err := llmguard.NewSystemOneClassifier(cli, model, forbidden).ClassifyPrompt(ctx, prompt)
	return interpretClassifyResult(res, err)
}

func getSystemOneClient() (*llmguard.SystemOneClient, error) {
	key := [2]string{llmguard.SystemOneBaseURLFromEnv(), os.Getenv(llmguard.EnvSystemOneAPIKey)}
	systemOneClientMu.Lock()
	defer systemOneClientMu.Unlock()
	if cli, ok := systemOneClients[key]; ok {
		return cli, nil
	}
	cli, err := llmguard.NewSystemOneClient(key[0], key[1])
	if err != nil {
		return nil, fmt.Errorf("%s: %w", llmguard.EnvSystemOneBaseURL, err)
	}
	// The environment is operator-controlled, so this map stays tiny;
	// the bound only guards against unbounded growth.
	if len(systemOneClients) >= llmClientCacheMaxEntries {
		return cli, nil
	}
	systemOneClients[key] = cli
	return cli, nil
}
