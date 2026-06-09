package llmguard

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is a minimal Ollama /api/chat client tuned for content
// classification. Stateless, safe for concurrent use.
type Client struct {
	BaseURL string        // e.g. "http://localhost:11434"
	HTTP    *http.Client  // defaults to a 60s-timeout client
	Timeout time.Duration // request timeout; 60s default
}

// NewClient returns a client pointed at baseURL with a 60-second
// default timeout. Pass a custom http.Client for instrumentation.
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 60 * time.Second},
		Timeout: 60 * time.Second,
	}
}

// ChatRequest mirrors Ollama /api/chat. Format = "json" forces
// strict-JSON output from the model so the classifier can parse it
// without retries.
type ChatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Format   string    `json:"format,omitempty"`
	Stream   bool      `json:"stream"`
	Options  *Options  `json:"options,omitempty"`
}

// Message is one turn. For multimodal Gemma the Images field carries
// base64-encoded image bytes.
type Message struct {
	Role    string   `json:"role"`
	Content string   `json:"content"`
	Images  []string `json:"images,omitempty"`
}

// Options controls sampling. Defaults (temperature=0) make the
// classifier deterministic so the same prompt + image yields the
// same decision and the audit chain is reproducible.
type Options struct {
	Temperature float64 `json:"temperature"`
	NumCtx      int     `json:"num_ctx,omitempty"`
	NumPredict  int     `json:"num_predict,omitempty"`
}

// ChatResponse is the subset we read.
type ChatResponse struct {
	Message Message `json:"message"`
	Done    bool    `json:"done"`
}

// Chat posts a non-streaming chat request and returns the model's
// response message. Errors propagate verbatim — the caller decides
// fail-open vs fail-closed semantics.
func (c *Client) Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	req.Stream = false
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	url := c.BaseURL + "/api/chat"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama call: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<22)) // 4 MiB cap
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama HTTP %d: %s", resp.StatusCode, string(respBytes))
	}
	var out ChatResponse
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w; body=%s", err, string(respBytes))
	}
	return &out, nil
}

// EncodeImageBase64 wraps base64.StdEncoding for the Images field.
// Useful when the policy supplies a fetched image as raw bytes.
func EncodeImageBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
