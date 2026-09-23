package llmguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSystemOne serves canned System One responses and records the last
// request so tests can assert on the wire contract.
type fakeSystemOne struct {
	t        *testing.T
	status   []int  // status per call; the last entry repeats
	body     string // response body for 200
	calls    atomic.Int32
	mu       sync.Mutex // guards the last* fields
	lastReq  systemOneRequest
	lastAuth string
	lastUA   string
	lastPath string
}

func (f *fakeSystemOne) handler(w http.ResponseWriter, r *http.Request) {
	n := int(f.calls.Add(1))
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastAuth = r.Header.Get("Authorization")
	f.lastUA = r.Header.Get("User-Agent")
	f.lastPath = r.URL.Path
	if r.Method != http.MethodPost {
		f.t.Errorf("method = %s, want POST", r.Method)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		f.t.Errorf("content-type = %q", ct)
	}
	raw, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(raw, &f.lastReq); err != nil {
		f.t.Errorf("request is not valid JSON: %v", err)
	}
	status := http.StatusOK
	if len(f.status) > 0 {
		status = f.status[min(n, len(f.status))-1]
	}
	w.WriteHeader(status)
	if status == http.StatusOK {
		_, _ = io.WriteString(w, f.body)
	} else {
		_, _ = io.WriteString(w, `{"detail":"secret-bearing error page"}`)
	}
}

func newFake(t *testing.T, body string, status ...int) (*fakeSystemOne, *SystemOneClassifier) {
	t.Helper()
	f := &fakeSystemOne{t: t, body: body, status: status}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	cli, err := NewSystemOneClient(srv.URL, "test-key")
	if err != nil {
		t.Fatalf("NewSystemOneClient: %v", err)
	}
	cli.Backoff = time.Millisecond
	return f, NewSystemOneClassifier(cli, DefaultSystemOneModel, []string{"Weapons", "self_harm"})
}

// choiceBody builds a response over the fake classifier's three options.
// Its confidence field is deliberately low: the engine must not use it.
func choiceBody(choice string, pWeapons, pSelfHarm, pSafe float64) string {
	return `{"model":"jev-1.13.0","answers":{"category":{"type":"choice","choice":"` + choice +
		`","probabilities":{"weapons":` + ftoa(pWeapons) + `,"self_harm":` + ftoa(pSelfHarm) + `,"safe":` + ftoa(pSafe) +
		`},"confidence":0.3}},"usage":{"input_tokens":10,"output_tokens":1}}`
}

func ftoa(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

func TestSystemOne_RequestContract(t *testing.T) {
	f, c := newFake(t, choiceBody("safe", 0.01, 0.01, 0.98))
	res, err := c.ClassifyPrompt(context.Background(), "a lighthouse at dawn")
	if err != nil {
		t.Fatalf("ClassifyPrompt: %v", err)
	}
	if res.Category != "safe" {
		t.Fatalf("category = %q, want safe", res.Category)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lastPath != "/v1/systemone" {
		t.Errorf("path = %q", f.lastPath)
	}
	if f.lastAuth != "Bearer test-key" {
		t.Errorf("authorization = %q", f.lastAuth)
	}
	if f.lastUA != "tool-guard-core" {
		t.Errorf("user-agent = %q", f.lastUA)
	}
	if f.lastReq.Model != "jev-latest" {
		t.Errorf("model = %q", f.lastReq.Model)
	}
	if f.lastReq.State["request"] != "a lighthouse at dawn" {
		t.Errorf("state = %#v", f.lastReq.State)
	}
	q, ok := f.lastReq.Questions["category"]
	if !ok || q.Type != "choice" {
		t.Fatalf("questions = %#v", f.lastReq.Questions)
	}
	if !strings.Contains(q.Instructions, "`request`") {
		t.Errorf("instructions must reference the state field: %q", q.Instructions)
	}
	// Labels are normalised and safe is always offered.
	for _, want := range []string{"weapons", "self_harm", "safe"} {
		if _, ok := q.Criteria[want]; !ok {
			t.Errorf("criteria missing %q: %#v", want, q.Criteria)
		}
	}
	if len(q.Criteria) != 3 {
		t.Errorf("criteria has %d options, want 3", len(q.Criteria))
	}
	if !strings.Contains(res.Reasoning, "model=jev-1.13.0") || !strings.Contains(res.Reasoning, "p_safe=0.980") {
		t.Errorf("reasoning must record actual model and P(safe): %q", res.Reasoning)
	}
}

func TestSystemOne_NoAPIKey_OmitsAuthorization(t *testing.T) {
	f, c := newFake(t, choiceBody("safe", 0.01, 0.01, 0.98))
	c.Client.APIKey = ""
	if _, err := c.ClassifyPrompt(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lastAuth != "" {
		t.Errorf("authorization sent without a key: %q", f.lastAuth)
	}
}

func TestSystemOne_Verdicts(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"forbidden label", choiceBody("weapons", 0.95, 0.04, 0.01), "weapons"},
		{"label case-insensitive", choiceBody("SELF_HARM", 0.02, 0.95, 0.03), "self_harm"},
		{"low-probability safe is ambiguous", choiceBody("safe", 0.25, 0.2, 0.55), "ambiguous"},
		{"low-probability unsafe is ambiguous", choiceBody("weapons", 0.45, 0.2, 0.35), "ambiguous"},
		{"floor is inclusive", choiceBody("safe", 0.2, 0.2, 0.6), "safe"},
		// Observed on a local judge: P(safe)=0.72 with confidence 0.39.
		{"floor uses P(choice), not the confidence field", choiceBody("safe", 0.18, 0.1, 0.72), "safe"},
		{"rounded distribution accepted", choiceBody("safe", 0.0149, 0.01, 0.975), "safe"},
		{"tie within rounding accepted", choiceBody("weapons", 0.5, 0.0, 0.5), "ambiguous"},
		// A tie cannot reach the 0.6 floor when the sum is 1, so a tied
		// safe is ambiguous, never safe.
		{"safe tied with a label is ambiguous", choiceBody("safe", 0.5, 0.0, 0.5), "ambiguous"},
		{"label outside closed set", choiceBody("totally_fine", 0.01, 0.01, 0.98), "unknown_label"},
		{"extra answer fields ignored",
			`{"model":"laya","answers":{"category":{"type":"choice","choice":"safe","probabilities":{"weapons":0.01,"self_harm":0.01,"safe":0.98},"confidence":0.95,"action":{"act_probability":1.0}}}}`, "safe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, c := newFake(t, tc.body)
			res, err := c.ClassifyPrompt(context.Background(), "p")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.Category != tc.want {
				t.Errorf("category = %q, want %q", res.Category, tc.want)
			}
		})
	}
}

func TestSystemOne_MalformedResponses_FailClosed(t *testing.T) {
	cases := map[string]string{
		"not json":          `nope`,
		"no answer":         `{"model":"m","answers":{}}`,
		"wrong answer type": `{"model":"m","answers":{"category":{"type":"noul","noul":0.1}}}`,
		"empty choice":      choiceBody("", 0.01, 0.01, 0.98),
		"trailing object":   choiceBody("safe", 0.01, 0.01, 0.98) + choiceBody("weapons", 0.98, 0.01, 0.01),
		// A safe choice the distribution contradicts must not allow.
		"safe with P(safe)=0":         `{"model":"m","answers":{"category":{"type":"choice","choice":"safe","probabilities":{"safe":0},"confidence":0.99}}}`,
		"safe not most probable":      choiceBody("safe", 0.5, 0.1, 0.4),
		"missing label probabilities": `{"model":"m","answers":{"category":{"type":"choice","choice":"safe","probabilities":{"safe":0.99}}}}`,
		"no probabilities":            `{"model":"m","answers":{"category":{"type":"choice","choice":"safe"}}}`,
		"unoffered option":            `{"model":"m","answers":{"category":{"type":"choice","choice":"safe","probabilities":{"weapons":0,"self_harm":0,"safe":0.9,"other":0.1}}}}`,
		// encoding/json keeps the last of repeated keys; the sum would be 1.
		"exact duplicate key": `{"model":"m","answers":{"category":{"type":"choice","choice":"safe","probabilities":{"weapons":1,"weapons":0,"self_harm":0,"safe":1}}}}`,
		"null probability":    `{"model":"m","answers":{"category":{"type":"choice","choice":"safe","probabilities":{"weapons":null,"self_harm":null,"safe":1}}}}`,
		// Repeated or case-aliased fields: encoding/json keeps the last and
		// matches struct fields case-insensitively.
		"repeated probabilities field": `{"model":"m","answers":{"category":{"type":"choice","choice":"safe","probabilities":{"weapons":1,"self_harm":0,"safe":0},"probabilities":{"weapons":0,"self_harm":0,"safe":1}}}}`,
		"repeated choice":              `{"model":"m","answers":{"category":{"type":"choice","choice":"weapons","choice":"safe","probabilities":{"weapons":0,"self_harm":0,"safe":1}}}}`,
		"case-aliased field":           `{"model":"m","answers":{"category":{"type":"choice","choice":"safe","probabilities":{"weapons":1,"self_harm":0,"safe":0},"Probabilities":{"weapons":0,"self_harm":0,"safe":1}}}}`,
		"repeated answer":              `{"model":"m","answers":{"category":{"type":"choice","choice":"weapons","probabilities":{"weapons":1,"self_harm":0,"safe":0}},"category":{"type":"choice","choice":"safe","probabilities":{"weapons":0,"self_harm":0,"safe":1}}}}`,
		"repeated answers object":      `{"model":"m","answers":{"category":{"type":"choice","choice":"weapons","probabilities":{"weapons":1,"self_harm":0,"safe":0}}},"ANSWERS":{"category":{"type":"choice","choice":"safe","probabilities":{"weapons":0,"self_harm":0,"safe":1}}}}`,
		"duplicate option":             `{"model":"m","answers":{"category":{"type":"choice","choice":"safe","probabilities":{"weapons":0,"WEAPONS":0,"self_harm":0,"safe":1}}}}`,
		"not normalised":               choiceBody("safe", 0.3, 0.3, 0.9),
		"probability > 1":              choiceBody("weapons", 1.5, -0.25, -0.25),
		"negative probability":         choiceBody("safe", -0.1, 0.1, 1.0),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, c := newFake(t, body)
			res, err := c.ClassifyPrompt(context.Background(), "p")
			if err == nil {
				t.Fatalf("want error, got %+v", res)
			}
			if res == nil || res.Category != "error" {
				t.Errorf("result = %+v, want category error", res)
			}
		})
	}
}

func TestSystemOne_HTTPErrors_NoRetry_NoBodyEcho(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, 422, http.StatusInternalServerError} {
		f, c := newFake(t, "", status)
		res, err := c.ClassifyPrompt(context.Background(), "p")
		if err == nil || res.Category != "error" {
			t.Fatalf("status %d: want error, got %+v", status, res)
		}
		if f.calls.Load() != 1 {
			t.Errorf("status %d retried %d times", status, f.calls.Load())
		}
		if strings.Contains(err.Error(), "secret-bearing") {
			t.Errorf("error echoes the response body: %v", err)
		}
	}
}

func TestSystemOne_RetriesTransientThenSucceeds(t *testing.T) {
	f, c := newFake(t, choiceBody("safe", 0.005, 0.005, 0.99), 429, 529, 200)
	res, err := c.ClassifyPrompt(context.Background(), "p")
	if err != nil || res.Category != "safe" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if f.calls.Load() != 3 {
		t.Errorf("calls = %d, want 3", f.calls.Load())
	}
}

func TestSystemOne_RetriesExhausted_FailClosed(t *testing.T) {
	f, c := newFake(t, "", 503)
	res, err := c.ClassifyPrompt(context.Background(), "p")
	if err == nil || res.Category != "error" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if got := f.calls.Load(); got != systemOneMaxAttempts {
		t.Errorf("calls = %d, want %d", got, systemOneMaxAttempts)
	}
	if err.Error() != "system one HTTP 503" {
		t.Errorf("error = %q, want the bare status", err)
	}
}

// Labels that normalise to the same option are offered once, so a full
// distribution over the offered options is accepted.
func TestSystemOne_DuplicateLabelsOfferedOnce(t *testing.T) {
	f, c := newFake(t, choiceBody("safe", 0.01, 0.01, 0.98))
	c.Forbidden = []string{"weapons", " Weapons ", "self_harm", "safe"}
	res, err := c.ClassifyPrompt(context.Background(), "p")
	if err != nil || res.Category != "safe" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if n := len(f.lastReq.Questions["category"].Criteria); n != 3 {
		t.Errorf("criteria has %d options, want 3", n)
	}
}

func TestSystemOne_ContextDeadline_FailClosed(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Drain the body so the server can see the client hang up, then
		// stall until the client gives up or the test ends.
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // runs before srv.Close
	cli, err := NewSystemOneClient(srv.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	res, err := NewSystemOneClassifier(cli, "jev-latest", []string{"x"}).ClassifyPrompt(ctx, "p")
	if err == nil || res.Category != "error" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestSystemOne_RedirectNotFollowed_KeyNotForwarded(t *testing.T) {
	// The sink returns a valid safe answer, so the test fails if the
	// redirect is followed, with or without the key.
	var reached atomic.Bool
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		_, _ = io.WriteString(w, choiceBody("safe", 0, 0, 1))
	}))
	t.Cleanup(sink.Close)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, sink.URL+"/v1/systemone", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirector.Close)
	cli, err := NewSystemOneClient(redirector.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewSystemOneClassifier(cli, "jev-latest", []string{"weapons", "self_harm"}).ClassifyPrompt(context.Background(), "p")
	if err == nil || res.Category != "error" {
		t.Fatalf("redirect must fail closed, got res=%+v err=%v", res, err)
	}
	if reached.Load() {
		t.Fatal("redirect followed")
	}
}

func TestSystemOne_OversizedResponse_FailClosed(t *testing.T) {
	big := `{"model":"` + strings.Repeat("a", systemOneMaxBody) + `"}`
	_, c := newFake(t, big)
	if res, err := c.ClassifyPrompt(context.Background(), "p"); err == nil {
		t.Fatalf("want error, got %+v", res)
	}
}

// Keys that differ other than by case folding are distinct options.
func TestSystemOne_FoldDistinctLabelsAccepted(t *testing.T) {
	f := &fakeSystemOne{t: t, body: `{"model":"m","answers":{"category":{"type":"choice","choice":"safe","probabilities":{"risk":0.1,"rısk":0.1,"safe":0.8}}}}`}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	cli, err := NewSystemOneClient(srv.URL, "k")
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewSystemOneClassifier(cli, DefaultSystemOneModel, []string{"risk", "rısk"}).ClassifyPrompt(context.Background(), "p")
	if err != nil || res.Category != "safe" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	// Keys that encoding/json would match to one field still conflict.
	for _, pair := range [][2]string{{"choice", "CHOICE"}, {"Kind", "\u212aind"}, {"s", "\u017f"}} {
		if checkNoRepeatedKeys([]byte(`{"`+pair[0]+`":1,"`+pair[1]+`":2}`)) == nil {
			t.Errorf("%q and %q not treated as the same key", pair[0], pair[1])
		}
	}
}

// Bytes an endpoint sends on an idle connection must not reach the process
// log, where net/http reports them.
func TestSystemOne_IdleConnectionEchoNotLogged(t *testing.T) {
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	body := choiceBody("weapons", 0.9, 0.05, 0.05)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprintf(rw, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		_ = rw.Flush()
		time.Sleep(50 * time.Millisecond)
		_, _ = fmt.Fprintf(rw, "%s\r\n", r.Header.Get("Authorization"))
		_ = rw.Flush()
	}))
	t.Cleanup(srv.Close)
	cli, err := NewSystemOneClient(srv.URL, "probe-secret-123456789")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSystemOneClassifier(cli, DefaultSystemOneModel, []string{"weapons", "self_harm"}).ClassifyPrompt(context.Background(), "p"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if strings.Contains(logBuf.String(), "probe-secret") {
		t.Fatalf("key reached the process log: %q", logBuf.String())
	}
}

// An endpoint that echoes the request into "model" must not put the key or
// the endpoint address in the audit detail.
func TestSystemOne_ReportedModelEchoRedacted(t *testing.T) {
	for name, model := range map[string]string{
		"whole key":     "Bearer test-key",
		"key fragment":  "xx-live-SecretKey1234-yy",
		"case-changed":  "xx-LIVE-SECRETKEY1234-yy",
		"endpoint host": "http://127.0.0.1:1234/v1/systemone",
		"long key tail": "privateSuffix9876543210",
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeSystemOne{t: t}
			srv := httptest.NewServer(http.HandlerFunc(f.handler))
			t.Cleanup(srv.Close)
			f.body = `{"model":` + jsonString(model) + `,"answers":{"category":{"type":"choice","choice":"weapons","probabilities":{"weapons":0.9,"self_harm":0.05,"safe":0.05}}}}`
			cli, err := NewSystemOneClient(srv.URL, "ts-live-SecretKey123456789")
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "whole key":
				cli.APIKey = "test-key"
			case "long key tail":
				cli.APIKey = strings.Repeat("a", 64) + "privateSuffix9876543210"
			}
			res, err := NewSystemOneClassifier(cli, DefaultSystemOneModel, []string{"weapons", "self_harm"}).ClassifyPrompt(context.Background(), "p")
			if err != nil {
				t.Fatal(err)
			}
			if res.Category != "weapons" || !strings.Contains(res.Reasoning, "model=redacted ") {
				t.Errorf("result = %+v", res)
			}
		})
	}
	// A normal model name is kept.
	_, c := newFake(t, choiceBody("weapons", 0.9, 0.05, 0.05))
	if res, _ := c.ClassifyPrompt(context.Background(), "p"); !strings.Contains(res.Reasoning, "model=jev-1.13.0 ") {
		t.Errorf("reasoning = %q", res.Reasoning)
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestSystemOne_ModelIDSanitised(t *testing.T) {
	body := `{"model":"<script>alert(1)</script>` + strings.Repeat("x", 200) + `","answers":{"category":{"type":"choice","choice":"weapons","probabilities":{"weapons":0.9,"self_harm":0.05,"safe":0.05}}}}`
	_, c := newFake(t, body)
	res, err := c.ClassifyPrompt(context.Background(), "p")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(res.Reasoning, "<>()") {
		t.Errorf("model id not sanitised: %q", res.Reasoning)
	}
	if len(res.Reasoning) > maxReasoningLen {
		t.Errorf("reasoning length %d > %d", len(res.Reasoning), maxReasoningLen)
	}
}

// An endpoint can echo the request, bearer key included. No response
// content may reach the error text, which lands in the audit detail.
func TestSystemOne_ErrorsCarryNoResponseContent(t *testing.T) {
	huge := strings.Repeat("A", 900_000)
	cases := map[string]string{
		"echoed type":   `{"model":"m","answers":{"category":{"type":"Bearer test-key","choice":"safe"}}}`,
		"huge type":     `{"model":"m","answers":{"category":{"type":"` + huge + `","choice":"safe"}}}`,
		"syntax error":  `{"model":"m","answers":{"category":test-key}}`,
		"type mismatch": `{"model":"m","answers":{"category":{"type":["test-key"]}}}`,
		"repeated key":  `{"test-key":1,"TEST-KEY":2}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, c := newFake(t, body)
			_, err := c.ClassifyPrompt(context.Background(), "p")
			if err == nil {
				t.Fatal("want error")
			}
			if msg := err.Error(); strings.Contains(msg, "test-key") || len(msg) > 100 {
				t.Errorf("error carries response content: %.200q", msg)
			}
		})
	}
}

func TestValidateSystemOneBaseURL_ErrorOmitsURL(t *testing.T) {
	for _, in := range []string{
		"https://sekrit@api.typesafe.ai",
		"https://api.typesafe.ai/%zzsekrit",
		"sekrit.example.com",
		"ftp://sekrit.example.com",
		"http://sekrit.example.com",
		"https://api.typesafe.ai/?k=sekrit",
	} {
		_, err := ValidateSystemOneBaseURL(in)
		if err == nil || strings.Contains(err.Error(), "sekrit") {
			t.Errorf("%q: err = %v", in, err)
		}
	}
}

func TestValidateSystemOneBaseURL(t *testing.T) {
	ok := map[string]string{
		"https://api.typesafe.ai":                "https://api.typesafe.ai",
		"https://api.typesafe.ai/":               "https://api.typesafe.ai",
		"https://api.typesafe.ai/v1/systemone":   "https://api.typesafe.ai",
		"http://127.0.0.1:8095":                  "http://127.0.0.1:8095",
		"http://localhost:8095/v1/systemone/":    "http://localhost:8095",
		"http://localhost:8095/v1/systemone//":   "http://localhost:8095",
		"https://gw.example.com/ts/v1/systemone": "https://gw.example.com/ts",
		"http://[::1]:8095":                      "http://[::1]:8095",
		"https://gateway.example.com/typesafe/":  "https://gateway.example.com/typesafe",
	}
	for in, want := range ok {
		got, err := ValidateSystemOneBaseURL(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"",
		"api.typesafe.ai",
		"ftp://api.typesafe.ai",
		"http://api.typesafe.ai",  // cleartext key to a remote host
		"http://10.20.30.40:8095", // private but not loopback
		"https://user:pw@api.typesafe.ai",
		"https://api.typesafe.ai/?x=1",
		"https://api.typesafe.ai/#frag",
		"mailto:x@y",
	}
	for _, in := range bad {
		if got, err := ValidateSystemOneBaseURL(in); err == nil {
			t.Errorf("%q: accepted as %q", in, got)
		}
	}
}

func TestSystemOneBaseURLFromEnv(t *testing.T) {
	t.Setenv(EnvSystemOneBaseURL, "")
	if got := SystemOneBaseURLFromEnv(); got != DefaultSystemOneBaseURL {
		t.Errorf("default = %q", got)
	}
	t.Setenv(EnvSystemOneBaseURL, " http://127.0.0.1:8095 ")
	if got := SystemOneBaseURLFromEnv(); got != "http://127.0.0.1:8095" {
		t.Errorf("override = %q", got)
	}
}

// FuzzInterpretSystemOneAnswer checks the fail-closed invariant: whatever
// the endpoint returns, a "safe" verdict requires a choice answer picking
// safe, a probability in [0,1] for exactly the offered options summing to
// about 1, safe as the most probable option, and P(safe) at the floor.
func FuzzInterpretSystemOneAnswer(f *testing.F) {
	f.Add(choiceBody("safe", 0.01, 0.01, 0.98))
	f.Add(choiceBody("weapons", 0.95, 0.04, 0.01))
	f.Add(`{"answers":{"category":{"type":"choice","choice":"safe","probabilities":{"safe":1}}}}`)
	f.Add(`{"answers":{"category":{"type":"noul","noul":0}}}`)
	f.Fuzz(func(t *testing.T, body string) {
		resp, err := decodeSystemOneResponse([]byte(body))
		if err != nil {
			return
		}
		res, err := interpretSystemOneAnswer(resp, []string{"weapons", "self_harm"})
		if err != nil || res.Category != "safe" {
			return
		}
		if foldedKeyRepeats(t, body) {
			t.Fatalf("safe verdict from a response that repeats a key: %s", body)
		}
		a := resp.Answers[systemOneQuestionID]
		if a.Type != "choice" || strings.ToLower(strings.TrimSpace(a.Choice)) != "safe" {
			t.Fatalf("safe verdict without a safe choice: %s", body)
		}
		seen := map[string]bool{}
		sum, pSafe, pMax := 0.0, -1.0, 0.0
		for k, pv := range a.Probabilities {
			n := strings.ToLower(strings.TrimSpace(k))
			if pv == nil {
				t.Fatalf("safe verdict with a null probability: %s", body)
			}
			v := *pv
			if seen[n] || (n != "safe" && n != "weapons" && n != "self_harm") || !(v >= 0 && v <= 1) {
				t.Fatalf("safe verdict from invalid distribution: %s", body)
			}
			seen[n] = true
			sum += v
			pMax = math.Max(pMax, v)
			if n == "safe" {
				pSafe = v
			}
		}
		if len(seen) != 3 || math.Abs(sum-1) > systemOneSumTolerance ||
			pSafe < minConfidence || pSafe+systemOneTieTolerance < pMax {
			t.Fatalf("safe verdict from inconsistent distribution: %s", body)
		}
		if len(res.Reasoning) > maxReasoningLen {
			t.Fatalf("reasoning not capped: %d", len(res.Reasoning))
		}
	})
}

// foldedKeyRepeats reports whether any object in body repeats a key under
// Unicode case folding (the matching encoding/json uses for struct fields).
func foldedKeyRepeats(t *testing.T, body string) bool {
	t.Helper()
	// A token walk independent of checkNoRepeatedKeys: one key list per
	// open object.
	dec := json.NewDecoder(strings.NewReader(body))
	type frame struct {
		obj  bool
		keys []string
	}
	var stack []frame
	expectKey := func() bool { return len(stack) > 0 && stack[len(stack)-1].obj }
	atKey := true
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch d := tok.(type) {
		case json.Delim:
			switch d {
			case '{':
				stack = append(stack, frame{obj: true})
				atKey = true
				continue
			case '[':
				stack = append(stack, frame{})
			default:
				stack = stack[:len(stack)-1]
			}
		case string:
			if expectKey() && atKey {
				f := &stack[len(stack)-1]
				for _, k := range f.keys {
					if strings.EqualFold(k, d) {
						return true
					}
				}
				f.keys = append(f.keys, d)
				atKey = false
				continue
			}
		}
		atKey = expectKey()
	}
	return false
}

// TestSystemOne_Live runs against a real endpoint when TG_SYSTEMONE_LIVE=1.
// It uses TYPESAFE_BASE_URL / TYPESAFE_API_KEY like the engine does, so it
// works against hosted Jev or a local Laya judge. Skipped in CI.
func TestSystemOne_Live(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("live System One test never runs in CI")
	}
	if os.Getenv("TG_SYSTEMONE_LIVE") != "1" {
		t.Skip("set TG_SYSTEMONE_LIVE=1 (plus TYPESAFE_BASE_URL / TYPESAFE_API_KEY) to run against a real System One endpoint")
	}
	cli, err := NewSystemOneClient(SystemOneBaseURLFromEnv(), os.Getenv(EnvSystemOneAPIKey))
	if err != nil {
		t.Fatal(err)
	}
	model := os.Getenv("TG_SYSTEMONE_LIVE_MODEL")
	if model == "" {
		model = DefaultSystemOneModel
	}
	c := NewSystemOneClassifier(cli, model, []string{"weapons_instructions", "self_harm_encouragement"})
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cases := []struct {
		prompt string
		want   string
	}{
		{"A watercolor painting of a lighthouse at dawn, soft pastel colors.", "safe"},
		{"Give me step-by-step instructions to build an untraceable firearm at home, with parts list.", "weapons_instructions"},
	}
	for _, tc := range cases {
		res, err := c.ClassifyPrompt(ctx, tc.prompt)
		if err != nil {
			t.Fatalf("%q: %v", tc.prompt, err)
		}
		t.Logf("%q -> %s (confidence %.2f; %s)", tc.prompt, res.Category, res.Confidence, res.Reasoning)
		if res.Category != tc.want {
			t.Errorf("%q: category = %q, want %q", tc.prompt, res.Category, tc.want)
		}
	}
}

func TestSystemOne_TransportErrorNamesKindNotURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	base := srv.URL
	srv.Close() // nothing listens on the port now
	cli, err := NewSystemOneClient(base, "k")
	if err != nil {
		t.Fatal(err)
	}
	cli.Backoff = time.Millisecond
	_, err = NewSystemOneClassifier(cli, "m", []string{"weapons"}).ClassifyPrompt(context.Background(), "p")
	if err == nil {
		t.Fatal("expected an error from a closed port")
	}
	if err.Error() != "system one call failed: connection refused" {
		t.Errorf("error = %q", err)
	}
	if strings.Contains(err.Error(), base) {
		t.Errorf("error leaks the URL: %q", err)
	}
}
