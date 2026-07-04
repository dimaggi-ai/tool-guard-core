package engine

import (
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

func hc(h *domain.HTTPClassify) domain.Condition { return domain.Condition{HTTPClassify: h} }

func TestHTTPClassify_AllowedHosts(t *testing.T) {
	cond := hc(&domain.HTTPClassify{Require: domain.HTTPRequire{
		AllowedHosts: []string{"api.internal", ".example.com"},
	}})
	cases := []struct {
		url  string
		fire bool
	}{
		{"https://api.internal/v1", false},
		{"https://api.example.com/x", false}, // suffix match
		{"https://example.com/x", false},     // .example.com matches bare too
		{"https://evil.com/x", true},         // not allowed
		{"https://notexample.com/x", true},   // suffix must be on a dot boundary
	}
	for _, c := range cases {
		got := EvalCondition(cond, map[string]interface{}{"parameters.url": c.url})
		if got != c.fire {
			t.Errorf("%s: fire=%v want %v", c.url, got, c.fire)
		}
	}
}

func TestHTTPClassify_DeniedHostsAndScheme(t *testing.T) {
	cond := hc(&domain.HTTPClassify{Require: domain.HTTPRequire{
		DeniedHosts:    []string{"169.254.169.254"}, // cloud metadata endpoint
		AllowedSchemes: []string{"https"},
	}})
	if !EvalCondition(cond, map[string]interface{}{"parameters.url": "http://169.254.169.254/latest/meta-data"}) {
		t.Error("denied host should fire")
	}
	if !EvalCondition(cond, map[string]interface{}{"parameters.url": "http://ok.com/x"}) {
		t.Error("non-https scheme should fire when only https is allowed")
	}
	if EvalCondition(cond, map[string]interface{}{"parameters.url": "https://ok.com/x"}) {
		t.Error("https to an un-denied host should not fire")
	}
}

func TestHTTPClassify_MethodAndPort(t *testing.T) {
	cond := hc(&domain.HTTPClassify{Require: domain.HTTPRequire{
		AllowedMethods: []string{"GET"},
		DeniedPorts:    []int{22, 25},
	}})
	if !EvalCondition(cond, map[string]interface{}{"parameters.url": "https://x.com", "parameters.method": "POST"}) {
		t.Error("disallowed method should fire")
	}
	if EvalCondition(cond, map[string]interface{}{"parameters.url": "https://x.com", "parameters.method": "get"}) {
		t.Error("allowed method (case-insensitive) should not fire")
	}
	if !EvalCondition(cond, map[string]interface{}{"parameters.url": "https://x.com:22/", "parameters.method": "GET"}) {
		t.Error("denied port should fire")
	}
}

func TestHTTPClassify_FailClosed(t *testing.T) {
	cond := hc(&domain.HTTPClassify{Require: domain.HTTPRequire{AllowedHosts: []string{"ok.com"}}})
	// Missing URL but an allow-list is set → fail closed.
	if !EvalCondition(cond, map[string]interface{}{}) {
		t.Error("missing url with an allow-list should fail closed (fire)")
	}
	// Unparseable URL → fire.
	if !EvalCondition(cond, map[string]interface{}{"parameters.url": "::::not a url"}) {
		t.Error("unparseable url should fire")
	}
	// No requirements at all → never fires.
	none := hc(&domain.HTTPClassify{})
	if EvalCondition(none, map[string]interface{}{"parameters.url": "https://anywhere.com"}) {
		t.Error("empty http_classify should not fire")
	}
}
