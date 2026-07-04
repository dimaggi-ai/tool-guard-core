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

func TestHTTPClassify_TrailingDotHost(t *testing.T) {
	// A trailing root dot must not dodge a denied host or an allow-list.
	deny := hc(&domain.HTTPClassify{Require: domain.HTTPRequire{DeniedHosts: []string{"evil.com"}}})
	if !EvalCondition(deny, map[string]interface{}{"parameters.url": "https://evil.com./x"}) {
		t.Error("trailing-dot host should still match the denied host")
	}
	allow := hc(&domain.HTTPClassify{Require: domain.HTTPRequire{AllowedHosts: []string{".example.com"}}})
	if EvalCondition(allow, map[string]interface{}{"parameters.url": "https://api.example.com./x"}) {
		t.Error("trailing-dot host under an allowed suffix should not fire")
	}
}

func TestHTTPClassify_UnknownPortFailsClosed(t *testing.T) {
	// allowed_ports is set but the URL uses a non-numeric/absent port we
	// can't resolve → fail closed.
	cond := hc(&domain.HTTPClassify{Require: domain.HTTPRequire{AllowedPorts: []int{443}}})
	if EvalCondition(cond, map[string]interface{}{"parameters.url": "https://ok.com/x"}) {
		t.Error("explicit https default port 443 should be allowed")
	}
	if !EvalCondition(cond, map[string]interface{}{"parameters.url": "ftp://ok.com/x"}) {
		t.Error("a scheme with no known default port should fail closed against allowed_ports")
	}
}

func TestHTTPClassify_SchemeRelativeFailsClosed(t *testing.T) {
	cond := hc(&domain.HTTPClassify{Require: domain.HTTPRequire{AllowedHosts: []string{"ok.com"}}})
	// A scheme-relative URL has an unverifiable destination when an
	// allow-list is set → fail closed even if the host looks allowed.
	if !EvalCondition(cond, map[string]interface{}{"parameters.url": "//ok.com/x"}) {
		t.Error("scheme-relative url with an allow-list set should fail closed (fire)")
	}
}

func TestHTTPClassify_UnknownMethodFailsClosed(t *testing.T) {
	cond := hc(&domain.HTTPClassify{Require: domain.HTTPRequire{AllowedMethods: []string{"GET"}}})
	// allowed_methods is set but the call carries no method → fail closed.
	if !EvalCondition(cond, map[string]interface{}{"parameters.url": "https://ok.com/x"}) {
		t.Error("allowed_methods set + missing method should fail closed (fire)")
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
