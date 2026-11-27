package mainfloor

import (
	"strings"
	"testing"

	"github.com/dimaggi-ai/tool-guard-core/pkg/domain"
)

// TestHTTPClassify_DetailDoesNotEchoURL pins that the fail-closed details
// never contain the raw URL. Rule details reach the audit log, and a URL can
// carry a credential in its query string.
func TestHTTPClassify_DetailDoesNotEchoURL(t *testing.T) {
	const marker = "TOPSECRET123"
	h := &domain.HTTPClassify{Require: domain.HTTPRequire{AllowedHosts: []string{"ok.com"}}}
	for _, u := range []string{
		"evil.example/c?k=" + marker,   // no scheme, no host: unparseable branch
		"//evil.example/c?k=" + marker, // scheme-relative: no-scheme branch
	} {
		fired, detail := evalHTTPClassifyWithDetail(h, map[string]interface{}{"parameters.url": u})
		if !fired {
			t.Fatalf("%q: want the rule to fire (fail closed)", u)
		}
		if strings.Contains(detail, marker) || strings.Contains(detail, "evil.example") {
			t.Errorf("%q: detail echoes the url: %s", u, detail)
		}
	}
}
