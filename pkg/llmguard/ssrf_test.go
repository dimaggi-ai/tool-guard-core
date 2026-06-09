package llmguard

import (
	"net"
	"strings"
	"testing"
)

func TestIsPublicUnicast_RejectsPrivateLoopbackLinkLocal(t *testing.T) {
	denied := []string{
		"127.0.0.1",        // loopback
		"127.255.255.254",  // loopback range
		"10.0.0.5",         // RFC1918
		"10.255.255.255",   // RFC1918 boundary
		"172.16.0.1",       // RFC1918
		"172.31.255.254",   // RFC1918 boundary
		"192.168.1.1",      // RFC1918
		"169.254.169.254",  // AWS metadata (link-local)
		"100.64.0.1",       // RFC6598 CGNAT
		"100.127.255.254",  // CGNAT boundary
		"0.0.0.0",          // unspecified
		"224.0.0.1",        // multicast
		"::1",              // IPv6 loopback
		"fe80::1",          // IPv6 link-local
		"fc00::1",          // IPv6 unique-local
		"fd00::1",          // IPv6 unique-local
	}
	for _, s := range denied {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test data malformed: %s", s)
		}
		if isPublicUnicast(ip) {
			t.Errorf("expected %s to be REJECTED as non-public-unicast", s)
		}
	}

	allowed := []string{
		"8.8.8.8",
		"1.1.1.1",
		"172.15.0.1",       // just outside RFC1918
		"172.32.0.1",       // just outside RFC1918
		"100.128.0.1",      // just outside CGNAT
		"192.169.0.1",      // just outside 192.168/16
		"2001:4860:4860::8888", // public IPv6
	}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test data malformed: %s", s)
		}
		if !isPublicUnicast(ip) {
			t.Errorf("expected %s to be ALLOWED as public unicast", s)
		}
	}
}

func TestValidateImageFetchURL(t *testing.T) {
	bad := map[string]string{
		"":                            "empty",
		"ftp://example.com/x.png":     "scheme",
		"file:///etc/passwd":          "scheme",
		"javascript:alert(1)":         "scheme",
		"data:image/png;base64,XXX":   "scheme",
		"http://user:pass@host/x.png": "userinfo",
	}
	for raw, wantSub := range bad {
		err := ValidateImageFetchURL(raw)
		if err == nil {
			t.Errorf("expected error for %q", raw)
			continue
		}
		if !strings.Contains(err.Error(), wantSub) {
			t.Errorf("expected %q error to mention %q, got %q", raw, wantSub, err.Error())
		}
	}
	good := []string{
		"http://example.com/image.png",
		"https://cdn.example.com/img.jpg?w=64",
	}
	for _, raw := range good {
		if err := ValidateImageFetchURL(raw); err != nil {
			t.Errorf("expected no error for %q, got %v", raw, err)
		}
	}
}
